"""Local SentinelAI API for URL investigation and real model lifecycle operations."""

from __future__ import annotations

import csv
import json
import os
import re
import shutil
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

import ml.database as db
from ml.features import FEATURE_NAMES, extract_domain_group, extract_features
from ml.train import run_pipeline

ROOT_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT_DIR / "ml" / "data"
MODELS_DIR = ROOT_DIR / "ml" / "models"
REGISTRY_DIR = MODELS_DIR / "registry"
ACTIVE_POINTER = MODELS_DIR / "active_model.json"
ANALYSIS_HISTORY = DATA_DIR / "platform_scan_history.json"
MAX_UPLOAD_BYTES = 2 * 1024 * 1024 * 1024
MAX_HISTORY = 500
DATASET_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}\.csv$")
CLASS_LABELS = {
    "0": 0, "benign": 0, "legitimate": 0, "legit": 0,
    "1": 1, "phishing": 1, "malicious": 1,
}

app = FastAPI(title="SentinelAI Local Security Platform", version="1.0.0")
_model_lock = threading.RLock()
_active_model: Any = None
_active_version: str | None = None
_jobs: dict[str, dict[str, Any]] = {}
_jobs_lock = threading.RLock()


class InvestigationRequest(BaseModel):
    url: str = Field(min_length=1, max_length=4096)


class TrainingRequest(BaseModel):
    dataset: str = Field(default="dataset.csv", min_length=5, max_length=80)
    n_estimators: int = Field(default=20, ge=10, le=500)
    max_depth: int = Field(default=7, ge=2, le=40)


class ExtensionEventRequest(BaseModel):
    url: str = Field(min_length=1, max_length=4096)


class RegisterRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    name: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=6, max_length=128)
    two_factor_enabled: bool = Field(default=True)


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=1, max_length=128)


class TwoFactorVerifyRequest(BaseModel):
    temp_token: str = Field(min_length=5, max_length=128)
    code: str = Field(min_length=6, max_length=10)


class GoogleAuthRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    name: str = Field(min_length=1, max_length=100)
    avatar_url: str | None = None
    google_id: str | None = None


class SearchRecordRequest(BaseModel):
    query_url: str = Field(min_length=1, max_length=4096)
    risk_score: float = Field(ge=0.0, le=1.0)
    verdict: str = Field(min_length=1, max_length=50)
    features_summary: str | None = Field(default="")
    user_email: str | None = Field(default=None)


app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r".*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _extract_user(request: Request) -> dict[str, Any] | None:
    auth_header = request.headers.get("Authorization")
    token = None
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
    elif "sentinel_session" in request.cookies:
        token = request.cookies.get("sentinel_session")
    if token:
        return db.get_user_from_session(token)
    return None


def _safe_dataset_path(name: str) -> Path:
    if not DATASET_NAME.fullmatch(name):
        raise HTTPException(status_code=400, detail="Dataset name must be a simple .csv filename.")
    path = (DATA_DIR / name).resolve()
    if path.parent != DATA_DIR.resolve():
        raise HTTPException(status_code=400, detail="Dataset path is not allowed.")
    return path


def _normalise_label(value: Any) -> int | None:
    if value is None or pd.isna(value):
        return None
    return CLASS_LABELS.get(str(value).strip().lower())


def _valid_http_url(value: Any) -> bool:
    if not isinstance(value, str) or not value.strip() or len(value) > 4096:
        return False
    try:
        parsed = urlparse(value.strip())
        return parsed.scheme.lower() in {"http", "https"} and bool(parsed.hostname)
    except ValueError:
        return False


def validate_dataset(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Dataset was not found.")

    total = valid = invalid_urls = invalid_labels = 0
    duplicates = 0
    counts = {0: 0, 1: 0}
    sample: list[dict[str, Any]] = []
    sqlite_path = path.with_name(f".{path.stem}.{uuid.uuid4().hex}.validate.sqlite3")
    database = sqlite3.connect(sqlite_path)
    database.execute("CREATE TABLE seen (url TEXT PRIMARY KEY)")
    try:
        for chunk in pd.read_csv(path, dtype=str, chunksize=100_000, keep_default_na=False):
            columns = set(chunk.columns.str.strip().str.lower())
            if not {"url", "label"}.issubset(columns):
                raise HTTPException(status_code=422, detail="CSV must include url and label columns.")
            chunk.columns = chunk.columns.str.strip().str.lower()
            for row in chunk.itertuples(index=False):
                record = row._asdict()
                total += 1
                url = str(record.get("url", "")).strip()
                label = _normalise_label(record.get("label"))
                if label is None:
                    invalid_labels += 1
                    continue
                if not _valid_http_url(url):
                    invalid_urls += 1
                    continue
                try:
                    database.execute("INSERT INTO seen(url) VALUES (?)", (url.casefold(),))
                except sqlite3.IntegrityError:
                    duplicates += 1
                    continue
                valid += 1
                counts[label] += 1
                if len(sample) < 8:
                    sample.append({"url": url, "label": label})
            database.commit()
    except HTTPException:
        raise
    except (pd.errors.ParserError, UnicodeDecodeError, ValueError) as error:
        raise HTTPException(status_code=422, detail=f"Could not parse CSV: {error}") from error
    finally:
        database.close()
        sqlite_path.unlink(missing_ok=True)

    if total == 0:
        raise HTTPException(status_code=422, detail="Dataset contains no data rows.")
    return {
        "filename": path.name,
        "total_rows": total,
        "valid_rows": valid,
        "invalid_urls": invalid_urls,
        "invalid_labels": invalid_labels,
        "duplicate_urls": duplicates,
        "class_counts": {"benign": counts[0], "phishing": counts[1]},
        "has_both_classes": counts[0] > 0 and counts[1] > 0,
        "sample": sample,
    }


def _load_active_model() -> tuple[Any, str]:
    global _active_model, _active_version
    with _model_lock:
        if _active_model is not None and _active_version is not None:
            return _active_model, _active_version
        if ACTIVE_POINTER.exists():
            pointer = json.loads(ACTIVE_POINTER.read_text(encoding="utf-8"))
            version = pointer["version"]
            model_path = REGISTRY_DIR / version / "phishing_rf.joblib"
        else:
            version = "rf-20261104-183213"
            model_path = MODELS_DIR / "phishing_rf.joblib"
        if not model_path.is_file():
            raise HTTPException(status_code=503, detail="No trained model artifact is available.")
        _active_model = joblib.load(model_path)
        _active_version = version
        return _active_model, _active_version


def _append_history(report: dict[str, Any]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    try:
        history = json.loads(ANALYSIS_HISTORY.read_text(encoding="utf-8")) if ANALYSIS_HISTORY.exists() else []
    except (json.JSONDecodeError, OSError):
        history = []
    history = [report, *[item for item in history if item.get("url") != report["url"]]][:MAX_HISTORY]
    temp = ANALYSIS_HISTORY.with_suffix(".tmp")
    temp.write_text(json.dumps(history, ensure_ascii=False), encoding="utf-8")
    os.replace(temp, ANALYSIS_HISTORY)


def _investigate(
    url: str,
    source: str = "dashboard",
    user_id: int | None = None,
    user_email: str | None = None,
    client_ip: str | None = None,
) -> dict[str, Any]:
    value = url.strip()
    if not _valid_http_url(value):
        raise HTTPException(status_code=422, detail="Enter a valid http:// or https:// URL.")
    model, version = _load_active_model()
    feature_values = extract_features(value)
    probabilities = model.predict_proba([feature_values])[0]
    score = float(probabilities[1])
    parsed = urlparse(value)
    host = parsed.hostname.lower() if parsed.hostname else ""
    signals: list[dict[str, str]] = []
    if feature_values[3]:
        signals.append({"type": "ip_host", "severity": "high", "detail": "The URL uses a raw IP address instead of a hostname."})
    if feature_values[4]:
        signals.append({"type": "credential_delimiter", "severity": "high", "detail": "The URL contains an @ character that can obscure the destination host."})
    if not feature_values[7]:
        signals.append({"type": "transport_scheme", "severity": "medium", "detail": "The URL uses HTTP rather than HTTPS; certificate status is not checked."})
    if feature_values[10]:
        signals.append({"type": "suspicious_tld", "severity": "medium", "detail": "The hostname ends in a TLD present in the local high-abuse heuristic list."})
    if feature_values[9]:
        signals.append({"type": "sensitive_path_terms", "severity": "medium", "detail": "The path or query contains authentication, account, or payment terms."})
    if feature_values[6] >= 2:
        signals.append({"type": "subdomain_depth", "severity": "low", "detail": "The hostname has multiple subdomain levels."})
    report = {
        "id": uuid.uuid4().hex,
        "url": value,
        "hostname": host,
        "risk_score": score,
        "risk_level": "high" if score > 0.75 else "medium" if score >= 0.40 else "low",
        "prediction": "phishing" if score >= 0.5 else "benign",
        "model_version": version,
        "model_type": "RandomForestClassifier",
        "source": source,
        "probabilities": {"benign": float(probabilities[0]), "phishing": score},
        "feature_names": FEATURE_NAMES,
        "features": {name: value for name, value in zip(FEATURE_NAMES, feature_values)},
        "signals": signals,
        "limitations": [
            "The classifier and signals evaluate URL structure; they do not query remote reputation services.",
            "The HTTPS scheme is observed, but certificate validity and page behavior are not tested.",
        ],
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _append_history(report)
    try:
        db.record_search(
            query_url=value,
            risk_score=score,
            verdict="PHISHING" if score >= 0.5 else "BENIGN",
            features_summary=f"Risk: {report['risk_level'].upper()}, Model: {version}",
            user_id=user_id,
            user_email=user_email,
            ip_address=client_ip,
        )
    except Exception:
        pass
    return report


@app.get("/api/health")
def health() -> dict[str, Any]:
    _, version = _load_active_model()
    return {"status": "ok", "model_version": version, "feature_count": len(FEATURE_NAMES)}


@app.get("/api/overview")
def overview() -> dict[str, Any]:
    _, version = _load_active_model()
    history = json.loads(ANALYSIS_HISTORY.read_text(encoding="utf-8")) if ANALYSIS_HISTORY.exists() else []
    high = sum(item.get("risk_level") == "high" for item in history)
    return {
        "model_version": version,
        "investigations": len(history),
        "high_risk": high,
        "datasets": len(list(DATA_DIR.glob("*.csv"))),
        "recent_scans": history[:8],
    }


@app.post("/api/investigate")
def investigate(payload: InvestigationRequest, request: Request) -> dict[str, Any]:
    user = _extract_user(request)
    user_id = user["id"] if user else None
    user_email = user["email"] if user else None
    client_ip = request.client.host if request.client else None
    return _investigate(payload.url, user_id=user_id, user_email=user_email, client_ip=client_ip)


@app.post("/api/extension-events")
def extension_event(request: ExtensionEventRequest) -> dict[str, Any]:
    return _investigate(request.url, source="browser_extension")


@app.get("/api/history")
def history(limit: int = 100) -> dict[str, Any]:
    if not 1 <= limit <= MAX_HISTORY:
        raise HTTPException(status_code=422, detail=f"limit must be between 1 and {MAX_HISTORY}.")
    scans = json.loads(ANALYSIS_HISTORY.read_text(encoding="utf-8")) if ANALYSIS_HISTORY.exists() else []
    return {"items": scans[:limit]}


# --- Authentication & User Database Endpoints ---

@app.post("/api/auth/register")
def register(payload: RegisterRequest) -> dict[str, Any]:
    existing = db.get_user_by_email(payload.email)
    if existing:
        raise HTTPException(status_code=409, detail="An account with this email address already exists.")
    user = db.create_user(
        email=payload.email,
        name=payload.name,
        password=payload.password,
        auth_provider="local",
        two_factor_enabled=payload.two_factor_enabled,
    )
    if payload.two_factor_enabled:
        temp_token, code = db.create_2fa_challenge(user["id"])
        return {
            "require_2fa": True,
            "temp_token": temp_token,
            "message": "Account created! 2FA verification required.",
            "totp_secret": user.get("two_factor_secret"),
            "dev_code_hint": code,
        }
    token = db.create_session(user["id"])
    return {
        "require_2fa": False,
        "token": token,
        "user": {
            "id": user["id"],
            "email": user["email"],
            "name": user["name"],
            "role": user.get("role", "user"),
            "two_factor_enabled": bool(user.get("two_factor_enabled")),
        },
    }


@app.post("/api/auth/login")
def login(payload: LoginRequest) -> dict[str, Any]:
    user = db.get_user_by_email(payload.email)
    if not user or not user.get("password_hash"):
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    if not db.verify_password(payload.password, user["password_hash"], user["password_salt"]):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if user.get("two_factor_enabled"):
        temp_token, code = db.create_2fa_challenge(user["id"])
        return {
            "require_2fa": True,
            "temp_token": temp_token,
            "message": "Enter your 6-digit authentication security code.",
            "totp_secret": user.get("two_factor_secret"),
            "dev_code_hint": code,
        }

    token = db.create_session(user["id"])
    return {
        "require_2fa": False,
        "token": token,
        "user": {
            "id": user["id"],
            "email": user["email"],
            "name": user["name"],
            "role": user.get("role", "user"),
            "two_factor_enabled": False,
        },
    }


@app.post("/api/auth/2fa/verify")
def verify_2fa(payload: TwoFactorVerifyRequest) -> dict[str, Any]:
    user = db.verify_2fa_challenge(payload.temp_token, payload.code)
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired 2FA code.")
    token = db.create_session(user["id"])
    return {
        "token": token,
        "user": {
            "id": user["id"],
            "email": user["email"],
            "name": user["name"],
            "role": user.get("role", "user"),
            "two_factor_enabled": True,
        },
    }


@app.post("/api/auth/google")
def google_auth(payload: GoogleAuthRequest) -> dict[str, Any]:
    user = db.get_user_by_email(payload.email)
    if not user:
        user = db.create_user(
            email=payload.email,
            name=payload.name,
            auth_provider="google",
            avatar_url=payload.avatar_url or "https://lh3.googleusercontent.com/a/default-user",
            two_factor_enabled=False,
        )
    token = db.create_session(user["id"])
    return {
        "token": token,
        "user": {
            "id": user["id"],
            "email": user["email"],
            "name": user["name"],
            "role": user.get("role", "user"),
            "avatar_url": user.get("avatar_url"),
            "two_factor_enabled": bool(user.get("two_factor_enabled")),
        },
    }


@app.get("/api/auth/me")
def current_user(request: Request) -> dict[str, Any]:
    user = _extract_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated.")
    return {
        "user": {
            "id": user["id"],
            "email": user["email"],
            "name": user["name"],
            "role": user.get("role", "user"),
            "auth_provider": user.get("auth_provider"),
            "avatar_url": user.get("avatar_url"),
            "two_factor_enabled": bool(user.get("two_factor_enabled")),
            "last_login": user.get("last_login"),
        }
    }


@app.post("/api/auth/logout")
def logout(request: Request) -> dict[str, str]:
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
        db.delete_session(token)
    return {"status": "logged_out"}


# --- Database Search Logging & History Endpoints ---

@app.post("/api/user/searches")
def save_search_entry(payload: SearchRecordRequest, request: Request) -> dict[str, Any]:
    user = _extract_user(request)
    user_id = user["id"] if user else None
    user_email = user["email"] if user else (payload.user_email or "guest@local")
    client_ip = request.client.host if request.client else None
    search_id = db.record_search(
        query_url=payload.query_url,
        risk_score=payload.risk_score,
        verdict=payload.verdict,
        features_summary=payload.features_summary,
        user_id=user_id,
        user_email=user_email,
        ip_address=client_ip,
    )
    return {"status": "recorded", "search_id": search_id}


@app.get("/api/user/searches")
def get_user_searches(request: Request, limit: int = 50) -> dict[str, Any]:
    user = _extract_user(request)
    user_id = user["id"] if user and user.get("role") != "admin" else None
    searches = db.get_search_history(user_id=user_id, limit=limit)
    return {"searches": searches, "total": len(searches), "user": user}


@app.delete("/api/history")
def clear_history() -> dict[str, str]:
    ANALYSIS_HISTORY.unlink(missing_ok=True)
    return {"status": "cleared"}


@app.get("/api/datasets")
def datasets() -> dict[str, Any]:
    items = []
    for path in sorted(DATA_DIR.glob("*.csv")):
        items.append({"filename": path.name, "size_bytes": path.stat().st_size})
    return {"items": items}


@app.get("/api/datasets/{name}/validate")
def dataset_validation(name: str) -> dict[str, Any]:
    return validate_dataset(_safe_dataset_path(name))


@app.get("/api/datasets/{name}/rows")
def dataset_rows(name: str, offset: int = 0, limit: int = 100) -> dict[str, Any]:
    path = _safe_dataset_path(name)
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Dataset was not found.")
    if offset < 0 or not 1 <= limit <= 500:
        raise HTTPException(status_code=422, detail="offset must be non-negative and limit must be 1..500.")
    try:
        frame = pd.read_csv(path, dtype=str, skiprows=range(1, offset + 1), nrows=limit, keep_default_na=False)
    except (pd.errors.ParserError, UnicodeDecodeError, ValueError) as error:
        raise HTTPException(status_code=422, detail=f"Could not parse CSV: {error}") from error
    return {"offset": offset, "limit": limit, "columns": list(frame.columns), "items": frame.to_dict(orient="records")}


@app.put("/api/datasets/{name}")
async def upload_dataset(name: str, request: Request) -> dict[str, Any]:
    path = _safe_dataset_path(name)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".upload")
    size = 0
    try:
        with temporary.open("wb") as target:
            async for chunk in request.stream():
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES:
                    raise HTTPException(status_code=413, detail="CSV exceeds the 2 GiB upload limit.")
                target.write(chunk)
        if size == 0:
            raise HTTPException(status_code=422, detail="Uploaded CSV is empty.")
        os.replace(temporary, path)
        return {"filename": path.name, "size_bytes": size, "validation": validate_dataset(path)}
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


@app.post("/api/datasets/{name}/clean")
def clean_dataset(name: str) -> dict[str, Any]:
    source = _safe_dataset_path(name)
    if not source.is_file():
        raise HTTPException(status_code=404, detail="Dataset was not found.")
    output = source.with_name(f"{source.stem}_cleaned.csv")
    sqlite_path = source.with_name(f".{source.stem}.{uuid.uuid4().hex}.dedupe.sqlite3")
    database = sqlite3.connect(sqlite_path)
    database.execute("CREATE TABLE IF NOT EXISTS seen (url TEXT PRIMARY KEY)")
    total = kept = rejected = duplicates = 0
    try:
        with output.open("w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=["url", "label", "domain_group", "type"])
            writer.writeheader()
            for chunk in pd.read_csv(source, dtype=str, chunksize=100_000, keep_default_na=False):
                chunk.columns = chunk.columns.str.strip().str.lower()
                if not {"url", "label"}.issubset(chunk.columns):
                    raise HTTPException(status_code=422, detail="CSV must include url and label columns.")
                for row in chunk.to_dict(orient="records"):
                    total += 1
                    url = str(row.get("url", "")).strip()
                    label = _normalise_label(row.get("label"))
                    if label is None or not _valid_http_url(url):
                        rejected += 1
                        continue
                    try:
                        database.execute("INSERT INTO seen(url) VALUES (?)", (url.casefold(),))
                    except sqlite3.IntegrityError:
                        duplicates += 1
                        continue
                    group = str(row.get("domain_group", "")).strip() or extract_domain_group(url)
                    writer.writerow({
                        "url": url,
                        "label": label,
                        "domain_group": group,
                        "type": "phishing" if label else "benign",
                    })
                    kept += 1
                database.commit()
        counts = validate_dataset(output)
        if not counts["has_both_classes"]:
            output.unlink(missing_ok=True)
            raise HTTPException(status_code=422, detail="Cleaned dataset must contain both benign and phishing classes.")
        return {"filename": output.name, "total_rows": total, "kept_rows": kept, "rejected_rows": rejected, "duplicate_rows": duplicates, "validation": counts}
    finally:
        database.close()
        sqlite_path.unlink(missing_ok=True)
        Path(f"{sqlite_path}-journal").unlink(missing_ok=True)


def _update_job(job_id: str, **values: Any) -> None:
    with _jobs_lock:
        _jobs[job_id].update(values)


def _run_training(job_id: str, dataset_path: Path, estimators: int, max_depth: int) -> None:
    _update_job(job_id, status="running", progress=2, stage="Validating selected dataset")
    try:
        validation = validate_dataset(dataset_path)
        if not validation["has_both_classes"]:
            raise ValueError("Training requires both benign and phishing labels.")
        if min(validation["class_counts"].values()) < 10:
            raise ValueError("Training requires at least 10 valid samples from each class.")
        cleaned = clean_dataset(dataset_path.name)
        if not cleaned["validation"]["has_both_classes"]:
            raise ValueError("Cleaned training data does not contain both classes.")
        training_path = DATA_DIR / cleaned["filename"]

        model_version = f"rf-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{job_id[:6]}"
        version_dir = REGISTRY_DIR / model_version
        version_dir.mkdir(parents=True, exist_ok=False)

        def progress(message: dict[str, Any]) -> None:
            _update_job(job_id, **message)

        metadata = run_pipeline(
            str(training_path),
            str(version_dir),
            progress,
            n_estimators=estimators,
            max_depth=max_depth,
            model_version=model_version,
        )

        metadata["model_version"] = model_version
        metadata["dataset"]["source_file"] = dataset_path.name
        metadata["deployment"] = "active"
        metadata_path = version_dir / "model_metadata.json"
        metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

        with _model_lock:
            for filename in ("phishing_rf.joblib", "model_exported.js", "model_metadata.json"):
                source = version_dir / filename
                target = MODELS_DIR / filename
                temporary = target.with_suffix(target.suffix + ".tmp")
                shutil.copyfile(source, temporary)
                os.replace(temporary, target)
            pointer_temp = ACTIVE_POINTER.with_suffix(".tmp")
            pointer_temp.write_text(json.dumps({"version": model_version}), encoding="utf-8")
            os.replace(pointer_temp, ACTIVE_POINTER)
            global _active_model, _active_version
            _active_model = joblib.load(version_dir / "phishing_rf.joblib")
            _active_version = model_version

        _update_job(job_id, status="completed", progress=100, stage="Model exported and deployed", model_version=model_version, metrics=metadata["evaluation_metrics"])
    except Exception as error:
        _update_job(job_id, status="failed", stage="Training failed", error=str(error))


@app.post("/api/training")
def start_training(payload: TrainingRequest) -> dict[str, Any]:
    dataset_path = _safe_dataset_path(payload.dataset)
    if not dataset_path.is_file():
        raise HTTPException(status_code=404, detail="Selected training dataset was not found.")
    job_id = uuid.uuid4().hex
    with _jobs_lock:
        if any(job["status"] in {"queued", "running"} for job in _jobs.values()):
            raise HTTPException(status_code=409, detail="A training run is already active.")
        _jobs[job_id] = {"id": job_id, "status": "queued", "progress": 0, "stage": "Queued"}
    thread = threading.Thread(target=_run_training, args=(job_id, dataset_path, payload.n_estimators, payload.max_depth), daemon=True)
    thread.start()
    return {"job_id": job_id}


@app.get("/api/training/{job_id}")
def training_status(job_id: str) -> dict[str, Any]:
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Training job was not found.")
        return dict(job)


@app.get("/api/models")
def models() -> dict[str, Any]:
    _, active_version = _load_active_model()
    entries = []
    if (MODELS_DIR / "model_metadata.json").is_file():
        metadata = json.loads((MODELS_DIR / "model_metadata.json").read_text(encoding="utf-8"))
        metadata.setdefault("model_version", active_version)
        metadata["active"] = active_version == metadata["model_version"]
        entries.append(metadata)
    if REGISTRY_DIR.exists():
        for directory in sorted(REGISTRY_DIR.iterdir(), reverse=True):
            metadata_path = directory / "model_metadata.json"
            if metadata_path.is_file() and directory.name != active_version:
                metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
                metadata["active"] = directory.name == active_version
                entries.append(metadata)
    return {"active_version": active_version, "items": entries}


@app.get("/api/models/compare")
def compare_models(left: str, right: str) -> dict[str, Any]:
    all_models = models()["items"]
    lookup = {item["model_version"]: item for item in all_models}
    if left not in lookup or right not in lookup:
        raise HTTPException(status_code=404, detail="Both model versions must exist in the registry.")
    metrics = ("accuracy", "precision", "recall", "f1_score", "roc_auc", "pr_auc", "false_positive_rate", "false_negative_rate")
    return {
        "left": left,
        "right": right,
        "metrics": {
            metric: {
                left: lookup[left].get("evaluation_metrics", {}).get(metric),
                right: lookup[right].get("evaluation_metrics", {}).get(metric),
            }
            for metric in metrics
        },
    }


@app.get("/api/models/{version}/export")
def export_model(version: str) -> FileResponse:
    if not re.fullmatch(r"rf-[A-Za-z0-9-]{8,40}", version):
        raise HTTPException(status_code=400, detail="Invalid model version.")
    path = REGISTRY_DIR / version / "model_exported.js"
    if not path.is_file() and version == _load_active_model()[1]:
        path = MODELS_DIR / "model_exported.js"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="JavaScript model export was not found.")
    return FileResponse(path, media_type="text/javascript", filename=f"{version}.js")


@app.get("/")
def root_index() -> FileResponse:
    index_path = ROOT_DIR / "index.html"
    if index_path.is_file():
        return FileResponse(index_path)
    return FileResponse(ROOT_DIR / "dashboard" / "index.html")


@app.get("/favicon.ico")
def favicon() -> FileResponse:
    icon_path = ROOT_DIR / "icons" / "icon48.png"
    if icon_path.is_file():
        return FileResponse(icon_path, media_type="image/png")
    raise HTTPException(status_code=404, detail="Favicon not found.")


@app.get("/dashboard.css")
def root_dashboard_css() -> FileResponse:
    path = ROOT_DIR / "dashboard" / "dashboard.css"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="dashboard.css not found.")
    return FileResponse(path, media_type="text/css")


@app.get("/dashboard.js")
def root_dashboard_js() -> FileResponse:
    path = ROOT_DIR / "dashboard" / "dashboard.js"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="dashboard.js not found.")
    return FileResponse(path, media_type="text/javascript")


@app.get("/dashboard/{asset_path:path}")
def dashboard_asset(asset_path: str) -> FileResponse:
    dashboard_root = (ROOT_DIR / "dashboard").resolve()
    if not asset_path or asset_path == "index.html":
        return FileResponse(dashboard_root / "index.html")
    path = (dashboard_root / asset_path).resolve()
    if dashboard_root not in path.parents or not path.is_file():
        raise HTTPException(status_code=404, detail="Dashboard asset was not found.")
    mime_types = {
        ".css": "text/css",
        ".js": "text/javascript",
        ".html": "text/html",
        ".woff2": "font/woff2",
        ".png": "image/png"
    }
    media_type = mime_types.get(path.suffix)
    return FileResponse(path, media_type=media_type)


@app.get("/ml/{asset_path:path}")
def ml_asset(asset_path: str) -> FileResponse:
    ml_root = (ROOT_DIR / "ml").resolve()
    path = (ml_root / asset_path).resolve()
    # Security: ensure path stays within ml directory and only serves web assets (js, json, css)
    if ml_root not in path.parents or not path.is_file():
        raise HTTPException(status_code=404, detail="ML asset was not found.")
    if path.suffix not in {".js", ".json", ".css"}:
        raise HTTPException(status_code=403, detail="File type not permitted.")
    media_type = "text/javascript" if path.suffix == ".js" else "application/json" if path.suffix == ".json" else None
    return FileResponse(path, media_type=media_type)


@app.get("/assets/{asset_path:path}")
def site_asset(asset_path: str) -> FileResponse:
    assets_root = (ROOT_DIR / "assets").resolve()
    path = (assets_root / asset_path).resolve()
    if assets_root not in path.parents or not path.is_file():
        raise HTTPException(status_code=404, detail="Asset was not found.")
    mime_types = {
        ".css": "text/css",
        ".js": "text/javascript",
        ".woff2": "font/woff2",
        ".png": "image/png",
        ".svg": "image/svg+xml"
    }
    media_type = mime_types.get(path.suffix)
    if media_type is None:
        raise HTTPException(status_code=403, detail="File type not permitted.")
    return FileResponse(path, media_type=media_type)


@app.get("/icons/{asset_path:path}")
def icon_asset(asset_path: str) -> FileResponse:
    icons_root = (ROOT_DIR / "icons").resolve()
    path = (icons_root / asset_path).resolve()
    if icons_root not in path.parents or not path.is_file():
        raise HTTPException(status_code=404, detail="Icon was not found.")
    return FileResponse(path, media_type="image/png")


@app.get("/demo")
@app.get("/demo.html")
def demo_page() -> FileResponse:
    demo_path = ROOT_DIR / "demo.html"
    if not demo_path.is_file():
        raise HTTPException(status_code=404, detail="Demo page was not found.")
    return FileResponse(demo_path)


@app.get("/landing")
@app.get("/landing.html")
def landing_page() -> FileResponse:
    landing_path = ROOT_DIR / "landing.html"
    if not landing_path.is_file():
        raise HTTPException(status_code=404, detail="Landing page was not found.")
    return FileResponse(landing_path)


@app.get("/auth")
@app.get("/auth.html")
@app.get("/login")
@app.get("/login.html")
def auth_page() -> FileResponse:
    auth_path = ROOT_DIR / "auth.html"
    if not auth_path.is_file():
        raise HTTPException(status_code=404, detail="Auth page was not found.")
    return FileResponse(auth_path)


@app.get("/popup/{asset_path:path}")
def popup_asset(asset_path: str) -> FileResponse:
    popup_root = (ROOT_DIR / "popup").resolve()
    path = (popup_root / asset_path).resolve()
    if popup_root not in path.parents or not path.is_file():
        raise HTTPException(status_code=404, detail="Popup asset was not found.")
    mime_types = {
        ".css": "text/css",
        ".js": "text/javascript",
        ".html": "text/html",
        ".woff2": "font/woff2",
        ".png": "image/png"
    }
    media_type = mime_types.get(path.suffix)
    return FileResponse(path, media_type=media_type)
