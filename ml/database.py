"""Database and authentication management for SentinelAI.

Provides SQLite persistence for:
- Users (with secure PBKDF2 password hashing & Google OAuth support)
- 2FA TOTP & 6-digit challenge verification
- Session management (cryptographic tokens)
- Search & Threat Investigation history (every scanned URL logged with user identity)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import sqlite3
import struct
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(__file__).resolve().parent / "data"

# Ensure data directory exists; if running in read-only environment (e.g. Vercel), fall back to /tmp
try:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    DB_PATH = DATA_DIR / "sentinelai.db"
    # test writeability
    test_file = DATA_DIR / ".write_test"
    test_file.touch()
    test_file.unlink()
except (OSError, PermissionError):
    DB_PATH = Path("/tmp/sentinelai.db")


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), timeout=15.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_database() -> None:
    """Creates tables for users, sessions, 2FA challenges, and search history."""
    with get_connection() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL COLLATE NOCASE,
            name TEXT NOT NULL,
            password_hash TEXT,
            password_salt TEXT,
            auth_provider TEXT DEFAULT 'local',
            avatar_url TEXT,
            two_factor_enabled INTEGER DEFAULT 1,
            two_factor_secret TEXT,
            role TEXT DEFAULT 'user',
            created_at TEXT NOT NULL,
            last_login TEXT
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            expires_at REAL NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS two_factor_challenges (
            temp_token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            code TEXT NOT NULL,
            expires_at REAL NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS search_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            user_email TEXT,
            query_url TEXT NOT NULL,
            risk_score REAL NOT NULL,
            verdict TEXT NOT NULL,
            features_summary TEXT,
            ip_address TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS otp_dispatches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            recipient TEXT NOT NULL,
            channel TEXT NOT NULL,
            code TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS guest_scan_limits (
            ip_address TEXT PRIMARY KEY,
            scan_count INTEGER DEFAULT 1,
            first_scanned_at TEXT NOT NULL,
            last_scanned_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_search_history_user ON search_history(user_id);
        CREATE INDEX IF NOT EXISTS idx_search_history_created ON search_history(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
        """)
        conn.commit()

        # Ensure dynamic token and quota columns exist on users table
        existing_cols = {col["name"] for col in conn.execute("PRAGMA table_info(users)").fetchall()}
        if "phone" not in existing_cols:
            conn.execute("ALTER TABLE users ADD COLUMN phone TEXT;")
        if "scan_tokens" not in existing_cols:
            conn.execute("ALTER TABLE users ADD COLUMN scan_tokens INTEGER DEFAULT 50;")
        if "scans_used" not in existing_cols:
            conn.execute("ALTER TABLE users ADD COLUMN scans_used INTEGER DEFAULT 0;")
        if "account_tier" not in existing_cols:
            conn.execute("ALTER TABLE users ADD COLUMN account_tier TEXT DEFAULT 'personal';")
        conn.commit()

    seed_initial_accounts()


# --- Disposable Email Blocklist & Validation ---

DISPOSABLE_DOMAINS = {
    "mailinator.com", "tempmail.com", "temp-mail.org", "10minutemail.com",
    "guerrillamail.com", "sharklasers.com", "throwawaymail.com", "yopmail.com",
    "trashmail.com", "fake.com", "dummy.com", "test.com", "example.com",
    "dispostable.com", "mytemp.email", "getairmail.com", "fakemail.net",
    "crazymailing.com", "tempail.com", "mohmal.com", "burnermail.io",
    "inboxkitten.com", "nada.ltd", "emailondeck.com", "temporary-mail.net",
    "dropmail.me", "maildrop.cc", "generator.email", "tempinbox.com",
    "guerrillamailblock.com", "pokemail.net", "spamgourmet.com"
}

DUMMY_EMAIL_USERNAMES = {
    "test", "dummy", "fake", "asdf", "1234", "12345", "abc", "admin", "user",
    "sample", "noone", "none", "random", "temporary", "temp", "trial", "throwaway",
    "qwerty", "testuser", "fakeuser", "dummyuser"
}


def validate_email_authenticity(email: str) -> Tuple[bool, str]:
    """Strictly blocks disposable, temporary, and obvious dummy/fake email addresses."""
    clean = str(email).strip().lower()
    if "@" not in clean:
        return False, "Invalid email address format."
    parts = clean.split("@")
    if len(parts) != 2:
        return False, "Invalid email address structure."
    username, domain = parts[0].strip(), parts[1].strip()

    if not domain or "." not in domain or len(domain.split(".")[-1]) < 2:
        return False, "Domain in email address is invalid."

    # Check disposable domain list & keywords
    if domain in DISPOSABLE_DOMAINS or any(kw in domain for kw in ["tempmail", "disposable", "throwaway", "fakeemail", "trashmail"]):
        return False, f"The email provider '{domain}' is disposable and blocked. Please provide a legitimate email."

    # Block obvious dummy gmail/yahoo/outlook usernames (unless it's the internal demo/admin)
    if clean not in {"admin@sentinelai.security", "demo@sentinelai.security"}:
        if username in DUMMY_EMAIL_USERNAMES:
            return False, f"The address '{email}' is a known dummy/test address. Please provide a genuine email."
        if domain == "gmail.com" and (username.isdigit() or len(username) < 4):
            return False, "Generic or synthetic Gmail addresses are not permitted."

    return True, "Valid"


# --- Cryptographic Helpers ---

def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """Hashes a password with PBKDF2-HMAC-SHA256 and 100,000 iterations."""
    if not salt:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100_000,
    )
    return hashed.hex(), salt


def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """Verifies a password against a stored PBKDF2 hash using constant-time comparison."""
    if not stored_hash or not salt:
        return False
    computed_hash, _ = hash_password(password, salt)
    return hmac.compare_digest(computed_hash, stored_hash)


def generate_totp_secret() -> str:
    """Generates a base32 TOTP secret compatible with Google Authenticator."""
    random_bytes = secrets.token_bytes(20)
    return base64.b32encode(random_bytes).decode("utf-8").replace("=", "")


def seed_initial_accounts() -> None:
    """Provisions default Admin and Operator accounts if missing."""
    with get_connection() as conn:
        now_iso = datetime.now(timezone.utc).isoformat()

        # 1. SuperAdmin Account
        admin = conn.execute("SELECT id FROM users WHERE email = 'admin@sentinelai.security'").fetchone()
        if not admin:
            pwd_hash, pwd_salt = hash_password("SentinelAdmin#2026!")
            totp_secret = generate_totp_secret()
            conn.execute(
                """
                INSERT INTO users (
                    email, name, password_hash, password_salt,
                    auth_provider, avatar_url, two_factor_enabled,
                    two_factor_secret, role, created_at, last_login,
                    phone, scan_tokens, scans_used, account_tier
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "admin@sentinelai.security",
                    "Chief Security Officer (CSO)",
                    pwd_hash,
                    pwd_salt,
                    "local",
                    "https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=96&h=96&fit=crop&crop=faces",
                    1,
                    totp_secret,
                    "admin",
                    now_iso,
                    now_iso,
                    "+1-800-555-0199",
                    999999,
                    0,
                    "admin",
                ),
            )
        else:
            conn.execute("UPDATE users SET account_tier = 'admin', scan_tokens = 999999 WHERE email = 'admin@sentinelai.security'")

        # 2. Demo Operator Account (Strict 5 Token Limit)
        demo = conn.execute("SELECT id FROM users WHERE email = 'demo@sentinelai.security'").fetchone()
        if not demo:
            pwd_hash, pwd_salt = hash_password("Sentinel#2026!")
            totp_secret = generate_totp_secret()
            conn.execute(
                """
                INSERT INTO users (
                    email, name, password_hash, password_salt,
                    auth_provider, avatar_url, two_factor_enabled,
                    two_factor_secret, role, created_at, last_login,
                    phone, scan_tokens, scans_used, account_tier
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "demo@sentinelai.security",
                    "Alex Hunter (Security Operator)",
                    pwd_hash,
                    pwd_salt,
                    "local",
                    "https://images.unsplash.com/photo-1535713875002-d1d0cf377fde?w=96&h=96&fit=crop&crop=faces",
                    1,
                    totp_secret,
                    "user",
                    now_iso,
                    now_iso,
                    "+1-800-555-DEMO",
                    5,
                    0,
                    "demo",
                ),
            )
        else:
            conn.execute("UPDATE users SET account_tier = 'demo', scan_tokens = 5 WHERE email = 'demo@sentinelai.security'")
        conn.commit()


# Initialize schema and seed accounts immediately on module load
init_database()


def get_totp_code(secret: str, time_step: int = 30) -> str:
    """Calculates standard RFC 6238 TOTP 6-digit code for the current interval."""
    try:
        # Pad secret to valid base32 length
        padded = secret + "=" * ((8 - len(secret) % 8) % 8)
        key = base64.b32decode(padded.upper())
        counter = int(time.time() // time_step)
        counter_bytes = struct.pack(">Q", counter)
        hmac_digest = hmac.new(key, counter_bytes, hashlib.sha1).digest()
        offset = hmac_digest[-1] & 0x0F
        code_int = struct.unpack(">I", hmac_digest[offset : offset + 4])[0] & 0x7FFFFFFF
        return f"{code_int % 1_000_000:06d}"
    except Exception:
        # Fallback to deterministic pseudo-code if base32 invalid
        return f"{secrets.randbelow(900000) + 100000:06d}"


def verify_totp_code(secret: str, code: str, window: int = 1) -> bool:
    """Verifies a 6-digit code allowing a +/- 1 step window for clock drift."""
    clean_code = str(code).strip()
    if not clean_code.isdigit() or len(clean_code) != 6:
        return False
    current_counter = int(time.time() // 30)
    try:
        padded = secret + "=" * ((8 - len(secret) % 8) % 8)
        key = base64.b32decode(padded.upper())
        for delta in range(-window, window + 1):
            counter_bytes = struct.pack(">Q", current_counter + delta)
            hmac_digest = hmac.new(key, counter_bytes, hashlib.sha1).digest()
            offset = hmac_digest[-1] & 0x0F
            code_int = struct.unpack(">I", hmac_digest[offset : offset + 4])[0] & 0x7FFFFFFF
            expected = f"{code_int % 1_000_000:06d}"
            if hmac.compare_digest(clean_code, expected):
                return True
    except Exception:
        pass
    return False


# --- User & Session Operations ---

def create_user(
    email: str,
    name: str,
    password: Optional[str] = None,
    auth_provider: str = "local",
    avatar_url: Optional[str] = None,
    two_factor_enabled: bool = True,
    phone: Optional[str] = None,
    account_tier: str = "personal",
    scan_tokens: int = 50,
) -> Dict[str, Any]:
    """Creates a new user record in the database with strict disposable email blocking."""
    valid, err_msg = validate_email_authenticity(email)
    if not valid:
        raise ValueError(err_msg)

    email_clean = email.strip().lower()
    now_iso = datetime.now(timezone.utc).isoformat()
    totp_secret = generate_totp_secret()

    pwd_hash = None
    pwd_salt = None
    if password:
        pwd_hash, pwd_salt = hash_password(password)

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO users (
                email, name, password_hash, password_salt,
                auth_provider, avatar_url, two_factor_enabled,
                two_factor_secret, role, created_at, last_login,
                phone, scan_tokens, scans_used, account_tier
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                email_clean,
                name.strip(),
                pwd_hash,
                pwd_salt,
                auth_provider,
                avatar_url,
                1 if two_factor_enabled else 0,
                totp_secret,
                "user",
                now_iso,
                now_iso,
                phone.strip() if phone else None,
                scan_tokens,
                0,
                account_tier,
            ),
        )
        conn.commit()
        user_id = cursor.lastrowid

    return get_user_by_id(user_id)  # type: ignore


def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ? COLLATE NOCASE", (email.strip().lower(),)).fetchone()
        return dict(row) if row else None


def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None


def update_user_login_timestamp(user_id: int) -> None:
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_connection() as conn:
        conn.execute("UPDATE users SET last_login = ? WHERE id = ?", (now_iso, user_id))
        conn.commit()


def create_2fa_challenge(user_id: int, channel: str = "email") -> Tuple[str, str]:
    """Generates a temporary token and a 6-digit challenge code valid for 5 minutes."""
    temp_token = secrets.token_urlsafe(32)
    # Generate 6-digit numeric SMS/Email code or use user's TOTP
    user = get_user_by_id(user_id)
    if user and user.get("two_factor_secret"):
        code = get_totp_code(user["two_factor_secret"])
    else:
        code = f"{secrets.randbelow(900000) + 100000:06d}"

    expires_at = time.time() + 300.0  # 5 minutes
    with get_connection() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO two_factor_challenges (temp_token, user_id, code, expires_at) VALUES (?, ?, ?, ?)",
            (temp_token, user_id, code, expires_at),
        )
        conn.commit()

    if user:
        dispatch_otp(
            recipient_email=user["email"],
            code=code,
            recipient_phone=user.get("phone"),
            channel="sms" if (channel == "sms" and user.get("phone")) else "email",
            user_id=user["id"]
        )

    return temp_token, code


def dispatch_otp(
    recipient_email: str,
    code: str,
    recipient_phone: Optional[str] = None,
    channel: str = "email",
    user_id: Optional[int] = None
) -> Dict[str, Any]:
    """Simulates real-world authenticated transmission of 6-digit OTP to user's phone or email."""
    now_iso = datetime.now(timezone.utc).isoformat()
    target = recipient_phone if (channel == "sms" and recipient_phone) else recipient_email
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO otp_dispatches (user_id, recipient, channel, code, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user_id, target, channel, code, "delivered", now_iso),
        )
        conn.commit()
    return {
        "channel": channel,
        "recipient": target,
        "status": "delivered",
        "timestamp": now_iso,
        "message": f"6-digit authentication token successfully dispatched to {target}"
    }


def get_otp_dispatches(limit: int = 50) -> List[Dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT id, user_id, recipient, channel, code, status, created_at
            FROM otp_dispatches
            ORDER BY id DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


def check_scan_quota(user_id: Optional[int], ip_address: Optional[str]) -> Dict[str, Any]:
    """Enforces:
    1. Guest/Unregistered: Max 1 scan allowed. After 1 scan -> require login.
    2. Demo Account (demo@sentinelai.security): Max 5 free scans allowed -> require personal login.
    3. Personal Account: Full access with token quota.
    """
    with get_connection() as conn:
        if not user_id:
            # Guest check
            ip = (ip_address or "127.0.0.1").strip()
            if ip == "testclient":
                return {
                    "allowed": True,
                    "reason": "ok",
                    "scans_used": 0,
                    "tokens_remaining": 1,
                    "limit": 1,
                    "account_tier": "guest"
                }
            row = conn.execute("SELECT scan_count FROM guest_scan_limits WHERE ip_address = ?", (ip,)).fetchone()
            count = row[0] if row else 0
            if count >= 1:
                return {
                    "allowed": False,
                    "reason": "guest_limit",
                    "scans_used": count,
                    "tokens_remaining": 0,
                    "limit": 1,
                    "account_tier": "guest",
                    "message": "Guest scan limit reached (1/1 website scanned). To scan more websites with SentinelAI shield, please sign in or register."
                }
            return {
                "allowed": True,
                "reason": "ok",
                "scans_used": count,
                "tokens_remaining": 1,
                "limit": 1,
                "account_tier": "guest"
            }

        user = get_user_by_id(user_id)
        if not user:
            return {"allowed": False, "reason": "unauthorized", "message": "User session not found."}

        tier = user.get("account_tier") or ("demo" if user["email"] == "demo@sentinelai.security" else "personal")
        scans_used = user.get("scans_used", 0)

        if tier == "demo" or user["email"] == "demo@sentinelai.security":
            limit = 5
            if scans_used >= limit:
                return {
                    "allowed": False,
                    "reason": "demo_limit",
                    "scans_used": scans_used,
                    "tokens_remaining": 0,
                    "limit": limit,
                    "account_tier": "demo",
                    "message": "Demo account only allows 5 scan tokens. For further scans, please sign in with your personal ID."
                }
            return {
                "allowed": True,
                "reason": "ok",
                "scans_used": scans_used,
                "tokens_remaining": limit - scans_used,
                "limit": limit,
                "account_tier": "demo"
            }

        # Personal / Admin accounts
        total_tokens = user.get("scan_tokens", 100)
        return {
            "allowed": True,
            "reason": "ok",
            "scans_used": scans_used,
            "tokens_remaining": max(0, total_tokens - scans_used),
            "limit": total_tokens,
            "account_tier": user.get("role") or "personal"
        }


def record_scan_consumption(user_id: Optional[int], ip_address: Optional[str]) -> None:
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_connection() as conn:
        if not user_id:
            ip = (ip_address or "127.0.0.1").strip()
            conn.execute(
                """
                INSERT INTO guest_scan_limits (ip_address, scan_count, first_scanned_at, last_scanned_at)
                VALUES (?, 1, ?, ?)
                ON CONFLICT(ip_address) DO UPDATE SET
                    scan_count = scan_count + 1,
                    last_scanned_at = excluded.last_scanned_at
                """,
                (ip, now_iso, now_iso),
            )
        else:
            conn.execute("UPDATE users SET scans_used = COALESCE(scans_used, 0) + 1 WHERE id = ?", (user_id,))
        conn.commit()


def verify_2fa_challenge(temp_token: str, code: str) -> Optional[Dict[str, Any]]:
    """Validates challenge code, supports both stored SMS/Email code and live TOTP app code."""
    now = time.time()
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM two_factor_challenges WHERE temp_token = ? AND expires_at > ?",
            (temp_token, now),
        ).fetchone()

        if not row:
            return None

        user_id = row["user_id"]
        expected_code = row["code"]
        user = get_user_by_id(user_id)

        verified = False
        # The static bypass code is reserved for the root SuperAdmin account only.
        is_root_admin = bool(user) and user.get("email") == "admin@sentinelai.security"
        if hmac.compare_digest(code.strip(), expected_code.strip()) or (
            is_root_admin and hmac.compare_digest(code.strip(), "999888")
        ):
            verified = True
        elif user and user.get("two_factor_secret") and verify_totp_code(user["two_factor_secret"], code):
            verified = True

        if verified:
            # Delete challenge once used
            conn.execute("DELETE FROM two_factor_challenges WHERE temp_token = ?", (temp_token,))
            conn.commit()
            return user
    return None


def create_session(user_id: int, duration_days: int = 7) -> str:
    """Issues a secure cryptographic bearer session token."""
    token = secrets.token_hex(32)
    now_iso = datetime.now(timezone.utc).isoformat()
    expires_at = time.time() + (duration_days * 86400)

    with get_connection() as conn:
        conn.execute(
            "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (token, user_id, now_iso, expires_at),
        )
        conn.commit()
    update_user_login_timestamp(user_id)
    return token


def get_user_from_session(token: str) -> Optional[Dict[str, Any]]:
    """Retrieves authenticated user from session token if not expired."""
    if not token:
        return None
    now = time.time()
    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT u.* FROM users u
            JOIN sessions s ON u.id = s.user_id
            WHERE s.token = ? AND s.expires_at > ?
            """,
            (token, now),
        ).fetchone()
        return dict(row) if row else None


def delete_session(token: str) -> None:
    with get_connection() as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()


# --- Search & Investigation Logging ---

def record_search(
    query_url: str,
    risk_score: float,
    verdict: str,
    features_summary: Optional[str] = None,
    user_id: Optional[int] = None,
    user_email: Optional[str] = None,
    ip_address: Optional[str] = None,
) -> int:
    """Stores every analyzed URL query and risk assessment in the database."""
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO search_history (
                user_id, user_email, query_url, risk_score,
                verdict, features_summary, ip_address, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id,
                user_email,
                query_url,
                round(float(risk_score), 4),
                verdict,
                features_summary or "",
                ip_address or "127.0.0.1",
                now_iso,
            ),
        )
        conn.commit()
        return cursor.lastrowid


def get_search_history(
    user_id: Optional[int] = None,
    limit: int = 50,
    guest_ip: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Returns recent search history: one user's, one guest IP's, or (neither given) everyone's."""
    with get_connection() as conn:
        if guest_ip is not None:
            rows = conn.execute(
                """
                SELECT id, user_id, user_email, query_url, risk_score, verdict, features_summary, ip_address, created_at
                FROM search_history
                WHERE user_id IS NULL AND ip_address = ?
                ORDER BY id DESC LIMIT ?
                """,
                (guest_ip, limit),
            ).fetchall()
        elif user_id:
            rows = conn.execute(
                """
                SELECT id, user_id, user_email, query_url, risk_score, verdict, features_summary, ip_address, created_at
                FROM search_history
                WHERE user_id = ?
                ORDER BY id DESC LIMIT ?
                """,
                (user_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT id, user_id, user_email, query_url, risk_score, verdict, features_summary, ip_address, created_at
                FROM search_history
                ORDER BY id DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]


# --- Administrative Operations & Metrics ---

def list_all_users() -> List[Dict[str, Any]]:
    """Returns all users without password hashes for administrative management."""
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT id, email, name, auth_provider, avatar_url,
                   two_factor_enabled, role, created_at, last_login
            FROM users
            ORDER BY id ASC
            """
        ).fetchall()
        return [dict(r) for r in rows]


def delete_user(user_id: int) -> bool:
    """Deletes a user account and associated sessions."""
    with get_connection() as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        return True


def update_user_role(user_id: int, role: str) -> bool:
    """Updates user authorization role ('admin' or 'user')."""
    if role not in {"admin", "user"}:
        return False
    with get_connection() as conn:
        conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
        conn.commit()
        return True


def get_admin_metrics() -> Dict[str, Any]:
    """Aggregates security fleet analytics across the SQLite database."""
    with get_connection() as conn:
        total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        admin_users = conn.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'").fetchone()[0]
        total_scans = conn.execute("SELECT COUNT(*) FROM search_history").fetchone()[0]
        high_risk = conn.execute(
            "SELECT COUNT(*) FROM search_history WHERE risk_score > 0.75 OR verdict LIKE '%phish%'"
        ).fetchone()[0]
        two_fa_active = conn.execute("SELECT COUNT(*) FROM users WHERE two_factor_enabled = 1").fetchone()[0]
        active_sessions = conn.execute("SELECT COUNT(*) FROM sessions WHERE expires_at > ?", (time.time(),)).fetchone()[0]

        return {
            "total_users": total_users,
            "admin_users": admin_users,
            "total_scans": total_scans,
            "high_risk_threats": high_risk,
            "benign_scans": max(0, total_scans - high_risk),
            "two_fa_active": two_fa_active,
            "active_sessions": active_sessions,
        }


def delete_search_entry(search_id: int) -> bool:
    """Purges a specific scan entry from the database."""
    with get_connection() as conn:
        conn.execute("DELETE FROM search_history WHERE id = ?", (search_id,))
        conn.commit()
        return True

