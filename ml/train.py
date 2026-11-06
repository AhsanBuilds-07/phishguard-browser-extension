"""
SentinelAI Phishing & Scam Link Shield
Model Training and Evaluation Pipeline

Key Architecture:
1. Canonical 14-feature extraction from legitimate and phishing URLs.
2. Domain-Aware train/test split via GroupShuffleSplit on registered domains (eTLD+1).
   Ensures ZERO domain leakage between training and held-out test evaluations.
3. Realistic performance evaluation: Accuracy, Precision, Recall, F1, ROC-AUC, PR-AUC,
   False Positive Rate (FPR), False Negative Rate (FNR), and Confusion Matrix.
4. 5-Fold GroupKFold Cross-Validation for generalization confidence intervals.
5. Model export to pure JavaScript via m2cgen for zero-overhead client-side inference.
"""

import json
import os
import sys
import time
from typing import Dict, Any, Tuple

import joblib
import m2cgen as m2c
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    average_precision_score,
    confusion_matrix,
    classification_report
)
from sklearn.model_selection import GroupShuffleSplit, GroupKFold

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)

from ml.features import extract_features, FEATURE_NAMES, extract_domain_group
from ml.dataset import DATASET_CSV, build_dataset

MODELS_DIR = os.path.join(ROOT_DIR, "ml", "models")
JOBLIB_PATH = os.path.join(MODELS_DIR, "phishing_rf.joblib")
EXPORTED_JS_PATH = os.path.join(MODELS_DIR, "model_exported.js")
METADATA_PATH = os.path.join(MODELS_DIR, "model_metadata.json")


def load_and_extract_features(csv_path: str) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, pd.DataFrame]:
    """Loads dataset and extracts the 14 canonical features."""
    if not os.path.exists(csv_path):
        print(f"Dataset CSV not found at {csv_path}, building automatically...")
        build_dataset(target_samples_per_class=4000)

    print(f"Loading dataset from {csv_path} ...")
    df = pd.read_csv(csv_path)
    print(f"Total samples: {len(df)} (Phishing: {sum(df['label'] == 1)}, Benign: {sum(df['label'] == 0)})")

    # If domain_group missing or invalid, re-extract
    if (
        "domain_group" not in df.columns
        or df["domain_group"].isnull().any()
        or (df["domain_group"].astype(str).str.strip() == "").any()
    ):
        print("Extracting domain groups...")
        df["domain_group"] = df["url"].apply(extract_domain_group)

    print("Extracting 14 canonical features for each URL...")
    t0 = time.time()
    feature_matrix = []
    for url in df["url"]:
        feature_matrix.append(extract_features(url))

    X = np.array(feature_matrix, dtype=np.float64)
    y = df["label"].values.astype(np.int64)
    groups = df["domain_group"].values
    urls = df["url"].values

    print(f"Feature extraction complete in {time.time() - t0:.2f}s. Matrix shape: {X.shape}")
    return X, y, groups, urls, df


def run_pipeline(
    csv_path: str = DATASET_CSV,
    output_dir: str = MODELS_DIR,
    progress_callback=None,
    n_estimators: int = 20,
    max_depth: int = 7,
    model_version: str | None = None,
):
    os.makedirs(output_dir, exist_ok=True)
    if model_version is None:
        model_version = f"rf-{time.strftime('%Y%m%d-%H%M%S', time.gmtime())}"
    joblib_path = os.path.join(output_dir, "phishing_rf.joblib")
    exported_js_path = os.path.join(output_dir, "model_exported.js")
    metadata_path = os.path.join(output_dir, "model_metadata.json")

    def report_progress(progress: int, stage: str):
        if progress_callback:
            progress_callback({"progress": progress, "stage": stage})

    print("=" * 70)
    print("SentinelAI ML Pipeline — Domain-Aware Phishing Classifier")
    print("=" * 70)

    report_progress(5, "Loading dataset and extracting canonical URL features")
    X, y, groups, urls, df = load_and_extract_features(csv_path)

    # 1. Domain-Aware Train / Test Split
    report_progress(25, "Splitting data by registered domain")
    print("\n[1/5] Performing Domain-Aware Train/Test Split (GroupShuffleSplit 80/20)...")
    gss = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=42)
    train_idx, test_idx = next(gss.split(X, y, groups=groups))

    X_train, X_test = X[train_idx], X[test_idx]
    y_train, y_test = y[train_idx], y[test_idx]
    groups_train, groups_test = groups[train_idx], groups[test_idx]

    train_domains = set(groups_train)
    test_domains = set(groups_test)
    domain_leakage = train_domains.intersection(test_domains)

    print(f"  Training samples:   {len(y_train)} ({sum(y_train == 1)} phishing, {sum(y_train == 0)} benign)")
    print(f"  Training domains:   {len(train_domains)} unique domain groups")
    print(f"  Held-out test:      {len(y_test)} ({sum(y_test == 1)} phishing, {sum(y_test == 0)} benign)")
    print(f"  Held-out domains:   {len(test_domains)} unique domain groups")
    print(f"  Domain Leakage:     {len(domain_leakage)} overlapping domains")
    assert len(domain_leakage) == 0, f"ERROR: Data leakage detected! Overlapping domains: {domain_leakage}"
    print("  -> Verification PASS: Exactly 0% domain overlap between train and test!")

    # 2. Train Random Forest Model
    report_progress(35, "Training Random Forest classifier")
    print("\n[2/5] Training Random Forest Classifier...")
    # Calibrated architecture: 20 trees, max_depth=7, min_samples_leaf=2.
    # Produces high generalization while maintaining a compact transpiled JS footprint (<150KB).
    clf = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        min_samples_leaf=2,
        max_features="sqrt",
        random_state=42,
        n_jobs=-1
    )

    t0 = time.time()
    clf.fit(X_train, y_train)
    train_time = time.time() - t0
    print(f"  Trained 20 trees in {train_time:.2f}s")

    # 3. Model Evaluation on Unseen Test Domains
    report_progress(60, "Evaluating on held-out domains")
    print("\n[3/5] Evaluating on Held-Out Test Set (Unseen Domains)...")
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred))
    rec = float(recall_score(y_test, y_pred))
    f1 = float(f1_score(y_test, y_pred))
    roc_auc = float(roc_auc_score(y_test, y_prob))
    pr_auc = float(average_precision_score(y_test, y_prob))

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = [int(v) for v in cm.ravel()]

    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    print("\n" + "=" * 50)
    print("      HELD-OUT TEST EVALUATION METRICS")
    print("=" * 50)
    print(f"  Accuracy:               {acc * 100:.2f}%")
    print(f"  Precision:              {prec * 100:.2f}%")
    print(f"  Recall (TPR):           {rec * 100:.2f}%")
    print(f"  F1-Score:               {f1 * 100:.2f}%")
    print(f"  ROC-AUC:                {roc_auc:.4f}")
    print(f"  PR-AUC:                 {pr_auc:.4f}")
    print(f"  False Positive Rate:    {fpr * 100:.2f}%  ({fp} benign flagged as phishing)")
    print(f"  False Negative Rate:    {fnr * 100:.2f}%  ({fn} phishing missed)")
    print("-" * 50)
    print("  Confusion Matrix:")
    print(f"    True Negative  (Benign correctly allowed):      {tn}")
    print(f"    False Positive (Benign falsely flagged):        {fp}")
    print(f"    False Negative (Phishing missed):               {fn}")
    print(f"    True Positive  (Phishing correctly intercepted): {tp}")
    print("=" * 50)

    # 4. 5-Fold Group Cross-Validation
    report_progress(70, "Running grouped cross-validation")
    print("\n[4/5] Running 5-Fold GroupKFold Cross-Validation across Domain Groups...")
    gkf = GroupKFold(n_splits=5)
    cv_roc_scores = []
    cv_f1_scores = []
    cv_acc_scores = []

    for fold, (cv_tr, cv_val) in enumerate(gkf.split(X, y, groups=groups)):
        cv_clf = RandomForestClassifier(
            n_estimators=n_estimators, max_depth=max_depth, min_samples_leaf=2,
            max_features="sqrt", random_state=42 + fold, n_jobs=-1
        )
        cv_clf.fit(X[cv_tr], y[cv_tr])
        val_prob = cv_clf.predict_proba(X[cv_val])[:, 1]
        val_pred = cv_clf.predict(X[cv_val])

        cv_roc_scores.append(roc_auc_score(y[cv_val], val_prob))
        cv_f1_scores.append(f1_score(y[cv_val], val_pred))
        cv_acc_scores.append(accuracy_score(y[cv_val], val_pred))

    print(f"  5-Fold Mean Accuracy:   {np.mean(cv_acc_scores) * 100:.2f}% (std: {np.std(cv_acc_scores) * 100:.2f}%)")
    print(f"  5-Fold Mean F1-Score:   {np.mean(cv_f1_scores) * 100:.2f}% (std: {np.std(cv_f1_scores) * 100:.2f}%)")
    print(f"  5-Fold Mean ROC-AUC:    {np.mean(cv_roc_scores):.4f} (std: {np.std(cv_roc_scores):.4f})")

    # Feature Importance Ranking
    print("\nFeature Importances (Gini):")
    importances = clf.feature_importances_
    sorted_feat_idx = np.argsort(importances)[::-1]
    feat_importance_list = []
    for rank, idx in enumerate(sorted_feat_idx):
        feat_name = FEATURE_NAMES[idx]
        imp = float(importances[idx])
        feat_importance_list.append({"rank": rank + 1, "name": feat_name, "index": int(idx), "importance": imp})
        print(f"  {rank+1:2d}. [{idx:2d}] {feat_name:<26} : {imp * 100:6.2f}%")

    # 5. Model Serialization & JavaScript Transpilation via m2cgen
    report_progress(90, "Exporting model and writing evaluation metadata")
    print("\n[5/5] Serializing Scikit-Learn Model & Transpiling to JavaScript via m2cgen...")
    joblib.dump(clf, joblib_path)
    print(f"  Saved Scikit-Learn model to {joblib_path}")

    # Generate raw transpiled JavaScript code
    raw_m2c_js = m2c.export_to_javascript(clf)

    # Wrap the raw score function into a complete, clean, self-contained module
    template_header = f"""/**
 * SentinelAI: Phishing & Scam Link Shield
 * Pre-Trained Machine Learning Model (Random Forest Ensemble)
 *
 * Generated via m2cgen transpiler from scikit-learn RandomForestClassifier.
 * Pure mathematical inference with ZERO external dependencies.
 *
 * Evaluation Metrics on Unseen Held-Out Domains:
 *   - Accuracy:            {acc * 100:.2f}%
 *   - Precision:           {prec * 100:.2f}%
 *   - Recall:              {rec * 100:.2f}%
 *   - F1-Score:            {f1 * 100:.2f}%
 *   - ROC-AUC:             {roc_auc:.4f}
 *   - False Positive Rate: {fpr * 100:.2f}%
 *   - False Negative Rate: {fnr * 100:.2f}%
 *
 * Input Feature Vector (14 dimensions):
 *   [0]  url_length               (integer)
 *   [1]  domain_length            (integer)
 *   [2]  num_dots                 (integer)
 *   [3]  has_ip                   (0 | 1)
 *   [4]  has_at_symbol            (0 | 1)
 *   [5]  num_hyphens              (integer)
 *   [6]  num_subdomains           (integer)
 *   [7]  is_https                 (0 | 1)
 *   [8]  has_double_slash_in_path (0 | 1)
 *   [9]  num_suspicious_keywords  (integer)
 *   [10] has_suspicious_tld       (0 | 1)
 *   [11] num_query_params         (integer)
 *   [12] special_char_count       (integer)
 *   [13] domain_entropy           (float)
 */
"""

    js_wrapper = """(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.SentinelModel = factory();
    // Expose root predictPhishingScore for service worker compatibility
    root.predictPhishingScore = root.SentinelModel.predictPhishingScore;
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const FEATURE_NAMES = __FEATURE_NAMES_JSON__;
  const MODEL_VERSION = __MODEL_VERSION_JSON__;

  __RAW_M2C_JS__

  /**
   * Sanitizes input into a 14-element numeric array.
   */
  function sanitizeInput(features) {
    if (Array.isArray(features)) {
      const arr = new Array(14).fill(0);
      for (let i = 0; i < Math.min(14, features.length); i++) {
        arr[i] = typeof features[i] === 'number' && !isNaN(features[i]) ? features[i] : 0;
      }
      return arr;
    }
    if (features && typeof features === 'object') {
      return [
        Number(features.url_length ?? features.urlLength ?? 0),
        Number(features.domain_length ?? features.domainLength ?? 0),
        Number(features.num_dots ?? features.numDots ?? 0),
        Number(features.has_ip ?? features.isIp ? 1 : 0),
        Number(features.has_at_symbol ?? features.hasAtSymbol ? 1 : 0),
        Number(features.num_hyphens ?? features.numHyphens ?? 0),
        Number(features.num_subdomains ?? features.numSubdomains ?? 0),
        Number(features.is_https !== undefined ? (features.is_https ? 1 : 0) : (features.isHttps ? 1 : 0)),
        Number(features.has_double_slash_in_path ?? features.hasDoubleSlashInPath ? 1 : 0),
        Number(features.num_suspicious_keywords ?? features.suspiciousKeywordsCount ?? 0),
        Number(features.has_suspicious_tld ?? features.hasSuspiciousTld ? 1 : 0),
        Number(features.num_query_params ?? features.numQueryParams ?? 0),
        Number(features.special_char_count ?? features.specialCharCount ?? 0),
        Number(features.domain_entropy ?? features.domainEntropy ?? 0)
      ];
    }
    return new Array(14).fill(0);
  }

  /**
   * Evaluates features and returns class probabilities [prob_legitimate, prob_phishing].
   * @param {number[] | object} features
   * @returns {number[]}
   */
  function predictProba(features) {
    const safeInput = sanitizeInput(features);
    return score(safeInput);
  }

  /**
   * Evaluates features and returns phishing risk probability float [0.0, 1.0].
   * @param {number[] | object} features
   * @returns {number}
   */
  function predictPhishingScore(features) {
    const proba = predictProba(features);
    // proba[1] is the phishing probability from the random forest ensemble
    const scoreVal = typeof proba[1] === 'number' && !isNaN(proba[1]) ? proba[1] : 0.0;
    return Number(scoreVal.toFixed(4));
  }

  return {
    MODEL_VERSION,
    FEATURE_NAMES,
    score,
    predictProba,
    predictPhishingScore
  };
});
"""

    exported_js_code = (
        template_header +
        js_wrapper.replace("__FEATURE_NAMES_JSON__", json.dumps(FEATURE_NAMES, indent=2))
                  .replace("__MODEL_VERSION_JSON__", json.dumps(model_version))
                  .replace("__RAW_M2C_JS__", raw_m2c_js)
    )

    with open(exported_js_path, "w", encoding="utf-8") as f:
        f.write(exported_js_code)

    file_size_kb = os.path.getsize(exported_js_path) / 1024
    print(f"  Successfully exported pure JavaScript model to {exported_js_path} ({file_size_kb:.1f} KB)")

    # Save comprehensive metadata
    metadata: Dict[str, Any] = {
        "model_version": model_version,
        "model_type": "RandomForestClassifier",
        "transpiler": "m2cgen 0.10.0",
        "date_trained": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "hyperparameters": {
            "n_estimators": n_estimators,
            "max_depth": max_depth,
            "min_samples_leaf": 2,
            "max_features": "sqrt",
            "random_state": 42
        },
        "dataset": {
            "total_samples": len(y),
            "phishing_samples": int(sum(y == 1)),
            "benign_samples": int(sum(y == 0)),
            "unique_domain_groups": int(len(set(groups))),
            "phishing_sources": [
                "Phishing.Database active feed (Mitchell Krogza)",
                "OpenPhish public community feed"
            ],
            "benign_sources": [
                "Majestic Million Top Domains (with path and subdomain enrichment)"
            ]
        },
        "split_strategy": {
            "type": "GroupShuffleSplit",
            "group_key": "domain_group (eTLD+1 registered domain or IP)",
            "train_size": len(y_train),
            "test_size": len(y_test),
            "train_unique_domains": len(train_domains),
            "test_unique_domains": len(test_domains),
            "domain_overlap": 0
        },
        "evaluation_metrics": {
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "f1_score": f1,
            "roc_auc": roc_auc,
            "pr_auc": pr_auc,
            "false_positive_rate": fpr,
            "false_negative_rate": fnr,
            "confusion_matrix": {
                "true_negative": tn,
                "false_positive": fp,
                "false_negative": fn,
                "true_positive": tp
            }
        },
        "cross_validation_5_fold": {
            "mean_accuracy": float(np.mean(cv_acc_scores)),
            "std_accuracy": float(np.std(cv_acc_scores)),
            "mean_f1": float(np.mean(cv_f1_scores)),
            "std_f1": float(np.std(cv_f1_scores)),
            "mean_roc_auc": float(np.mean(cv_roc_scores)),
            "std_roc_auc": float(np.std(cv_roc_scores))
        },
        "feature_importances": feat_importance_list,
        "feature_schema": FEATURE_NAMES,
        "recommended_thresholds": {
            "safe_upper_bound": 0.40,
            "suspicious_lower_bound": 0.40,
            "high_risk_threshold": 0.75
        }
    }

    with open(metadata_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"  Saved complete metadata to {metadata_path}")
    print("\nTraining & evaluation completed successfully!")
    report_progress(100, "Training complete")
    return metadata


if __name__ == "__main__":
    run_pipeline()
