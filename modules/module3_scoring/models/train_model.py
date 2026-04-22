"""
train_model.py — ML Model Training Script  (Module 3)

Steps this script performs:
  1. Generate a realistic synthetic vulnerability dataset (if CSV not present)
  2. Feature-engineer the raw data
  3. Train a Random Forest classifier  (target: RISK_LABEL)
  4. Evaluate with cross-validation and print accuracy report
  5. Save  risk_model.pkl  and  label_encoder.pkl  to this directory

Run from project root:
    python3 -m modules.module3_scoring.models.train_model

Expected output:
    Accuracy:  ~85 %+
    Saved:     risk_model.pkl
    Saved:     label_encoder.pkl
"""

import os
import sys
import json
import pickle
import logging
from pathlib import Path

import pandas as pd
import numpy as np

# ── Path setup ─────────────────────────────────────────────────
_HERE = Path(__file__).parent                           # .../models/
_PROJECT_ROOT = _HERE.parent.parent.parent             # project root
sys.path.insert(0, str(_PROJECT_ROOT))

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import LabelEncoder, OrdinalEncoder
from sklearn.model_selection import cross_val_score, train_test_split, StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.pipeline import Pipeline

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
logger = logging.getLogger(__name__)

DATASET_PATH = _PROJECT_ROOT / "data" / "training" / "vulnerability_dataset.csv"
MODEL_PATH   = _HERE / "risk_model.pkl"
ENCODER_PATH = _HERE / "label_encoder.pkl"

# ── Vulnerability type metadata (base CVSS, exploit, patch) ───
VULN_META = {
    "ssh_root_login_enabled":      {"cvss": 7.5, "exploit": 1, "patch": 1},
    "ssh_password_auth_enabled":   {"cvss": 6.5, "exploit": 1, "patch": 1},
    "ssh_protocol_v1":             {"cvss": 8.0, "exploit": 1, "patch": 1},
    "ssh_default_port":            {"cvss": 3.5, "exploit": 0, "patch": 1},
    "ssh_empty_passwords_allowed": {"cvss": 9.0, "exploit": 1, "patch": 1},
    "ssh_x11_forwarding":          {"cvss": 4.5, "exploit": 0, "patch": 1},
    "firewall_disabled":           {"cvss": 7.5, "exploit": 0, "patch": 1},
    "firewall_default_allow":      {"cvss": 6.0, "exploit": 0, "patch": 1},
    "root_equivalent_user":        {"cvss": 9.0, "exploit": 0, "patch": 1},
    "user_empty_password":         {"cvss": 9.5, "exploit": 1, "patch": 1},
    "weak_password_policy":        {"cvss": 6.0, "exploit": 0, "patch": 1},
    "mysql_public_port":           {"cvss": 8.0, "exploit": 1, "patch": 1},
    "suspicious_suid_file":        {"cvss": 6.5, "exploit": 0, "patch": 0},
    "ssl_certificate_expired":     {"cvss": 5.5, "exploit": 0, "patch": 1},
    "ssl_certificate_expiring_soon":{"cvss":3.0, "exploit": 0, "patch": 1},
    "ssl_certificate_missing":     {"cvss": 6.5, "exploit": 0, "patch": 1},
    "high_failed_login_count":     {"cvss": 5.0, "exploit": 1, "patch": 0},
    "open_sensitive_port":         {"cvss": 7.0, "exploit": 1, "patch": 1},
    "unpatched_package":           {"cvss": 7.0, "exploit": 0, "patch": 1},
    "apache_outdated":             {"cvss": 7.5, "exploit": 1, "patch": 1},
    "nginx_outdated":              {"cvss": 7.0, "exploit": 1, "patch": 1},
    "lynis_low_hardening_score":   {"cvss": 5.0, "exploit": 0, "patch": 1},
    "disk_usage_critical":         {"cvss": 4.0, "exploit": 0, "patch": 0},
    "ntp_not_configured":          {"cvss": 3.0, "exploit": 0, "patch": 1},
}

BUSINESS_TYPES    = ["E-commerce", "Healthcare", "Finance", "IT Services", "Restaurant", "Other"]
EMPLOYEE_COUNTS   = ["1-10", "11-50", "51-300"]
SERVER_PURPOSES   = ["Database", "Web Server", "App Server", "Email Server", "File Storage"]
SENSITIVE_OPTIONS = ["Yes", "No"]
IT_STAFF_OPTIONS  = ["Yes", "No"]
BUDGET_OPTIONS    = ["Under $50", "$50-200", "$200+"]

# Context risk additions — mirrors config.py exactly
BIZ_MULT   = {"E-commerce":1.8,"Healthcare":1.8,"Finance":1.8,"IT Services":1.4,"Restaurant":1.0,"Other":1.0}
EMP_ADD    = {"1-10":0.3,"11-50":0.1,"51-300":0.0}
SRV_ADD    = {"Database":0.4,"App Server":0.3,"Web Server":0.2,"Email Server":0.1,"File Storage":0.0}
DATA_ADD   = {"Yes":0.4,"No":0.0}
STAFF_ADD  = {"No":0.3,"Yes":0.0}
BUDGET_ADD = {"Under $50":0.2,"$50-200":0.1,"$200+":0.0}


def _context_modifier(biz, emp, srv, data, staff, budget):
    return (BIZ_MULT.get(biz, 1.0)
            + EMP_ADD.get(emp, 0.0)
            + SRV_ADD.get(srv, 0.0)
            + DATA_ADD.get(data, 0.0)
            + STAFF_ADD.get(staff, 0.0)
            + BUDGET_ADD.get(budget, 0.0))


def _assign_label(cvss, exploit, patch, context_mod, days):
    """Deterministic risk label assignment (ground truth for training)."""
    score = cvss
    if exploit:
        score = min(10.0, score + 1.5)
    if not patch:
        score = min(10.0, score + 0.5)
    context_boost = 1.0 + min(0.3, (context_mod - 1.0) * 0.08)
    score = min(10.0, score * context_boost)

    if score >= 8.5:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 5.0:
        return "MEDIUM"
    else:
        return "LOW"


# ── Dataset Generation ─────────────────────────────────────────

def generate_dataset() -> pd.DataFrame:
    """
    Generate a synthetic vulnerability dataset.
    Each row = one vulnerability observed in one SME context.
    ~25 vuln types × ~24 context combos = ~600 base rows.
    Then we add noise variations to reach ~1000 rows.
    """
    rows = []
    rng = np.random.default_rng(seed=42)

    context_sample = [
        # (business_type, employee_count, server_purpose, sensitive_data, has_it_staff, budget)
        ("E-commerce",  "1-10",   "Database",    "Yes", "No",  "Under $50"),
        ("E-commerce",  "11-50",  "Web Server",  "Yes", "No",  "Under $50"),
        ("E-commerce",  "51-300", "App Server",  "Yes", "Yes", "$50-200"),
        ("Healthcare",  "1-10",   "Database",    "Yes", "No",  "Under $50"),
        ("Healthcare",  "11-50",  "File Storage","Yes", "No",  "$50-200"),
        ("Finance",     "1-10",   "Database",    "Yes", "No",  "Under $50"),
        ("Finance",     "11-50",  "App Server",  "Yes", "Yes", "$200+"),
        ("IT Services", "11-50",  "Web Server",  "No",  "Yes", "$200+"),
        ("IT Services", "51-300", "App Server",  "No",  "Yes", "$200+"),
        ("Restaurant",  "1-10",   "File Storage","No",  "No",  "Under $50"),
        ("Restaurant",  "11-50",  "Web Server",  "No",  "No",  "$50-200"),
        ("Other",       "1-10",   "Email Server","Yes", "No",  "Under $50"),
        ("Other",       "11-50",  "Database",    "Yes", "No",  "$50-200"),
        ("Finance",     "51-300", "Database",    "Yes", "Yes", "$200+"),
        ("Healthcare",  "51-300", "App Server",  "Yes", "Yes", "$200+"),
        ("E-commerce",  "1-10",   "Database",    "Yes", "Yes", "$200+"),
        ("Restaurant",  "1-10",   "Web Server",  "No",  "No",  "Under $50"),
        ("Other",       "51-300", "File Storage","No",  "Yes", "$200+"),
        ("IT Services", "1-10",   "Database",    "No",  "No",  "$50-200"),
        ("Finance",     "1-10",   "Email Server","Yes", "No",  "Under $50"),
        ("Healthcare",  "1-10",   "Web Server",  "Yes", "No",  "Under $50"),
        ("E-commerce",  "51-300", "Database",    "Yes", "Yes", "$50-200"),
        ("Restaurant",  "11-50",  "Email Server","No",  "No",  "Under $50"),
        ("Other",       "11-50",  "File Storage","No",  "No",  "$50-200"),
    ]

    for vuln_type, meta in VULN_META.items():
        for (biz, emp, srv, data, staff, budget) in context_sample:
            # Base row
            cvss = meta["cvss"]
            exploit = meta["exploit"]
            patch = meta["patch"]
            days = int(rng.integers(7, 730))
            ctx = _context_modifier(biz, emp, srv, data, staff, budget)
            label = _assign_label(cvss, exploit, patch, ctx, days)

            rows.append({
                "vuln_type":          vuln_type,
                "cvss":               cvss,
                "exploit_exists":     exploit,
                "patch_available":    patch,
                "days_since_published": days,
                "business_type":      biz,
                "employee_count":     emp,
                "server_purpose":     srv,
                "sensitive_data":     1 if data == "Yes" else 0,
                "has_it_staff":       1 if staff == "Yes" else 0,
                "budget":             budget,
                "RISK_LABEL":         label,
            })

            # CVSS noise variation ±0.5 to add diversity
            for delta in (-0.5, 0.5):
                noisy_cvss = max(0.0, min(10.0, cvss + delta))
                noisy_label = _assign_label(noisy_cvss, exploit, patch, ctx, days)
                rows.append({
                    "vuln_type":            vuln_type,
                    "cvss":                 round(noisy_cvss, 1),
                    "exploit_exists":       exploit,
                    "patch_available":      patch,
                    "days_since_published": days,
                    "business_type":        biz,
                    "employee_count":       emp,
                    "server_purpose":       srv,
                    "sensitive_data":       1 if data == "Yes" else 0,
                    "has_it_staff":         1 if staff == "Yes" else 0,
                    "budget":               budget,
                    "RISK_LABEL":           noisy_label,
                })

    df = pd.DataFrame(rows)
    logger.info("Generated dataset: %d rows, label distribution:\n%s",
                len(df), df["RISK_LABEL"].value_counts().to_string())
    return df


# ── Feature Engineering ────────────────────────────────────────

# Categorical feature encodings (ordinal — preserves risk ordering)
ORDINAL_ENCODERS = {
    "vuln_type":      sorted(VULN_META.keys()),         # alphabetical
    "business_type":  BUSINESS_TYPES,
    "employee_count": ["1-10", "11-50", "51-300"],      # ascending
    "server_purpose": SERVER_PURPOSES,
    "budget":         ["Under $50", "$50-200", "$200+"],# ascending cost
}

FEATURE_COLS = [
    "vuln_type", "cvss", "exploit_exists", "patch_available",
    "days_since_published", "business_type", "employee_count",
    "server_purpose", "sensitive_data", "has_it_staff", "budget",
]


def engineer_features(df: pd.DataFrame, encoders: dict = None) -> tuple:
    """
    Encode categorical columns and return feature matrix X plus
    the fitted encoders dict (so ml_scorer can re-use them at inference).
    """
    df = df.copy()

    fitted_encoders = {}
    for col, categories in ORDINAL_ENCODERS.items():
        if col not in df.columns:
            continue
        enc = OrdinalEncoder(categories=[categories],
                             handle_unknown="use_encoded_value",
                             unknown_value=-1)
        df[col] = enc.fit_transform(df[[col]])
        fitted_encoders[col] = enc

    X = df[FEATURE_COLS].values.astype(float)
    return X, fitted_encoders


# ── Training ───────────────────────────────────────────────────

def train():
    # Step 1: Load or generate dataset
    if DATASET_PATH.exists():
        logger.info("Loading existing dataset from %s", DATASET_PATH)
        df = pd.read_csv(DATASET_PATH)
    else:
        logger.info("No dataset found — generating synthetic data...")
        df = generate_dataset()
        DATASET_PATH.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(DATASET_PATH, index=False)
        logger.info("Dataset saved to %s", DATASET_PATH)

    logger.info("Dataset: %d rows, %d columns", len(df), len(df.columns))

    # Step 2: Feature engineering
    X, fitted_encoders = engineer_features(df)

    # Step 3: Encode labels
    le = LabelEncoder()
    y = le.fit_transform(df["RISK_LABEL"])
    logger.info("Classes: %s", list(le.classes_))

    # Step 4: Train / test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # Step 5: Train Random Forest
    logger.info("Training Random Forest classifier...")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        min_samples_split=2,
        min_samples_leaf=1,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train, y_train)

    # Step 6: Cross-validation
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(model, X, y, cv=cv, scoring="accuracy")
    logger.info("Cross-validation accuracy: %.2f ± %.2f",
                cv_scores.mean(), cv_scores.std())

    # Step 7: Test-set evaluation
    y_pred = model.predict(X_test)
    print("\n" + "=" * 55)
    print("  CLASSIFICATION REPORT")
    print("=" * 55)
    print(classification_report(y_test, y_pred, target_names=le.classes_))
    print(f"  CV Accuracy (5-fold): {cv_scores.mean():.3f} ± {cv_scores.std():.3f}")
    print("=" * 55)

    # Step 8: Feature importances
    importances = sorted(
        zip(FEATURE_COLS, model.feature_importances_),
        key=lambda x: x[1], reverse=True,
    )
    print("\n  Feature Importances:")
    for feat, imp in importances:
        bar = "█" * int(imp * 50)
        print(f"    {feat:<28} {imp:.3f}  {bar}")

    # Step 9: Save artefacts
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)

    # Bundle: model + fitted encoders + feature column order + label encoder
    bundle = {
        "model":            model,
        "label_encoder":    le,
        "feature_encoders": fitted_encoders,
        "feature_cols":     FEATURE_COLS,
        "ordinal_map":      ORDINAL_ENCODERS,
        "classes":          list(le.classes_),
    }

    with open(MODEL_PATH, "wb") as f:
        pickle.dump(bundle, f)
    logger.info("Model bundle saved → %s", MODEL_PATH)

    # Also save label encoder separately (for backwards-compat with ml_scorer.py)
    with open(ENCODER_PATH, "wb") as f:
        pickle.dump(le, f)
    logger.info("Label encoder saved → %s", ENCODER_PATH)

    return bundle


# ── Entry point ────────────────────────────────────────────────
if __name__ == "__main__":
    logger.info("=== HybridSec — Module 3 ML Training ===")
    bundle = train()
    print(f"\n  risk_model.pkl   → {MODEL_PATH}")
    print(f"  label_encoder.pkl→ {ENCODER_PATH}")
    print("\nTraining complete.")
