"""
ml_scorer.py — Random Forest ML Risk Scorer  (Module 3, Step 2 of 3)

Loads the trained Random Forest model bundle (risk_model.pkl) and
scores a single vulnerability using class probability outputs.

Weight in final hybrid score: 35%

Continuous score formula:
    ml_score = p(LOW)×2.0 + p(MEDIUM)×5.0 + p(HIGH)×7.5 + p(CRITICAL)×9.5

This produces a smooth 0–10 value that reflects how confidently the
model places the vulnerability in each risk class, rather than a hard
classification that discards probability information.
"""

import pickle
import logging
import warnings
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_HERE       = Path(__file__).parent
MODEL_PATH  = _HERE / "models" / "risk_model.pkl"

# Score representatives for each class (centre of each priority band)
CLASS_SCORE_MAP = {
    "LOW":      2.0,
    "MEDIUM":   5.0,
    "HIGH":     7.5,
    "CRITICAL": 9.5,
}


class MLScorer:
    """
    Wraps the trained Random Forest bundle for inference.
    Lazy-loads the model on first use to keep startup fast.
    """

    def __init__(self, model_path: Path = MODEL_PATH):
        self._model_path = model_path
        self._bundle: Optional[dict] = None

    # ── Public API ─────────────────────────────────────────────

    def score(self, vuln: dict, context: dict) -> dict:
        """
        Score a single vulnerability.

        Args:
            vuln:    vulnerability dict (from Module 1)
            context: SME profile dict OR weights dict (from Module 2).
                     Must contain at minimum: business_type, employee_count,
                     server_purpose, sensitive_data, has_it_staff, budget.

        Returns:
            dict:
              score          (float 0-10, or None if model unavailable)
              predicted_class (str: CRITICAL/HIGH/MEDIUM/LOW)
              probabilities  (dict class→probability)
              available      (bool: False if model not loaded)
              error          (str|None)
        """
        bundle = self._load_bundle()
        if bundle is None:
            return {
                "score": None,
                "predicted_class": None,
                "probabilities": {},
                "available": False,
                "error": "ML model not loaded — run train_model.py first",
            }

        try:
            X = self._build_feature_vector(vuln, context, bundle)
            model = bundle["model"]
            le    = bundle["label_encoder"]

            # Probabilities: shape (1, n_classes)
            proba = model.predict_proba(X)[0]
            classes = le.classes_         # e.g. ['CRITICAL', 'HIGH', 'LOW', 'MEDIUM']

            # Map to dict and compute continuous score
            prob_dict = {cls: round(float(p), 4) for cls, p in zip(classes, proba)}
            ml_score = sum(
                prob_dict.get(cls, 0.0) * CLASS_SCORE_MAP.get(cls, 5.0)
                for cls in CLASS_SCORE_MAP
            )
            ml_score = round(min(10.0, max(0.0, ml_score)), 4)

            # Hard predicted class (highest probability)
            predicted_idx = int(np.argmax(proba))
            predicted_class = classes[predicted_idx]

            logger.debug(
                "MLScorer: type=%s → score=%.4f class=%s proba=%s",
                vuln.get("type", "?"), ml_score, predicted_class,
                {k: f"{v:.2f}" for k, v in prob_dict.items()},
            )

            return {
                "score":           ml_score,
                "predicted_class": predicted_class,
                "probabilities":   prob_dict,
                "available":       True,
                "error":           None,
            }

        except Exception as e:
            logger.error("MLScorer inference error: %s", e)
            return {
                "score": None,
                "predicted_class": None,
                "probabilities": {},
                "available": False,
                "error": str(e),
            }

    def is_available(self) -> bool:
        """Return True if the model bundle was successfully loaded."""
        return self._load_bundle() is not None

    # ── Private Helpers ────────────────────────────────────────

    def _load_bundle(self) -> Optional[dict]:
        """Lazy-load the model bundle from disk."""
        if self._bundle is not None:
            return self._bundle

        if not self._model_path.exists():
            logger.warning("Model file not found: %s", self._model_path)
            return None

        try:
            with open(self._model_path, "rb") as f:
                self._bundle = pickle.load(f)
            logger.info("ML model loaded from %s", self._model_path)
            return self._bundle
        except Exception as e:
            logger.error("Failed to load ML model: %s", e)
            return None

    def _build_feature_vector(self, vuln: dict, context: dict, bundle: dict) -> np.ndarray:
        """
        Build a (1, n_features) numpy array from the vulnerability and context dicts,
        applying the same ordinal encoding used during training.
        """
        feature_encoders = bundle["feature_encoders"]
        feature_cols     = bundle["feature_cols"]

        # Normalise sensitive_data / has_it_staff to 0/1 regardless of input format
        sensitive = context.get("sensitive_data", "No")
        has_staff = context.get("has_it_staff",   "No")
        sensitive_int = 1 if str(sensitive).strip().lower() in ("yes", "1", "true") else 0
        staff_int     = 1 if str(has_staff).strip().lower()  in ("yes", "1", "true") else 0

        raw = {
            "vuln_type":             vuln.get("type",           "unpatched_package"),
            "cvss":                  float(vuln.get("cvss_score", 5.0)),
            "exploit_exists":        int(bool(vuln.get("exploit_exists", False))),
            "patch_available":       int(bool(vuln.get("patch_available", True))),
            "days_since_published":  int(vuln.get("days_since_published", 180)),
            "business_type":         context.get("business_type",    "Other"),
            "employee_count":        context.get("employee_count",   "1-10"),
            "server_purpose":        context.get("server_purpose",   "File Storage"),
            "sensitive_data":        sensitive_int,
            "has_it_staff":          staff_int,
            "budget":                context.get("security_budget",  "Under $50"),
        }

        row = []
        for col in feature_cols:
            val = raw[col]
            if col in feature_encoders:
                enc = feature_encoders[col]
                # Pass a DataFrame to avoid sklearn feature-name warnings
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    val = float(enc.transform(pd.DataFrame([[val]], columns=[col]))[0][0])
            row.append(float(val))

        return np.array([row], dtype=float)


# ── Standalone test ────────────────────────────────────────────
if __name__ == "__main__":
    import sys, os
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")

    scorer = MLScorer()

    if not scorer.is_available():
        print("[ERROR] Model not loaded. Run train_model.py first.")
        sys.exit(1)

    test_cases = [
        (
            "SSH root login — E-commerce, no IT, sensitive DB",
            {"type": "ssh_root_login_enabled", "cvss_score": 7.5,
             "exploit_exists": True, "patch_available": True},
            {"business_type": "E-commerce", "employee_count": "11-50",
             "server_purpose": "Database", "sensitive_data": "Yes",
             "has_it_staff": "No", "security_budget": "Under $50"},
        ),
        (
            "NTP not configured — Restaurant, no sensitive data",
            {"type": "ntp_not_configured", "cvss_score": 3.0,
             "exploit_exists": False, "patch_available": True},
            {"business_type": "Restaurant", "employee_count": "1-10",
             "server_purpose": "File Storage", "sensitive_data": "No",
             "has_it_staff": "No", "security_budget": "$50-200"},
        ),
        (
            "MySQL public — Finance, large team",
            {"type": "mysql_public_port", "cvss_score": 8.0,
             "exploit_exists": True, "patch_available": True},
            {"business_type": "Finance", "employee_count": "51-300",
             "server_purpose": "Database", "sensitive_data": "Yes",
             "has_it_staff": "Yes", "security_budget": "$200+"},
        ),
    ]

    print("\n" + "=" * 60)
    print("  ML Scorer Test Cases")
    print("=" * 60)
    for desc, vuln, ctx in test_cases:
        result = scorer.score(vuln, ctx)
        s = result["score"]
        c = result["predicted_class"]
        p = result["probabilities"]
        label = ("CRITICAL" if s >= 8.5 else "HIGH" if s >= 7.0
                 else "MEDIUM" if s >= 5.0 else "LOW")
        print(f"\n  {desc}")
        print(f"    Score: {s:.2f}  ({label})  |  Predicted class: {c}")
        print(f"    Probabilities: " +
              "  ".join(f"{k}={v:.2f}" for k, v in sorted(p.items())))
