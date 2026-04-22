"""
tests/test_module2.py — Unit Tests for Module 2: SME Context Interface

Tests cover:
  - ProfileValidator accepts valid answers and rejects invalid ones
  - ContextManager.save_profile / get_active_profile round-trip
  - ContextManager.compute_weights returns numeric modifier
  - Context weight is higher for high-risk profiles than low-risk ones
"""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.module2_context.profile_validator import ProfileValidator, VALID_OPTIONS

def validate(profile):
    """Thin helper matching the original test API."""
    return ProfileValidator().validate(profile)


VALID_PROFILE = {
    "business_name":  "TestCo",
    "business_type":  "E-commerce",
    "employee_count": "11-50",
    "server_purpose": "Database",
    "sensitive_data": "Yes",
    "has_it_staff":   "No",
    "security_budget": "Under $50",
}

LOW_RISK_PROFILE = {
    "business_name":  "LowRiskCafe",
    "business_type":  "Restaurant",
    "employee_count": "1-10",
    "server_purpose": "File Storage",
    "sensitive_data": "No",
    "has_it_staff":   "Yes",
    "security_budget": "$200+",
}


class TestProfileValidator(unittest.TestCase):
    def test_valid_profile_passes(self):
        ok, errors = validate(VALID_PROFILE)
        self.assertTrue(ok, f"Unexpected errors: {errors}")
        self.assertEqual(errors, [])

    def test_missing_field_fails(self):
        bad = dict(VALID_PROFILE)
        del bad["business_type"]
        ok, errors = validate(bad)
        self.assertFalse(ok)
        # Error message includes the question label, not the field key
        self.assertTrue(any("business" in e.lower() for e in errors))

    def test_invalid_business_type_fails(self):
        bad = dict(VALID_PROFILE)
        bad["business_type"] = "Nuclear Plant"
        ok, errors = validate(bad)
        self.assertFalse(ok)

    def test_invalid_employee_count_fails(self):
        bad = dict(VALID_PROFILE)
        bad["employee_count"] = "999-1000"
        ok, errors = validate(bad)
        self.assertFalse(ok)

    def test_all_valid_options_accepted(self):
        """Every value listed in VALID_OPTIONS must pass validation."""
        for field, options in VALID_OPTIONS.items():
            for opt in options:
                profile = dict(VALID_PROFILE)
                profile[field] = opt
                ok, errors = validate(profile)
                self.assertTrue(ok, f"Field={field} value={opt!r} failed: {errors}")


class TestContextManagerDB(unittest.TestCase):
    """Use a temporary database so tests never touch the real DB."""

    def setUp(self):
        self._tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self._db_path = self._tmp.name
        self._tmp.close()

    def tearDown(self):
        Path(self._db_path).unlink(missing_ok=True)

    def _get_cm(self):
        from modules.module2_context.context_manager import ContextManager
        from pathlib import Path
        return ContextManager(db_path=Path(self._db_path))

    def test_no_profile_returns_none(self):
        cm = self._get_cm()
        self.assertIsNone(cm.get_active_profile())

    def test_save_and_reload_profile(self):
        cm = self._get_cm()
        cm.save_profile(VALID_PROFILE)
        loaded = cm.get_active_profile()
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded["business_type"],  VALID_PROFILE["business_type"])
        self.assertEqual(loaded["employee_count"], VALID_PROFILE["employee_count"])
        self.assertEqual(loaded["sensitive_data"], VALID_PROFILE["sensitive_data"])

    def test_update_profile(self):
        cm = self._get_cm()
        cm.save_profile(VALID_PROFILE)
        profile = cm.get_active_profile()
        updated = dict(VALID_PROFILE)
        updated["employee_count"] = "51-300"
        cm.update_profile(profile["id"], updated)
        reloaded = cm.get_active_profile()
        self.assertEqual(reloaded["employee_count"], "51-300")


class TestContextWeightComputation(unittest.TestCase):
    def _weight(self, profile):
        """Returns the context_modifier float for a profile."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            from modules.module2_context.context_manager import ContextManager
            cm = ContextManager(db_path=Path(db_path))
            cm.save_profile(profile)
            loaded = cm.get_active_profile()
            weights = cm.compute_weights(loaded)
            return weights["context_modifier"]
        finally:
            Path(db_path).unlink(missing_ok=True)

    def test_weight_is_positive_float(self):
        w = self._weight(VALID_PROFILE)
        self.assertIsInstance(w, float)
        self.assertGreater(w, 0)

    def test_high_risk_profile_higher_weight_than_low(self):
        high = self._weight(VALID_PROFILE)
        low  = self._weight(LOW_RISK_PROFILE)
        self.assertGreater(high, low,
            f"High-risk weight ({high}) should exceed low-risk ({low})")

    def test_weight_within_reasonable_bounds(self):
        w = self._weight(VALID_PROFILE)
        self.assertGreaterEqual(w, 1.0)
        self.assertLessEqual(w,  6.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
