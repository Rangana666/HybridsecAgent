"""
context_manager.py — SME Profile Save / Load / Weight Computation  (Module 2)

Responsibilities:
  1. Initialize the SQLite database table 'sme_profiles'
  2. Save a new profile or update the existing one
  3. Load the active profile
  4. Compute context weight modifiers from the 6 profile answers
     (used by Module 3 — Triple Hybrid Scoring Engine)

Context weight formula
──────────────────────
  business_multiplier  =  BUSINESS_TYPE_MULTIPLIERS[business_type]   (1.0 – 1.8)
  additive_bonus       =  sum of additions for the other 5 answers   (0.0 – 1.6)

  context_modifier     =  business_multiplier + additive_bonus

The modifier is passed to Module 3 where it is applied as:
  adjusted_score = min(10.0, raw_hybrid_score * context_modifier)
"""

import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Resolve paths relative to project root
_PROJECT_ROOT = Path(__file__).parent.parent.parent

# Import config values
import sys
sys.path.insert(0, str(_PROJECT_ROOT))
from config import (
    DATABASE_PATH,
    BUSINESS_TYPE_MULTIPLIERS,
    EMPLOYEE_COUNT_ADDITIONS,
    SERVER_PURPOSE_ADDITIONS,
    SENSITIVE_DATA_ADDITION,
    IT_STAFF_ADDITION,
    BUDGET_ADDITION,
)
from modules.module2_context.profile_validator import ProfileValidator

# ── Database Schema ────────────────────────────────────────────
_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS sme_profiles (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    business_name   TEXT    NOT NULL,
    business_type   TEXT    NOT NULL,
    employee_count  TEXT    NOT NULL,
    server_purpose  TEXT    NOT NULL,
    sensitive_data  TEXT    NOT NULL,
    has_it_staff    TEXT    NOT NULL,
    security_budget TEXT    NOT NULL,
    weights_json    TEXT    NOT NULL,
    is_active       INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL
);
"""

# Profile field names (used for SELECT/INSERT ordering)
_PROFILE_FIELDS = [
    "business_name", "business_type", "employee_count",
    "server_purpose", "sensitive_data", "has_it_staff", "security_budget",
]


class ContextManager:
    """
    Manages SME business profiles in SQLite and computes context weights.
    A single instance is safe to share across threads (each method opens
    its own short-lived connection).
    """

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = Path(db_path) if db_path else DATABASE_PATH
        self._validator = ProfileValidator()
        self._init_db()

    # ── Public API ─────────────────────────────────────────────

    def save_profile(self, profile: dict) -> tuple[bool, int | list[str]]:
        """
        Validate and persist a profile.

        Args:
            profile: dict with keys business_name + the 6 question fields.

        Returns:
            (True,  profile_id)  on success
            (False, [errors])    on validation failure
        """
        # Validate first
        is_valid, errors = self._validator.validate(profile)
        if not is_valid:
            logger.warning("Profile validation failed: %s", errors)
            return False, errors

        weights = self.compute_weights(profile)
        now = datetime.now().isoformat(timespec="seconds")

        with self._connect() as conn:
            # Deactivate any previously active profiles
            conn.execute("UPDATE sme_profiles SET is_active = 0")

            cur = conn.execute(
                """
                INSERT INTO sme_profiles
                    (business_name, business_type, employee_count,
                     server_purpose, sensitive_data, has_it_staff,
                     security_budget, weights_json, is_active,
                     created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    profile["business_name"].strip(),
                    profile["business_type"],
                    profile["employee_count"],
                    profile["server_purpose"],
                    profile["sensitive_data"],
                    profile["has_it_staff"],
                    profile["security_budget"],
                    json.dumps(weights),
                    now,
                    now,
                ),
            )
            profile_id = cur.lastrowid
            conn.commit()

        logger.info(
            "Saved SME profile id=%d  business='%s'  modifier=%.2f",
            profile_id,
            profile["business_name"],
            weights["context_modifier"],
        )
        return True, profile_id

    def update_profile(self, profile_id: int, profile: dict) -> tuple[bool, list[str]]:
        """
        Update an existing profile by ID and make it the active profile.

        Returns:
            (True,  [])       on success
            (False, [errors]) on validation failure or missing ID
        """
        is_valid, errors = self._validator.validate(profile)
        if not is_valid:
            return False, errors

        weights = self.compute_weights(profile)
        now = datetime.now().isoformat(timespec="seconds")

        with self._connect() as conn:
            conn.execute("UPDATE sme_profiles SET is_active = 0")
            rows = conn.execute(
                """
                UPDATE sme_profiles SET
                    business_name   = ?,
                    business_type   = ?,
                    employee_count  = ?,
                    server_purpose  = ?,
                    sensitive_data  = ?,
                    has_it_staff    = ?,
                    security_budget = ?,
                    weights_json    = ?,
                    is_active       = 1,
                    updated_at      = ?
                WHERE id = ?
                """,
                (
                    profile["business_name"].strip(),
                    profile["business_type"],
                    profile["employee_count"],
                    profile["server_purpose"],
                    profile["sensitive_data"],
                    profile["has_it_staff"],
                    profile["security_budget"],
                    json.dumps(weights),
                    now,
                    profile_id,
                ),
            ).rowcount
            conn.commit()

        if rows == 0:
            return False, [f"No profile found with id={profile_id}"]

        logger.info("Updated SME profile id=%d", profile_id)
        return True, []

    def get_active_profile(self) -> Optional[dict]:
        """
        Return the currently active SME profile, or None if none exists.
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM sme_profiles WHERE is_active = 1 "
                "ORDER BY updated_at DESC LIMIT 1"
            ).fetchone()

        return self._row_to_dict(row) if row else None

    def get_profile_by_id(self, profile_id: int) -> Optional[dict]:
        """Return a specific profile by its database ID."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM sme_profiles WHERE id = ?",
                (profile_id,),
            ).fetchone()
        return self._row_to_dict(row) if row else None

    def list_profiles(self) -> list[dict]:
        """Return all saved profiles, newest first."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM sme_profiles ORDER BY updated_at DESC"
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def set_active_profile(self, profile_id: int) -> bool:
        """
        Make a specific profile the active one.
        Returns True if the profile was found and activated.
        """
        with self._connect() as conn:
            conn.execute("UPDATE sme_profiles SET is_active = 0")
            rows = conn.execute(
                "UPDATE sme_profiles SET is_active = 1 WHERE id = ?",
                (profile_id,),
            ).rowcount
            conn.commit()

        if rows == 0:
            logger.warning("set_active_profile: no profile with id=%d", profile_id)
            return False

        logger.info("Active profile set to id=%d", profile_id)
        return True

    def delete_profile(self, profile_id: int) -> bool:
        """Delete a profile. If it was active, no profile will be active after."""
        with self._connect() as conn:
            rows = conn.execute(
                "DELETE FROM sme_profiles WHERE id = ?", (profile_id,)
            ).rowcount
            conn.commit()
        return rows > 0

    # ── Weight Computation ─────────────────────────────────────

    def compute_weights(self, profile: dict) -> dict:
        """
        Compute context weight modifiers from a profile dict.

        Returns a weights dict used by Module 3 (scoring engine):
        {
            "business_multiplier": 1.8,    # base multiplier (Q1)
            "employee_addition":   0.1,    # Q2 addition
            "server_addition":     0.4,    # Q3 addition
            "data_addition":       0.4,    # Q4 addition
            "staff_addition":      0.3,    # Q5 addition
            "budget_addition":     0.1,    # Q6 addition
            "total_addition":      1.3,    # sum of Q2–Q6 additions
            "context_modifier":    3.1,    # business_multiplier + total_addition
        }
        """
        biz_multiplier = BUSINESS_TYPE_MULTIPLIERS.get(
            profile.get("business_type", "Other"), 1.0
        )
        emp_add = EMPLOYEE_COUNT_ADDITIONS.get(
            profile.get("employee_count", "1-10"), 0.3
        )
        server_add = SERVER_PURPOSE_ADDITIONS.get(
            profile.get("server_purpose", "File Storage"), 0.0
        )
        data_add = SENSITIVE_DATA_ADDITION.get(
            profile.get("sensitive_data", "No"), 0.0
        )
        staff_add = IT_STAFF_ADDITION.get(
            profile.get("has_it_staff", "No"), 0.3
        )
        budget_add = BUDGET_ADDITION.get(
            profile.get("security_budget", "Under $50"), 0.2
        )

        total_add = round(emp_add + server_add + data_add + staff_add + budget_add, 2)
        context_modifier = round(biz_multiplier + total_add, 2)

        return {
            "business_multiplier": biz_multiplier,
            "employee_addition":   emp_add,
            "server_addition":     server_add,
            "data_addition":       data_add,
            "staff_addition":      staff_add,
            "budget_addition":     budget_add,
            "total_addition":      total_add,
            "context_modifier":    context_modifier,
        }

    # ── Private Helpers ────────────────────────────────────────

    def _init_db(self):
        """Create the sme_profiles table if it does not exist."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(_CREATE_TABLE_SQL)
            conn.commit()
        logger.debug("Database initialised at %s", self.db_path)

    def _connect(self) -> sqlite3.Connection:
        """Open a connection with row factory for dict-like access."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict:
        """Convert a sqlite3.Row to a plain dict, deserialising weights_json."""
        d = dict(row)
        if "weights_json" in d and d["weights_json"]:
            try:
                d["weights"] = json.loads(d["weights_json"])
            except (json.JSONDecodeError, TypeError):
                d["weights"] = {}
            del d["weights_json"]
        else:
            d["weights"] = {}
        return d


# ── Standalone test ────────────────────────────────────────────
if __name__ == "__main__":
    import tempfile
    import os

    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")

    # Use a temp DB so we don't pollute the real database during testing
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp_db = Path(f.name)

    try:
        cm = ContextManager(db_path=tmp_db)

        # ── Test 1: Save a valid profile ─────────────────────
        profile = {
            "business_name": "Sri Lanka E-Shop",
            "business_type": "E-commerce",
            "employee_count": "11-50",
            "server_purpose": "Database",
            "sensitive_data": "Yes",
            "has_it_staff": "No",
            "security_budget": "Under $50",
        }
        ok, result = cm.save_profile(profile)
        assert ok, f"save_profile failed: {result}"
        pid = result
        print(f"[PASS] save_profile  → id={pid}")

        # ── Test 2: Retrieve active profile ──────────────────
        active = cm.get_active_profile()
        assert active is not None
        assert active["business_name"] == "Sri Lanka E-Shop"
        print(f"[PASS] get_active_profile → '{active['business_name']}'")

        # ── Test 3: Weights computed correctly ───────────────
        w = active["weights"]
        print(f"       Weights → multiplier={w['business_multiplier']}  "
              f"additions={w['total_addition']}  "
              f"modifier={w['context_modifier']}")
        # E-commerce=1.8, 11-50=0.1, DB=0.4, Yes=0.4, No=0.3, Under $50=0.2
        assert w["business_multiplier"] == 1.8
        assert w["employee_addition"] == 0.1
        assert w["server_addition"] == 0.4
        assert w["data_addition"] == 0.4
        assert w["staff_addition"] == 0.3
        assert w["budget_addition"] == 0.2
        assert w["total_addition"] == 1.4
        assert w["context_modifier"] == 3.2
        print(f"[PASS] compute_weights — all assertions passed")

        # ── Test 4: Save a second profile ────────────────────
        ok2, pid2 = cm.save_profile({
            "business_name": "Colombo Restaurant",
            "business_type": "Restaurant",
            "employee_count": "1-10",
            "server_purpose": "File Storage",
            "sensitive_data": "No",
            "has_it_staff": "No",
            "security_budget": "$50-200",
        })
        assert ok2
        print(f"[PASS] save second profile → id={pid2}")

        # First profile should now be inactive
        all_profiles = cm.list_profiles()
        assert len(all_profiles) == 2
        print(f"[PASS] list_profiles → {len(all_profiles)} profiles")

        # ── Test 5: Set first profile active again ───────────
        result = cm.set_active_profile(pid)
        assert result
        active2 = cm.get_active_profile()
        assert active2["id"] == pid
        print(f"[PASS] set_active_profile → id={pid} is active")

        # ── Test 6: Validation failure ───────────────────────
        bad_ok, errors = cm.save_profile({"business_name": "X"})
        assert not bad_ok
        assert len(errors) >= 6
        print(f"[PASS] validation failure → {len(errors)} error(s) returned")

        # ── Test 7: Delete profile ────────────────────────────
        deleted = cm.delete_profile(pid2)
        assert deleted
        assert len(cm.list_profiles()) == 1
        print(f"[PASS] delete_profile → 1 profile remaining")

        print("\nAll ContextManager tests PASSED.")

    finally:
        os.unlink(tmp_db)
