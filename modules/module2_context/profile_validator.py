"""
profile_validator.py — SME Profile Data Validator
Validates that a profile dict contains valid, non-empty answers
to all 6 context questions before they are stored in the database.

Also provides the master list of allowed options for each question,
used by both validation and the web form (Module 5).
"""

from typing import Any

# ── Allowed Options for Each Question ─────────────────────────
# These must match the keys in config.py multiplier/addition dicts.

VALID_OPTIONS: dict[str, list[str]] = {
    "business_type": [
        "E-commerce",
        "Healthcare",
        "Finance",
        "IT Services",
        "Restaurant",
        "Other",
    ],
    "employee_count": [
        "1-10",
        "11-50",
        "51-300",
    ],
    "server_purpose": [
        "Database",
        "Web Server",
        "App Server",
        "Email Server",
        "File Storage",
    ],
    "sensitive_data": [
        "Yes",
        "No",
    ],
    "has_it_staff": [
        "Yes",
        "No",
    ],
    "security_budget": [
        "Under $50",
        "$50-200",
        "$200+",
    ],
}

# Human-readable question labels (used in web UI and reports)
QUESTION_LABELS: dict[str, str] = {
    "business_type":    "Q1: What type of business are you?",
    "employee_count":   "Q2: How many employees does your business have?",
    "server_purpose":   "Q3: What is this server primarily used for?",
    "sensitive_data":   "Q4: Does this server store sensitive customer data?",
    "has_it_staff":     "Q5: Do you have dedicated IT/security staff?",
    "security_budget":  "Q6: What is your monthly IT security budget (USD)?",
}

# Required string field with a max length
BUSINESS_NAME_MAX_LEN = 120
REQUIRED_FIELDS = list(VALID_OPTIONS.keys())


class ProfileValidator:
    """Validates SME profile dicts before saving to the database."""

    def validate(self, profile: dict) -> tuple[bool, list[str]]:
        """
        Validate all fields in a profile dict.

        Args:
            profile: dict containing profile fields

        Returns:
            (is_valid, errors)
              is_valid — True if all checks pass
              errors   — list of human-readable error strings
        """
        errors: list[str] = []

        # Business name
        name = profile.get("business_name", "").strip()
        if not name:
            errors.append("Business name is required.")
        elif len(name) > BUSINESS_NAME_MAX_LEN:
            errors.append(
                f"Business name must be {BUSINESS_NAME_MAX_LEN} characters or fewer."
            )

        # Each of the 6 question fields
        for field, allowed in VALID_OPTIONS.items():
            value = profile.get(field)

            if value is None or str(value).strip() == "":
                label = QUESTION_LABELS.get(field, field)
                errors.append(f"'{label}' is required.")
                continue

            if value not in allowed:
                label = QUESTION_LABELS.get(field, field)
                errors.append(
                    f"Invalid value '{value}' for '{label}'. "
                    f"Allowed: {', '.join(allowed)}"
                )

        is_valid = len(errors) == 0
        return is_valid, errors

    def validate_field(self, field: str, value: Any) -> tuple[bool, str]:
        """
        Validate a single field value.
        Useful for live form validation in the web UI.

        Returns:
            (is_valid, error_message)
        """
        if field == "business_name":
            value = str(value).strip()
            if not value:
                return False, "Business name is required."
            if len(value) > BUSINESS_NAME_MAX_LEN:
                return False, f"Max {BUSINESS_NAME_MAX_LEN} characters."
            return True, ""

        allowed = VALID_OPTIONS.get(field)
        if allowed is None:
            return False, f"Unknown field '{field}'."

        if value not in allowed:
            return False, f"Must be one of: {', '.join(allowed)}"

        return True, ""

    @staticmethod
    def get_options(field: str) -> list[str]:
        """Return the list of allowed values for a given field."""
        return VALID_OPTIONS.get(field, [])

    @staticmethod
    def get_all_options() -> dict[str, list[str]]:
        """Return the complete options dict (used by the web form)."""
        return VALID_OPTIONS

    @staticmethod
    def get_question_labels() -> dict[str, str]:
        """Return human-readable labels for each field."""
        return QUESTION_LABELS


# ── Standalone test ────────────────────────────────────────────
if __name__ == "__main__":
    validator = ProfileValidator()

    # Test 1: Valid profile
    good = {
        "business_name": "MyShop Ltd",
        "business_type": "E-commerce",
        "employee_count": "11-50",
        "server_purpose": "Database",
        "sensitive_data": "Yes",
        "has_it_staff": "No",
        "security_budget": "Under $50",
    }
    ok, errs = validator.validate(good)
    print(f"Valid profile   → is_valid={ok}, errors={errs}")
    assert ok is True

    # Test 2: Missing fields
    bad = {"business_name": "X"}
    ok, errs = validator.validate(bad)
    print(f"Missing fields  → is_valid={ok}, errors={errs}")
    assert ok is False
    assert len(errs) == 6   # one per missing question

    # Test 3: Invalid option
    invalid_option = {**good, "business_type": "Hacker Corp"}
    ok, errs = validator.validate(invalid_option)
    print(f"Invalid option  → is_valid={ok}, errors={errs}")
    assert ok is False

    # Test 4: Empty business name
    empty_name = {**good, "business_name": "   "}
    ok, errs = validator.validate(empty_name)
    print(f"Empty name      → is_valid={ok}, errors={errs}")
    assert ok is False

    print("\nAll ProfileValidator tests passed.")
