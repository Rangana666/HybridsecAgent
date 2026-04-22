"""
password_fixes.py — Password Policy Fix Templates  (Module 4)
"""

PASSWORD_FIXES: dict[str, dict] = {

    "weak_password_policy": {
        "vuln_type":        "weak_password_policy",
        "title":            "Enforce Strong Password Policy",
        "description":      "Installs libpam-pwquality and configures minimum length 12, "
                            "complexity requirements, and 90-day maximum age "
                            "via /etc/security/pwquality.conf and /etc/login.defs.",
        "autofix_available": True,
        "risk_level":       "low",
        "config_file":      "/etc/login.defs",
        "service_to_restart": None,
        "commands": [
            # Install pwquality PAM module
            "apt-get install -y libpam-pwquality 2>/dev/null || yum install -y libpwquality 2>/dev/null || true",
            # Write pwquality config
            "cat > /etc/security/pwquality.conf << 'EOF'\n"
            "minlen = 12\n"
            "dcredit = -1\n"
            "ucredit = -1\n"
            "lcredit = -1\n"
            "ocredit = -1\n"
            "maxrepeat = 3\n"
            "EOF",
            # Set password aging in login.defs
            "sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs",
            "sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/'  /etc/login.defs",
            "sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN    12/'  /etc/login.defs",
            "grep -qE '^PASS_MAX_DAYS' /etc/login.defs || echo 'PASS_MAX_DAYS   90' >> /etc/login.defs",
            "grep -qE '^PASS_MIN_DAYS' /etc/login.defs || echo 'PASS_MIN_DAYS   1'  >> /etc/login.defs",
            "grep -qE '^PASS_MIN_LEN'  /etc/login.defs || echo 'PASS_MIN_LEN    12' >> /etc/login.defs",
        ],
        "verify_command":   "grep -E '^(PASS_MAX_DAYS|PASS_MIN_LEN)' /etc/login.defs",
        "verify_expected":  "PASS_MAX_DAYS",
        "manual_steps": [
            "1. Install pwquality:  sudo apt install libpam-pwquality",
            "2. Edit /etc/security/pwquality.conf:",
            "   minlen   = 12    # Minimum 12 characters",
            "   dcredit  = -1    # At least 1 digit",
            "   ucredit  = -1    # At least 1 uppercase",
            "   lcredit  = -1    # At least 1 lowercase",
            "   ocredit  = -1    # At least 1 special character",
            "3. Edit /etc/login.defs:",
            "   PASS_MAX_DAYS   90",
            "   PASS_MIN_DAYS   1",
            "   PASS_MIN_LEN    12",
            "4. Apply to existing users (example for 'ubuntu'):",
            "   sudo chage -M 90 ubuntu",
        ],
        "estimated_time":  "3–5 minutes",
        "requires_root":   True,
        "rollback_note":   "Original /etc/login.defs restored from backup.",
    },

    "user_empty_password": {
        "vuln_type":        "user_empty_password",
        "title":            "Lock Accounts with Empty Passwords",
        "description":      "Locks all user accounts that have no password set using passwd -l. "
                            "The affected users will need to set a new password.",
        "autofix_available": False,
        "risk_level":       "medium",
        "config_file":      None,
        "service_to_restart": None,
        "commands": [],
        "verify_command":   None,
        "verify_expected":  None,
        "manual_steps": [
            "1. Find accounts with empty passwords:",
            "   sudo awk -F: '($2 == \"\" || $2 == \"!\") {print $1}' /etc/shadow",
            "2. Set a password for each account:",
            "   sudo passwd <username>",
            "3. OR lock the account if it is not needed:",
            "   sudo passwd -l <username>",
            "4. Verify: sudo passwd -S <username>",
            "   (Status should show 'P' = password set, or 'L' = locked)",
            "",
            "This fix is semi-automatic because each account needs",
            "individual attention — a new password must be communicated",
            "to the account owner.",
        ],
        "estimated_time":  "5–10 minutes per account",
        "requires_root":   True,
        "rollback_note":   "Run 'sudo passwd -u <username>' to unlock an account.",
    },

    "root_equivalent_user": {
        "vuln_type":        "root_equivalent_user",
        "title":            "Remove Non-Root Account with UID 0",
        "description":      "Only the 'root' account should have UID 0. "
                            "Any other account with UID 0 is a backdoor-level finding "
                            "and must be investigated and removed.",
        "autofix_available": False,
        "risk_level":       "high",
        "config_file":      "/etc/passwd",
        "service_to_restart": None,
        "commands": [],
        "verify_command":   "awk -F: '($3 == 0) {print $1}' /etc/passwd",
        "verify_expected":  "root",
        "manual_steps": [
            "⚠️  INVESTIGATE FIRST — this may indicate a compromise.",
            "1. Find all UID 0 accounts:",
            "   awk -F: '($3 == 0) {print $1}' /etc/passwd",
            "2. For each non-root UID 0 account, investigate:",
            "   - When was it created? (last, who, auth.log)",
            "   - Who created it?",
            "   - Does it have authorized use?",
            "3. Change the UID to a normal non-zero value:",
            "   sudo usermod -u <new_uid> <username>",
            "4. OR delete the account if it is malicious:",
            "   sudo userdel -r <username>",
            "5. Review all system logs for signs of compromise.",
        ],
        "estimated_time":  "30+ minutes (investigation required)",
        "requires_root":   True,
        "rollback_note":   "Manual rollback only — restore original /etc/passwd from backup.",
    },
}


def get_fix(vuln_type: str) -> dict | None:
    return PASSWORD_FIXES.get(vuln_type)


def list_supported_types() -> list[str]:
    return list(PASSWORD_FIXES.keys())
