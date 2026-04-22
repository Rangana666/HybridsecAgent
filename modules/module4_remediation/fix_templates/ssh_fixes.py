"""
ssh_fixes.py — SSH Vulnerability Fix Templates  (Module 4)

Provides auto-fix commands and manual remediation steps for every
SSH vulnerability detected by Module 1 (system_scanner.py).

Each template is a dict with the following keys:
  vuln_type          — matches Module 1 vulnerability type string
  title              — short display title
  description        — what the fix achieves
  autofix_available  — True = can be executed automatically
  risk_level         — "low" | "medium" | "high"
                       (how dangerous the auto-fix operation is)
  config_file        — absolute path to back up before applying fix
  service_to_restart — systemd service name to reload after fix
  commands           — ordered list of shell commands to apply the fix
  verify_command     — command whose output we check to confirm success
  verify_expected    — substring that must appear in verify output
  manual_steps       — human-readable numbered instructions
  estimated_time     — approximate fix duration
  requires_root      — whether sudo/root is required
  rollback_note      — what BackupManager.restore() reverts
"""

SSH_FIXES: dict[str, dict] = {

    "ssh_root_login_enabled": {
        "vuln_type":        "ssh_root_login_enabled",
        "title":            "Disable SSH Direct Root Login",
        "description":      "Sets PermitRootLogin to 'no' in sshd_config. "
                            "Administrators must SSH as a regular user and then "
                            "use 'sudo' or 'su' to gain root access.",
        "autofix_available": True,
        "risk_level":       "low",
        "config_file":      "/etc/ssh/sshd_config",
        "service_to_restart": "sshd",
        "commands": [
            # Replace any existing PermitRootLogin line
            "sed -i 's/^#*\\s*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
            # Add the line if it is not present at all
            "grep -qE '^PermitRootLogin' /etc/ssh/sshd_config "
            "|| echo 'PermitRootLogin no' >> /etc/ssh/sshd_config",
        ],
        "verify_command":   "sshd -T | grep -i permitrootlogin",
        "verify_expected":  "permitrootlogin no",
        "manual_steps": [
            "1. Open /etc/ssh/sshd_config in a text editor.",
            "2. Find the line starting with 'PermitRootLogin'.",
            "3. Change it to:  PermitRootLogin no",
            "4. If the line does not exist, add it at the end of the file.",
            "5. Restart SSH:   sudo systemctl restart sshd",
            "6. IMPORTANT: Make sure you have a non-root sudo user before applying.",
        ],
        "estimated_time":  "< 1 minute",
        "requires_root":   True,
        "rollback_note":   "Original sshd_config restored — root login re-enabled.",
    },

    "ssh_password_auth_enabled": {
        "vuln_type":        "ssh_password_auth_enabled",
        "title":            "Disable SSH Password Authentication",
        "description":      "Enforces key-based SSH authentication only. "
                            "All users must have an SSH key pair before this fix is applied.",
        "autofix_available": True,
        "risk_level":       "medium",
        "config_file":      "/etc/ssh/sshd_config",
        "service_to_restart": "sshd",
        "commands": [
            "sed -i 's/^#*\\s*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config",
            "grep -qE '^PasswordAuthentication' /etc/ssh/sshd_config "
            "|| echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config",
        ],
        "verify_command":   "sshd -T | grep -i passwordauthentication",
        "verify_expected":  "passwordauthentication no",
        "manual_steps": [
            "⚠️  WARNING: Do this ONLY after confirming your SSH key pair works!",
            "1. Generate an SSH key (if you don't have one):",
            "   ssh-keygen -t ed25519 -C 'your_email@example.com'",
            "2. Copy your public key to the server:",
            "   ssh-copy-id user@your-server-ip",
            "3. Test that key-based login works BEFORE disabling passwords.",
            "4. Edit /etc/ssh/sshd_config  →  PasswordAuthentication no",
            "5. Restart SSH:  sudo systemctl restart sshd",
        ],
        "estimated_time":  "5–10 minutes",
        "requires_root":   True,
        "rollback_note":   "Original sshd_config restored — password auth re-enabled.",
    },

    "ssh_protocol_v1": {
        "vuln_type":        "ssh_protocol_v1",
        "title":            "Enforce SSH Protocol Version 2 Only",
        "description":      "Removes Protocol 1 from sshd_config. "
                            "All modern clients support Protocol 2.",
        "autofix_available": True,
        "risk_level":       "low",
        "config_file":      "/etc/ssh/sshd_config",
        "service_to_restart": "sshd",
        "commands": [
            "sed -i 's/^#*\\s*Protocol.*/Protocol 2/' /etc/ssh/sshd_config",
            "grep -qE '^Protocol' /etc/ssh/sshd_config "
            "|| echo 'Protocol 2' >> /etc/ssh/sshd_config",
        ],
        "verify_command":   "sshd -T | grep -i protocol",
        "verify_expected":  "2",
        "manual_steps": [
            "1. Open /etc/ssh/sshd_config.",
            "2. Set:  Protocol 2",
            "3. Remove or comment out any 'Protocol 1' line.",
            "4. Restart SSH:  sudo systemctl restart sshd",
        ],
        "estimated_time":  "< 1 minute",
        "requires_root":   True,
        "rollback_note":   "Original sshd_config restored.",
    },

    "ssh_default_port": {
        "vuln_type":        "ssh_default_port",
        "title":            "Move SSH to a Non-Standard Port",
        "description":      "Changes SSH from port 22 to port 2222 (or custom). "
                            "Significantly reduces automated scan noise. "
                            "Ensure your firewall allows the new port before applying.",
        "autofix_available": True,
        "risk_level":       "medium",
        "config_file":      "/etc/ssh/sshd_config",
        "service_to_restart": "sshd",
        "commands": [
            "sed -i 's/^#*\\s*Port.*/Port 2222/' /etc/ssh/sshd_config",
            "grep -qE '^Port' /etc/ssh/sshd_config "
            "|| echo 'Port 2222' >> /etc/ssh/sshd_config",
            # Open the new port in UFW before restarting
            "which ufw && ufw allow 2222/tcp || true",
        ],
        "verify_command":   "sshd -T | grep -i '^port'",
        "verify_expected":  "port 2222",
        "manual_steps": [
            "⚠️  WARNING: Open the new port in your firewall FIRST!",
            "1. Allow new port:  sudo ufw allow 2222/tcp",
            "2. Edit /etc/ssh/sshd_config  →  Port 2222",
            "3. Restart SSH:  sudo systemctl restart sshd",
            "4. Test in a new session:  ssh -p 2222 user@server",
            "5. Once confirmed, block port 22:  sudo ufw deny 22/tcp",
        ],
        "estimated_time":  "5 minutes",
        "requires_root":   True,
        "rollback_note":   "Original sshd_config restored — SSH moved back to port 22.",
    },

    "ssh_empty_passwords_allowed": {
        "vuln_type":        "ssh_empty_passwords_allowed",
        "title":            "Disallow Empty Passwords in SSH",
        "description":      "Sets PermitEmptyPasswords no in sshd_config. "
                            "Prevents login to accounts that have no password set.",
        "autofix_available": True,
        "risk_level":       "low",
        "config_file":      "/etc/ssh/sshd_config",
        "service_to_restart": "sshd",
        "commands": [
            "sed -i 's/^#*\\s*PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config",
            "grep -qE '^PermitEmptyPasswords' /etc/ssh/sshd_config "
            "|| echo 'PermitEmptyPasswords no' >> /etc/ssh/sshd_config",
        ],
        "verify_command":   "sshd -T | grep -i permitemptypasswords",
        "verify_expected":  "permitemptypasswords no",
        "manual_steps": [
            "1. Edit /etc/ssh/sshd_config.",
            "2. Set:  PermitEmptyPasswords no",
            "3. Also set passwords on all accounts: sudo passwd <username>",
            "4. Restart SSH:  sudo systemctl restart sshd",
        ],
        "estimated_time":  "< 1 minute",
        "requires_root":   True,
        "rollback_note":   "Original sshd_config restored.",
    },

    "ssh_x11_forwarding": {
        "vuln_type":        "ssh_x11_forwarding",
        "title":            "Disable SSH X11 Forwarding",
        "description":      "Sets X11Forwarding no in sshd_config. "
                            "Most server environments do not need graphical forwarding.",
        "autofix_available": True,
        "risk_level":       "low",
        "config_file":      "/etc/ssh/sshd_config",
        "service_to_restart": "sshd",
        "commands": [
            "sed -i 's/^#*\\s*X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config",
            "grep -qE '^X11Forwarding' /etc/ssh/sshd_config "
            "|| echo 'X11Forwarding no' >> /etc/ssh/sshd_config",
        ],
        "verify_command":   "sshd -T | grep -i x11forwarding",
        "verify_expected":  "x11forwarding no",
        "manual_steps": [
            "1. Edit /etc/ssh/sshd_config.",
            "2. Set:  X11Forwarding no",
            "3. Restart SSH:  sudo systemctl restart sshd",
        ],
        "estimated_time":  "< 1 minute",
        "requires_root":   True,
        "rollback_note":   "Original sshd_config restored.",
    },
}


def get_fix(vuln_type: str) -> dict | None:
    """Return the fix template for a given SSH vulnerability type, or None."""
    return SSH_FIXES.get(vuln_type)


def list_supported_types() -> list[str]:
    """Return all SSH vulnerability types that have an auto-fix template."""
    return list(SSH_FIXES.keys())
