"""
firewall_fixes.py — Firewall Vulnerability Fix Templates  (Module 4)
"""

FIREWALL_FIXES: dict[str, dict] = {

    "firewall_disabled": {
        "vuln_type":        "firewall_disabled",
        "title":            "Enable and Configure UFW Firewall",
        "description":      "Enables UFW, sets default deny for incoming traffic, "
                            "and allows SSH so you are not locked out.",
        "autofix_available": True,
        "risk_level":       "medium",
        "config_file":      None,
        "service_to_restart": None,
        "commands": [
            # Reset to a known state
            "ufw --force reset",
            # Default deny incoming, allow outgoing
            "ufw default deny incoming",
            "ufw default allow outgoing",
            # Allow SSH — detect which port is configured
            "SSH_PORT=$(sshd -T 2>/dev/null | grep '^port' | awk '{print $2}' || echo 22) "
            "&& ufw allow ${SSH_PORT}/tcp",
            # Allow HTTP/HTTPS if a web server is running
            "systemctl is-active --quiet apache2 nginx 2>/dev/null "
            "&& ufw allow 80/tcp && ufw allow 443/tcp || true",
            # Enable UFW non-interactively
            "ufw --force enable",
        ],
        "verify_command":   "ufw status",
        "verify_expected":  "Status: active",
        "manual_steps": [
            "⚠️  IMPORTANT: Make sure SSH port is allowed BEFORE enabling firewall!",
            "1. Reset UFW:           sudo ufw --force reset",
            "2. Default deny:        sudo ufw default deny incoming",
            "3. Allow outgoing:      sudo ufw default allow outgoing",
            "4. Allow SSH (port 22): sudo ufw allow 22/tcp",
            "5. Allow HTTP if needed:sudo ufw allow 80/tcp",
            "6. Allow HTTPS:         sudo ufw allow 443/tcp",
            "7. Enable firewall:     sudo ufw --force enable",
            "8. Check status:        sudo ufw status verbose",
        ],
        "estimated_time":  "2–3 minutes",
        "requires_root":   True,
        "rollback_note":   "UFW disabled and reset. Run 'sudo ufw --force reset' to undo manually.",
    },

    "firewall_default_allow": {
        "vuln_type":        "firewall_default_allow",
        "title":            "Change Firewall Default Policy to DENY",
        "description":      "Sets UFW default incoming policy to DENY. "
                            "All inbound traffic is blocked unless explicitly allowed.",
        "autofix_available": True,
        "risk_level":       "medium",
        "config_file":      None,
        "service_to_restart": None,
        "commands": [
            "SSH_PORT=$(sshd -T 2>/dev/null | grep '^port' | awk '{print $2}' || echo 22) "
            "&& ufw allow ${SSH_PORT}/tcp",
            "ufw default deny incoming",
            "ufw reload",
        ],
        "verify_command":   "ufw status verbose",
        "verify_expected":  "Default: deny (incoming)",
        "manual_steps": [
            "1. First ensure SSH is allowed: sudo ufw allow 22/tcp",
            "2. Set default deny:            sudo ufw default deny incoming",
            "3. Reload UFW:                  sudo ufw reload",
            "4. Check status:                sudo ufw status verbose",
        ],
        "estimated_time":  "< 1 minute",
        "requires_root":   True,
        "rollback_note":   "Run 'sudo ufw default allow incoming' to revert.",
    },

    "high_failed_login_count": {
        "vuln_type":        "high_failed_login_count",
        "title":            "Block Brute Force IPs with UFW",
        "description":      "Installs and configures fail2ban to automatically block "
                            "IPs that exceed the SSH brute force threshold.",
        "autofix_available": True,
        "risk_level":       "low",
        "config_file":      "/etc/fail2ban/jail.local",
        "service_to_restart": "fail2ban",
        "commands": [
            "apt-get install -y fail2ban",
            # Write a basic jail.local if it doesn't exist
            "test -f /etc/fail2ban/jail.local || cat > /etc/fail2ban/jail.local << 'EOF'\n"
            "[DEFAULT]\nbantime  = 3600\nfindtime = 600\nmaxretry = 5\n\n"
            "[sshd]\nenabled = true\nport    = ssh\nlogpath = %(sshd_log)s\nbackend = %(sshd_backend)s\nEOF",
            "systemctl enable fail2ban",
            "systemctl restart fail2ban",
        ],
        "verify_command":   "systemctl is-active fail2ban",
        "verify_expected":  "active",
        "manual_steps": [
            "1. Install fail2ban: sudo apt install fail2ban",
            "2. Create /etc/fail2ban/jail.local with:",
            "   [DEFAULT]",
            "   bantime  = 3600",
            "   findtime = 600",
            "   maxretry = 5",
            "   [sshd]",
            "   enabled = true",
            "3. Start:  sudo systemctl enable --now fail2ban",
            "4. Status: sudo fail2ban-client status sshd",
        ],
        "estimated_time":  "2–3 minutes",
        "requires_root":   True,
        "rollback_note":   "Stop fail2ban: sudo systemctl stop fail2ban",
    },

    "open_sensitive_port": {
        "vuln_type":        "open_sensitive_port",
        "title":            "Block Sensitive Port in Firewall",
        "description":      "Denies access to sensitive service ports from external IPs "
                            "while allowing localhost connections.",
        "autofix_available": False,
        "risk_level":       "high",
        "config_file":      None,
        "service_to_restart": None,
        "commands": [],
        "verify_command":   None,
        "verify_expected":  None,
        "manual_steps": [
            "1. Identify the sensitive port (e.g. 3306 for MySQL).",
            "2. Delete any existing allow rule: sudo ufw delete allow <PORT>/tcp",
            "3. Block from external: sudo ufw deny <PORT>/tcp",
            "4. Applications on the same server can still use 127.0.0.1:<PORT>.",
            "5. Check: sudo ufw status verbose",
        ],
        "estimated_time":  "5 minutes",
        "requires_root":   True,
        "rollback_note":   "Run 'sudo ufw allow <PORT>/tcp' to re-open the port.",
    },
}


def get_fix(vuln_type: str) -> dict | None:
    return FIREWALL_FIXES.get(vuln_type)


def list_supported_types() -> list[str]:
    return list(FIREWALL_FIXES.keys())
