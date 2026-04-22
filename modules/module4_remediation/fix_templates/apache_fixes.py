"""
apache_fixes.py — Web Server Vulnerability Fix Templates  (Module 4)
Covers Apache and Nginx update and basic hardening.
"""

APACHE_FIXES: dict[str, dict] = {

    "apache_outdated": {
        "vuln_type":        "apache_outdated",
        "title":            "Update Apache HTTP Server",
        "description":      "Applies all pending security updates for apache2 via apt. "
                            "Config files are preserved during the upgrade.",
        "autofix_available": True,
        "risk_level":       "low",
        "config_file":      "/etc/apache2/apache2.conf",
        "service_to_restart": "apache2",
        "commands": [
            "apt-get update -qq",
            "apt-get install --only-upgrade -y apache2",
            "systemctl restart apache2",
        ],
        "verify_command":   "apache2 -v 2>/dev/null | head -1",
        "verify_expected":  "Apache",
        "manual_steps": [
            "1. Update package list:  sudo apt update",
            "2. Upgrade Apache only:  sudo apt install --only-upgrade apache2",
            "3. Restart service:      sudo systemctl restart apache2",
            "4. Check new version:    apache2 -v",
            "5. Check for errors:     sudo systemctl status apache2",
        ],
        "estimated_time":  "2–5 minutes",
        "requires_root":   True,
        "rollback_note":   "apt-get install apache2=<previous_version> to downgrade.",
    },

    "nginx_outdated": {
        "vuln_type":        "nginx_outdated",
        "title":            "Update Nginx Web Server",
        "description":      "Applies all pending security updates for nginx via apt.",
        "autofix_available": True,
        "risk_level":       "low",
        "config_file":      "/etc/nginx/nginx.conf",
        "service_to_restart": "nginx",
        "commands": [
            "apt-get update -qq",
            "apt-get install --only-upgrade -y nginx",
            "nginx -t",
            "systemctl restart nginx",
        ],
        "verify_command":   "nginx -v 2>&1",
        "verify_expected":  "nginx",
        "manual_steps": [
            "1. Update package list: sudo apt update",
            "2. Upgrade Nginx only:  sudo apt install --only-upgrade nginx",
            "3. Test config:         sudo nginx -t",
            "4. Restart service:     sudo systemctl restart nginx",
            "5. Check new version:   nginx -v",
        ],
        "estimated_time":  "2–5 minutes",
        "requires_root":   True,
        "rollback_note":   "apt-get install nginx=<previous_version> to downgrade.",
    },

    "unpatched_package": {
        "vuln_type":        "unpatched_package",
        "title":            "Apply Security Package Updates",
        "description":      "Applies all pending security updates using "
                            "'apt-get upgrade --with-new-pkgs' (security sources only).",
        "autofix_available": True,
        "risk_level":       "low",
        "config_file":      None,
        "service_to_restart": None,
        "commands": [
            "apt-get update -qq",
            "apt-get -y upgrade",
        ],
        "verify_command":   "apt list --upgradable 2>/dev/null | wc -l",
        "verify_expected":  None,
        "manual_steps": [
            "1. Update package list:         sudo apt update",
            "2. View pending upgrades:       apt list --upgradable",
            "3. Apply security upgrades:     sudo apt upgrade",
            "4. Reboot if kernel was updated: sudo reboot",
            "5. Enable automatic security updates:",
            "   sudo apt install unattended-upgrades",
            "   sudo dpkg-reconfigure unattended-upgrades",
        ],
        "estimated_time":  "5–15 minutes",
        "requires_root":   True,
        "rollback_note":   "No automatic rollback — test on a staging server first.",
    },

    "ssl_certificate_missing": {
        "vuln_type":        "ssl_certificate_missing",
        "title":            "Install Free SSL Certificate with Let's Encrypt",
        "description":      "Installs Certbot and obtains a free SSL certificate "
                            "from Let's Encrypt. Requires a domain name and port 80 open.",
        "autofix_available": False,
        "risk_level":       "medium",
        "config_file":      None,
        "service_to_restart": "apache2",
        "commands": [],
        "verify_command":   None,
        "verify_expected":  None,
        "manual_steps": [
            "Prerequisites: domain pointing to this server, port 80 open.",
            "",
            "For Apache:",
            "1. Install Certbot:  sudo apt install certbot python3-certbot-apache",
            "2. Get certificate:  sudo certbot --apache -d yourdomain.com",
            "3. Auto-renewal:     sudo certbot renew --dry-run",
            "",
            "For Nginx:",
            "1. Install Certbot:  sudo apt install certbot python3-certbot-nginx",
            "2. Get certificate:  sudo certbot --nginx -d yourdomain.com",
            "",
            "For a self-signed certificate (internal use only):",
            "openssl req -x509 -nodes -days 365 -newkey rsa:2048 "
            "-keyout /etc/ssl/private/selfsigned.key "
            "-out /etc/ssl/certs/selfsigned.crt",
        ],
        "estimated_time":  "10–15 minutes",
        "requires_root":   True,
        "rollback_note":   "Remove Certbot certificate: sudo certbot delete",
    },

    "ssl_certificate_expired": {
        "vuln_type":        "ssl_certificate_expired",
        "title":            "Renew Expired SSL Certificate",
        "description":      "Attempts to renew the SSL certificate using Certbot.",
        "autofix_available": True,
        "risk_level":       "low",
        "config_file":      None,
        "service_to_restart": None,
        "commands": [
            "certbot renew --force-renewal",
        ],
        "verify_command":   "certbot certificates 2>/dev/null | grep -i 'expiry date'",
        "verify_expected":  None,
        "manual_steps": [
            "1. Renew with Certbot:  sudo certbot renew",
            "2. Force renewal:       sudo certbot renew --force-renewal",
            "3. Check expiry:        sudo certbot certificates",
            "4. Set up auto-renewal in cron:",
            "   0 12 * * * /usr/bin/certbot renew --quiet",
        ],
        "estimated_time":  "2–5 minutes",
        "requires_root":   True,
        "rollback_note":   "Previous certificate restored from /etc/letsencrypt/archive/.",
    },
}


def get_fix(vuln_type: str) -> dict | None:
    return APACHE_FIXES.get(vuln_type)


def list_supported_types() -> list[str]:
    return list(APACHE_FIXES.keys())
