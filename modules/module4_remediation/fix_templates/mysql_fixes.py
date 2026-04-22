"""
mysql_fixes.py — MySQL / MariaDB Vulnerability Fix Templates  (Module 4)
"""

MYSQL_FIXES: dict[str, dict] = {

    "mysql_public_port": {
        "vuln_type":        "mysql_public_port",
        "title":            "Bind MySQL to Localhost Only",
        "description":      "Sets bind-address = 127.0.0.1 in MySQL/MariaDB config "
                            "so the database only accepts connections from the same server. "
                            "External clients must use an SSH tunnel.",
        "autofix_available": True,
        "risk_level":       "low",
        "config_file":      "/etc/mysql/mysql.conf.d/mysqld.cnf",
        "service_to_restart": "mysql",
        "commands": [
            # Determine the correct config file (differs between MySQL and MariaDB)
            "MYSQL_CNF=$([ -f /etc/mysql/mysql.conf.d/mysqld.cnf ] "
            "&& echo /etc/mysql/mysql.conf.d/mysqld.cnf "
            "|| echo /etc/mysql/my.cnf)",
            # Replace or add bind-address
            "sed -i 's/^#*\\s*bind-address.*/bind-address = 127.0.0.1/' $MYSQL_CNF",
            "grep -qE '^bind-address' $MYSQL_CNF "
            "|| echo 'bind-address = 127.0.0.1' >> $MYSQL_CNF",
            # Block port 3306 in firewall
            "which ufw && ufw deny 3306/tcp || true",
        ],
        "verify_command":   "mysql -u root -e 'SHOW VARIABLES LIKE \"bind_address\";' 2>/dev/null "
                            "|| grep -i bind-address /etc/mysql/mysql.conf.d/mysqld.cnf /etc/mysql/my.cnf 2>/dev/null | head -1",
        "verify_expected":  "127.0.0.1",
        "manual_steps": [
            "1. Find your MySQL config file:",
            "   /etc/mysql/mysql.conf.d/mysqld.cnf   (MySQL on Ubuntu)",
            "   /etc/mysql/my.cnf                    (MariaDB)",
            "2. Under the [mysqld] section, add or edit:",
            "   bind-address = 127.0.0.1",
            "3. Restart MySQL:  sudo systemctl restart mysql",
            "4. Block port in firewall:  sudo ufw deny 3306/tcp",
            "5. Verify:  mysql -u root -e 'SHOW VARIABLES LIKE \"bind_address\";'",
            "   Expected output: 127.0.0.1",
            "",
            "For remote access, use an SSH tunnel instead of opening port 3306:",
            "   ssh -L 3306:127.0.0.1:3306 user@server",
        ],
        "estimated_time":  "2–3 minutes",
        "requires_root":   True,
        "rollback_note":   "Original MySQL config restored — port 3306 may be re-exposed.",
    },
}


def get_fix(vuln_type: str) -> dict | None:
    return MYSQL_FIXES.get(vuln_type)


def list_supported_types() -> list[str]:
    return list(MYSQL_FIXES.keys())
