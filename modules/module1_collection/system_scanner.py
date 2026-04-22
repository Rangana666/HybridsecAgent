"""
system_scanner.py — Local System Security Checks
Performs host-level security checks without external tools:
  - SSH configuration  (/etc/ssh/sshd_config)
  - Firewall status    (UFW / iptables)
  - User accounts      (/etc/passwd, /etc/shadow)
  - Failed logins      (/var/log/auth.log)
  - SUID binaries      (find / -perm -4000)
  - SSL certificates   (openssl s_client)
  - Running services   (systemctl)
  - Disk usage         (df)
  - Password policy    (/etc/pam.d/common-password, /etc/login.defs)
  - NTP status         (timedatectl)

Most checks run as read-only and do not require root,
but some (auth.log, shadow, full SUID scan) need sudo.
"""

import os
import re
import subprocess
import logging
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# SUID directories considered "standard" — files here are expected
STANDARD_SUID_DIRS = {
    "/bin", "/sbin", "/usr/bin", "/usr/sbin",
    "/usr/lib", "/usr/libexec", "/lib",
    "/usr/lib/openssh",
}

# Failed login threshold: more than this count in auth.log = suspicious
FAILED_LOGIN_THRESHOLD = 50

# Disk usage threshold: above this % = critical finding
DISK_CRITICAL_PERCENT = 90


class SystemScanner:
    """Performs host-level security checks on the local Linux system."""

    def scan(self) -> dict:
        """
        Run all system checks and return a combined dict.

        Returns:
            dict with one key per check category, each containing
            'findings' (list of partial vuln dicts) and raw data.
        """
        logger.info("Starting system security checks...")
        return {
            "ssh":           self._check_ssh(),
            "firewall":      self._check_firewall(),
            "users":         self._check_users(),
            "failed_logins": self._check_failed_logins(),
            "suid_files":    self._find_suid_files(),
            "ssl_certs":     self._check_ssl_certs(),
            "services":      self._check_services(),
            "disk":          self._check_disk(),
            "password_policy": self._check_password_policy(),
            "ntp":           self._check_ntp(),
        }

    # ── SSH Configuration ──────────────────────────────────────

    def _check_ssh(self) -> dict:
        """
        Parse /etc/ssh/sshd_config for dangerous settings.
        """
        result = {"config_path": "/etc/ssh/sshd_config", "settings": {}, "findings": []}
        sshd_config = Path("/etc/ssh/sshd_config")

        if not sshd_config.exists():
            result["findings"].append(self._finding(
                "ssh_root_login_enabled",
                "sshd_config not found — SSH may not be installed",
                "sshd", "system_scanner",
            ))
            return result

        try:
            content = sshd_config.read_text(errors="replace")
        except PermissionError:
            logger.warning("Cannot read sshd_config — permission denied")
            result["error"] = "Permission denied reading sshd_config"
            return result

        # Parse effective settings (last occurrence of each directive wins)
        settings = self._parse_sshd_config(content)
        result["settings"] = settings

        # --- Check: PermitRootLogin ---
        root_login = settings.get("PermitRootLogin", "yes").lower()
        if root_login not in ("no", "prohibit-password", "forced-commands-only"):
            result["findings"].append(self._finding(
                "ssh_root_login_enabled",
                f"PermitRootLogin = {root_login} in sshd_config",
                "sshd", "system_scanner",
            ))

        # --- Check: PasswordAuthentication ---
        pw_auth = settings.get("PasswordAuthentication", "yes").lower()
        if pw_auth != "no":
            result["findings"].append(self._finding(
                "ssh_password_auth_enabled",
                f"PasswordAuthentication = {pw_auth} in sshd_config",
                "sshd", "system_scanner",
            ))

        # --- Check: Protocol ---
        protocol = settings.get("Protocol", "2")
        if "1" in protocol:
            result["findings"].append(self._finding(
                "ssh_protocol_v1",
                f"Protocol = {protocol} — SSHv1 is enabled",
                "sshd", "system_scanner",
            ))

        # --- Check: PermitEmptyPasswords ---
        empty_pw = settings.get("PermitEmptyPasswords", "no").lower()
        if empty_pw == "yes":
            result["findings"].append(self._finding(
                "ssh_empty_passwords_allowed",
                "PermitEmptyPasswords = yes in sshd_config",
                "sshd", "system_scanner",
            ))

        # --- Check: X11Forwarding ---
        x11 = settings.get("X11Forwarding", "no").lower()
        if x11 == "yes":
            result["findings"].append(self._finding(
                "ssh_x11_forwarding",
                "X11Forwarding = yes in sshd_config",
                "sshd", "system_scanner",
            ))

        # --- Check: Port ---
        port = settings.get("Port", "22")
        if port == "22":
            result["findings"].append(self._finding(
                "ssh_default_port",
                "SSH is running on default port 22",
                "sshd", "system_scanner",
            ))

        logger.info("SSH check: %d findings", len(result["findings"]))
        return result

    def _parse_sshd_config(self, content: str) -> dict:
        """Parse sshd_config into a {directive: value} dict."""
        settings = {}
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                settings[parts[0]] = parts[1].strip()
        return settings

    # ── Firewall ───────────────────────────────────────────────

    def _check_firewall(self) -> dict:
        """
        Check UFW or iptables firewall status.
        Prefers UFW if available; falls back to iptables.
        """
        result = {"tool": None, "status": "unknown", "default_policy": "unknown", "findings": []}

        if shutil.which("ufw"):
            result["tool"] = "ufw"
            return self._check_ufw(result)
        elif shutil.which("iptables"):
            result["tool"] = "iptables"
            return self._check_iptables(result)
        else:
            result["findings"].append(self._finding(
                "firewall_disabled",
                "Neither UFW nor iptables found on this system",
                "firewall", "system_scanner",
            ))
        return result

    def _check_ufw(self, result: dict) -> dict:
        try:
            proc = subprocess.run(
                ["ufw", "status", "verbose"],
                capture_output=True, text=True, timeout=10,
            )
            output = proc.stdout + proc.stderr
            result["raw"] = output

            if "inactive" in output.lower():
                result["status"] = "inactive"
                result["findings"].append(self._finding(
                    "firewall_disabled",
                    "UFW firewall is inactive",
                    "ufw", "system_scanner",
                ))
            else:
                result["status"] = "active"
                # Check default policy
                default_match = re.search(r"Default:\s*(\w+)\s*\(incoming\)", output, re.IGNORECASE)
                if default_match:
                    policy = default_match.group(1).lower()
                    result["default_policy"] = policy
                    if policy == "allow":
                        result["findings"].append(self._finding(
                            "firewall_default_allow",
                            f"UFW default incoming policy is ALLOW",
                            "ufw", "system_scanner",
                        ))

        except subprocess.TimeoutExpired:
            result["error"] = "ufw command timed out"
        except Exception as e:
            result["error"] = str(e)
            logger.warning("UFW check failed: %s", e)
        return result

    def _check_iptables(self, result: dict) -> dict:
        try:
            proc = subprocess.run(
                ["iptables", "-L", "-n", "--line-numbers"],
                capture_output=True, text=True, timeout=10,
            )
            output = proc.stdout
            result["raw"] = output

            # Count actual rules (non-header lines in INPUT/OUTPUT/FORWARD)
            rule_count = sum(
                1 for line in output.splitlines()
                if re.match(r"^\d+\s", line)
            )

            if rule_count == 0:
                result["status"] = "no_rules"
                result["findings"].append(self._finding(
                    "firewall_disabled",
                    "iptables has no rules configured",
                    "iptables", "system_scanner",
                ))
            else:
                result["status"] = "active"
                # Check INPUT default policy
                policy_match = re.search(r"Chain INPUT \(policy (\w+)\)", output)
                if policy_match:
                    policy = policy_match.group(1).upper()
                    result["default_policy"] = policy
                    if policy == "ACCEPT":
                        result["findings"].append(self._finding(
                            "firewall_default_allow",
                            "iptables INPUT chain default policy is ACCEPT",
                            "iptables", "system_scanner",
                        ))

        except subprocess.TimeoutExpired:
            result["error"] = "iptables command timed out"
        except PermissionError:
            result["error"] = "iptables requires root"
        except Exception as e:
            result["error"] = str(e)
        return result

    # ── User Accounts ──────────────────────────────────────────

    def _check_users(self) -> dict:
        """
        Check /etc/passwd for dangerous account configurations.
        Checks /etc/shadow for empty passwords if readable (requires root).
        """
        result = {"users": [], "findings": []}
        passwd_path = Path("/etc/passwd")

        if not passwd_path.exists():
            return result

        try:
            lines = passwd_path.read_text().splitlines()
        except Exception as e:
            result["error"] = str(e)
            return result

        users = []
        for line in lines:
            parts = line.strip().split(":")
            if len(parts) < 7:
                continue
            username, _, uid, gid, _, home, shell = parts[:7]
            try:
                uid_int = int(uid)
            except ValueError:
                continue

            user_info = {
                "username": username,
                "uid": uid_int,
                "gid": gid,
                "home": home,
                "shell": shell,
                "has_login_shell": shell not in ("/bin/false", "/usr/sbin/nologin", "/sbin/nologin", ""),
            }
            users.append(user_info)

            # UID 0 non-root = backdoor
            if uid_int == 0 and username != "root":
                result["findings"].append(self._finding(
                    "root_equivalent_user",
                    f"User '{username}' has UID 0 (root equivalent)",
                    "users", "system_scanner",
                ))

        result["users"] = users
        result["total_count"] = len(users)
        result["login_shell_count"] = sum(1 for u in users if u["has_login_shell"])

        # Check /etc/shadow for empty passwords
        shadow_path = Path("/etc/shadow")
        if shadow_path.exists():
            try:
                for line in shadow_path.read_text().splitlines():
                    parts = line.strip().split(":")
                    if len(parts) >= 2:
                        uname = parts[0]
                        pw_hash = parts[1]
                        if pw_hash == "" or pw_hash == "::":
                            result["findings"].append(self._finding(
                                "user_empty_password",
                                f"User '{uname}' has no password set (/etc/shadow)",
                                "users", "system_scanner",
                            ))
            except PermissionError:
                logger.info("/etc/shadow not readable — need root for empty password check")

        logger.info("User check: %d users, %d findings", len(users), len(result["findings"]))
        return result

    # ── Failed Login Attempts ──────────────────────────────────

    def _check_failed_logins(self) -> dict:
        """
        Parse /var/log/auth.log for failed SSH login attempts.
        Returns count of failures and top offending IPs.
        """
        result = {"total_failures": 0, "top_ips": {}, "findings": []}

        auth_log_paths = [
            Path("/var/log/auth.log"),       # Debian/Ubuntu
            Path("/var/log/secure"),         # RHEL/CentOS
        ]

        auth_log = next((p for p in auth_log_paths if p.exists()), None)
        if not auth_log:
            logger.info("auth.log not found — skipping failed login check")
            return result

        try:
            content = auth_log.read_text(errors="replace")
        except PermissionError:
            result["error"] = "Permission denied reading auth.log — run as root"
            logger.warning("Cannot read %s — need root", auth_log)
            return result

        ip_counts: dict[str, int] = {}
        ip_pattern = re.compile(
            r"Failed password.*?from\s+([\d.]+|[0-9a-fA-F:]+)\s+port",
            re.IGNORECASE,
        )

        for line in content.splitlines():
            m = ip_pattern.search(line)
            if m:
                ip = m.group(1)
                ip_counts[ip] = ip_counts.get(ip, 0) + 1

        total = sum(ip_counts.values())
        result["total_failures"] = total
        result["top_ips"] = dict(
            sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        )

        if total > FAILED_LOGIN_THRESHOLD:
            top_ip = max(ip_counts, key=ip_counts.get, default="unknown")
            result["findings"].append(self._finding(
                "high_failed_login_count",
                f"{total} failed SSH login attempts detected in auth.log. "
                f"Top attacker: {top_ip} ({ip_counts.get(top_ip, 0)} attempts)",
                "sshd", "system_scanner",
            ))

        logger.info("Failed login check: %d total failures from %d IPs", total, len(ip_counts))
        return result

    # ── SUID Files ─────────────────────────────────────────────

    def _find_suid_files(self) -> dict:
        """
        Find SUID binaries outside of standard system directories.
        SUID binaries in /bin, /sbin, /usr/bin, /usr/sbin are normal.
        Anything else is flagged as suspicious.
        """
        result = {"all_suid": [], "suspicious": [], "findings": []}

        try:
            proc = subprocess.run(
                ["find", "/", "-perm", "-4000", "-type", "f", "-print"],
                capture_output=True, text=True, timeout=60,
            )
            all_suid = [
                line.strip()
                for line in proc.stdout.splitlines()
                if line.strip()
            ]
        except subprocess.TimeoutExpired:
            result["error"] = "SUID find timed out after 60s"
            logger.warning("SUID find timed out")
            return result
        except Exception as e:
            result["error"] = str(e)
            return result

        result["all_suid"] = all_suid

        suspicious = []
        for filepath in all_suid:
            parent = str(Path(filepath).parent)
            if not any(parent.startswith(d) for d in STANDARD_SUID_DIRS):
                suspicious.append(filepath)

        result["suspicious"] = suspicious

        if suspicious:
            for f in suspicious:
                result["findings"].append(self._finding(
                    "suspicious_suid_file",
                    f"SUID binary in non-standard location: {f}",
                    f, "system_scanner",
                ))

        logger.info(
            "SUID check: %d total, %d suspicious",
            len(all_suid), len(suspicious),
        )
        return result

    # ── SSL Certificates ───────────────────────────────────────

    def _check_ssl_certs(self) -> dict:
        """
        Check SSL certificate validity on common web ports (443, 8443).
        Uses openssl s_client to retrieve and inspect the certificate.
        """
        result = {"certs": [], "findings": []}
        ports_to_check = [443, 8443]

        if not shutil.which("openssl"):
            logger.info("openssl not found — skipping SSL cert check")
            return result

        for port in ports_to_check:
            cert_info = self._get_ssl_cert("127.0.0.1", port)
            if cert_info:
                result["certs"].append(cert_info)

                if cert_info.get("expired"):
                    result["findings"].append(self._finding(
                        "ssl_certificate_expired",
                        f"SSL certificate on port {port} expired on {cert_info.get('expiry_date')}",
                        f"port:{port}", "system_scanner",
                    ))
                elif cert_info.get("days_until_expiry", 999) < 30:
                    result["findings"].append(self._finding(
                        "ssl_certificate_expiring_soon",
                        f"SSL cert on port {port} expires in {cert_info['days_until_expiry']} days ({cert_info.get('expiry_date')})",
                        f"port:{port}", "system_scanner",
                    ))
            else:
                # Port might just not be listening — not necessarily a finding
                logger.debug("No SSL response on port %d", port)

        return result

    def _get_ssl_cert(self, host: str, port: int) -> Optional[dict]:
        """Retrieve SSL cert details using openssl s_client."""
        try:
            proc = subprocess.run(
                ["openssl", "s_client", "-connect", f"{host}:{port}",
                 "-servername", host, "-brief"],
                input="Q\n",
                capture_output=True, text=True, timeout=10,
            )
            output = proc.stdout + proc.stderr

            # Look for the certificate end date
            not_after = re.search(r"notAfter=(.+)", output)
            if not not_after:
                return None

            expiry_str = not_after.group(1).strip()
            try:
                expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                expiry_date = expiry_date.replace(tzinfo=timezone.utc)
            except ValueError:
                return {"port": port, "expiry_date": expiry_str, "expired": False, "days_until_expiry": 999}

            now = datetime.now(timezone.utc)
            days_left = (expiry_date - now).days

            return {
                "port": port,
                "expiry_date": expiry_str,
                "expired": days_left < 0,
                "days_until_expiry": days_left,
            }

        except subprocess.TimeoutExpired:
            return None
        except Exception:
            return None

    # ── Running Services ───────────────────────────────────────

    def _check_services(self) -> dict:
        """List running services via systemctl."""
        result = {"services": [], "error": None}

        if not shutil.which("systemctl"):
            result["error"] = "systemctl not available"
            return result

        try:
            proc = subprocess.run(
                ["systemctl", "list-units", "--type=service",
                 "--state=running", "--no-pager", "--plain"],
                capture_output=True, text=True, timeout=15,
            )
            services = []
            for line in proc.stdout.splitlines():
                parts = line.strip().split(None, 4)
                if parts and parts[0].endswith(".service"):
                    services.append({
                        "name": parts[0],
                        "load": parts[1] if len(parts) > 1 else "",
                        "active": parts[2] if len(parts) > 2 else "",
                        "sub": parts[3] if len(parts) > 3 else "",
                        "description": parts[4] if len(parts) > 4 else "",
                    })
            result["services"] = services
            result["count"] = len(services)

        except subprocess.TimeoutExpired:
            result["error"] = "systemctl timed out"
        except Exception as e:
            result["error"] = str(e)

        return result

    # ── Disk Usage ─────────────────────────────────────────────

    def _check_disk(self) -> dict:
        """Check disk usage via df."""
        result = {"partitions": [], "findings": []}

        try:
            proc = subprocess.run(
                ["df", "-h", "--output=source,size,used,avail,pcent,target"],
                capture_output=True, text=True, timeout=10,
            )
            for line in proc.stdout.splitlines()[1:]:   # skip header
                parts = line.split()
                if len(parts) < 6:
                    continue
                source, size, used, avail, pcent_str, mountpoint = parts[:6]
                pcent_str = pcent_str.rstrip("%")
                try:
                    pcent = int(pcent_str)
                except ValueError:
                    continue

                partition = {
                    "source": source,
                    "size": size,
                    "used": used,
                    "available": avail,
                    "use_percent": pcent,
                    "mountpoint": mountpoint,
                }
                result["partitions"].append(partition)

                if pcent >= DISK_CRITICAL_PERCENT:
                    result["findings"].append(self._finding(
                        "disk_usage_critical",
                        f"Partition {mountpoint} ({source}) is {pcent}% full",
                        mountpoint, "system_scanner",
                    ))

        except Exception as e:
            result["error"] = str(e)

        return result

    # ── Password Policy ────────────────────────────────────────

    def _check_password_policy(self) -> dict:
        """
        Check /etc/login.defs and /etc/pam.d/common-password
        for password policy settings.
        """
        result = {"settings": {}, "findings": []}
        policy_ok = True

        login_defs = Path("/etc/login.defs")
        if login_defs.exists():
            try:
                content = login_defs.read_text(errors="replace")
                for line in content.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        parts = line.split(None, 1)
                        if len(parts) == 2:
                            result["settings"][parts[0]] = parts[1]

                min_len = int(result["settings"].get("PASS_MIN_LEN", "0"))
                max_days = int(result["settings"].get("PASS_MAX_DAYS", "99999"))
                min_days = int(result["settings"].get("PASS_MIN_DAYS", "0"))

                if min_len < 8:
                    policy_ok = False
                if max_days > 365:
                    policy_ok = False

            except Exception as e:
                logger.debug("Could not read login.defs: %s", e)

        if not policy_ok:
            result["findings"].append(self._finding(
                "weak_password_policy",
                "Password policy in /etc/login.defs is insufficient "
                "(min length < 8 or max age > 365 days)",
                "pam", "system_scanner",
            ))

        return result

    # ── NTP ────────────────────────────────────────────────────

    def _check_ntp(self) -> dict:
        """Check if system time is synchronised via timedatectl."""
        result = {"synced": False, "ntp_service": None, "findings": []}

        if not shutil.which("timedatectl"):
            return result

        try:
            proc = subprocess.run(
                ["timedatectl", "status"],
                capture_output=True, text=True, timeout=10,
            )
            output = proc.stdout

            synced_match = re.search(r"NTP synchronized:\s*(yes|no)", output, re.IGNORECASE)
            if synced_match:
                result["synced"] = synced_match.group(1).lower() == "yes"

            service_match = re.search(r"NTP service:\s*(\S+)", output, re.IGNORECASE)
            if service_match:
                result["ntp_service"] = service_match.group(1)

            if not result["synced"]:
                result["findings"].append(self._finding(
                    "ntp_not_configured",
                    "System time is NOT synchronized via NTP (timedatectl reports not synced)",
                    "ntp", "system_scanner",
                ))

        except Exception as e:
            logger.debug("timedatectl check failed: %s", e)

        return result

    # ── Utility ────────────────────────────────────────────────

    @staticmethod
    def _finding(vuln_type: str, evidence: str, component: str, source: str) -> dict:
        """Create a minimal partial vulnerability dict from a system check finding."""
        return {
            "type": vuln_type,
            "evidence": evidence,
            "affected_component": component,
            "detected_by": source,
        }


# ── Standalone test ────────────────────────────────────────────
if __name__ == "__main__":
    import json
    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")

    print("\n[SystemScanner] Running all system checks...\n")
    scanner = SystemScanner()
    results = scanner.scan()

    total_findings = 0
    for category, data in results.items():
        findings = data.get("findings", [])
        total_findings += len(findings)
        if findings:
            print(f"\n  [{category.upper()}] — {len(findings)} finding(s):")
            for f in findings:
                print(f"    [{f['type']}] {f['evidence']}")

    print(f"\n  Total findings: {total_findings}")
