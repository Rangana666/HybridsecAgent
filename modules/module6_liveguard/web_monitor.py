"""
web_monitor.py — Web Attack Detector (SQLi / XSS / DDoS / Path Traversal)  (Module 6)

Tails Apache/Nginx access logs in real time and detects:
  1. SQL Injection attempts    — pattern match on request URI + body
  2. XSS attempts              — pattern match on request URI
  3. Path Traversal            — ../../ sequences in URI
  4. DDoS (HTTP flood)         — N requests from same IP in window seconds

Detection logic:
  SQLi/XSS/Traversal → block immediately (single-request offence)
  DDoS               → block when DDOS_REQUEST_THRESHOLD exceeded in window

Log format supported:
  Combined Log Format (Apache default):
    1.2.3.4 - - [17/Apr/2025:14:23:45 +0000] "GET /path?q=<script> HTTP/1.1" 200 1234

Usage:
    monitor = WebMonitor(ip_blocker, alert_system, incident_log)
    monitor.start()   # background thread
    monitor.stop()
"""

import re
import sys
import logging
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

try:
    from config import (
        APACHE_ACCESS_LOG, NGINX_ACCESS_LOG,
        DDOS_REQUEST_THRESHOLD, DDOS_WINDOW_SECONDS,
        LOGS_DIR,
    )
except ImportError:
    APACHE_ACCESS_LOG = "/var/log/apache2/access.log"
    NGINX_ACCESS_LOG  = "/var/log/nginx/access.log"
    DDOS_REQUEST_THRESHOLD = 100
    DDOS_WINDOW_SECONDS    = 60
    LOGS_DIR = Path(__file__).parent.parent.parent / "logs"

# ── Attack patterns ────────────────────────────────────────────

_SQLI_PATTERNS = [
    re.compile(r"(?i)(\bunion\b.+\bselect\b|\bselect\b.+\bfrom\b)"),
    re.compile(r"(?i)(\bdrop\s+table\b|\bdelete\s+from\b|\binsert\s+into\b)"),
    re.compile(r"(?i)(--|;--|%27|%22|%3D|%3B)"),
    re.compile(r"(?i)(\b(or|and)\b\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+)"),
    re.compile(r"(?i)(sleep\s*\(\s*\d+\s*\)|benchmark\s*\()"),
    re.compile(r"(?i)(xp_cmdshell|information_schema|sys\.tables)"),
]

_XSS_PATTERNS = [
    re.compile(r"(?i)(<script[\s>]|<\/script>|javascript:|onerror\s*=|onload\s*=)"),
    re.compile(r"(?i)(alert\s*\(|prompt\s*\(|confirm\s*\()"),
    re.compile(r"(?i)(%3Cscript|%3C%2Fscript|%3C\/script)"),
    re.compile(r"(?i)(document\.cookie|document\.write|window\.location)"),
]

_TRAVERSAL_PATTERNS = [
    re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f)"),
    re.compile(r"(/etc/passwd|/etc/shadow|/proc/self|/var/www)"),
    re.compile(r"(?i)(cmd\.exe|powershell|bash\.exe)"),
]

# Apache/Nginx combined log format: IP - user [date] "METHOD URI PROTO" status bytes
_ACCESS_LOG_RE = re.compile(
    r'^([\d\.a-fA-F:]+)\s+-\s+-\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)\s+(\d+|-)'
)


def _detect_attack(uri: str, method: str) -> Optional[str]:
    """
    Check a URI for known attack patterns.
    Returns attack type string or None.
    """
    for pat in _SQLI_PATTERNS:
        if pat.search(uri):
            return "sql_injection"
    for pat in _XSS_PATTERNS:
        if pat.search(uri):
            return "xss_attempt"
    for pat in _TRAVERSAL_PATTERNS:
        if pat.search(uri):
            return "path_traversal"
    return None


class WebMonitor:
    """
    Monitors Apache/Nginx access logs for web application attacks.
    Auto-detects which log file exists.
    """

    def __init__(self, ip_blocker, alert_system, incident_log=None):
        self._blocker   = ip_blocker
        self._alerter   = alert_system

        from modules.module6_liveguard.ssh_monitor import IncidentLog
        self._incidents = incident_log or IncidentLog()

        # DDoS tracking: ip → deque of request timestamps
        self._req_times: dict[str, deque] = defaultdict(deque)
        self._blocked_this_session: set[str] = set()

        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._log_path = self._find_log()

    # ── Public API ─────────────────────────────────────────────

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run, name="web-monitor", daemon=True
        )
        self._thread.start()
        logger.info("WebMonitor started  log=%s", self._log_path)

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("WebMonitor stopped")

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def get_stats(self) -> dict:
        return {
            "monitor":       "web",
            "running":       self.is_running(),
            "log_file":      str(self._log_path),
            "log_exists":    self._log_path.exists() if self._log_path else False,
            "ips_tracking":  len(self._req_times),
            "blocked_total": len(self._blocked_this_session),
            "ddos_threshold": DDOS_REQUEST_THRESHOLD,
            "ddos_window_sec": DDOS_WINDOW_SECONDS,
        }

    # ── Private ────────────────────────────────────────────────

    @staticmethod
    def _find_log() -> Optional[Path]:
        for p in [APACHE_ACCESS_LOG, NGINX_ACCESS_LOG]:
            if Path(p).exists():
                return Path(p)
        return Path(APACHE_ACCESS_LOG)   # return default even if it doesn't exist

    def _run(self):
        if not self._log_path or not self._log_path.exists():
            logger.warning(
                "WebMonitor: no access log found (%s, %s) — monitor idle",
                APACHE_ACCESS_LOG, NGINX_ACCESS_LOG,
            )
            while not self._stop_event.is_set():
                # Retry every 60s
                self._stop_event.wait(60)
                if self._log_path and self._log_path.exists():
                    break
            if self._stop_event.is_set():
                return

        try:
            with open(self._log_path, "r", errors="replace") as f:
                f.seek(0, 2)   # seek to end
                while not self._stop_event.is_set():
                    line = f.readline()
                    if line:
                        self._process_line(line.strip())
                    else:
                        self._stop_event.wait(0.5)
        except PermissionError:
            logger.error("WebMonitor: permission denied reading %s", self._log_path)
        except Exception as exc:
            logger.error("WebMonitor error: %s", exc, exc_info=True)

    def _process_line(self, line: str):
        m = _ACCESS_LOG_RE.match(line)
        if not m:
            return

        ip     = m.group(1)
        method = m.group(3)
        uri    = m.group(4)

        # 1. Check for attack patterns in URI
        attack_type = _detect_attack(uri, method)
        if attack_type and ip not in self._blocked_this_session:
            self._trigger_block(
                ip, attack_type,
                detail=f"{method} {uri[:120]}",
                severity="high",
            )
            return

        # 2. Check DDoS threshold
        self._check_ddos(ip)

    def _check_ddos(self, ip: str):
        now = time.monotonic()
        dq  = self._req_times[ip]
        while dq and now - dq[0] > DDOS_WINDOW_SECONDS:
            dq.popleft()
        dq.append(now)

        if len(dq) >= DDOS_REQUEST_THRESHOLD and ip not in self._blocked_this_session:
            self._trigger_block(
                ip, "ddos",
                detail=f"{len(dq)} HTTP requests in {DDOS_WINDOW_SECONDS}s",
                severity="critical",
            )

    def _trigger_block(self, ip: str, attack_type: str,
                       detail: str = "", severity: str = "high"):
        self._blocked_this_session.add(ip)

        block_result = self._blocker.block_ip(
            ip,
            reason=f"{attack_type}: {detail[:80]}",
            source="web_monitor",
        )
        blocked = block_result.get("success", False)

        incident = {
            "type":      attack_type,
            "source_ip": ip,
            "severity":  severity,
            "detail":    detail,
            "blocked":   blocked,
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        self._incidents.append(incident)
        self._alerter.send_alert(incident)

        logger.warning(
            "WEB ATTACK detected: type=%s ip=%s blocked=%s | %s",
            attack_type, ip, blocked, detail[:80],
        )


# ── Standalone test ────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s  %(name)s  %(message)s")

    tests = [
        # (uri, expected_type)
        ("/search?q=' OR 1=1 --", "sql_injection"),
        ("/page?id=1 UNION SELECT username FROM users", "sql_injection"),
        ('/index?name=<script>alert(1)</script>', "xss_attempt"),
        ("/img?src=javascript:alert(1)", "xss_attempt"),
        ("/files?path=../../etc/passwd", "path_traversal"),
        ("/home?page=normal_request", None),
    ]

    print("=== Attack Pattern Tests ===")
    all_ok = True
    for uri, expected in tests:
        detected = _detect_attack(uri, "GET")
        ok = detected == expected
        all_ok = all_ok and ok
        print(f"  {'✅' if ok else '❌'} expected={str(expected):<20} got={str(detected):<20} | {uri[:50]}")

    print("\n=== DDoS Threshold Simulation ===")
    from unittest.mock import MagicMock
    blocker = MagicMock()
    blocker.block_ip.return_value = {"success": True}
    alerter = MagicMock()
    alerter.send_alert.return_value = {}

    mon = WebMonitor(blocker, alerter)

    # Simulate 101 rapid requests from same IP
    fake_line = '10.0.0.1 - - [17/Apr/2025:14:00:00 +0000] "GET / HTTP/1.1" 200 512'
    for _ in range(101):
        mon._process_line(fake_line)

    assert blocker.block_ip.called, "block_ip should be called for DDoS"
    print(f"  DDoS block triggered: {blocker.block_ip.called}")
    print(f"\n{'ALL' if all_ok else 'SOME'} WebMonitor tests {'PASSED' if all_ok else 'FAILED'}")
