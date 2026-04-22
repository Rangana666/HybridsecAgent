"""
ssh_monitor.py — SSH Brute Force Detector  (Module 6)

Tails /var/log/auth.log in real time and detects brute-force attacks:
  - Counts failed SSH login attempts per source IP inside a rolling window
  - Triggers auto-block + alert when threshold is exceeded
  - Records every incident to logs/incidents.json

Detection logic:
    IF  failed_attempts(ip, last N seconds) >= SSH_BRUTE_FORCE_THRESHOLD
    THEN block(ip) + alert(ip)

Supported log lines (Ubuntu/Debian auth.log format):
  Failed password for root from 1.2.3.4 port 54321 ssh2
  Failed password for invalid user admin from 1.2.3.4 port 12345 ssh2
  Invalid user pi from 1.2.3.4 port 8888

Usage:
    monitor = SSHMonitor(ip_blocker, alert_system, incident_log)
    monitor.start()   # starts background thread
    monitor.stop()
"""

import re
import sys
import json
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
        AUTH_LOG_PATH,
        SSH_BRUTE_FORCE_THRESHOLD,
        SSH_BRUTE_FORCE_WINDOW_SECONDS,
        LOGS_DIR,
    )
except ImportError:
    AUTH_LOG_PATH = "/var/log/auth.log"
    SSH_BRUTE_FORCE_THRESHOLD = 5
    SSH_BRUTE_FORCE_WINDOW_SECONDS = 60
    LOGS_DIR = Path(__file__).parent.parent.parent / "logs"

# Regex patterns for failed SSH logins (covers most common Linux distros)
_FAIL_PATTERNS = [
    re.compile(
        r"Failed password for (?:invalid user )?(\S+) from ([\d\.a-fA-F:]+) port \d+"
    ),
    re.compile(
        r"Invalid user \S+ from ([\d\.a-fA-F:]+)"
    ),
    re.compile(
        r"pam_unix\(sshd:auth\): authentication failure;.*rhost=([\d\.a-fA-F:]+)"
    ),
    re.compile(
        r"error: maximum authentication attempts exceeded for .* from ([\d\.a-fA-F:]+)"
    ),
    re.compile(
        r"Disconnected from invalid user \S+ ([\d\.a-fA-F:]+)"
    ),
]

_INCIDENTS_FILE = Path(LOGS_DIR) / "incidents.json"


def _extract_ip(line: str) -> Optional[str]:
    """Extract the source IP from an auth.log line."""
    for pat in _FAIL_PATTERNS:
        m = pat.search(line)
        if m:
            # Last group is always the IP
            return m.group(m.lastindex)
    return None


class SSHMonitor:
    """
    Watches auth.log for SSH brute-force activity.
    Calls ip_blocker and alert_system when threshold is crossed.
    """

    def __init__(self, ip_blocker, alert_system, incident_log=None):
        self._blocker   = ip_blocker
        self._alerter   = alert_system
        self._incidents = incident_log or IncidentLog()

        # ip → deque of epoch timestamps of recent failures
        self._fail_times: dict[str, deque] = defaultdict(deque)
        self._blocked_this_session: set[str] = set()

        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._log_path = Path(AUTH_LOG_PATH)

    # ── Public API ─────────────────────────────────────────────

    def start(self):
        """Start the monitoring thread."""
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run, name="ssh-monitor", daemon=True
        )
        self._thread.start()
        logger.info("SSHMonitor started  log=%s  threshold=%d/%ds",
                    AUTH_LOG_PATH, SSH_BRUTE_FORCE_THRESHOLD,
                    SSH_BRUTE_FORCE_WINDOW_SECONDS)

    def stop(self):
        """Signal the monitoring thread to stop."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("SSHMonitor stopped")

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def get_stats(self) -> dict:
        return {
            "monitor":       "ssh",
            "running":       self.is_running(),
            "log_file":      str(self._log_path),
            "log_exists":    self._log_path.exists(),
            "ips_tracking":  len(self._fail_times),
            "blocked_total": len(self._blocked_this_session),
            "threshold":     SSH_BRUTE_FORCE_THRESHOLD,
            "window_sec":    SSH_BRUTE_FORCE_WINDOW_SECONDS,
        }

    # ── Private: tail loop ─────────────────────────────────────

    def _run(self):
        """Main loop: tail auth.log and process each new line."""
        if not self._log_path.exists():
            logger.warning("SSHMonitor: auth.log not found at %s — monitor idle", AUTH_LOG_PATH)
            # Keep thread alive so is_running() stays True; retry every 30s
            while not self._stop_event.is_set():
                if self._log_path.exists():
                    break
                self._stop_event.wait(30)
            if self._stop_event.is_set():
                return

        try:
            with open(self._log_path, "r", errors="replace") as f:
                # Seek to end so we only watch NEW lines
                f.seek(0, 2)
                while not self._stop_event.is_set():
                    line = f.readline()
                    if line:
                        self._process_line(line)
                    else:
                        # No new data — sleep briefly then retry
                        self._stop_event.wait(0.5)
        except PermissionError:
            logger.error("SSHMonitor: permission denied reading %s — run as root", AUTH_LOG_PATH)
        except Exception as exc:
            logger.error("SSHMonitor error: %s", exc, exc_info=True)

    def _process_line(self, line: str):
        """Parse a log line and check brute-force threshold."""
        ip = _extract_ip(line)
        if not ip:
            return

        now = time.monotonic()
        window = SSH_BRUTE_FORCE_WINDOW_SECONDS
        threshold = SSH_BRUTE_FORCE_THRESHOLD

        # Prune timestamps outside window
        dq = self._fail_times[ip]
        while dq and now - dq[0] > window:
            dq.popleft()
        dq.append(now)

        count = len(dq)
        logger.debug("SSH fail: ip=%s count=%d/%d", ip, count, threshold)

        if count >= threshold and ip not in self._blocked_this_session:
            self._trigger_block(ip, count)

    def _trigger_block(self, ip: str, count: int):
        """Block the IP, record incident, send alert."""
        self._blocked_this_session.add(ip)

        # Block
        block_result = self._blocker.block_ip(
            ip,
            reason=f"SSH brute force: {count} failures in {SSH_BRUTE_FORCE_WINDOW_SECONDS}s",
            source="ssh_monitor",
        )
        blocked = block_result.get("success", False)

        # Incident record
        incident = {
            "type":      "ssh_brute_force",
            "source_ip": ip,
            "severity":  "critical",
            "detail":    f"{count} failed SSH attempts in {SSH_BRUTE_FORCE_WINDOW_SECONDS}s",
            "blocked":   blocked,
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        self._incidents.append(incident)

        # Alert
        self._alerter.send_alert(incident)

        logger.warning(
            "SSH BRUTE FORCE detected: ip=%s attempts=%d blocked=%s",
            ip, count, blocked,
        )


# ══════════════════════════════════════════════════════════════════
#   Shared incident log (thread-safe append to incidents.json)
# ══════════════════════════════════════════════════════════════════

class IncidentLog:
    """Thread-safe append-only log of security incidents."""

    def __init__(self, path: Optional[Path] = None):
        self._path = path or _INCIDENTS_FILE
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def append(self, incident: dict):
        with self._lock:
            try:
                existing = self._load()
                existing.append(incident)
                # Keep last 1000 incidents
                if len(existing) > 1000:
                    existing = existing[-1000:]
                self._path.write_text(json.dumps(existing, indent=2))
            except Exception as exc:
                logger.error("IncidentLog write failed: %s", exc)

    def read_recent(self, n: int = 50) -> list[dict]:
        incidents = self._load()
        return sorted(incidents, key=lambda x: x.get("timestamp", ""), reverse=True)[:n]

    def _load(self) -> list:
        if not self._path.exists():
            return []
        try:
            return json.loads(self._path.read_text())
        except Exception:
            return []


# ── Standalone test ────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s  %(name)s  %(message)s")

    # Test the regex extraction
    test_lines = [
        "Apr 17 14:23:45 server sshd[1234]: Failed password for root from 1.2.3.4 port 54321 ssh2",
        "Apr 17 14:23:46 server sshd[1234]: Failed password for invalid user admin from 1.2.3.4 port 12345 ssh2",
        "Apr 17 14:23:47 server sshd[1235]: Invalid user pi from 1.2.3.4 port 8888",
        "Apr 17 14:23:48 server sshd[1236]: Disconnected from invalid user test 5.6.7.8 port 1234",
        "Apr 17 14:23:49 server CRON[9999]: some unrelated cron line",
    ]

    print("=== Regex Tests ===")
    for line in test_lines:
        ip = _extract_ip(line)
        print(f"  {'✅' if ip else '⬜'} IP={ip or 'none':15}  | {line[30:80]}")

    print("\n=== Threshold Simulation ===")
    from unittest.mock import MagicMock
    blocker = MagicMock()
    blocker.block_ip.return_value = {"success": True}
    alerter = MagicMock()
    alerter.send_alert.return_value = {"telegram": False, "email": False}
    incident_log = IncidentLog()

    mon = SSHMonitor(blocker, alerter, incident_log)
    for i in range(6):
        mon._process_line(
            f"Apr 17 14:23:4{i} server sshd[100]: Failed password for root from 10.0.0.99 port 22 ssh2"
        )

    assert blocker.block_ip.called, "block_ip should have been called"
    print(f"  block_ip called: {blocker.block_ip.called}")
    print(f"  alert sent: {alerter.send_alert.called}")
    print("\nSSHMonitor tests PASSED")
