"""
port_scan_monitor.py — Port Scan Detector  (Module 6)

Monitors syslog / kern.log / UFW logs for signs of port scanning:
  - Tracks how many distinct destination ports an IP has hit in a rolling window
  - Triggers auto-block when PORT_SCAN_THRESHOLD is exceeded

Detection logic:
    IF unique_ports_hit(ip, last N seconds) >= PORT_SCAN_THRESHOLD
    THEN block(ip) + alert(ip)

Log sources watched (in order of preference):
  1. /var/log/ufw.log         — UFW blocked packets (best signal)
  2. /var/log/kern.log        — kernel netfilter log lines
  3. /var/log/syslog          — general fallback

UFW log line example:
  [UFW BLOCK] IN=eth0 ... SRC=1.2.3.4 DST=10.0.0.1 ... DPT=22 ...

kern.log line example:
  kernel: [UFW BLOCK] IN=eth0 SRC=1.2.3.4 DST=5.6.7.8 DPT=80 ...

Usage:
    monitor = PortScanMonitor(ip_blocker, alert_system, incident_log)
    monitor.start()
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
        SYSLOG_PATH,
        PORT_SCAN_THRESHOLD,
        PORT_SCAN_WINDOW_SECONDS,
    )
except ImportError:
    SYSLOG_PATH = "/var/log/syslog"
    PORT_SCAN_THRESHOLD = 10
    PORT_SCAN_WINDOW_SECONDS = 30

# Log files to try (order matters — most specific first)
_CANDIDATE_LOGS = [
    "/var/log/ufw.log",
    "/var/log/kern.log",
    SYSLOG_PATH,
]

# Regex for UFW / kernel netfilter lines
_UFW_RE = re.compile(
    r"SRC=([\d\.a-fA-F:]+).*DPT=(\d+)"
)

# Also catch nmap SYN scan fingerprint in dmesg-style logs
_NMAP_RE = re.compile(
    r"IN=\S+\s+OUT=\s+.*SRC=([\d\.a-fA-F:]+).*DPT=(\d+)"
)


def _extract_src_dport(line: str) -> Optional[tuple[str, int]]:
    """Extract (src_ip, dst_port) from a UFW/kernel log line."""
    for pat in (_UFW_RE, _NMAP_RE):
        m = pat.search(line)
        if m:
            try:
                return m.group(1), int(m.group(2))
            except (IndexError, ValueError):
                continue
    return None


class PortScanMonitor:
    """
    Watches firewall/syslog for signs of port scanning activity.
    """

    def __init__(self, ip_blocker, alert_system, incident_log=None):
        self._blocker   = ip_blocker
        self._alerter   = alert_system

        from modules.module6_liveguard.ssh_monitor import IncidentLog
        self._incidents = incident_log or IncidentLog()

        # ip → deque of (timestamp, port) tuples
        self._scan_data: dict[str, deque] = defaultdict(deque)
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
            target=self._run, name="portscan-monitor", daemon=True
        )
        self._thread.start()
        logger.info("PortScanMonitor started  log=%s  threshold=%d ports/%ds",
                    self._log_path, PORT_SCAN_THRESHOLD, PORT_SCAN_WINDOW_SECONDS)

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("PortScanMonitor stopped")

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def get_stats(self) -> dict:
        return {
            "monitor":       "port_scan",
            "running":       self.is_running(),
            "log_file":      str(self._log_path) if self._log_path else None,
            "log_exists":    (self._log_path.exists() if self._log_path else False),
            "ips_tracking":  len(self._scan_data),
            "blocked_total": len(self._blocked_this_session),
            "threshold":     PORT_SCAN_THRESHOLD,
            "window_sec":    PORT_SCAN_WINDOW_SECONDS,
        }

    # ── Private ────────────────────────────────────────────────

    @staticmethod
    def _find_log() -> Optional[Path]:
        for p in _CANDIDATE_LOGS:
            if Path(p).exists():
                return Path(p)
        return Path(_CANDIDATE_LOGS[-1])   # fallback to syslog path

    def _run(self):
        if not self._log_path or not self._log_path.exists():
            logger.warning(
                "PortScanMonitor: no suitable log found — monitor idle. "
                "Enable UFW logging: sudo ufw logging on"
            )
            while not self._stop_event.is_set():
                self._stop_event.wait(60)
                if self._log_path and self._log_path.exists():
                    break
            if self._stop_event.is_set():
                return

        try:
            with open(self._log_path, "r", errors="replace") as f:
                f.seek(0, 2)
                while not self._stop_event.is_set():
                    line = f.readline()
                    if line:
                        self._process_line(line)
                    else:
                        self._stop_event.wait(0.5)
        except PermissionError:
            logger.error("PortScanMonitor: permission denied reading %s — run as root",
                         self._log_path)
        except Exception as exc:
            logger.error("PortScanMonitor error: %s", exc, exc_info=True)

    def _process_line(self, line: str):
        result = _extract_src_dport(line)
        if not result:
            return

        ip, port = result
        now = time.monotonic()
        dq  = self._scan_data[ip]

        # Prune old entries
        while dq and now - dq[0][0] > PORT_SCAN_WINDOW_SECONDS:
            dq.popleft()
        dq.append((now, port))

        # Count unique ports in window
        unique_ports = {entry[1] for entry in dq}
        count = len(unique_ports)

        logger.debug("Port hit: ip=%s port=%d  unique=%d/%d",
                     ip, port, count, PORT_SCAN_THRESHOLD)

        if count >= PORT_SCAN_THRESHOLD and ip not in self._blocked_this_session:
            self._trigger_block(ip, unique_ports)

    def _trigger_block(self, ip: str, ports: set):
        self._blocked_this_session.add(ip)

        block_result = self._blocker.block_ip(
            ip,
            reason=f"Port scan: {len(ports)} ports in {PORT_SCAN_WINDOW_SECONDS}s",
            source="port_scan_monitor",
        )
        blocked = block_result.get("success", False)

        incident = {
            "type":      "port_scan",
            "source_ip": ip,
            "severity":  "high",
            "detail":    f"{len(ports)} distinct ports probed in {PORT_SCAN_WINDOW_SECONDS}s "
                         f"(sample: {sorted(ports)[:8]})",
            "blocked":   blocked,
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        self._incidents.append(incident)
        self._alerter.send_alert(incident)

        logger.warning(
            "PORT SCAN detected: ip=%s unique_ports=%d blocked=%s",
            ip, len(ports), blocked,
        )


# ── Standalone test ────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s  %(name)s  %(message)s")

    test_lines = [
        "Apr 17 14:23:45 server kernel: [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=1.2.3.4 DST=10.0.0.1 ... DPT=22 WINDOW=1024",
        "Apr 17 14:23:46 server kernel: [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=1.2.3.4 DST=10.0.0.1 ... DPT=80 WINDOW=1024",
        "Apr 17 14:23:47 server kernel: [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=1.2.3.4 DST=10.0.0.1 ... DPT=443 WINDOW=1024",
        "Apr 17 14:23:47 unrelated line that should not parse",
    ]

    print("=== Regex Tests ===")
    for line in test_lines:
        result = _extract_src_dport(line)
        print(f"  {'✅' if result else '⬜'} {result}  | {line[50:100]}")

    print("\n=== Threshold Simulation (10 ports) ===")
    from unittest.mock import MagicMock
    blocker = MagicMock()
    blocker.block_ip.return_value = {"success": True}
    alerter = MagicMock()
    alerter.send_alert.return_value = {}

    mon = PortScanMonitor(blocker, alerter)

    for port in range(22, 22 + 12):   # 12 distinct ports → exceeds threshold of 10
        line = (
            f"Apr 17 14:23:45 server kernel: [UFW BLOCK] IN=eth0 OUT= "
            f"SRC=10.0.0.50 DST=192.168.1.1 DPT={port}"
        )
        mon._process_line(line)

    assert blocker.block_ip.called, "block_ip should have been called"
    print(f"  Port scan block triggered: {blocker.block_ip.called}")
    print(f"  Alert sent: {alerter.send_alert.called}")
    print("\nPortScanMonitor tests PASSED")
