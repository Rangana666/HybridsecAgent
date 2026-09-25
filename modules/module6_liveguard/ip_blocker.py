"""
ip_blocker.py — Automatic IP Blocking via UFW / iptables  (Module 6)

Maintains a set of blocked IPs, persisted to disk so blocks survive restarts.
Uses UFW when available; falls back to iptables; final fallback is dry-run
logging (safe for dev machines where we don't want to touch the firewall).

Public API:
    blocker = IPBlocker()
    blocker.block_ip("1.2.3.4", reason="SSH brute force")
    blocker.unblock_ip("1.2.3.4")
    blocker.is_blocked("1.2.3.4")          → True/False
    blocker.list_blocked()                 → [{"ip":…, "reason":…, "blocked_at":…}, …]
"""

import json
import logging
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

try:
    from config import LOGS_DIR
except ImportError:
    LOGS_DIR = Path(__file__).parent.parent.parent / "logs"

_BLOCKED_IPS_FILE = Path(LOGS_DIR) / "blocked_ips.json"


def _local_ips() -> set[str]:
    """
    Every IP address this machine actually owns (all interfaces, not just
    the primary one) — these must never be auto-blocked. With `ufw logging
    full`, blocked-packet log lines can legitimately show SRC=127.0.0.53
    (systemd-resolved's stub resolver) or even the server's own public IP
    (self-directed / reflected traffic), and naively blocking those would
    break local DNS or firewall off the dashboard from itself.
    """
    ips = {"127.0.0.1", "::1", "localhost"}
    try:
        import psutil
        for addrs in psutil.net_if_addrs().values():
            for a in addrs:
                if a.family in (socket.AF_INET, socket.AF_INET6):
                    ips.add(a.address.split("%")[0])  # strip IPv6 zone id
    except Exception as e:
        logger.warning("Could not enumerate local interface IPs: %s", e)
    return ips


# IPs that must NEVER be blocked (localhost, loopback, every local interface)
_WHITELIST: set[str] = _local_ips()


def _is_loopback(ip: str) -> bool:
    return ip.startswith("127.") or ip in ("::1", "localhost")

# Absolute paths so systemd's restricted PATH doesn't hide the binaries
_UFW      = "/usr/sbin/ufw"
_IPTABLES = "/sbin/iptables"

def _firewall_backend() -> str:
    for path in (_UFW, _IPTABLES):
        try:
            subprocess.run([path, "--version"], capture_output=True, timeout=3)
            return "ufw" if "ufw" in path else "iptables"
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return "none"


_BACKEND = _firewall_backend()
logger.info("IPBlocker backend: %s", _BACKEND)


class IPBlocker:
    """
    Thread-safe IP blocker that uses UFW or iptables.
    Keeps a JSON ledger of currently blocked IPs for the web UI.
    """

    def __init__(self):
        self._file = _BLOCKED_IPS_FILE
        self._file.parent.mkdir(parents=True, exist_ok=True)
        # Ensure the file exists
        if not self._file.exists():
            self._write({})

    # ── Public API ─────────────────────────────────────────────

    def block_ip(self, ip: str, reason: str = "", source: str = "") -> dict:
        """
        Block an IP at the firewall level.

        Returns:
            dict: {"success": bool, "ip": str, "already_blocked": bool, "error": str|None}
        """
        ip = ip.strip()

        if not ip or ip in _WHITELIST or _is_loopback(ip):
            return {"success": False, "ip": ip, "already_blocked": False,
                    "error": f"IP {ip!r} is whitelisted or invalid."}

        ledger = self._read()
        if ip in ledger:
            return {"success": True, "ip": ip, "already_blocked": True, "error": None}

        # Execute firewall command
        ok, err, backend_used = self._fw_block(ip)
        if ok:
            ledger[ip] = {
                "ip":         ip,
                "reason":     reason,
                "source":     source,
                "backend":    backend_used,
                "blocked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "unblocked":  False,
            }
            self._write(ledger)
            logger.warning("BLOCKED IP: %s | reason=%s | backend=%s", ip, reason, backend_used)

        return {"success": ok, "ip": ip, "already_blocked": False, "error": err}

    def unblock_ip(self, ip: str) -> dict:
        """Remove a firewall block for an IP."""
        ip = ip.strip()
        ledger = self._read()

        if ip not in ledger:
            return {"success": False, "ip": ip, "error": "IP not in blocked list."}

        # Reverse with whichever backend actually enforced the block —
        # it may differ from the current _BACKEND if UFW was toggled since.
        backend_used = ledger[ip].get("backend", _BACKEND)
        ok, err = self._fw_unblock(ip, backend_used)
        if ok:
            entry = ledger.pop(ip)
            entry["unblocked"] = True
            entry["unblocked_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            # Keep in a separate "history" section
            history = ledger.setdefault("__history__", [])
            if isinstance(history, list):
                history.append(entry)
            self._write(ledger)
            logger.info("UNBLOCKED IP: %s | backend=%s", ip, backend_used)

        return {"success": ok, "ip": ip, "error": err}

    def is_blocked(self, ip: str) -> bool:
        return ip.strip() in self._read()

    def list_blocked(self) -> list[dict]:
        ledger = self._read()
        return [v for k, v in ledger.items() if not k.startswith("__")]

    def block_count(self) -> int:
        return len(self.list_blocked())

    # ── Firewall commands ──────────────────────────────────────

    @staticmethod
    def _ufw_is_active() -> bool:
        """`ufw deny ...` succeeds even when UFW is disabled — it just
        queues the rule without loading it into netfilter, so the block
        would silently have no real effect. Check live status first."""
        try:
            proc = subprocess.run(
                [_UFW, "status"], capture_output=True, text=True, timeout=5,
            )
            return "Status: active" in proc.stdout
        except Exception:
            return False

    def _fw_block(self, ip: str) -> tuple[bool, Optional[str], str]:
        """Returns (success, error, backend_used) — backend_used is recorded
        per-IP so unblock_ip() can reverse it with the same tool later."""
        backend = _BACKEND
        if backend == "ufw" and not self._ufw_is_active():
            # UFW is disabled — a `ufw deny` rule wouldn't actually be
            # enforced. Fall back to raw iptables so the block is real.
            logger.warning(
                "UFW is installed but inactive — blocking %s via iptables "
                "directly so the block actually takes effect.", ip,
            )
            backend = "iptables" if Path(_IPTABLES).exists() else "none"

        if backend == "ufw":
            cmd = [_UFW, "deny", "from", ip, "to", "any"]
        elif backend == "iptables":
            cmd = [_IPTABLES, "-I", "INPUT", "1", "-s", ip, "-j", "DROP"]
        else:
            logger.warning("DRY-RUN block: %s (no firewall backend available)", ip)
            return False, "No firewall backend found", backend

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if proc.returncode == 0:
                logger.info("Firewall blocked %s via %s", ip, backend)
                return True, None, backend
            err = proc.stderr.strip() or proc.stdout.strip()
            logger.error("Firewall block failed for %s: %s", ip, err)
            return False, err, backend
        except Exception as e:
            logger.error("Firewall block exception for %s: %s", ip, e)
            return False, str(e), backend

    @staticmethod
    def _fw_unblock(ip: str, backend: str) -> tuple[bool, Optional[str]]:
        if backend == "ufw":
            cmd = [_UFW, "delete", "deny", "from", ip, "to", "any"]
        elif backend == "iptables":
            cmd = [_IPTABLES, "-D", "INPUT", "-s", ip, "-j", "DROP"]
        else:
            return False, "No firewall backend found"

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if proc.returncode == 0:
                return True, None
            return False, (proc.stderr.strip() or proc.stdout.strip())
        except Exception as e:
            return False, str(e)

    # ── Persistence ────────────────────────────────────────────

    def _read(self) -> dict:
        try:
            return json.loads(self._file.read_text())
        except Exception:
            return {}

    def _write(self, data: dict):
        self._file.write_text(json.dumps(data, indent=2))


# ── Standalone test ────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
    blocker = IPBlocker()

    # Use a fake IP to avoid touching real firewall rules in test
    test_ip = "192.0.2.1"   # TEST-NET — safe to use in tests

    print(f"Backend: {_BACKEND}")
    print(f"Is {test_ip} blocked? {blocker.is_blocked(test_ip)}")

    result = blocker.block_ip(test_ip, reason="test", source="unit_test")
    print(f"Block result: {result}")
    print(f"Is {test_ip} blocked? {blocker.is_blocked(test_ip)}")
    print(f"Blocked IPs: {blocker.list_blocked()}")

    result = blocker.unblock_ip(test_ip)
    print(f"Unblock result: {result}")
    print(f"Is {test_ip} blocked? {blocker.is_blocked(test_ip)}")
    print("\nIPBlocker test PASSED")
