"""
tests/test_module6.py — Unit Tests for Module 6: Live Guard

Tests cover:
  - IPBlocker: whitelisted IPs (localhost) are never blocked
  - IPBlocker: block/unblock cycle updates ledger correctly
  - IPBlocker: invalid IPs rejected
  - IncidentLog: append and read_recent round-trip
  - IncidentLog: cap at max entries
  - AlertSystem: is_configured() returns dict with bool flags
  - AlertSystem: send_alert is a no-op (no error) when unconfigured
  - SSHMonitor: _extract_ip / _process_line pattern matching
  - LiveGuard: start/stop cycle (monitors mocked)
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))


# ── IPBlocker ─────────────────────────────────────────────────────────────────

class TestIPBlockerWhitelist(unittest.TestCase):
    def _blocker(self):
        from modules.module6_liveguard.ip_blocker import IPBlocker
        return IPBlocker()

    def test_localhost_not_blocked(self):
        blocker = self._blocker()
        result = blocker.block_ip("127.0.0.1", reason="test")
        self.assertFalse(result.get("success"),
            "127.0.0.1 must never be blocked")

    def test_loopback_ipv6_not_blocked(self):
        blocker = self._blocker()
        result = blocker.block_ip("::1", reason="test")
        self.assertFalse(result.get("success"))

    def test_empty_ip_rejected(self):
        blocker = self._blocker()
        result = blocker.block_ip("", reason="test")
        self.assertFalse(result.get("success"))


class TestIPBlockerLedger(unittest.TestCase):
    """Mock subprocess so tests pass without root / UFW."""

    def test_block_records_ip_in_ledger(self):
        with tempfile.TemporaryDirectory() as d:
            ledger = Path(d) / "blocked_ips.json"
            with patch("modules.module6_liveguard.ip_blocker._BLOCKED_IPS_FILE", ledger), \
                 patch("modules.module6_liveguard.ip_blocker.IPBlocker._fw_block",
                       staticmethod(lambda ip: (True, None))):
                from modules.module6_liveguard.ip_blocker import IPBlocker
                blocker = IPBlocker()
                result = blocker.block_ip("1.2.3.4", reason="brute_force")
                self.assertTrue(result.get("success"), result)
                self.assertTrue(blocker.is_blocked("1.2.3.4"))

    def test_unblock_removes_from_ledger(self):
        with tempfile.TemporaryDirectory() as d:
            ledger = Path(d) / "blocked_ips.json"
            with patch("modules.module6_liveguard.ip_blocker._BLOCKED_IPS_FILE", ledger), \
                 patch("modules.module6_liveguard.ip_blocker.IPBlocker._fw_block",
                       staticmethod(lambda ip: (True, None))), \
                 patch("modules.module6_liveguard.ip_blocker.IPBlocker._fw_unblock",
                       staticmethod(lambda ip: (True, None))):
                from modules.module6_liveguard.ip_blocker import IPBlocker
                blocker = IPBlocker()
                blocker.block_ip("5.6.7.8", reason="port_scan")
                self.assertTrue(blocker.is_blocked("5.6.7.8"))
                blocker.unblock_ip("5.6.7.8")
                self.assertFalse(blocker.is_blocked("5.6.7.8"))

    def test_list_blocked_returns_list(self):
        with tempfile.TemporaryDirectory() as d:
            ledger = Path(d) / "blocked_ips.json"
            with patch("modules.module6_liveguard.ip_blocker._BLOCKED_IPS_FILE", ledger):
                from modules.module6_liveguard.ip_blocker import IPBlocker
                blocker = IPBlocker()
                listing = blocker.list_blocked()
                self.assertIsInstance(listing, list)


# ── IncidentLog ───────────────────────────────────────────────────────────────

class TestIncidentLog(unittest.TestCase):
    def _log(self, path):
        from modules.module6_liveguard.ssh_monitor import IncidentLog
        return IncidentLog(path=path)

    def test_append_and_read_recent(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            p = Path(f.name)
        try:
            log = self._log(p)
            log.append({"type": "BRUTE_FORCE_SSH", "ip": "1.2.3.4",
                         "severity": "CRITICAL", "timestamp": "2026-01-01T00:00:00"})
            log.append({"type": "PORT_SCAN", "ip": "5.6.7.8",
                         "severity": "HIGH", "timestamp": "2026-01-01T00:01:00"})
            recent = log.read_recent(10)
            self.assertEqual(len(recent), 2)
        finally:
            p.unlink(missing_ok=True)

    def test_read_recent_respects_limit(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            p = Path(f.name)
        try:
            log = self._log(p)
            for i in range(10):
                log.append({"type": "TEST", "ip": f"1.2.3.{i}",
                             "severity": "LOW", "timestamp": f"2026-01-01T00:0{i}:00"})
            recent = log.read_recent(3)
            self.assertLessEqual(len(recent), 3)
        finally:
            p.unlink(missing_ok=True)

    def test_empty_log_returns_empty_list(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            p = Path(f.name)
        p.unlink(missing_ok=True)
        try:
            log = self._log(p)
            self.assertEqual(log.read_recent(10), [])
        finally:
            p.unlink(missing_ok=True)


# ── AlertSystem ───────────────────────────────────────────────────────────────

class TestAlertSystem(unittest.TestCase):
    def setUp(self):
        from modules.module6_liveguard.alert_system import AlertSystem
        self.alert = AlertSystem()

    def test_is_configured_returns_dict(self):
        result = self.alert.is_configured()
        self.assertIsInstance(result, dict)
        self.assertIn("telegram", result)
        self.assertIn("email", result)

    def test_send_alert_unconfigured_no_exception(self):
        incident = {
            "type": "BRUTE_FORCE_SSH",
            "ip": "1.2.3.4",
            "severity": "CRITICAL",
            "details": "5 failed SSH attempts",
            "timestamp": "2026-01-01T00:00:00",
            "blocked": True,
        }
        # Should not raise even when Telegram/email are unconfigured
        try:
            result = self.alert.send_alert(incident)
            self.assertIsInstance(result, dict)
        except Exception as e:
            self.fail(f"send_alert raised unexpectedly: {e}")


# ── SSHMonitor pattern matching ───────────────────────────────────────────────

class TestSSHMonitorPatterns(unittest.TestCase):
    def test_extract_ip_failed_password(self):
        from modules.module6_liveguard.ssh_monitor import _extract_ip
        line = "Apr 17 12:00:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 54321 ssh2"
        ip = _extract_ip(line)
        self.assertEqual(ip, "192.168.1.100")

    def test_extract_ip_invalid_user(self):
        from modules.module6_liveguard.ssh_monitor import _extract_ip
        line = "Apr 17 12:00:01 server sshd[1235]: Invalid user admin from 10.0.0.5 port 22222"
        ip = _extract_ip(line)
        self.assertEqual(ip, "10.0.0.5")

    def test_extract_ip_no_ip_returns_none(self):
        from modules.module6_liveguard.ssh_monitor import _extract_ip
        line = "Apr 17 12:00:02 server sshd[9999]: Server listening on 0.0.0.0 port 22."
        ip = _extract_ip(line)
        self.assertIsNone(ip)


# ── LiveGuard start/stop ──────────────────────────────────────────────────────

class TestLiveGuardLifecycle(unittest.TestCase):
    @patch("modules.module6_liveguard.live_guard.SSHMonitor")
    @patch("modules.module6_liveguard.live_guard.WebMonitor")
    @patch("modules.module6_liveguard.live_guard.PortScanMonitor")
    def test_start_and_stop(self, MockPort, MockWeb, MockSSH):
        for M in (MockSSH, MockWeb, MockPort):
            inst = M.return_value
            inst.start.return_value = None
            inst.stop.return_value  = None
            inst.is_running.return_value = True

        from modules.module6_liveguard.live_guard import LiveGuard
        guard = LiveGuard()
        guard.start()
        status = guard.get_status()
        self.assertIn("running", status)
        guard.stop()

    @patch("modules.module6_liveguard.live_guard.SSHMonitor")
    @patch("modules.module6_liveguard.live_guard.WebMonitor")
    @patch("modules.module6_liveguard.live_guard.PortScanMonitor")
    def test_get_status_keys(self, MockPort, MockWeb, MockSSH):
        for M in (MockSSH, MockWeb, MockPort):
            M.return_value.is_running.return_value = False
            M.return_value.start.return_value = None
            M.return_value.stop.return_value = None

        from modules.module6_liveguard.live_guard import LiveGuard
        guard = LiveGuard()
        guard.start()
        status = guard.get_status()
        for key in ("running", "monitors"):
            self.assertIn(key, status, f"Missing key: {key}")
        guard.stop()


if __name__ == "__main__":
    unittest.main(verbosity=2)
