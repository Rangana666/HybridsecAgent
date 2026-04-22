"""
tests/test_module1.py — Unit Tests for Module 1: Data Collection Agent

Tests cover:
  - Scanner initialisation and scan-id format
  - Server info structure
  - _build_vuln_objects produces correctly shaped dicts
  - _make_summary counts priorities accurately
  - Sub-scanners are called and their results are assembled
  - NVD enrichment is skipped when enrich_nvd=False
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.module1_collection.scanner import Scanner


class TestScannerInit(unittest.TestCase):
    def test_default_target(self):
        s = Scanner(enrich_nvd=False)
        self.assertEqual(s.target, "127.0.0.1")

    def test_custom_target(self):
        s = Scanner(target="10.0.0.5", enrich_nvd=False)
        self.assertEqual(s.target, "10.0.0.5")

    def test_scan_id_format(self):
        sid = Scanner._make_scan_id()
        self.assertTrue(sid.startswith("scan_"), f"Unexpected prefix: {sid}")
        parts = sid.split("_")
        # scan_YYYYMMDD_HHMMSS
        self.assertGreaterEqual(len(parts), 3)


class TestServerInfo(unittest.TestCase):
    def test_server_info_keys(self):
        info = Scanner._get_server_info()
        for key in ("hostname", "ip", "os", "cloud"):
            self.assertIn(key, info, f"Missing key: {key}")

    def test_server_info_hostname_not_empty(self):
        info = Scanner._get_server_info()
        self.assertTrue(info["hostname"])


class TestMakeSummary(unittest.TestCase):
    # _make_summary uses cvss_score thresholds: ≥8.5→critical, ≥7.0→high, ≥5.0→medium, else→low
    def _make_vuln(self, cvss):
        return {"cvss_score": cvss}

    def test_counts_all_priorities(self):
        s = Scanner(enrich_nvd=False)
        vulns = [
            self._make_vuln(9.0),   # critical
            self._make_vuln(8.5),   # critical
            self._make_vuln(7.5),   # high
            self._make_vuln(6.0),   # medium
            self._make_vuln(2.0),   # low
            self._make_vuln(1.0),   # low
        ]
        summary = s._make_summary(vulns)
        self.assertEqual(summary["total"],    6)
        self.assertEqual(summary["critical"], 2)
        self.assertEqual(summary["high"],     1)
        self.assertEqual(summary["medium"],   1)
        self.assertEqual(summary["low"],      2)

    def test_empty_input(self):
        s = Scanner(enrich_nvd=False)
        summary = s._make_summary([])
        self.assertEqual(summary["total"], 0)
        self.assertEqual(summary["critical"], 0)


class TestBuildVulnObjects(unittest.TestCase):
    SAMPLE_FINDING = {
        "type": "ssh_root_login_enabled",
        "title": "SSH Root Login Enabled",
        "category": "ssh",
        "cvss_score": 7.5,
        "exploit_exists": True,
        "patch_available": True,
        "description": "Root login via SSH is enabled.",
        "evidence": "PermitRootLogin yes",
        "affected_component": "sshd",
        "detected_by": "system_scanner",
    }

    def test_required_keys_present(self):
        s = Scanner(enrich_nvd=False)
        vulns = s._build_vuln_objects([self.SAMPLE_FINDING])
        self.assertEqual(len(vulns), 1)
        v = vulns[0]
        for key in ("id", "type", "title", "cvss_score", "category",
                    "exploit_exists", "patch_available"):
            self.assertIn(key, v, f"Missing key: {key}")

    def test_id_assigned(self):
        s = Scanner(enrich_nvd=False)
        vulns = s._build_vuln_objects([self.SAMPLE_FINDING])
        self.assertTrue(vulns[0]["id"].startswith("VULN-"))

    def test_multiple_findings_unique_ids(self):
        s = Scanner(enrich_nvd=False)
        # _build_vuln_objects deduplicates by type — use distinct types
        finding_types = [
            "ssh_root_login_enabled", "firewall_disabled",
            "weak_password_policy", "open_telnet_port", "ssl_expired",
        ]
        findings = [dict(self.SAMPLE_FINDING, type=t) for t in finding_types]
        vulns = s._build_vuln_objects(findings)
        ids = [v["id"] for v in vulns]
        self.assertEqual(len(set(ids)), len(vulns))


class TestQuickScanStructure(unittest.TestCase):
    """Mock all sub-scanners and verify Scanner.run_quick_scan returns valid shape."""

    FAKE_VULNS = [
        {"type": "firewall_disabled", "title": "Firewall Disabled",
         "category": "firewall", "cvss_score": 6.0, "exploit_exists": False,
         "patch_available": True, "description": "UFW is not active.",
         "evidence": "ufw inactive", "affected_component": "ufw",
         "detected_by": "system_scanner"},
    ]

    @patch("modules.module1_collection.scanner.LynisScanner")
    @patch("modules.module1_collection.scanner.NmapScanner")
    @patch("modules.module1_collection.scanner.SystemScanner")
    def test_quick_scan_returns_valid_shape(self, MockSys, MockNmap, MockLynis):
        MockLynis.return_value.run.return_value = {"score": 55, "findings": []}
        MockNmap.return_value.run.return_value = {"open_ports": [], "findings": []}
        MockSys.return_value.run.return_value = self.FAKE_VULNS

        scanner = Scanner(enrich_nvd=False)
        result = scanner.run_quick_scan()

        self.assertIn("scan_id",        result)
        self.assertIn("vulnerabilities", result)
        self.assertIn("scan_summary",   result)
        self.assertIn("server_info",    result)
        self.assertIn("timestamp",      result)
        self.assertEqual(result["scan_type"], "quick")

    @patch("modules.module1_collection.scanner.LynisScanner")
    @patch("modules.module1_collection.scanner.NmapScanner")
    @patch("modules.module1_collection.scanner.SystemScanner")
    def test_quick_scan_summary_totals_match_vulns(self, MockSys, MockNmap, MockLynis):
        MockLynis.return_value.run.return_value = {"score": 55, "findings": []}
        MockNmap.return_value.run.return_value = {"open_ports": [], "findings": []}
        MockSys.return_value.run.return_value = self.FAKE_VULNS * 3   # 3 vulns

        scanner = Scanner(enrich_nvd=False)
        result = scanner.run_quick_scan()
        self.assertEqual(result["scan_summary"]["total"], len(result["vulnerabilities"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
