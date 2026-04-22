"""
tests/test_module4.py — Unit Tests for Module 4: Remediation + AutoFix Agent

Tests cover:
  - RemediationGenerator returns structured dict for known vuln types
  - RemediationGenerator lists supported types
  - BackupManager creates a backup file and records it in the index
  - BackupManager restore returns the backed-up content
  - AutoFixAgent rejects unsupported vuln types gracefully
  - AutoFixAgent requires confirmation when AUTOFIX_REQUIRE_CONFIRMATION=True
"""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

SSH_VULN = {
    "id": "VULN-001",
    "type": "ssh_root_login_enabled",
    "title": "SSH Root Login Enabled",
    "category": "ssh",
    "cvss_score": 7.5,
    "exploit_exists": True,
    "patch_available": True,
    "description": "Root login via SSH is enabled.",
    "priority": "CRITICAL",
}

CONTEXT = {
    "business_type":  "E-commerce",
    "employee_count": "11-50",
    "server_purpose": "Database",
    "sensitive_data": "Yes",
    "has_it_staff":   "No",
    "budget":         "Under $50",
}


class TestRemediationGenerator(unittest.TestCase):
    def setUp(self):
        from modules.module4_remediation.remediation_generator import RemediationGenerator
        self.gen = RemediationGenerator(use_llm=False)

    def test_get_remediation_returns_dict(self):
        result = self.gen.get_remediation(SSH_VULN, CONTEXT)
        self.assertIsInstance(result, dict)

    def test_known_type_has_steps(self):
        result = self.gen.get_remediation(SSH_VULN, CONTEXT)
        steps = result.get("steps") or result.get("fix_steps") or result.get("commands", [])
        self.assertTrue(len(steps) > 0, "Expected at least one fix step")

    def test_supported_types_is_list(self):
        types = self.gen.list_supported_types()
        self.assertIsInstance(types, list)
        self.assertGreater(len(types), 0)

    def test_ssh_root_login_is_supported(self):
        types = self.gen.list_supported_types()
        self.assertIn("ssh_root_login_enabled", types)

    def test_unknown_type_returns_dict(self):
        unknown = dict(SSH_VULN, type="totally_unknown_vuln_xyz")
        result = self.gen.get_remediation(unknown, CONTEXT)
        self.assertIsInstance(result, dict)

    def test_get_all_remediations(self):
        vulns = [SSH_VULN, dict(SSH_VULN, id="V2", type="firewall_disabled")]
        results = self.gen.get_all_remediations(vulns, CONTEXT)
        self.assertEqual(len(results), 2)
        for r in results:
            self.assertIsInstance(r, dict)


class TestBackupManager(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._backups_dir = Path(self._tmpdir.name) / "backups"

        # Create a fake target file to back up
        self._target = Path(self._tmpdir.name) / "sshd_config"
        self._target.write_text("PermitRootLogin yes\nPort 22\n")

    def tearDown(self):
        self._tmpdir.cleanup()

    def _bm(self):
        from modules.module4_remediation.backup_manager import BackupManager
        return BackupManager(backups_dir=self._backups_dir)

    def test_backup_creates_file(self):
        bm = self._bm()
        result = bm.backup(str(self._target), vuln_type="ssh_root_login_enabled")
        self.assertTrue(result.get("success"), result)
        backup_path = Path(result["backup_path"])
        self.assertTrue(backup_path.exists())

    def test_backup_content_matches_original(self):
        bm = self._bm()
        result = bm.backup(str(self._target))
        backup_path = Path(result["backup_path"])
        self.assertEqual(backup_path.read_text(), self._target.read_text())

    def test_list_backups_after_backup(self):
        bm = self._bm()
        bm.backup(str(self._target))
        listing = bm.list_backups()
        self.assertGreater(len(listing), 0)

    def test_restore_returns_success(self):
        bm = self._bm()
        result = bm.backup(str(self._target))
        backup_id = result["backup_id"]

        # Modify the target
        self._target.write_text("PermitRootLogin no\n")

        restored = bm.restore(backup_id)
        self.assertTrue(restored.get("success"), restored)
        # Original content should be restored
        self.assertIn("PermitRootLogin yes", self._target.read_text())


class TestAutoFixAgent(unittest.TestCase):
    def _agent(self):
        from modules.module4_remediation.autofix_agent import AutoFixAgent
        return AutoFixAgent()

    def test_unsupported_type_returns_failure(self):
        agent = self._agent()
        result = agent.execute_fix(
            {"type": "no_such_vuln_type_xyz", "title": "Unknown"},
            confirmed=True,
        )
        self.assertFalse(result.get("success"), "Expected failure for unsupported type")

    def test_unconfirmed_fix_returns_failure(self):
        agent = self._agent()
        with patch("modules.module4_remediation.autofix_agent.AUTOFIX_REQUIRE_CONFIRMATION", True):
            result = agent.execute_fix(SSH_VULN, confirmed=False)
        self.assertFalse(result.get("success"))
        # Agent returns needs_confirmation=True instead of an error string
        self.assertTrue(
            result.get("needs_confirmation") or
            "confirm" in str(result.get("error") or result.get("confirmation_message", "")).lower()
        )

    def test_list_recent_fixes_returns_list(self):
        agent = self._agent()
        listing = agent.list_recent_fixes()
        self.assertIsInstance(listing, list)


if __name__ == "__main__":
    unittest.main(verbosity=2)
