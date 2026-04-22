"""
tests/test_module7.py — Unit Tests for Module 7: Report Generator

Tests cover:
  - PDFGenerator creates a non-empty PDF file
  - HTMLGenerator creates a valid HTML file with expected sections
  - ReportGenerator facade generates both formats
  - ReportGenerator.list_reports returns correct metadata shape
  - Generated filenames follow the hybridsec_report_* naming convention
"""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

# ── shared fixture data ────────────────────────────────────────────────────────

FAKE_SCAN = {
    "scan_id": "scan_test_phase8",
    "timestamp": "2026-04-18T10:00:00",
    "scan_type": "quick",
    "server_info": {
        "hostname": "hybridsec-test",
        "ip": "127.0.0.1",
        "os": "Ubuntu 22.04 LTS",
        "cloud": "Local VM",
    },
    "lynis_score": 52,
    "scan_summary": {"total": 3, "critical": 1, "high": 1, "medium": 1, "low": 0},
    "vulnerabilities": [
        {
            "id": "VULN-001",
            "type": "ssh_root_login_enabled",
            "title": "SSH Root Login Enabled",
            "category": "ssh",
            "cvss_score": 7.5,
            "hybrid_score": 9.1,
            "priority": "CRITICAL",
            "exploit_exists": True,
            "patch_available": True,
            "rule_score": 8.5,
            "ml_score": 9.5,
            "llm_score": 9.3,
            "description": "Root login via SSH is enabled.",
        },
        {
            "id": "VULN-002",
            "type": "firewall_disabled",
            "title": "Firewall Disabled",
            "category": "firewall",
            "cvss_score": 6.0,
            "hybrid_score": 7.2,
            "priority": "HIGH",
            "exploit_exists": False,
            "patch_available": True,
            "rule_score": 6.0,
            "ml_score": 7.5,
            "llm_score": 8.0,
            "description": "UFW firewall is not active.",
        },
        {
            "id": "VULN-003",
            "type": "weak_password_policy",
            "title": "Weak Password Policy",
            "category": "authentication",
            "cvss_score": 5.0,
            "hybrid_score": 5.8,
            "priority": "MEDIUM",
            "exploit_exists": False,
            "patch_available": True,
            "rule_score": 5.0,
            "ml_score": 6.0,
            "llm_score": 6.5,
            "description": "Password complexity rules are not enforced.",
        },
    ],
}

FAKE_PROFILE = {
    "id": 1,
    "business_type":  "E-commerce",
    "employee_count": "11-50",
    "server_purpose": "Database",
    "sensitive_data": "Yes",
    "has_it_staff":   "No",
    "budget":         "Under $50",
}

FAKE_INCIDENTS = [
    {
        "type": "BRUTE_FORCE_SSH",
        "ip": "192.168.1.99",
        "severity": "CRITICAL",
        "details": "6 failed SSH attempts in 60s",
        "timestamp": "2026-04-18T09:00:00",
        "blocked": True,
    }
]


class TestPDFGenerator(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._out = Path(self._tmpdir.name)

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_generates_pdf_file(self):
        from modules.module7_reports.pdf_generator import PDFGenerator
        path = PDFGenerator().generate(FAKE_SCAN, FAKE_PROFILE, FAKE_INCIDENTS, self._out)
        self.assertTrue(path.exists(), f"PDF not found: {path}")
        self.assertEqual(path.suffix, ".pdf")

    def test_pdf_is_not_empty(self):
        from modules.module7_reports.pdf_generator import PDFGenerator
        path = PDFGenerator().generate(FAKE_SCAN, FAKE_PROFILE, FAKE_INCIDENTS, self._out)
        self.assertGreater(path.stat().st_size, 1024, "PDF is suspiciously small")

    def test_pdf_filename_convention(self):
        from modules.module7_reports.pdf_generator import PDFGenerator
        path = PDFGenerator().generate(FAKE_SCAN, FAKE_PROFILE, FAKE_INCIDENTS, self._out)
        self.assertTrue(path.name.startswith("hybridsec_report_"), path.name)

    def test_pdf_with_no_incidents(self):
        from modules.module7_reports.pdf_generator import PDFGenerator
        path = PDFGenerator().generate(FAKE_SCAN, FAKE_PROFILE, [], self._out)
        self.assertTrue(path.exists())

    def test_pdf_with_no_profile(self):
        from modules.module7_reports.pdf_generator import PDFGenerator
        path = PDFGenerator().generate(FAKE_SCAN, None, [], self._out)
        self.assertTrue(path.exists())


class TestHTMLGenerator(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._out = Path(self._tmpdir.name)

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_generates_html_file(self):
        from modules.module7_reports.html_generator import HTMLGenerator
        path = HTMLGenerator().generate(FAKE_SCAN, FAKE_PROFILE, FAKE_INCIDENTS, self._out)
        self.assertTrue(path.exists())
        self.assertEqual(path.suffix, ".html")

    def test_html_is_not_empty(self):
        from modules.module7_reports.html_generator import HTMLGenerator
        path = HTMLGenerator().generate(FAKE_SCAN, FAKE_PROFILE, FAKE_INCIDENTS, self._out)
        self.assertGreater(path.stat().st_size, 1024)

    def test_html_contains_vuln_title(self):
        from modules.module7_reports.html_generator import HTMLGenerator
        path = HTMLGenerator().generate(FAKE_SCAN, FAKE_PROFILE, FAKE_INCIDENTS, self._out)
        content = path.read_text()
        self.assertIn("SSH Root Login", content)

    def test_html_contains_bootstrap(self):
        from modules.module7_reports.html_generator import HTMLGenerator
        path = HTMLGenerator().generate(FAKE_SCAN, FAKE_PROFILE, FAKE_INCIDENTS, self._out)
        content = path.read_text()
        self.assertIn("bootstrap", content.lower())

    def test_html_filename_convention(self):
        from modules.module7_reports.html_generator import HTMLGenerator
        path = HTMLGenerator().generate(FAKE_SCAN, FAKE_PROFILE, FAKE_INCIDENTS, self._out)
        self.assertTrue(path.name.startswith("hybridsec_report_"))


class TestReportGeneratorFacade(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self._out = Path(self._tmpdir.name)

    def tearDown(self):
        self._tmpdir.cleanup()

    def test_generate_pdf_returns_path(self):
        from modules.module7_reports.report_generator import ReportGenerator
        path = ReportGenerator().generate(
            FAKE_SCAN, profile=FAKE_PROFILE, incidents=FAKE_INCIDENTS,
            format="pdf", output_dir=self._out,
        )
        self.assertEqual(path.suffix, ".pdf")
        self.assertTrue(path.exists())

    def test_generate_html_returns_path(self):
        from modules.module7_reports.report_generator import ReportGenerator
        path = ReportGenerator().generate(
            FAKE_SCAN, profile=FAKE_PROFILE, incidents=FAKE_INCIDENTS,
            format="html", output_dir=self._out,
        )
        self.assertEqual(path.suffix, ".html")
        self.assertTrue(path.exists())

    def test_generate_both_returns_pdf_path(self):
        from modules.module7_reports.report_generator import ReportGenerator
        path = ReportGenerator().generate(
            FAKE_SCAN, profile=FAKE_PROFILE, incidents=FAKE_INCIDENTS,
            format="both", output_dir=self._out,
        )
        self.assertEqual(path.suffix, ".pdf")
        # Both files should exist
        files = list(self._out.iterdir())
        suffixes = {f.suffix for f in files}
        self.assertIn(".pdf",  suffixes)
        self.assertIn(".html", suffixes)

    def test_list_reports_metadata_shape(self):
        from modules.module7_reports.report_generator import ReportGenerator
        rg = ReportGenerator()
        rg.generate(FAKE_SCAN, profile=FAKE_PROFILE, incidents=[],
                    format="pdf", output_dir=self._out)
        # Temporarily point list_reports at our temp dir
        import modules.module7_reports.report_generator as rg_mod
        orig = rg_mod._REPORTS_DIR
        rg_mod._REPORTS_DIR = self._out
        try:
            listing = rg.list_reports()
            self.assertGreater(len(listing), 0)
            entry = listing[0]
            for key in ("filename", "format", "size_kb", "created_at", "path"):
                self.assertIn(key, entry, f"Missing key: {key}")
        finally:
            rg_mod._REPORTS_DIR = orig


if __name__ == "__main__":
    unittest.main(verbosity=2)
