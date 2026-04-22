"""
tests/test_integration.py — End-to-End Integration Tests

Tests cover:
  1. Full scan → score → report pipeline (mocked sub-scanners)
  2. Flask web app smoke tests via test client:
     - Login page loads
     - Invalid credentials rejected
     - Valid credentials grant session
     - Protected routes redirect when unauthenticated
     - /api/dashboard/stats returns JSON
     - /api/reports/generate returns JSON
  3. Module chain: Scanner result feeds HybridEngine feeds ReportGenerator
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

# ── shared fixtures ────────────────────────────────────────────────────────────

FAKE_SCAN_RESULT = {
    "scan_id": "scan_integration_test",
    "scan_type": "quick",
    "timestamp": "2026-04-18T10:00:00",
    "server_info": {"hostname": "test", "ip": "127.0.0.1",
                    "os": "Ubuntu 22.04", "cloud": "Local"},
    "lynis_score": 48,
    "scan_summary": {"total": 2, "critical": 1, "high": 1, "medium": 0, "low": 0},
    "vulnerabilities": [
        {
            "id": "VULN-001", "type": "ssh_root_login_enabled",
            "title": "SSH Root Login Enabled", "category": "ssh",
            "cvss_score": 7.5, "exploit_exists": True, "patch_available": True,
            "description": "Root login via SSH is enabled.",
        },
        {
            "id": "VULN-002", "type": "firewall_disabled",
            "title": "Firewall Disabled", "category": "firewall",
            "cvss_score": 6.0, "exploit_exists": False, "patch_available": True,
            "description": "UFW firewall is not active.",
        },
    ],
}

CONTEXT = {
    "business_type": "E-commerce", "employee_count": "11-50",
    "server_purpose": "Database", "sensitive_data": "Yes",
    "has_it_staff": "No", "budget": "Under $50",
}


# ── 1. Pipeline integration ────────────────────────────────────────────────────

class TestScanToScoreToReport(unittest.TestCase):
    """Verify Modules 1 → 3 → 7 produce a complete artefact chain."""

    def test_score_all_then_generate_report(self):
        # Step 1: Score the fake scan through HybridEngine (mock LLM)
        from modules.module3_scoring.hybrid_engine import HybridEngine
        engine = HybridEngine()
        mock_llm = MagicMock()
        mock_llm.score.return_value = {
            "llm_score": 8.0, "llm_reasoning": "Mock.", "llm_available": True,
        }
        engine._llm = mock_llm

        scored = engine.score_all(FAKE_SCAN_RESULT["vulnerabilities"], CONTEXT)
        self.assertEqual(len(scored), 2)
        for v in scored:
            self.assertIn("hybrid_score", v)
            self.assertIn("priority", v)

        # Step 2: Build a scored scan result
        scan_with_scores = dict(FAKE_SCAN_RESULT)
        scan_with_scores["vulnerabilities"] = scored

        # Step 3: Generate PDF report
        with tempfile.TemporaryDirectory() as d:
            from modules.module7_reports.report_generator import ReportGenerator
            path = ReportGenerator().generate(
                scan_with_scores,
                profile=CONTEXT,
                incidents=[],
                format="pdf",
                output_dir=Path(d),
            )
            self.assertTrue(path.exists())
            self.assertGreater(path.stat().st_size, 1024)

    def test_summary_totals_match_after_scoring(self):
        from modules.module3_scoring.hybrid_engine import HybridEngine
        engine = HybridEngine()
        engine._llm = MagicMock()
        engine._llm.score.return_value = {
            "llm_score": 7.0, "llm_reasoning": "Mock.", "llm_available": True,
        }
        scored = engine.score_all(FAKE_SCAN_RESULT["vulnerabilities"], CONTEXT)
        self.assertEqual(len(scored), len(FAKE_SCAN_RESULT["vulnerabilities"]))


# ── 2. Flask app smoke tests ───────────────────────────────────────────────────

class TestFlaskAppSmoke(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Create a single test-client instance shared by all tests in this class."""
        from modules.module5_web.app import create_app
        app = create_app()
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        cls.client = app.test_client()
        cls.app = app

    # ── unauthenticated access ─────────────────────────────────────
    def test_login_page_loads(self):
        resp = self.client.get("/login")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"login", resp.data.lower())

    def test_dashboard_redirects_when_not_logged_in(self):
        resp = self.client.get("/dashboard", follow_redirects=False)
        self.assertIn(resp.status_code, (302, 401))

    def test_api_stats_requires_login(self):
        resp = self.client.get("/api/dashboard/stats")
        self.assertIn(resp.status_code, (302, 401, 403))

    def _get_csrf_token(self, client):
        """GET the login page, extract csrf_token from the session."""
        client.get("/login")
        with client.session_transaction() as sess:
            return sess.get("csrf_token", "")

    # ── login flow ─────────────────────────────────────────────────
    def test_invalid_credentials_rejected(self):
        client = self.app.test_client()
        csrf = self._get_csrf_token(client)
        resp = client.post("/login", data={
            "username": "admin",
            "password": "wrongpassword",
            "csrf_token": csrf,
        }, follow_redirects=True)
        self.assertIn(resp.status_code, (200, 401, 403))
        self.assertNotIn(b"dashboard", resp.data.lower())

    def test_valid_login_creates_session(self):
        client = self.app.test_client()
        csrf = self._get_csrf_token(client)
        resp = client.post("/login", data={
            "username": "admin",
            "password": "Admin@HybridSec2025!",
            "csrf_token": csrf,
        }, follow_redirects=True)
        self.assertIn(resp.status_code, (200, 302))
        content = resp.data.lower()
        self.assertTrue(
            b"dashboard" in content or b"verify" in content or b"2fa" in content,
            "Expected dashboard or 2FA page after valid login"
        )

    def _logged_in_client(self):
        """Return a client with a live admin session (skipping 2FA if not enabled)."""
        client = self.app.test_client()
        with self.app.app_context():
            from modules.module5_web.auth import _get_db
            db = _get_db()
            try:
                user = db.execute(
                    "SELECT id, totp_enabled FROM users WHERE username='admin'"
                ).fetchone()
                totp_enabled = user["totp_enabled"] if user else 0
            finally:
                db.close()

        with client.session_transaction() as sess:
            sess["user_id"] = 1
            sess["username"] = "admin"
            if not totp_enabled:
                sess["2fa_verified"] = True

        return client

    def test_dashboard_loads_when_logged_in(self):
        client = self._logged_in_client()
        resp = client.get("/dashboard", follow_redirects=True)
        self.assertEqual(resp.status_code, 200)

    def test_api_dashboard_stats_returns_json(self):
        client = self._logged_in_client()
        resp = client.get("/api/dashboard/stats")
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertIsInstance(data, dict)
        for key in ("total", "critical", "high", "medium", "low"):
            self.assertIn(key, data)

    def test_all_page_routes_load(self):
        client = self._logged_in_client()
        pages = ["/dashboard", "/scan", "/risks", "/remediation",
                 "/threats", "/reports", "/audit", "/settings"]
        for page in pages:
            resp = client.get(page, follow_redirects=True)
            self.assertEqual(resp.status_code, 200,
                             f"Page {page} returned {resp.status_code}")

    def test_api_profile_returns_json(self):
        client = self._logged_in_client()
        resp = client.get("/api/profile")
        self.assertEqual(resp.status_code, 200)
        self.assertIsInstance(json.loads(resp.data), dict)

    def test_api_threats_recent_returns_list(self):
        client = self._logged_in_client()
        resp = client.get("/api/threats/recent")
        self.assertEqual(resp.status_code, 200)
        self.assertIsInstance(json.loads(resp.data), list)

    def test_csrf_required_on_scan_start(self):
        client = self._logged_in_client()
        resp = client.post("/api/scan/start",
                           json={"scan_type": "quick"},
                           content_type="application/json")
        # Without a valid CSRF token it must be rejected
        self.assertIn(resp.status_code, (200, 403))
        if resp.status_code == 200:
            data = json.loads(resp.data)
            self.assertIn("error", data)


# ── 3. Module 2 → Module 3 context weight integration ─────────────────────────

class TestContextWeightFeedsScoring(unittest.TestCase):
    def test_high_risk_profile_changes_hybrid_score(self):
        from modules.module3_scoring.hybrid_engine import HybridEngine
        engine = HybridEngine()
        engine._llm = MagicMock()
        engine._llm.score.return_value = {
            "llm_score": 7.0, "llm_reasoning": "Mock.", "llm_available": True,
        }

        high_risk = {
            "business_type": "Healthcare", "employee_count": "1-10",
            "server_purpose": "Database", "sensitive_data": "Yes",
            "has_it_staff": "No", "budget": "Under $50",
        }
        low_risk = {
            "business_type": "Restaurant", "employee_count": "51-300",
            "server_purpose": "File Storage", "sensitive_data": "No",
            "has_it_staff": "Yes", "budget": "$200+",
        }

        vuln = FAKE_SCAN_RESULT["vulnerabilities"][0]
        high_score = engine.score(vuln, high_risk)["hybrid_score"]
        low_score  = engine.score(vuln, low_risk)["hybrid_score"]
        self.assertGreaterEqual(high_score, low_score,
            f"Healthcare/DB/sensitive ({high_score:.2f}) should ≥ restaurant ({low_score:.2f})")


if __name__ == "__main__":
    unittest.main(verbosity=2)
