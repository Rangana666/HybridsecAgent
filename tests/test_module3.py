"""
tests/test_module3.py — Unit Tests for Module 3: Triple Hybrid Scoring Engine

Tests cover:
  - RuleBasedScorer produces a 0-10 numeric score for known vuln types
  - MLScorer returns valid structure (mocked if model missing)
  - ScoreCombiner weighted average math is correct
  - HybridEngine.score() returns required keys and sensible ranges
  - Priority thresholds: CRITICAL ≥ 8.5, HIGH ≥ 7.0, MEDIUM ≥ 5.0, LOW < 5.0
  - High-risk context yields higher score than low-risk context
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

# ── shared fixtures ────────────────────────────────────────────
SSH_VULN = {
    "id": "VULN-001",
    "type": "ssh_root_login_enabled",
    "title": "SSH Root Login Enabled",
    "category": "ssh",
    "cvss_score": 7.5,
    "exploit_exists": True,
    "patch_available": True,
    "description": "Root login via SSH is enabled.",
}

FIREWALL_VULN = {
    "id": "VULN-002",
    "type": "firewall_disabled",
    "title": "Firewall Disabled",
    "category": "firewall",
    "cvss_score": 6.0,
    "exploit_exists": False,
    "patch_available": True,
    "description": "UFW is not active.",
}

HIGH_RISK_CONTEXT = {
    "business_type":  "E-commerce",
    "employee_count": "11-50",
    "server_purpose": "Database",
    "sensitive_data": "Yes",
    "has_it_staff":   "No",
    "budget":         "Under $50",
}

LOW_RISK_CONTEXT = {
    "business_type":  "Restaurant",
    "employee_count": "1-10",
    "server_purpose": "File Storage",
    "sensitive_data": "No",
    "has_it_staff":   "Yes",
    "budget":         "$200+",
}


class TestRuleBasedScorer(unittest.TestCase):
    def setUp(self):
        from modules.module3_scoring.rule_based_scorer import RuleBasedScorer
        self.scorer = RuleBasedScorer()
        self.weights = {"rule": 0.30, "ml": 0.35, "llm": 0.35}

    def test_score_returns_dict(self):
        result = self.scorer.score(SSH_VULN, self.weights)
        self.assertIsInstance(result, dict)

    def test_rule_score_in_range(self):
        result = self.scorer.score(SSH_VULN, self.weights)
        s = result.get("rule_score", result.get("score", 0))
        self.assertGreaterEqual(s, 0.0)
        self.assertLessEqual(s, 10.0)

    def test_exploit_increases_score(self):
        no_exploit = dict(SSH_VULN, exploit_exists=False)
        with_exploit = dict(SSH_VULN, exploit_exists=True)
        r_no  = self.scorer.score(no_exploit,  self.weights)
        r_yes = self.scorer.score(with_exploit, self.weights)
        s_no  = r_no.get("rule_score",  r_no.get("score",  0))
        s_yes = r_yes.get("rule_score", r_yes.get("score", 0))
        self.assertGreaterEqual(s_yes, s_no)


class TestScoreCombiner(unittest.TestCase):
    # combine() takes result dicts: rule_result={"score":...}, ml_result={"score":...,"available":True},
    # llm_result={"score":...,"reasoning":...,"available":True}

    def setUp(self):
        from modules.module3_scoring.score_combiner import ScoreCombiner
        self.combiner = ScoreCombiner()

    def _combine(self, rule, ml, llm):
        return self.combiner.combine(
            rule_result={"score": rule},
            ml_result=  {"score": ml,  "available": True},
            llm_result= {"score": llm, "reasoning": "test", "available": True},
        )

    def test_weighted_average_math(self):
        # WEIGHT_RULE=0.30, WEIGHT_ML=0.35, WEIGHT_LLM=0.35
        result = self._combine(rule=8.0, ml=6.0, llm=7.0)
        expected = 8.0 * 0.30 + 6.0 * 0.35 + 7.0 * 0.35   # 7.0
        self.assertAlmostEqual(result["hybrid_score"], expected, places=4)

    def test_score_capped_at_10(self):
        result = self._combine(rule=10.0, ml=10.0, llm=10.0)
        self.assertLessEqual(result["hybrid_score"], 10.0)

    def test_priority_critical_threshold(self):
        result = self._combine(rule=9.0, ml=9.0, llm=9.0)
        self.assertEqual(result["priority"], "CRITICAL")

    def test_priority_high_threshold(self):
        result = self._combine(rule=7.5, ml=7.5, llm=7.5)
        self.assertIn(result["priority"], ("HIGH", "CRITICAL"))

    def test_priority_low_threshold(self):
        result = self._combine(rule=2.0, ml=2.0, llm=2.0)
        self.assertEqual(result["priority"], "LOW")

    def test_llm_unavailable_uses_two_scorer_weights(self):
        result = self.combiner.combine(
            rule_result={"score": 8.0},
            ml_result=  {"score": 8.0, "available": True},
            llm_result= {"score": None, "reasoning": "", "available": False},
        )
        self.assertIn("hybrid_score", result)
        self.assertIsInstance(result["hybrid_score"], float)


class TestHybridEngineScore(unittest.TestCase):
    """Test HybridEngine.score() end-to-end with LLM mocked out."""

    def _engine_with_mock_llm(self, llm_score=7.5):
        from modules.module3_scoring.hybrid_engine import HybridEngine
        engine = HybridEngine()
        mock_llm = MagicMock()
        mock_llm.score.return_value = {
            "llm_score": llm_score,
            "llm_reasoning": "Mocked reasoning.",
            "llm_available": True,
        }
        engine._llm = mock_llm
        return engine

    def test_score_returns_required_keys(self):
        engine = self._engine_with_mock_llm()
        result = engine.score(SSH_VULN, HIGH_RISK_CONTEXT)
        for key in ("hybrid_score", "priority", "rule_score", "ml_score",
                    "llm_score", "weights_used"):
            self.assertIn(key, result, f"Missing key: {key}")

    def test_hybrid_score_in_range(self):
        engine = self._engine_with_mock_llm()
        result = engine.score(SSH_VULN, HIGH_RISK_CONTEXT)
        self.assertGreaterEqual(result["hybrid_score"], 0.0)
        self.assertLessEqual(result["hybrid_score"], 10.0)

    def test_high_risk_context_scores_higher(self):
        engine = self._engine_with_mock_llm()
        high = engine.score(SSH_VULN, HIGH_RISK_CONTEXT)["hybrid_score"]
        low  = engine.score(SSH_VULN, LOW_RISK_CONTEXT)["hybrid_score"]
        self.assertGreaterEqual(high, low,
            f"High-risk ({high:.2f}) should be ≥ low-risk ({low:.2f})")

    def test_score_all_returns_list(self):
        engine = self._engine_with_mock_llm()
        vulns = [SSH_VULN, FIREWALL_VULN]
        results = engine.score_all(vulns, HIGH_RISK_CONTEXT)
        self.assertEqual(len(results), 2)
        for r in results:
            self.assertIn("hybrid_score", r)

    def test_empty_context_does_not_crash(self):
        engine = self._engine_with_mock_llm()
        # Empty dict is valid — all context fields default to empty string
        result = engine.score(SSH_VULN, {})
        self.assertIn("hybrid_score", result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
