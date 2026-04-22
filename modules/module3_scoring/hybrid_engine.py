"""
hybrid_engine.py — Triple Hybrid Scoring Engine  (Module 3 Master)

Orchestrates all three scorers and the combiner to produce the final
context-aware hybrid priority score for each vulnerability.

  Hybrid Score = (Rule × 0.30) + (ML × 0.35) + (LLM × 0.35)

Usage (from project root):
    python3 -m modules.module3_scoring.hybrid_engine

Input:
    vuln    — vulnerability dict from Module 1 (scanner.py output)
    context — SME profile dict from Module 2 (ContextManager.get_active_profile())

Output per vulnerability:
{
    "vuln_id":        "VULN-001",
    "vuln_type":      "ssh_root_login_enabled",
    "title":          "SSH Root Login Enabled",
    "hybrid_score":   9.12,
    "priority":       "CRITICAL",
    "priority_label": "Fix immediately — business-critical risk",
    "priority_color": "#DC3545",
    "rule_score":     8.45,
    "ml_score":       9.20,
    "llm_score":      9.50,
    "llm_reasoning":  "E-commerce with sensitive DB...",
    "weights_used":   {"rule": 0.30, "ml": 0.35, "llm": 0.35},
    "llm_available":  true,
    "context_modifier": 3.2,
    "sme_context":    { ...full profile... },
    "rule_breakdown": { ...step-by-step rule scoring... },
    "ml_predicted_class": "CRITICAL",
    "ml_probabilities": { "CRITICAL": 0.92, ... },
}
"""

import logging
import sys
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from modules.module3_scoring.rule_based_scorer import RuleBasedScorer
from modules.module3_scoring.ml_scorer         import MLScorer
from modules.module3_scoring.llm_scorer        import LLMScorer
from modules.module3_scoring.score_combiner    import ScoreCombiner


class HybridEngine:
    """
    Master orchestrator for the Triple Hybrid Scoring Engine.

    Instantiate once and call score() or score_all() repeatedly.
    All sub-scorers are initialised lazily so startup is fast.
    """

    def __init__(self):
        self._rule_scorer = RuleBasedScorer()
        self._ml_scorer   = MLScorer()
        self._llm_scorer  = LLMScorer()
        self._combiner    = ScoreCombiner()
        logger.info(
            "HybridEngine ready  |  ML=%s  LLM=%s",
            "✓" if self._ml_scorer.is_available()  else "✗ (train model first)",
            "✓" if self._llm_scorer.is_available() else "✗ (set API key in .env)",
        )

    # ── Public API ─────────────────────────────────────────────

    @staticmethod
    def _engine_flags() -> tuple[bool, bool, bool]:
        """Read engine enable/disable flags fresh from config each call."""
        try:
            import config as _cfg
            return (
                getattr(_cfg, "ENGINE_RULE_ENABLED", True),
                getattr(_cfg, "ENGINE_ML_ENABLED",   True),
                getattr(_cfg, "ENGINE_LLM_ENABLED",  True),
            )
        except Exception:
            return True, True, True

    def score(self, vuln: dict, context: dict) -> dict:
        """
        Score a single vulnerability against an SME context.

        Args:
            vuln:    One vulnerability dict from Module 1 scanner output.
                     Required keys: type, title, cvss_score, exploit_exists,
                                    patch_available, category
            context: SME profile dict from Module 2.
                     Required keys: business_type, employee_count,
                                    server_purpose, sensitive_data,
                                    has_it_staff, security_budget
                     Also accepts a profile dict returned by
                     ContextManager.get_active_profile() (has 'weights' nested).

        Returns:
            Complete scoring result dict (see module docstring).
        """
        rule_on, ml_on, llm_on = self._engine_flags()

        # Extract weights — handle both direct profile and profile-with-weights
        weights = context.get("weights") or self._compute_weights(context)

        # Run enabled scorers; substitute rule score for any disabled engine
        rule_result = self._rule_scorer.score(vuln, weights)
        ml_result   = self._ml_scorer.score(vuln, context)   if ml_on  else {"score": rule_result["score"], "available": False, "predicted_class": "", "probabilities": {}}
        llm_result  = self._llm_scorer.score(vuln, context)  if llm_on else {"score": None, "available": False, "reasoning": "LLM disabled", "provider": ""}

        # Combine into hybrid score (combiner handles None llm_score already)
        combined = self._combiner.combine(
            rule_result if rule_on else {"score": rule_result["score"]},
            ml_result,
            llm_result,
            engines_enabled=(rule_on, ml_on, llm_on),
        )

        # Build complete output
        return {
            # Vulnerability identity
            "vuln_id":          vuln.get("id",    ""),
            "vuln_type":        vuln.get("type",  ""),
            "title":            vuln.get("title", vuln.get("type", "")),
            "category":         vuln.get("category", ""),
            "cve_id":           vuln.get("cve_id", ""),

            # Combined score
            "hybrid_score":     combined["hybrid_score"],
            "priority":         combined["priority"],
            "priority_label":   combined["priority_label"],
            "priority_color":   combined["priority_color"],

            # Individual scores
            "rule_score":       combined["rule_score"],
            "ml_score":         combined["ml_score"],
            "llm_score":        combined["llm_score"],
            "llm_reasoning":    combined["llm_reasoning"],
            "llm_provider":     combined["llm_provider"],

            # Weights applied
            "weights_used":     combined["weights_used"],
            "llm_available":    combined["llm_available"],

            # Context metadata (for reports)
            "context_modifier": round(weights.get("context_modifier", 1.0), 4),
            "sme_context": {
                "business_type":  context.get("business_type",  ""),
                "employee_count": context.get("employee_count", ""),
                "server_purpose": context.get("server_purpose", ""),
                "sensitive_data": context.get("sensitive_data", ""),
                "has_it_staff":   context.get("has_it_staff",   ""),
                "security_budget":context.get("security_budget",""),
            },

            # Explainability
            "rule_breakdown":       rule_result.get("breakdown", {}),
            "ml_predicted_class":   ml_result.get("predicted_class", ""),
            "ml_probabilities":     ml_result.get("probabilities", {}),
        }

    def score_all(self, vulnerabilities: list[dict], context: dict) -> list[dict]:
        """
        Score a list of vulnerabilities, sorted by hybrid_score descending.

        Args:
            vulnerabilities: list of vuln dicts (Module 1 output)
            context:         SME profile dict (Module 2 output)

        Returns:
            List of scored result dicts, highest priority first.
        """
        if not vulnerabilities:
            return []

        logger.info(
            "Scoring %d vulnerabilities for %s...",
            len(vulnerabilities),
            context.get("business_name", context.get("business_type", "SME")),
        )

        results = []
        for vuln in vulnerabilities:
            try:
                result = self.score(vuln, context)
                results.append(result)
            except Exception as e:
                logger.error(
                    "Failed to score vuln %s: %s",
                    vuln.get("id", vuln.get("type", "?")), e,
                )

        # Sort: CRITICAL first, then by hybrid_score descending
        priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        results.sort(
            key=lambda r: (
                priority_order.get(r["priority"], 4),
                -r["hybrid_score"],
            )
        )

        summary = self._summarise(results)
        logger.info(
            "Scoring complete: CRITICAL=%d HIGH=%d MEDIUM=%d LOW=%d",
            summary["critical"], summary["high"],
            summary["medium"],   summary["low"],
        )
        return results

    def get_summary(self, scored_results: list[dict]) -> dict:
        """Return a count summary dict from a list of score results."""
        return self._summarise(scored_results)

    # ── Private Helpers ────────────────────────────────────────

    @staticmethod
    def _compute_weights(context: dict) -> dict:
        """
        Compute weights on the fly when a context dict without pre-computed
        weights is passed. Mirrors ContextManager.compute_weights() logic.
        """
        from config import (
            BUSINESS_TYPE_MULTIPLIERS, EMPLOYEE_COUNT_ADDITIONS,
            SERVER_PURPOSE_ADDITIONS, SENSITIVE_DATA_ADDITION,
            IT_STAFF_ADDITION, BUDGET_ADDITION,
        )
        bm = BUSINESS_TYPE_MULTIPLIERS.get(context.get("business_type", "Other"), 1.0)
        ta = (
            EMPLOYEE_COUNT_ADDITIONS.get(context.get("employee_count",   "1-10"),        0.3)
            + SERVER_PURPOSE_ADDITIONS.get(context.get("server_purpose",  "File Storage"), 0.0)
            + SENSITIVE_DATA_ADDITION.get(context.get("sensitive_data",   "No"),           0.0)
            + IT_STAFF_ADDITION.get(context.get("has_it_staff",           "No"),           0.3)
            + BUDGET_ADDITION.get(context.get("security_budget",          "Under $50"),    0.2)
        )
        return {
            "business_multiplier": bm,
            "total_addition":      round(ta, 2),
            "context_modifier":    round(bm + ta, 2),
        }

    @staticmethod
    def _summarise(results: list[dict]) -> dict:
        s = {"total": len(results), "critical": 0, "high": 0, "medium": 0, "low": 0}
        for r in results:
            p = r.get("priority", "LOW").lower()
            if p in s:
                s[p] += 1
        return s


# ── Standalone entry point ─────────────────────────────────────
if __name__ == "__main__":
    import json, argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%H:%M:%S",
    )

    # Example vulnerability and SME context (from the README)
    vuln_example = {
        "id":              "VULN-001",
        "type":            "ssh_root_login_enabled",
        "title":           "SSH Root Login Enabled",
        "description":     "The SSH server permits direct root login.",
        "category":        "ssh",
        "cvss_score":      7.5,
        "exploit_exists":  True,
        "patch_available": True,
    }

    context_example = {
        "business_name":  "Colombo E-Shop",
        "business_type":  "E-commerce",
        "employee_count": "11-50",
        "server_purpose": "Database",
        "sensitive_data": "Yes",
        "has_it_staff":   "No",
        "security_budget":"Under $50",
    }

    engine = HybridEngine()
    result = engine.score(vuln_example, context_example)

    print("\n" + "=" * 60)
    print("  TRIPLE HYBRID SCORING RESULT")
    print("=" * 60)
    print(f"  Vulnerability : {result['title']}")
    print(f"  SME Context   : {context_example['business_type']} | "
          f"{context_example['employee_count']} employees | "
          f"{context_example['server_purpose']}")
    print(f"  Context Modifier: {result['context_modifier']}")
    print()
    print(f"  Rule Score    : {result['rule_score']:.2f}  (weight {result['weights_used']['rule']:.0%})")
    print(f"  ML Score      : {result['ml_score']:.2f}  (weight {result['weights_used']['ml']:.0%})")
    if result["llm_score"] is not None:
        print(f"  LLM Score     : {result['llm_score']:.2f}  (weight {result['weights_used']['llm']:.0%})")
        print(f"  LLM Reasoning : {result['llm_reasoning']}")
    else:
        print(f"  LLM Score     : N/A  (LLM not configured — weights redistributed)")
    print()
    print(f"  ─────────────────────────────────────────────────")
    colour = result['priority_color']
    print(f"  HYBRID SCORE  : {result['hybrid_score']:.2f} / 10.0")
    print(f"  PRIORITY      : {result['priority']}  — {result['priority_label']}")
    print(f"  ─────────────────────────────────────────────────")

    # Score multiple vulnerabilities
    print("\n" + "=" * 60)
    print("  SCORING MULTIPLE VULNERABILITIES")
    print("=" * 60)

    vulns = [
        {"id": "VULN-001", "type": "ssh_root_login_enabled",   "title": "SSH Root Login",
         "category": "ssh",      "cvss_score": 7.5, "exploit_exists": True,  "patch_available": True},
        {"id": "VULN-002", "type": "firewall_disabled",         "title": "Firewall Disabled",
         "category": "firewall", "cvss_score": 7.5, "exploit_exists": False, "patch_available": True},
        {"id": "VULN-003", "type": "ntp_not_configured",        "title": "NTP Not Configured",
         "category": "system",   "cvss_score": 3.0, "exploit_exists": False, "patch_available": True},
        {"id": "VULN-004", "type": "mysql_public_port",         "title": "MySQL Port Exposed",
         "category": "database", "cvss_score": 8.0, "exploit_exists": True,  "patch_available": True},
        {"id": "VULN-005", "type": "ssl_certificate_expiring_soon", "title": "SSL Expiring",
         "category": "ssl",      "cvss_score": 3.0, "exploit_exists": False, "patch_available": True},
    ]

    all_results = engine.score_all(vulns, context_example)
    for r in all_results:
        lbl = r["priority"]
        print(f"  {r['vuln_id']}  {lbl:8s}  {r['hybrid_score']:.2f}  {r['title']}")

    summary = engine.get_summary(all_results)
    print(f"\n  Summary: {summary['total']} total | "
          f"CRITICAL={summary['critical']} HIGH={summary['high']} "
          f"MEDIUM={summary['medium']} LOW={summary['low']}")
    print()
