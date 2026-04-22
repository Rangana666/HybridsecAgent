"""
rule_based_scorer.py — Rule-Based Risk Scorer  (Module 3, Step 1 of 3)

Implements CIS Benchmark-inspired scoring rules.
Weight in final hybrid score: 30%

Inputs:
  vuln   — vulnerability dict (from Module 1 scanner output)
  weights — context weights dict (from Module 2 ContextManager.compute_weights())

Output:
  float in [0.0 – 10.0]

Scoring pipeline:
  1. Start with CVSS base score
  2. Add exploit urgency bonus
  3. Add no-patch penalty
  4. Apply CIS category multiplier
  5. Apply SME context amplification (bounded)
  6. Clamp to [0, 10]
"""

import logging

logger = logging.getLogger(__name__)

# ── CIS Benchmark Category Weights ────────────────────────────
# Reflects CIS Control priorities for SME environments.
# Categories with direct remote exploitation potential score higher.
CIS_CATEGORY_WEIGHTS = {
    "users":            1.20,   # CIS Control 5: Account Management
    "ssh":              1.15,   # CIS Control 4: Secure Configuration
    "database":         1.15,   # CIS Control 3: Data Protection
    "firewall":         1.10,   # CIS Control 12: Network Infrastructure
    "network":          1.08,   # CIS Control 9: Email/Web Protections
    "software":         1.05,   # CIS Control 2: Software Asset Management
    "intrusion":        1.00,   # CIS Control 17: Incident Response
    "ssl":              0.95,   # CIS Control 14: Controlled Access
    "file_permissions": 0.95,   # CIS Control 3: Data Protection
    "hardening":        0.88,   # CIS Control 4: Secure Configuration
    "system":           0.80,   # CIS Control 1: Hardware Asset Management
}

# Exploit bonus: known exploits increase urgency significantly
EXPLOIT_BONUS = 1.5

# No-patch penalty: unfixable vulns sustain higher risk
NO_PATCH_PENALTY = 0.5

# Max context amplification: context can increase score by at most 25%
MAX_CONTEXT_AMPLIFICATION = 0.25

# Sensitivity of context amplification (lower = softer effect)
CONTEXT_SENSITIVITY = 0.075


class RuleBasedScorer:
    """
    Scores a single vulnerability using CIS Benchmark-derived rules
    combined with the SME business context weights from Module 2.
    """

    def score(self, vuln: dict, weights: dict) -> dict:
        """
        Score a vulnerability.

        Args:
            vuln:    vulnerability dict. Must contain at minimum:
                       cvss_score (float 0-10)
                       exploit_exists (bool)
                       patch_available (bool)
                       category (str)
            weights: output of ContextManager.compute_weights()
                       context_modifier (float)

        Returns:
            dict:
              score         (float 0-10)
              breakdown     (dict with each step's contribution)
        """
        cvss            = float(vuln.get("cvss_score", 5.0))
        exploit_exists  = bool(vuln.get("exploit_exists", False))
        patch_available = bool(vuln.get("patch_available", True))
        category        = vuln.get("category", "unknown")
        context_modifier = float(weights.get("context_modifier", 1.0))

        # ── Step 1: Base score from CVSS ─────────────────────
        score = cvss
        base = score

        # ── Step 2: Exploit urgency bonus ────────────────────
        exploit_adj = 0.0
        if exploit_exists:
            exploit_adj = EXPLOIT_BONUS
            score = min(10.0, score + exploit_adj)

        # ── Step 3: No-patch sustained-risk penalty ───────────
        patch_adj = 0.0
        if not patch_available:
            patch_adj = NO_PATCH_PENALTY
            score = min(10.0, score + patch_adj)

        # ── Step 4: CIS category multiplier ──────────────────
        cat_weight = CIS_CATEGORY_WEIGHTS.get(category, 1.0)
        pre_category = score
        score = min(10.0, score * cat_weight)
        category_adj = round(score - pre_category, 4)

        # ── Step 5: SME context amplification ────────────────
        # context_modifier ∈ [1.0, ~4.5]
        # Map to a small amplification factor in [1.0, 1.25]
        amplification = 1.0 + min(
            MAX_CONTEXT_AMPLIFICATION,
            (context_modifier - 1.0) * CONTEXT_SENSITIVITY
        )
        pre_context = score
        score = min(10.0, score * amplification)
        context_adj = round(score - pre_context, 4)

        # ── Step 6: Final clamp ───────────────────────────────
        final_score = round(min(10.0, max(0.0, score)), 4)

        breakdown = {
            "base_cvss":          round(base, 4),
            "exploit_bonus":      round(exploit_adj, 4),
            "no_patch_penalty":   round(patch_adj, 4),
            "category_weight":    round(cat_weight, 4),
            "category_adjustment":round(category_adj, 4),
            "context_modifier":   round(context_modifier, 4),
            "context_amplification": round(amplification, 4),
            "context_adjustment": round(context_adj, 4),
        }

        logger.debug(
            "RuleBasedScorer: type=%s cvss=%.1f exploit=%s patch=%s "
            "category=%s ctx_mod=%.2f → score=%.4f",
            vuln.get("type", "?"), cvss, exploit_exists, patch_available,
            category, context_modifier, final_score,
        )

        return {"score": final_score, "breakdown": breakdown}


# ── Standalone test ────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s  %(message)s")
    scorer = RuleBasedScorer()

    test_cases = [
        # (description, vuln_dict, weights_dict)
        (
            "SSH root login — E-commerce, no IT, sensitive DB",
            {"type": "ssh_root_login_enabled", "cvss_score": 7.5,
             "exploit_exists": True, "patch_available": True, "category": "ssh"},
            {"context_modifier": 3.2},
        ),
        (
            "NTP not configured — Restaurant, no sensitive data",
            {"type": "ntp_not_configured", "cvss_score": 3.0,
             "exploit_exists": False, "patch_available": True, "category": "system"},
            {"context_modifier": 1.5},
        ),
        (
            "MySQL public port — Finance, no IT staff",
            {"type": "mysql_public_port", "cvss_score": 8.0,
             "exploit_exists": True, "patch_available": True, "category": "database"},
            {"context_modifier": 3.8},
        ),
        (
            "Disk usage critical — IT Services, large team",
            {"type": "disk_usage_critical", "cvss_score": 4.0,
             "exploit_exists": False, "patch_available": False, "category": "system"},
            {"context_modifier": 1.4},
        ),
    ]

    print("\n" + "=" * 60)
    print("  Rule-Based Scorer Test Cases")
    print("=" * 60)
    for desc, vuln, weights in test_cases:
        result = scorer.score(vuln, weights)
        s = result["score"]
        b = result["breakdown"]
        label = ("CRITICAL" if s >= 8.5 else "HIGH" if s >= 7.0
                 else "MEDIUM" if s >= 5.0 else "LOW")
        print(f"\n  {desc}")
        print(f"    Score: {s:.2f}  →  {label}")
        print(f"    CVSS={b['base_cvss']}  +exploit={b['exploit_bonus']}  "
              f"+nopatch={b['no_patch_penalty']}  "
              f"×cat={b['category_weight']}  ×ctx={b['context_amplification']:.3f}")
