"""
score_combiner.py — Weighted Score Combiner  (Module 3, Final Step)

Takes the three individual scorer outputs and combines them into a single
hybrid score using the weights defined in the README and config.py.

  Hybrid Score = (Rule × 0.30) + (ML × 0.35) + (LLM × 0.35)

When the LLM scorer is unavailable, weights are redistributed:
  Hybrid Score = (Rule × 0.50) + (ML × 0.50)

Priority classification:
  8.5 – 10.0  →  CRITICAL  (fix immediately)
  7.0 –  8.4  →  HIGH      (fix within 24 hours)
  5.0 –  6.9  →  MEDIUM    (fix this week)
  0.0 –  4.9  →  LOW       (fix this month)
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Nominal weights (when all 3 scorers are available)
WEIGHT_RULE = 0.30
WEIGHT_ML   = 0.35
WEIGHT_LLM  = 0.35

# Fallback weights when LLM is unavailable
WEIGHT_RULE_NO_LLM = 0.50
WEIGHT_ML_NO_LLM   = 0.50

# Priority thresholds (mirrors config.py)
PRIORITY_THRESHOLDS = [
    (8.5, "CRITICAL", "Fix immediately — business-critical risk",    "#DC3545"),
    (7.0, "HIGH",     "Fix within 24 hours",                         "#FD7E14"),
    (5.0, "MEDIUM",   "Fix this week",                               "#FFC107"),
    (0.0, "LOW",      "Fix this month",                              "#28A745"),
]


class ScoreCombiner:
    """
    Combines rule-based, ML, and LLM scores into a single hybrid score
    and classifies the result into a priority label.
    """

    def combine(
        self,
        rule_result: dict,
        ml_result:   dict,
        llm_result:  dict,
        engines_enabled: tuple = (True, True, True),
    ) -> dict:
        """
        Combine the three scorer outputs.

        Args:
            rule_result: output of RuleBasedScorer.score()
            ml_result:   output of MLScorer.score()
            llm_result:  output of LLMScorer.score()

        Returns:
            dict:
              hybrid_score   (float 0-10)
              priority        (str: CRITICAL / HIGH / MEDIUM / LOW)
              priority_label  (str: human-readable action)
              priority_color  (str: hex colour for the web UI)
              rule_score      (float)
              ml_score        (float)
              llm_score       (float|None)
              llm_reasoning   (str)
              weights_used    (dict)
              llm_available   (bool)
        """
        rule_on, ml_on, llm_on = engines_enabled
        rule_score = rule_result.get("score", 5.0)
        ml_score   = ml_result.get("score")
        llm_score  = llm_result.get("score")
        llm_avail  = llm_result.get("available", False) and llm_on

        # ── Handle unavailable ML ──────────────────────────────────────
        if ml_score is None:
            ml_score = rule_score

        # ── Dynamic weight redistribution based on enabled engines ─────
        # Nominal weights: rule=0.30, ml=0.35, llm=0.35
        # Disabled engines have their weight distributed proportionally
        use_llm  = llm_on and llm_avail and llm_score is not None
        use_ml   = ml_on
        use_rule = rule_on

        # Assign base weights only for active engines then normalise
        raw = {
            "rule": WEIGHT_RULE if use_rule else 0.0,
            "ml":   WEIGHT_ML   if use_ml   else 0.0,
            "llm":  WEIGHT_LLM  if use_llm  else 0.0,
        }
        total_w = sum(raw.values()) or 1.0   # avoid division by zero
        w = {k: v / total_w for k, v in raw.items()}

        # At least one engine must contribute — fall back to rule if all off
        if total_w == 0.0:
            use_rule, w = True, {"rule": 1.0, "ml": 0.0, "llm": 0.0}

        hybrid = (
            (rule_score * w["rule"] if use_rule else 0.0)
            + (ml_score  * w["ml"]   if use_ml   else 0.0)
            + (llm_score * w["llm"]  if use_llm  else 0.0)
        )
        weights_used = {"rule": round(w["rule"], 4), "ml": round(w["ml"], 4), "llm": round(w["llm"], 4)}

        logger.info(
            "Weights: rule=%.0f%% ml=%.0f%% llm=%.0f%% (enabled: rule=%s ml=%s llm=%s)",
            w["rule"]*100, w["ml"]*100, w["llm"]*100, use_rule, use_ml, use_llm,
        )

        hybrid_score = round(min(10.0, max(0.0, hybrid)), 4)
        priority, label, colour = self._classify(hybrid_score)

        logger.info(
            "ScoreCombiner: rule=%.2f ml=%.2f llm=%s → hybrid=%.4f [%s]",
            rule_score,
            ml_score,
            f"{llm_score:.2f}" if llm_score is not None else "N/A",
            hybrid_score,
            priority,
        )

        return {
            "hybrid_score":   hybrid_score,
            "priority":       priority,
            "priority_label": label,
            "priority_color": colour,
            "rule_score":     round(rule_score, 4),
            "ml_score":       round(ml_score, 4),
            "llm_score":      round(llm_score, 4) if llm_score is not None else None,
            "llm_reasoning":  llm_result.get("reasoning", ""),
            "llm_provider":   llm_result.get("provider", "unavailable"),
            "weights_used":   weights_used,
            "llm_available":  llm_avail,
        }

    @staticmethod
    def _classify(score: float) -> tuple[str, str, str]:
        """Map a 0-10 score to (priority_key, human_label, hex_colour)."""
        for threshold, key, label, colour in PRIORITY_THRESHOLDS:
            if score >= threshold:
                return key, label, colour
        return "LOW", "Fix this month", "#28A745"


# ── Standalone test ────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")

    combiner = ScoreCombiner()

    print("\n" + "=" * 55)
    print("  ScoreCombiner Test Cases")
    print("=" * 55)

    # Test 1: All three scorers available
    result = combiner.combine(
        rule_result={"score": 8.2},
        ml_result=  {"score": 7.9, "available": True},
        llm_result= {"score": 8.5, "reasoning": "E-commerce with sensitive DB, no IT.", "available": True},
    )
    print(f"\n  [All 3 available] hybrid={result['hybrid_score']}  priority={result['priority']}")
    print(f"    rule×{result['weights_used']['rule']} + ml×{result['weights_used']['ml']} + llm×{result['weights_used']['llm']}")
    assert result["priority"] == "CRITICAL", f"Expected CRITICAL, got {result['priority']}"

    # Test 2: LLM unavailable
    result2 = combiner.combine(
        rule_result={"score": 6.5},
        ml_result=  {"score": 6.0, "available": True},
        llm_result= {"score": None, "reasoning": "", "available": False, "provider": "unavailable"},
    )
    print(f"\n  [No LLM] hybrid={result2['hybrid_score']}  priority={result2['priority']}")
    assert result2["weights_used"]["llm"] == 0.0
    assert result2["priority"] in ("MEDIUM", "HIGH")

    # Test 3: Low-risk scenario
    result3 = combiner.combine(
        rule_result={"score": 2.5},
        ml_result=  {"score": 3.0, "available": True},
        llm_result= {"score": 2.0, "reasoning": "Low risk for this SME.", "available": True},
    )
    print(f"\n  [Low risk] hybrid={result3['hybrid_score']}  priority={result3['priority']}")
    assert result3["priority"] == "LOW"

    print("\nAll ScoreCombiner tests PASSED.")
