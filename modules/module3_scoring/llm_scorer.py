"""
llm_scorer.py — LLM Context-Aware Risk Scorer  (Module 3, Step 3 of 3)

Calls an LLM (GPT-4o-mini via OpenAI API, or a local LLaMA 3 via Ollama)
to produce a context-aware risk score and plain-English reasoning.

Weight in final hybrid score: 35%

Fallback chain:
  1. OpenAI GPT-4o-mini  (if OPENAI_API_KEY is set)
  2. Local LLaMA 3        (if USE_LOCAL_LLM=true and Ollama is running)
  3. Rule-based fallback  (returns None → combiner redistributes weights)

The prompt is designed to elicit a JSON response:
  {"score": 8.5, "reasoning": "...one or two sentences..."}
"""

import json
import logging
import re
import sys
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Project root for config import
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
import config as _cfg  # import module, not individual vars — so _apply_env() patches are visible

# ── helpers to read config values at call time (not import time) ─
def _provider()      -> str:  return (getattr(_cfg, "LLM_PROVIDER",       "openai") or "openai").lower()
def _openai_key()    -> str:  return getattr(_cfg, "OPENAI_API_KEY",       "") or ""
def _openrouter_key()-> str:  return getattr(_cfg, "OPENROUTER_API_KEY",   "") or ""
def _openrouter_model()->str:
    m = getattr(_cfg, "OPENROUTER_MODEL", "") or ""
    return m.strip() or "openai/gpt-4o-mini"   # default when .env has empty value
def _gemini_key()    -> str:  return getattr(_cfg, "GEMINI_API_KEY",       "") or ""
def _gemini_model()  -> str:  return getattr(_cfg, "GEMINI_MODEL",  "gemini-1.5-flash") or "gemini-1.5-flash"
def _use_local()     -> bool: return bool(getattr(_cfg, "USE_LOCAL_LLM",   False))
def _local_url()     -> str:  return getattr(_cfg, "LOCAL_LLM_URL",  "http://localhost:11434/api/generate") or ""
def _local_model()   -> str:  return getattr(_cfg, "LOCAL_LLM_MODEL", "llama3") or "llama3"
def _llm_model_name()-> str:  return getattr(_cfg, "LLM_MODEL_NAME",  "gpt-4o-mini") or "gpt-4o-mini"
def _max_tokens()    -> int:  return int(getattr(_cfg, "LLM_MAX_TOKENS",  500))
def _temperature()   -> float:return float(getattr(_cfg, "LLM_TEMPERATURE", 0.2))

# ── Prompt Template ────────────────────────────────────────────
_SYSTEM_PROMPT = (
    "You are a senior cybersecurity analyst specialising in risk assessment "
    "for small and medium enterprises (SMEs) in developing countries. "
    "You understand that SMEs have limited IT budgets, no dedicated security "
    "teams, and that a single breach can be catastrophic for their business."
)

_USER_PROMPT_TEMPLATE = """
Assess the risk level of the following Linux server vulnerability for this specific SME.
Consider the vulnerability severity AND the business context together.

VULNERABILITY:
  Type        : {vuln_type}
  Title       : {title}
  Description : {description}
  CVSS Score  : {cvss_score} / 10.0
  Exploit Available  : {exploit_exists}
  Patch Available    : {patch_available}

SME BUSINESS CONTEXT:
  Business Type      : {business_type}
  Employees          : {employee_count}
  Server Purpose     : {server_purpose}
  Stores Sensitive Data : {sensitive_data}
  Has Dedicated IT Staff: {has_it_staff}
  Monthly Security Budget (USD): {security_budget}

TASK:
Based on both the vulnerability severity and this SME's specific risk exposure,
assign a final risk score from 0.0 (no risk) to 10.0 (catastrophic risk).
A score above 8.5 means the business must act immediately.

Respond with ONLY a valid JSON object, no markdown, no extra text:
{{"score": <float 0.0-10.0>, "reasoning": "<1-2 sentences explaining your score>"}}
"""


class LLMScorer:
    """
    Calls an LLM to produce a context-aware risk score and reasoning.
    Gracefully falls back to None when no LLM is available.
    """

    def score(self, vuln: dict, context: dict) -> dict:
        """
        Score a vulnerability using an LLM.

        Args:
            vuln:    vulnerability dict (from Module 1)
            context: SME profile dict (from Module 2 — the full profile,
                     not just the weights)

        Returns:
            dict:
              score      (float 0-10, or None if unavailable)
              reasoning  (str explanation from the LLM)
              available  (bool)
              provider   (str: "openai" | "local_llm" | "unavailable")
              error      (str|None)
        """
        prompt = self._build_prompt(vuln, context)

        # Read provider + keys at call time (picks up _apply_env() changes without restart)
        provider = _provider()
        logger.debug("LLMScorer.score(): provider=%s openrouter_key=%s gemini_key=%s openai_key=%s",
                     provider,
                     "SET" if _openrouter_key() else "EMPTY",
                     "SET" if _gemini_key() else "EMPTY",
                     "SET" if _openai_key() else "EMPTY")

        if provider == "openrouter" and _openrouter_key():
            result = self._call_openrouter(prompt)
            if result["available"]:
                return result
            logger.warning("LLMScorer: openrouter failed (%s), trying fallbacks", result.get("error"))

        if provider == "gemini" and _gemini_key():
            result = self._call_gemini(prompt)
            if result["available"]:
                return result
            logger.warning("LLMScorer: gemini failed (%s), trying fallbacks", result.get("error"))

        if provider in ("openai", "") and _openai_key():
            result = self._call_openai(prompt)
            if result["available"]:
                return result
            logger.warning("LLMScorer: openai failed (%s), trying fallbacks", result.get("error"))

        if provider == "local" or _use_local():
            result = self._call_local_llm(prompt)
            if result["available"]:
                return result

        # Fallback: try any configured provider
        for try_fn, key in [
            (self._call_openai,      _openai_key()),
            (self._call_openrouter,  _openrouter_key()),
            (self._call_gemini,      _gemini_key()),
        ]:
            if key:
                result = try_fn(prompt)
                if result["available"]:
                    return result

        logger.info("LLMScorer: no LLM configured — set an API key in Settings → Integrations")
        return {
            "score":     None,
            "reasoning": "",
            "available": False,
            "provider":  "unavailable",
            "error":     "No LLM configured. Add an API key in Settings → Integrations.",
        }

    def is_available(self) -> bool:
        """Return True if at least one LLM backend is configured."""
        return bool(_openai_key() or _openrouter_key() or _gemini_key()) or _use_local()

    # ── Prompt Builder ─────────────────────────────────────────

    @staticmethod
    def _build_prompt(vuln: dict, context: dict) -> str:
        sensitive = context.get("sensitive_data", "No")
        has_staff = context.get("has_it_staff", "No")
        return _USER_PROMPT_TEMPLATE.format(
            vuln_type      = vuln.get("type",        "unknown"),
            title          = vuln.get("title",        vuln.get("type", "Unknown Vulnerability")),
            description    = vuln.get("description",  "No description available.")[:300],
            cvss_score     = vuln.get("cvss_score",   5.0),
            exploit_exists = "YES — active exploits exist" if vuln.get("exploit_exists") else "No",
            patch_available= "YES" if vuln.get("patch_available") else "No — no patch exists",
            business_type  = context.get("business_type",   "Unknown"),
            employee_count = context.get("employee_count",  "Unknown"),
            server_purpose = context.get("server_purpose",  "Unknown"),
            sensitive_data = "YES — customer/financial data stored" if str(sensitive).lower() in ("yes","1","true") else "No",
            has_it_staff   = "YES" if str(has_staff).lower() in ("yes","1","true") else "No — non-technical staff only",
            security_budget= context.get("security_budget", "Unknown"),
        )

    # ── OpenAI Backend ─────────────────────────────────────────

    def _call_openai(self, prompt: str) -> dict:
        try:
            from openai import OpenAI, APIConnectionError, AuthenticationError, RateLimitError

            client = OpenAI(api_key=_openai_key())
            response = client.chat.completions.create(
                model=_llm_model_name(),
                messages=[
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user",   "content": prompt},
                ],
                max_tokens=_max_tokens(),
                temperature=_temperature(),
                response_format={"type": "json_object"},
            )
            raw = response.choices[0].message.content.strip()
            return self._parse_llm_response(raw, provider="openai")

        except ImportError:
            return self._error_result("openai package not installed", "openai")
        except Exception as e:
            logger.warning("OpenAI API error: %s", e)
            return self._error_result(str(e), "openai")

    # ── OpenRouter Backend ─────────────────────────────────────

    def _call_openrouter(self, prompt: str) -> dict:
        try:
            from openai import OpenAI
            model = _openrouter_model()
            logger.debug("LLMScorer._call_openrouter(): model=%s", model)
            client = OpenAI(
                api_key=_openrouter_key(),
                base_url="https://openrouter.ai/api/v1",
            )
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user",   "content": prompt},
                ],
                max_tokens=_max_tokens(),
                temperature=_temperature(),
            )
            raw = response.choices[0].message.content.strip()
            return self._parse_llm_response(raw, provider="openrouter")
        except ImportError:
            return self._error_result("openai package not installed", "openrouter")
        except Exception as e:
            logger.warning("OpenRouter API error: %s", e)
            return self._error_result(str(e), "openrouter")

    # ── Gemini Backend ─────────────────────────────────────────

    def _call_gemini(self, prompt: str) -> dict:
        try:
            import google.generativeai as genai
            genai.configure(api_key=_gemini_key())
            model = genai.GenerativeModel(_gemini_model())
            full_prompt = f"{_SYSTEM_PROMPT}\n\n{prompt}"
            response = model.generate_content(full_prompt)
            raw = response.text.strip()
            return self._parse_llm_response(raw, provider="gemini")
        except ImportError:
            return self._error_result(
                "google-generativeai not installed. Run: pip install google-generativeai",
                "gemini",
            )
        except Exception as e:
            logger.warning("Gemini API error: %s", e)
            return self._error_result(str(e), "gemini")

    # ── Local LLaMA Backend (Ollama) ───────────────────────────

    def _call_local_llm(self, prompt: str) -> dict:
        try:
            import requests as req

            payload = {
                "model":  _local_model(),
                "prompt": f"{_SYSTEM_PROMPT}\n\n{prompt}",
                "stream": False,
                "options": {
                    "temperature": _temperature(),
                    "num_predict": _max_tokens(),
                },
            }
            resp = req.post(_local_url(), json=payload, timeout=60)
            resp.raise_for_status()
            raw = resp.json().get("response", "").strip()
            return self._parse_llm_response(raw, provider="local_llm")

        except Exception as e:
            logger.warning("Local LLM error: %s", e)
            return self._error_result(str(e), "local_llm")

    # ── Response Parser ────────────────────────────────────────

    @staticmethod
    def _parse_llm_response(raw: str, provider: str) -> dict:
        """
        Extract {"score": X, "reasoning": "..."} from the LLM response.
        Handles cases where the model wraps the JSON in markdown code fences.
        """
        # Strip markdown code fences if present
        raw = re.sub(r"```(?:json)?", "", raw).strip()

        try:
            data = json.loads(raw)
            score = float(data.get("score", 5.0))
            score = min(10.0, max(0.0, score))
            reasoning = str(data.get("reasoning", "")).strip()

            logger.debug("LLMScorer (%s): score=%.2f  reasoning=%s",
                         provider, score, reasoning[:80])
            return {
                "score":     round(score, 2),
                "reasoning": reasoning,
                "available": True,
                "provider":  provider,
                "error":     None,
            }

        except (json.JSONDecodeError, ValueError, KeyError) as e:
            # Try regex extraction as last resort
            m = re.search(r'"score"\s*:\s*([\d.]+)', raw)
            if m:
                score = min(10.0, max(0.0, float(m.group(1))))
                return {
                    "score":     round(score, 2),
                    "reasoning": raw[:200],
                    "available": True,
                    "provider":  provider,
                    "error":     None,
                }
            logger.warning("LLMScorer: could not parse response: %s", raw[:200])
            return LLMScorer._error_result(
                f"JSON parse error: {e}. Raw: {raw[:100]}", provider
            )

    @staticmethod
    def _error_result(error: str, provider: str) -> dict:
        return {
            "score":     None,
            "reasoning": "",
            "available": False,
            "provider":  provider,
            "error":     error,
        }


# ── Standalone test ────────────────────────────────────────────
if __name__ == "__main__":
    import os
    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")

    scorer = LLMScorer()

    vuln = {
        "type":          "ssh_root_login_enabled",
        "title":         "SSH Root Login Enabled",
        "description":   "The SSH server is configured to allow direct root login.",
        "cvss_score":    7.5,
        "exploit_exists": True,
        "patch_available": True,
    }
    context = {
        "business_type":  "E-commerce",
        "employee_count": "11-50",
        "server_purpose": "Database",
        "sensitive_data": "Yes",
        "has_it_staff":   "No",
        "security_budget":"Under $50",
    }

    print(f"\nLLM Available: {scorer.is_available()}")
    print(f"Provider:       {_provider()}")
    print(f"OpenAI key set: {'Yes' if _openai_key() else 'No'}")
    print(f"OpenRouter key: {'Yes' if _openrouter_key() else 'No'}  model={_openrouter_model()}")
    print(f"Gemini key set: {'Yes' if _gemini_key() else 'No'}  model={_gemini_model()}")
    print(f"Local LLM:      {_use_local()}")

    result = scorer.score(vuln, context)
    print(f"\nResult:")
    print(f"  Score     : {result['score']}")
    print(f"  Provider  : {result['provider']}")
    print(f"  Reasoning : {result['reasoning']}")
    if result["error"]:
        print(f"  Error     : {result['error']}")
