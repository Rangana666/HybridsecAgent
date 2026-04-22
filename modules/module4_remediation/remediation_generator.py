"""
remediation_generator.py — Remediation Advice Generator  (Module 4)

For each scored vulnerability this module produces a complete
RemediationResult containing:
  - Manual step-by-step instructions (always available)
  - Auto-fix availability flag + commands (for supported types)
  - LLM-generated explanation for types without a template
  - Estimated effort and risk level

The web UI (Module 5) calls get_remediation() for each vulnerability
on the Remediation page and uses the result to render fix cards and
the "AUTO-FIX" button.
"""

import logging
import sys
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# Import all fix template modules
from modules.module4_remediation.fix_templates import ssh_fixes
from modules.module4_remediation.fix_templates import firewall_fixes
from modules.module4_remediation.fix_templates import apache_fixes
from modules.module4_remediation.fix_templates import mysql_fixes
from modules.module4_remediation.fix_templates import password_fixes

# Registry: maps vuln_type → fix-getter function
_FIX_REGISTRY: dict[str, callable] = {}
for _module in (ssh_fixes, firewall_fixes, apache_fixes, mysql_fixes, password_fixes):
    for _vtype in _module.list_supported_types():
        _FIX_REGISTRY[_vtype] = _module.get_fix

# Fallback manual instructions for types without a template
_GENERIC_STEPS: dict[str, list[str]] = {
    "suspicious_suid_file": [
        "1. List all SUID files:  find / -perm -4000 -type f 2>/dev/null",
        "2. For each unexpected file, check its purpose and owner.",
        "3. Remove SUID bit if not needed:  sudo chmod u-s /path/to/file",
        "4. If the file is malicious, remove it and investigate the breach.",
    ],
    "lynis_low_hardening_score": [
        "1. Run Lynis for a detailed report:  sudo lynis audit system",
        "2. Review the WARNING lines first — these have the highest impact.",
        "3. Apply each suggested fix one at a time and re-run Lynis.",
        "4. Target score: 70+ (good), 85+ (excellent).",
    ],
    "disk_usage_critical": [
        "1. Find large files:  sudo du -sh /* 2>/dev/null | sort -rh | head -20",
        "2. Check log files:   sudo du -sh /var/log/*",
        "3. Remove old logs:   sudo journalctl --vacuum-size=500M",
        "4. Clean apt cache:   sudo apt clean",
        "5. Remove unused packages: sudo apt autoremove",
    ],
    "ntp_not_configured": [
        "1. Install NTP:          sudo apt install ntp",
        "2. Enable and start:     sudo systemctl enable --now ntp",
        "3. Check sync status:    timedatectl status",
        "   (NTP synchronized: yes)",
        "4. Alternative (systemd-timesyncd):",
        "   sudo timedatectl set-ntp true",
    ],
    "ssl_certificate_expiring_soon": [
        "1. Check certificate expiry:  sudo certbot certificates",
        "2. Renew now (Certbot):       sudo certbot renew",
        "3. Verify renewal:            sudo certbot certificates",
        "4. Set up auto-renewal cron:  0 12 * * * /usr/bin/certbot renew --quiet",
    ],
    "high_failed_login_count": [
        "1. Check current attackers:   sudo grep 'Failed password' /var/log/auth.log | awk '{print $11}' | sort | uniq -c | sort -rn | head -10",
        "2. Block top attacker IPs:    sudo ufw deny from <IP> to any",
        "3. Install fail2ban:          sudo apt install fail2ban",
        "4. Check fail2ban status:     sudo fail2ban-client status sshd",
    ],
}


class RemediationGenerator:
    """
    Generates complete remediation advice for a vulnerability.
    Uses templates when available; falls back to generic steps or LLM.
    """

    def __init__(self, use_llm: bool = True):
        """
        Args:
            use_llm: if True, call LLM for types without a template.
                     Set to False to stay offline (uses generic steps only).
        """
        self._use_llm = use_llm

    # ── Public API ─────────────────────────────────────────────

    def get_remediation(self, vuln: dict, context: Optional[dict] = None) -> dict:
        """
        Generate a full remediation result for one vulnerability.

        Args:
            vuln:    vulnerability dict (from Module 1 / Module 3 output).
                     Required: type, title, description, cvss_score
            context: SME profile dict from Module 2 (optional — used for LLM prompt)

        Returns:
            RemediationResult dict (see _build_result docstring).
        """
        # Support both raw scanner format ("type") and scored format ("vuln_type")
        vuln_type = vuln.get("type", "") or vuln.get("vuln_type", "")
        fix_getter = _FIX_REGISTRY.get(vuln_type)

        if fix_getter:
            template = fix_getter(vuln_type)
            if template is not None:
                return self._build_result(vuln, template, source="template")
            # template returned None — fall through to generic/fallback

        # No template — try generic steps first
        generic_steps = _GENERIC_STEPS.get(vuln_type)
        if generic_steps:
            return self._build_result(
                vuln,
                template={
                    "title":            f"Fix: {vuln.get('title', vuln_type)}",
                    "description":      vuln.get("description", ""),
                    "autofix_available": False,
                    "risk_level":       "medium",
                    "config_file":      None,
                    "service_to_restart": None,
                    "commands":         [],
                    "verify_command":   None,
                    "verify_expected":  None,
                    "manual_steps":     generic_steps,
                    "estimated_time":   "Varies",
                    "requires_root":    True,
                    "rollback_note":    "Manual rollback only.",
                },
                source="generic",
            )

        # Unknown type — try LLM
        if self._use_llm:
            llm_steps = self._generate_llm_steps(vuln, context)
            if llm_steps:
                return self._build_result(
                    vuln,
                    template={
                        "title":            f"Fix: {vuln.get('title', vuln_type)}",
                        "description":      vuln.get("description", ""),
                        "autofix_available": False,
                        "risk_level":       "medium",
                        "config_file":      None,
                        "service_to_restart": None,
                        "commands":         [],
                        "verify_command":   None,
                        "verify_expected":  None,
                        "manual_steps":     llm_steps,
                        "estimated_time":   "Varies",
                        "requires_root":    True,
                        "rollback_note":    "Manual rollback only.",
                    },
                    source="llm",
                )

        # Last resort — generic fallback
        return self._build_result(
            vuln,
            template={
                "title":            f"Manual Review Required: {vuln.get('title', vuln_type)}",
                "description":      vuln.get("description", ""),
                "autofix_available": False,
                "risk_level":       "unknown",
                "config_file":      None,
                "service_to_restart": None,
                "commands":         [],
                "verify_command":   None,
                "verify_expected":  None,
                "manual_steps": [
                    "1. Research this vulnerability type: " + vuln_type,
                    "2. Search for CIS Benchmark guidance for your Linux distribution.",
                    "3. Apply the recommended fix from your OS vendor.",
                    "4. Document the change in your security log.",
                ],
                "estimated_time":   "Unknown",
                "requires_root":    True,
                "rollback_note":    "Manual rollback only.",
            },
            source="fallback",
        )

    def get_all_remediations(
        self, vulnerabilities: list[dict], context: Optional[dict] = None
    ) -> list[dict]:
        """
        Generate remediation results for a list of vulnerabilities,
        sorted by autofix_available (auto-fixable first) then by cvss_score.
        """
        results = []
        for vuln in vulnerabilities:
            try:
                results.append(self.get_remediation(vuln, context))
            except Exception as e:
                logger.error("Remediation generation failed for %s: %s",
                             vuln.get("type"), e)
        results.sort(
            key=lambda r: (
                0 if r["autofix_available"] else 1,
                -r.get("cvss_score", 0),
            )
        )
        return results

    @staticmethod
    def list_supported_types() -> list[str]:
        """Return all vuln types that have an explicit fix template."""
        return sorted(_FIX_REGISTRY.keys())

    # ── Private Helpers ────────────────────────────────────────

    @staticmethod
    def _build_result(vuln: dict, template: dict, source: str) -> dict:
        """
        Merge vulnerability metadata with fix template into a
        single RemediationResult dict.

        Keys:
          vuln_type, vuln_id, title, description, cvss_score
          autofix_available, risk_level, config_file, service_to_restart
          commands, verify_command, verify_expected
          manual_steps, estimated_time, requires_root, rollback_note
          source  ("template" | "generic" | "llm" | "fallback")
        """
        return {
            # Vulnerability identity — support both raw ("type") and scored ("vuln_type") formats
            "vuln_type":           vuln.get("type", "") or vuln.get("vuln_type", ""),
            "vuln_id":             vuln.get("id",   "") or vuln.get("vuln_id",   ""),
            "cvss_score":          vuln.get("cvss_score", 0.0) or vuln.get("hybrid_score", 0.0),
            "priority":            vuln.get("priority", ""),

            # Fix metadata from template
            "title":               template.get("title", ""),
            "description":         template.get("description", ""),
            "autofix_available":   template.get("autofix_available", False),
            "risk_level":          template.get("risk_level", "unknown"),
            "config_file":         template.get("config_file"),
            "service_to_restart":  template.get("service_to_restart"),

            # Execution
            "commands":            template.get("commands", []),
            "verify_command":      template.get("verify_command"),
            "verify_expected":     template.get("verify_expected"),

            # Human-readable
            "manual_steps":        template.get("manual_steps", []),
            "estimated_time":      template.get("estimated_time", "Unknown"),
            "requires_root":       template.get("requires_root", True),
            "rollback_note":       template.get("rollback_note", ""),

            # Traceability
            "source":              source,
        }

    def _generate_llm_steps(
        self, vuln: dict, context: Optional[dict]
    ) -> Optional[list[str]]:
        """
        Ask the LLM for remediation steps for an unknown vulnerability type.
        Returns a list of step strings, or None on failure.
        """
        try:
            import config as _cfg
        except ImportError:
            return None

        _openai = getattr(_cfg, "OPENAI_API_KEY", "") or ""
        _local  = getattr(_cfg, "USE_LOCAL_LLM", False)
        if not _openai and not _local:
            return None

        prompt = (
            f"Provide a numbered step-by-step remediation guide for this "
            f"Linux server vulnerability:\n\n"
            f"Vulnerability: {vuln.get('title', vuln.get('type', 'Unknown'))}\n"
            f"CVSS Score:    {vuln.get('cvss_score', 'N/A')}\n"
            f"Description:   {vuln.get('description', 'N/A')[:300]}\n"
        )
        if context:
            prompt += (
                f"\nSME Context: {context.get('business_type')} business, "
                f"{context.get('employee_count')} employees, "
                f"{'has' if context.get('has_it_staff') == 'Yes' else 'no'} IT staff."
            )
        prompt += (
            "\n\nProvide ONLY the numbered steps (no introduction, no conclusion). "
            "Keep each step concise and actionable for a non-technical admin."
        )

        try:
            from openai import OpenAI
            client = OpenAI(api_key=_openai)
            resp = client.chat.completions.create(
                model=getattr(_cfg, "LLM_MODEL_NAME", "gpt-4o-mini") or "gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=400,
                temperature=0.2,
            )
            raw = resp.choices[0].message.content.strip()
            steps = [line.strip() for line in raw.splitlines() if line.strip()]
            return steps if steps else None
        except Exception as e:
            logger.warning("LLM remediation generation failed: %s", e)
            return None


# ── Standalone test ────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
    gen = RemediationGenerator(use_llm=False)

    test_vulns = [
        {"id": "VULN-001", "type": "ssh_root_login_enabled",
         "title": "SSH Root Login Enabled", "cvss_score": 7.5, "priority": "CRITICAL"},
        {"id": "VULN-002", "type": "firewall_disabled",
         "title": "Firewall Disabled", "cvss_score": 7.5, "priority": "CRITICAL"},
        {"id": "VULN-003", "type": "disk_usage_critical",
         "title": "Disk Critical", "cvss_score": 4.0, "priority": "MEDIUM"},
        {"id": "VULN-004", "type": "unknown_vuln_xyz",
         "title": "Unknown Vuln", "cvss_score": 5.0, "priority": "MEDIUM"},
    ]

    print(f"\nSupported auto-fix types: {len(gen.list_supported_types())}")
    print("=" * 60)

    for vuln in test_vulns:
        r = gen.get_remediation(vuln)
        auto = "✅ AUTO-FIX" if r["autofix_available"] else "📋 MANUAL"
        print(f"\n  [{r['vuln_type']}]")
        print(f"    {auto}  |  source={r['source']}  |  risk={r['risk_level']}")
        print(f"    Steps: {len(r['manual_steps'])}")
        if r["autofix_available"]:
            print(f"    Commands: {len(r['commands'])}")
            print(f"    Backup: {r['config_file']}")
        print(f"    First step: {r['manual_steps'][0] if r['manual_steps'] else 'N/A'}")
