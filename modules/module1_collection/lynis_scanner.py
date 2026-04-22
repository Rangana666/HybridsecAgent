"""
lynis_scanner.py — Lynis Security Audit Wrapper
Runs Lynis on the local system and parses the results into a
structured dict that the master scanner can consume.

Lynis writes two outputs:
  1. Terminal stdout  — human-readable report
  2. /var/log/lynis-report.dat — machine-readable key=value log

We prefer the .dat file when available (more reliable parsing).
Requires root: lynis audit system must run as root.
"""

import subprocess
import re
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

LYNIS_REPORT_DAT = Path("/var/log/lynis-report.dat")
LYNIS_LOG = Path("/var/log/lynis.log")
LYNIS_TIMEOUT = 300  # 5 minutes — lynis can be slow on large systems

# Map Lynis test IDs to our internal vulnerability types
# Extend this as you discover more Lynis test IDs in the wild
LYNIS_TEST_VULN_MAP = {
    "SSH-7408": "ssh_root_login_enabled",
    "SSH-7412": "ssh_password_auth_enabled",
    "SSH-7414": "ssh_empty_passwords_allowed",
    "SSH-7440": "ssh_protocol_v1",
    "AUTH-9282": "weak_password_policy",
    "AUTH-9286": "weak_password_policy",
    "FIRE-4508": "firewall_disabled",
    "FIRE-4512": "firewall_disabled",
    "HTTP-6640": "ssl_certificate_missing",
    "HTTP-6641": "ssl_certificate_expired",
    "SSL-7530": "ssl_certificate_expired",
    "FILE-7524": "suspicious_suid_file",
    "TIME-3104": "ntp_not_configured",
    "TIME-3106": "ntp_not_configured",
}


class LynisScanner:
    """Runs Lynis and parses the security audit results."""

    def run(self) -> dict:
        """
        Execute a Lynis audit and return structured results.

        Returns:
            dict with keys:
              available (bool)    — was Lynis installed and able to run?
              hardening_score (int) — 0-100 Lynis hardening index
              warnings (list)     — list of {test_id, message} dicts
              suggestions (list)  — list of {test_id, message} dicts
              mapped_vulns (list) — vulnerability types derived from Lynis warnings
              error (str|None)    — error message if something failed
        """
        result = {
            "available": False,
            "hardening_score": 0,
            "warnings": [],
            "suggestions": [],
            "mapped_vulns": [],
            "error": None,
        }

        if not self._is_installed():
            # Lynis not installed — but maybe a previous run left the .dat file
            cached = self._read_dat_score()
            if cached > 0:
                result["available"] = True
                result["hardening_score"] = cached
                result["error"] = "Lynis binary not found; score read from cached report.dat"
                logger.info("Lynis not installed but found cached score %d in report.dat", cached)
                warnings, suggestions = self._parse_report_dat()
                result["warnings"] = warnings
                result["suggestions"] = suggestions
                result["mapped_vulns"] = self._map_to_vuln_types(warnings)
            else:
                result["error"] = (
                    "Lynis is not installed. "
                    "Install with: sudo apt install lynis  (Debian/Ubuntu) "
                    "or: sudo yum install lynis  (RHEL/CentOS)"
                )
                logger.warning("Lynis not found on this system")
            return result

        result["available"] = True

        try:
            raw_output = self._run_lynis()
            result["hardening_score"] = self._extract_score(raw_output)

            if LYNIS_REPORT_DAT.exists():
                warnings, suggestions = self._parse_report_dat()
            else:
                warnings = self._extract_from_stdout(raw_output, tag="WARNING")
                suggestions = self._extract_from_stdout(raw_output, tag="SUGGESTION")

            result["warnings"] = warnings
            result["suggestions"] = suggestions
            result["mapped_vulns"] = self._map_to_vuln_types(warnings)

            logger.info(
                "Lynis scan complete — score=%d, warnings=%d, suggestions=%d",
                result["hardening_score"],
                len(warnings),
                len(suggestions),
            )

        except subprocess.TimeoutExpired:
            result["error"] = "Lynis timed out after 5 minutes"
            logger.error("Lynis scan timed out")
        except PermissionError:
            result["error"] = "Lynis requires root privileges. Run with sudo."
            logger.error("Permission denied running Lynis")
        except Exception as e:
            result["error"] = str(e)
            logger.error("Lynis scan failed: %s", e)

        return result

    # ── Private Helpers ────────────────────────────────────────

    def _is_installed(self) -> bool:
        """Check whether lynis binary exists."""
        try:
            proc = subprocess.run(
                ["which", "lynis"],
                capture_output=True,
                timeout=5,
            )
            return proc.returncode == 0
        except Exception:
            return False

    def _run_lynis(self) -> str:
        """Execute lynis audit system and return combined stdout/stderr."""
        logger.info("Running: lynis audit system --quick --no-colors")
        # Try with sudo first (service may run as non-root), fall back to plain
        for cmd in (
            ["sudo", "-n", "lynis", "audit", "system", "--quick", "--no-colors"],
            ["lynis", "audit", "system", "--quick", "--no-colors"],
        ):
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=LYNIS_TIMEOUT,
                )
                output = proc.stdout + proc.stderr
                if "Hardening index" in output or proc.returncode == 0:
                    return output
            except (subprocess.TimeoutExpired, PermissionError):
                raise
            except Exception:
                continue
        return ""

    def _extract_score(self, output: str) -> int:
        """
        Parse hardening index from lynis stdout or directly from .dat file.
        Stdout example: "  Hardening index : 42 [########            ]"
        .dat example:   "hardening_index=42"
        """
        # Try stdout first
        match = re.search(r"Hardening index\s*:\s*(\d+)", output, re.IGNORECASE)
        if match:
            score = int(match.group(1))
            logger.info("Lynis hardening index from stdout: %d", score)
            return score

        # Fall back to reading the .dat file directly
        score = self._read_dat_score()
        if score > 0:
            logger.info("Lynis hardening index from report.dat: %d", score)
            return score

        logger.warning("Could not parse Lynis hardening index from output or .dat file")
        return 0

    def _read_dat_score(self) -> int:
        """Read hardening_index directly from /var/log/lynis-report.dat without running lynis."""
        if not LYNIS_REPORT_DAT.exists():
            return 0
        try:
            for line in LYNIS_REPORT_DAT.read_text(errors="replace").splitlines():
                line = line.strip()
                if line.startswith("hardening_index="):
                    val = line.split("=", 1)[1].strip()
                    if val.isdigit():
                        return int(val)
        except Exception as e:
            logger.debug("Could not read lynis-report.dat: %s", e)
        return 0

    def _parse_report_dat(self) -> tuple[list, list]:
        """
        Parse /var/log/lynis-report.dat for warnings and suggestions.

        File format (one record per line):
          warning[]=SSH-7408|PermitRootLogin is enabled|Details here|
          suggestion[]=SSH-7408|Consider disabling SSH root login|
          hardening_index=42
        """
        warnings = []
        suggestions = []

        try:
            content = LYNIS_REPORT_DAT.read_text(errors="replace")
        except Exception as e:
            logger.warning("Could not read %s: %s", LYNIS_REPORT_DAT, e)
            return warnings, suggestions

        for line in content.splitlines():
            line = line.strip()

            if line.startswith("warning[]="):
                entry = self._parse_dat_entry(line[len("warning[]="):])
                if entry:
                    warnings.append(entry)

            elif line.startswith("suggestion[]="):
                entry = self._parse_dat_entry(line[len("suggestion[]="):])
                if entry:
                    suggestions.append(entry)

        return warnings, suggestions

    def _parse_dat_entry(self, raw: str) -> Optional[dict]:
        """
        Split a lynis .dat entry like:
          SSH-7408|PermitRootLogin is enabled|sshd_config line 32|
        into {"test_id": "SSH-7408", "message": "PermitRootLogin is enabled", "details": "..."}
        """
        parts = [p.strip() for p in raw.split("|") if p.strip()]
        if not parts:
            return None
        return {
            "test_id": parts[0] if len(parts) > 0 else "",
            "message": parts[1] if len(parts) > 1 else parts[0],
            "details": parts[2] if len(parts) > 2 else "",
        }

    def _extract_from_stdout(self, output: str, tag: str) -> list:
        """
        Fallback: pull WARNING or SUGGESTION lines straight from stdout.
        Lynis stdout lines look like:
          ! [WARNING]  SSH-7408 - PermitRootLogin is set to yes
        """
        results = []
        pattern = re.compile(
            rf"\[{tag}\]\s*([\w-]+)\s*[-–]\s*(.+)", re.IGNORECASE
        )
        for line in output.splitlines():
            m = pattern.search(line)
            if m:
                results.append({
                    "test_id": m.group(1).strip(),
                    "message": m.group(2).strip(),
                    "details": "",
                })
            elif tag in line.upper():
                # Catch any line that mentions the tag even without standard format
                clean = re.sub(r"[\[\]]", "", line).strip()
                if clean:
                    results.append({"test_id": "", "message": clean, "details": ""})
        return results

    def _map_to_vuln_types(self, warnings: list) -> list:
        """
        Convert Lynis test IDs in warnings to our internal vulnerability type strings.
        Only includes types that have a known mapping in LYNIS_TEST_VULN_MAP.
        Returns a deduplicated list of vuln type strings.
        """
        found = set()
        for w in warnings:
            test_id = w.get("test_id", "")
            if test_id in LYNIS_TEST_VULN_MAP:
                found.add(LYNIS_TEST_VULN_MAP[test_id])
        return list(found)


# ── Standalone test ────────────────────────────────────────────
if __name__ == "__main__":
    import json
    import os
    import sys
    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")

    scanner = LynisScanner()
    print("\n[LynisScanner] Running audit (requires root)...\n")
    result = scanner.run()

    if result["error"]:
        print(f"[ERROR] {result['error']}")
    else:
        print(f"  Hardening score : {result['hardening_score']}/100")
        print(f"  Warnings        : {len(result['warnings'])}")
        print(f"  Suggestions     : {len(result['suggestions'])}")
        print(f"  Mapped vulns    : {result['mapped_vulns']}")
        print("\n  First 5 warnings:")
        for w in result["warnings"][:5]:
            print(f"    [{w['test_id']}] {w['message']}")
