"""
scanner.py — Master Data Collection Orchestrator  (Module 1)
Coordinates all sub-scanners and assembles the final scan result
in the standard HybridSec JSON format consumed by Module 3 (scoring).

Usage:
    python3 -m modules.module1_collection.scanner

Output format:
{
    "scan_id":    "scan_20250417_093000",
    "scan_type":  "deep" | "quick",
    "timestamp":  "2025-04-17T09:30:00",
    "server_info": { "os", "hostname", "ip", "cloud" },
    "lynis_score": 42,
    "vulnerabilities": [
        {
            "id":                "VULN-001",
            "type":              "ssh_root_login_enabled",
            "title":             "SSH Root Login Enabled",
            "description":       "...",
            "category":          "ssh",
            "cvss_score":        7.5,
            "exploit_exists":    true,
            "patch_available":   true,
            "cve_id":            "CVE-...",    <- added by NVD enrichment
            "evidence":          "PermitRootLogin yes in sshd_config",
            "affected_component":"sshd",
            "detected_by":       "system_scanner",
        },
        ...
    ],
    "scan_summary": {
        "total":    12,
        "critical": 2,
        "high":     4,
        "medium":   4,
        "low":      2,
    }
}
"""

import json
import logging
import platform
import socket
import subprocess
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from .lynis_scanner import LynisScanner
from .nmap_scanner import NmapScanner
from .system_scanner import SystemScanner
from .nvd_api import NVDClient

logger = logging.getLogger(__name__)

RULES_FILE = Path(__file__).parent.parent.parent / "data" / "rules" / "security_rules.json"

# CVE keywords to search for each vulnerability type (used for NVD enrichment)
VULN_CVE_KEYWORDS = {
    "ssh_root_login_enabled":    "openssh root login",
    "ssh_password_auth_enabled": "openssh brute force",
    "ssh_protocol_v1":           "ssh protocol 1 vulnerability",
    "firewall_disabled":         None,   # No CVE for a missing firewall
    "mysql_public_port":         "mysql remote access unauthenticated",
    "apache_outdated":           "apache httpd vulnerability",
    "nginx_outdated":            "nginx vulnerability",
    "user_empty_password":       None,
    "suspicious_suid_file":      None,
    "ssl_certificate_expired":   None,
}


class Scanner:
    """
    Master scanner that orchestrates all Module 1 sub-scanners.
    Produces a standardised scan result dict.
    """

    def __init__(self, target: str = "127.0.0.1", enrich_nvd: bool = True):
        """
        Args:
            target:     IP or hostname to scan with Nmap (default: localhost)
            enrich_nvd: If True, query NVD API to enrich vulnerability CVE data
        """
        self.target = target
        self.enrich_nvd = enrich_nvd
        self._rules = self._load_rules()

        # Import config here to avoid circular imports when running standalone
        try:
            import sys
            sys.path.insert(0, str(Path(__file__).parent.parent.parent))
            from config import NVD_API_KEY
        except ImportError:
            NVD_API_KEY = ""

        self._nvd = NVDClient(api_key=NVD_API_KEY) if enrich_nvd else None

    # ── Public API ─────────────────────────────────────────────

    def run_deep_scan(self) -> dict:
        """
        Full scan: Lynis + Nmap + all system checks + NVD enrichment.
        Takes 2-10 minutes depending on system size.
        """
        logger.info("=== Starting DEEP SCAN ===")
        return self._run(scan_type="deep", include_lynis=True, include_nmap=True)

    def run_quick_scan(self) -> dict:
        """
        Quick scan: system checks only (no Lynis, no Nmap).
        Typically completes in under 30 seconds.
        """
        logger.info("=== Starting QUICK SCAN ===")
        return self._run(scan_type="quick", include_lynis=False, include_nmap=False)

    # ── Core Orchestration ─────────────────────────────────────

    def _run(self, scan_type: str, include_lynis: bool, include_nmap: bool) -> dict:
        """Internal scan runner."""
        scan_id = self._make_scan_id()
        timestamp = datetime.now().isoformat(timespec="seconds")

        result = {
            "scan_id": scan_id,
            "scan_type": scan_type,
            "timestamp": timestamp,
            "server_info": self._get_server_info(),
            "lynis_score": 0,
            "vulnerabilities": [],
            "scan_summary": {},
            "scanner_errors": [],
        }

        raw_findings: list[dict] = []

        # ── 1. System Scanner (always runs) ─────────────────
        logger.info("[1/4] Running system scanner...")
        try:
            sys_results = SystemScanner().scan()
            for category_data in sys_results.values():
                for finding in category_data.get("findings", []):
                    raw_findings.append(finding)
        except Exception as e:
            msg = f"SystemScanner failed: {e}"
            logger.error(msg)
            result["scanner_errors"].append(msg)

        # ── 2. Lynis (deep scan only) ────────────────────────
        if include_lynis:
            logger.info("[2/4] Running Lynis...")
            try:
                lynis_result = LynisScanner().run()
                result["lynis_score"] = lynis_result.get("hardening_score", 0)

                # Map Lynis warnings to our vulnerability types
                for vuln_type in lynis_result.get("mapped_vulns", []):
                    # Only add if not already found by system scanner
                    existing_types = {f["type"] for f in raw_findings}
                    if vuln_type not in existing_types:
                        raw_findings.append({
                            "type": vuln_type,
                            "evidence": f"Detected by Lynis audit (test mapping)",
                            "affected_component": "system",
                            "detected_by": "lynis_scanner",
                        })

                # Low hardening score is itself a finding
                if 0 < result["lynis_score"] < 60:
                    raw_findings.append({
                        "type": "lynis_low_hardening_score",
                        "evidence": f"Lynis hardening index is {result['lynis_score']}/100 (threshold: 60)",
                        "affected_component": "system",
                        "detected_by": "lynis_scanner",
                    })

                if lynis_result.get("error"):
                    result["scanner_errors"].append(f"Lynis: {lynis_result['error']}")

            except Exception as e:
                msg = f"LynisScanner failed: {e}"
                logger.error(msg)
                result["scanner_errors"].append(msg)
        else:
            logger.info("[2/4] Skipping Lynis (quick scan)")

        # ── 3. Nmap (deep scan only) ─────────────────────────
        if include_nmap:
            logger.info("[3/4] Running Nmap against %s...", self.target)
            try:
                nmap_result = NmapScanner(target=self.target).scan()
                for finding in nmap_result.get("vulnerabilities", []):
                    existing_types = {f["type"] for f in raw_findings}
                    if finding["type"] not in existing_types:
                        raw_findings.append(finding)

                if nmap_result.get("error"):
                    result["scanner_errors"].append(f"Nmap: {nmap_result['error']}")

            except Exception as e:
                msg = f"NmapScanner failed: {e}"
                logger.error(msg)
                result["scanner_errors"].append(msg)
        else:
            logger.info("[3/4] Skipping Nmap (quick scan)")

        # ── 4. Build full vulnerability objects ─────────────
        logger.info("[4/4] Building vulnerability objects...")
        vulnerabilities = self._build_vuln_objects(raw_findings)

        # ── 5. NVD Enrichment (if enabled) ──────────────────
        if self.enrich_nvd and self._nvd and vulnerabilities:
            logger.info("[+] Enriching with NVD CVE data...")
            vulnerabilities = self._enrich_with_nvd(vulnerabilities)

        result["vulnerabilities"] = vulnerabilities
        result["scan_summary"] = self._make_summary(vulnerabilities)

        logger.info(
            "Scan %s complete — %d vulnerabilities found",
            scan_id,
            len(vulnerabilities),
        )
        return result

    # ── Vulnerability Object Builder ───────────────────────────

    def _build_vuln_objects(self, raw_findings: list[dict]) -> list[dict]:
        """
        Merge raw findings with the rule definitions from security_rules.json
        to produce complete vulnerability dicts.

        Deduplicates by type (keeps the first occurrence).
        Assigns sequential VULN-NNN IDs.
        """
        seen_types: set[str] = set()
        vulnerabilities = []
        counter = 1

        for finding in raw_findings:
            vuln_type = finding.get("type", "")
            if not vuln_type or vuln_type in seen_types:
                continue
            seen_types.add(vuln_type)

            rule = self._rules.get(vuln_type, {})

            vuln = {
                "id":                 f"VULN-{counter:03d}",
                "type":               vuln_type,
                "title":              rule.get("title", vuln_type.replace("_", " ").title()),
                "description":        rule.get("description", ""),
                "category":           rule.get("category", "unknown"),
                "cvss_score":         float(rule.get("base_cvss", 5.0)),
                "exploit_exists":     bool(rule.get("exploit_exists", False)),
                "patch_available":    bool(rule.get("patch_available", False)),
                "cwe_id":             rule.get("cwe_id", ""),
                "fix_type":           rule.get("fix_type"),
                "evidence":           finding.get("evidence", ""),
                "affected_component": finding.get("affected_component", ""),
                "detected_by":        finding.get("detected_by", "unknown"),
                "cve_id":             finding.get("cve_id", ""),
                "cve_description":    "",
            }
            vulnerabilities.append(vuln)
            counter += 1

        return vulnerabilities

    # ── NVD Enrichment ─────────────────────────────────────────

    def _enrich_with_nvd(self, vulnerabilities: list[dict]) -> list[dict]:
        """
        For each vulnerability, search NVD for a relevant CVE and add
        the CVE ID + updated CVSS score if a higher score is found.
        """
        for vuln in vulnerabilities:
            keyword = VULN_CVE_KEYWORDS.get(vuln["type"])
            if not keyword:
                continue

            try:
                cves = self._nvd.search_by_keyword(keyword, max_results=1)
                if cves:
                    best = cves[0]
                    vuln["cve_id"] = best.get("cve_id", "")
                    vuln["cve_description"] = best.get("description", "")
                    # Use NVD score only if it is higher than our rule base score
                    nvd_score = float(best.get("cvss_score", 0.0))
                    if nvd_score > vuln["cvss_score"]:
                        vuln["cvss_score"] = nvd_score
                    if best.get("exploit_exists"):
                        vuln["exploit_exists"] = True
            except Exception as e:
                logger.debug("NVD enrichment failed for %s: %s", vuln["type"], e)

        return vulnerabilities

    # ── Summary ────────────────────────────────────────────────

    def _make_summary(self, vulnerabilities: list[dict]) -> dict:
        """Count vulnerabilities by severity using CVSS thresholds."""
        summary = {"total": len(vulnerabilities), "critical": 0, "high": 0, "medium": 0, "low": 0}
        for v in vulnerabilities:
            score = v.get("cvss_score", 0.0)
            if score >= 8.5:
                summary["critical"] += 1
            elif score >= 7.0:
                summary["high"] += 1
            elif score >= 5.0:
                summary["medium"] += 1
            else:
                summary["low"] += 1
        return summary

    # ── Helpers ────────────────────────────────────────────────

    def _load_rules(self) -> dict:
        """Load security_rules.json and index by vulnerability type."""
        if not RULES_FILE.exists():
            logger.warning("Rules file not found: %s", RULES_FILE)
            return {}
        try:
            data = json.loads(RULES_FILE.read_text())
            return {rule["type"]: rule for rule in data.get("rules", [])}
        except Exception as e:
            logger.error("Failed to load rules file: %s", e)
            return {}

    @staticmethod
    def _make_scan_id() -> str:
        return "scan_" + datetime.now().strftime("%Y%m%d_%H%M%S")

    @staticmethod
    def _get_server_info() -> dict:
        """Collect basic server identification info."""
        info = {
            "hostname": socket.gethostname(),
            "ip": "127.0.0.1",
            "os": "unknown",
            "os_version": platform.version(),
            "cloud": "unknown",
        }

        # OS name
        try:
            uname = platform.uname()
            info["os"] = f"{uname.system} {uname.release}"
        except Exception:
            pass

        # Attempt to read /etc/os-release for a nice distro name
        os_release = Path("/etc/os-release")
        if os_release.exists():
            try:
                for line in os_release.read_text().splitlines():
                    if line.startswith("PRETTY_NAME="):
                        info["os"] = line.split("=", 1)[1].strip().strip('"')
                        break
            except Exception:
                pass

        # Primary non-loopback IP
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            info["ip"] = s.getsockname()[0]
            s.close()
        except Exception:
            pass

        # Cloud provider detection via metadata service
        try:
            import urllib.request
            # AWS
            req = urllib.request.Request(
                "http://169.254.169.254/latest/meta-data/",
                headers={"User-Agent": "HybridSec"},
            )
            with urllib.request.urlopen(req, timeout=1):
                info["cloud"] = "AWS EC2"
        except Exception:
            pass

        if info["cloud"] == "unknown":
            try:
                import urllib.request
                req = urllib.request.Request(
                    "http://metadata.google.internal/computeMetadata/v1/",
                    headers={"Metadata-Flavor": "Google"},
                )
                with urllib.request.urlopen(req, timeout=1):
                    info["cloud"] = "Google Cloud"
            except Exception:
                pass

        if info["cloud"] == "unknown":
            dmi_path = Path("/sys/class/dmi/id/sys_vendor")
            if dmi_path.exists():
                try:
                    vendor = dmi_path.read_text().strip().lower()
                    if "microsoft" in vendor:
                        info["cloud"] = "Azure VM"
                    elif "amazon" in vendor:
                        info["cloud"] = "AWS EC2"
                    elif "google" in vendor:
                        info["cloud"] = "Google Cloud"
                except Exception:
                    pass

        return info


# ── Standalone entry point ─────────────────────────────────────
if __name__ == "__main__":
    import sys
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%H:%M:%S",
    )

    parser = argparse.ArgumentParser(description="HybridSec — Module 1 Scanner")
    parser.add_argument("--quick", action="store_true", help="Run quick scan (no Lynis/Nmap)")
    parser.add_argument("--target", default="127.0.0.1", help="Nmap target IP (default: 127.0.0.1)")
    parser.add_argument("--no-nvd", action="store_true", help="Skip NVD CVE enrichment")
    parser.add_argument("--output", help="Save JSON result to this file")
    args = parser.parse_args()

    scanner = Scanner(target=args.target, enrich_nvd=not args.no_nvd)

    if args.quick:
        result = scanner.run_quick_scan()
    else:
        result = scanner.run_deep_scan()

    # Pretty-print summary
    print("\n" + "=" * 60)
    print(f"  Scan ID   : {result['scan_id']}")
    print(f"  Server    : {result['server_info']['hostname']} ({result['server_info']['ip']})")
    print(f"  OS        : {result['server_info']['os']}")
    print(f"  Cloud     : {result['server_info']['cloud']}")
    print(f"  Lynis     : {result['lynis_score']}/100")
    print("=" * 60)

    summary = result["scan_summary"]
    print(f"\n  Vulnerabilities: {summary.get('total', 0)} total")
    print(f"    CRITICAL : {summary.get('critical', 0)}")
    print(f"    HIGH     : {summary.get('high', 0)}")
    print(f"    MEDIUM   : {summary.get('medium', 0)}")
    print(f"    LOW      : {summary.get('low', 0)}")

    print(f"\n  Details:")
    for v in result["vulnerabilities"]:
        cve = f"  [{v['cve_id']}]" if v.get("cve_id") else ""
        print(f"    {v['id']}  CVSS {v['cvss_score']:.1f}  {v['title']}{cve}")
        if v.get("evidence"):
            print(f"           Evidence: {v['evidence']}")

    if result.get("scanner_errors"):
        print(f"\n  Errors/Warnings:")
        for err in result["scanner_errors"]:
            print(f"    ! {err}")

    if args.output:
        out = Path(args.output)
        out.write_text(json.dumps(result, indent=2))
        print(f"\n  Results saved to: {out}")

    print()
