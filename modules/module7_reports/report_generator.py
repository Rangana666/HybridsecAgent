"""
report_generator.py — Unified Report Generation Facade  (Module 7)

Single entry point for all report generation.
Called by:
  - modules/module5_web/api.py  → POST /api/reports/generate
  - modules/module6_liveguard/live_guard.py  → scheduled daily report

Usage:
    rg = ReportGenerator()
    path = rg.generate(scan_data, format="pdf")   # or "html"
    path = rg.generate(scan_data, format="both")  # generates both, returns PDF path

    # With explicit profile / incidents
    path = rg.generate(scan_data, profile=profile_dict, incidents=incident_list, format="pdf")
"""

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

try:
    from config import BASE_DIR, LOGS_DIR
except ImportError:
    BASE_DIR = Path(__file__).parent.parent.parent
    LOGS_DIR = BASE_DIR / "logs"

_REPORTS_DIR = BASE_DIR / "data" / "reports"


class ReportGenerator:
    """
    Facade that delegates to PDFGenerator or HTMLGenerator
    based on the requested format.

    Also loads profile and incidents automatically if not provided.
    """

    def __init__(self):
        _REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    # ── Public API ─────────────────────────────────────────────

    def generate(
        self,
        scan_data: dict,
        format: str = "pdf",                  # "pdf" | "html" | "both"
        profile: Optional[dict] = None,
        incidents: Optional[list] = None,
        output_dir: Optional[Path] = None,
    ) -> Path:
        """
        Generate a security report.

        Args:
            scan_data:  Full scan result dict (from Module 1 / scan_results DB)
            format:     "pdf", "html", or "both"
            profile:    SME profile dict. Auto-loaded from DB if not provided.
            incidents:  List of Live Guard incidents. Auto-loaded from incidents.json if None.
            output_dir: Where to save the report. Defaults to data/reports/.

        Returns:
            Path to the primary generated file (PDF if format="both").
        """
        out_dir = Path(output_dir) if output_dir else _REPORTS_DIR

        # Auto-load profile if not provided
        if profile is None:
            profile = self._load_profile()

        # Auto-load incidents if not provided
        if incidents is None:
            incidents = self._load_incidents()

        fmt = format.lower().strip()

        if fmt in ("pdf", "both"):
            from modules.module7_reports.pdf_generator import PDFGenerator
            pdf_path = PDFGenerator().generate(scan_data, profile, incidents, out_dir)
            logger.info("PDF report: %s", pdf_path)

            if fmt == "pdf":
                return pdf_path

        if fmt in ("html", "both"):
            from modules.module7_reports.html_generator import HTMLGenerator
            html_path = HTMLGenerator().generate(scan_data, profile, incidents, out_dir)
            logger.info("HTML report: %s", html_path)

            if fmt == "html":
                return html_path

        # "both" → return PDF path
        return pdf_path   # type: ignore[return-value]

    def list_reports(self) -> list[dict]:
        """Return metadata for all generated reports in data/reports/."""
        reports = []
        for p in sorted(_REPORTS_DIR.glob("hybridsec_report_*"), reverse=True):
            reports.append({
                "filename":   p.name,
                "format":     "pdf" if p.suffix == ".pdf" else "html",
                "size_kb":    round(p.stat().st_size / 1024, 1),
                "created_at": datetime.fromtimestamp(p.stat().st_mtime).isoformat(timespec="seconds"),
                "path":       str(p),
            })
        return reports

    # ── Auto-loaders ───────────────────────────────────────────

    @staticmethod
    def _load_profile() -> Optional[dict]:
        try:
            from modules.module2_context.context_manager import ContextManager
            return ContextManager().get_active_profile()
        except Exception as exc:
            logger.debug("Profile auto-load failed: %s", exc)
            return None

    @staticmethod
    def _load_incidents() -> list:
        incidents_path = Path(LOGS_DIR) / "incidents.json"
        try:
            if incidents_path.exists():
                import json
                return json.loads(incidents_path.read_text())
        except Exception as exc:
            logger.debug("Incidents auto-load failed: %s", exc)
        return []


# ── Standalone test ────────────────────────────────────────────
if __name__ == "__main__":
    import json
    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")

    fake_scan = {
        "scan_id": "scan_test_facade",
        "timestamp": "2025-04-17T14:00:00",
        "server_info": {"hostname": "test-server", "ip": "10.0.0.1",
                        "os": "Ubuntu 22.04 LTS", "cloud": "AWS EC2"},
        "lynis_score": 45,
        "scan_summary": {"total": 2, "critical": 1, "high": 1, "medium": 0, "low": 0},
        "vulnerabilities": [
            {"id": "V1", "type": "ssh_root_login_enabled",
             "title": "SSH Root Login Enabled",
             "category": "ssh", "cvss_score": 7.5, "hybrid_score": 9.1,
             "priority": "CRITICAL", "exploit_exists": True, "patch_available": True,
             "rule_score": 8.5, "ml_score": 9.5, "llm_score": 9.3,
             "description": "Root login via SSH is enabled."},
            {"id": "V2", "type": "firewall_disabled", "title": "Firewall Disabled",
             "category": "firewall", "cvss_score": 7.5, "hybrid_score": 7.8,
             "priority": "HIGH", "exploit_exists": False, "patch_available": True,
             "description": "UFW firewall is not active."},
        ],
    }

    rg = ReportGenerator()

    print("--- Generating PDF ---")
    pdf = rg.generate(fake_scan, format="pdf")
    print(f"[PASS] PDF: {pdf.name}  ({pdf.stat().st_size // 1024} KB)")

    print("--- Generating HTML ---")
    html = rg.generate(fake_scan, format="html")
    print(f"[PASS] HTML: {html.name}  ({html.stat().st_size // 1024} KB)")

    print("--- Listing reports ---")
    reports = rg.list_reports()
    for r in reports[:4]:
        print(f"  {r['format'].upper():<4}  {r['filename']:<45}  {r['size_kb']} KB")

    print("\nReportGenerator facade tests PASSED")
