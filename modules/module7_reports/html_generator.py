"""
html_generator.py — HTML Security Report Generator  (Module 7)

Generates a self-contained, single-file HTML security report with:
  - Embedded Bootstrap 5.3 (CDN link only — requires internet on open)
  - Dark security dashboard theme matching the web UI
  - All 8 report sections in a tabbed layout
  - Printable CSS (print button included)

The output is one .html file that can be:
  - Opened in any browser
  - Emailed as an attachment
  - Hosted on an internal web server

Usage:
    gen = HTMLGenerator()
    path = gen.generate(scan_data, profile, incidents, output_dir)
    # returns Path to the generated .html file
"""

import logging
import sys
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

try:
    from config import BASE_DIR
except ImportError:
    BASE_DIR = Path(__file__).parent.parent.parent

_REPORTS_DIR = BASE_DIR / "data" / "reports"

_PRIORITY_BADGE = {
    "CRITICAL": "bg-danger",
    "HIGH":     "bg-warning text-dark",
    "MEDIUM":   "bg-info text-dark",
    "LOW":      "bg-secondary",
}
_SEV_BADGE = {
    "critical": "bg-danger",
    "high":     "bg-warning text-dark",
    "medium":   "bg-info text-dark",
    "low":      "bg-secondary",
}


class HTMLGenerator:
    """Generates a self-contained HTML security report."""

    def generate(
        self,
        scan_data: dict,
        profile: Optional[dict] = None,
        incidents: Optional[list] = None,
        output_dir: Optional[Path] = None,
    ) -> Path:
        out_dir = Path(output_dir) if output_dir else _REPORTS_DIR
        out_dir.mkdir(parents=True, exist_ok=True)

        ts       = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"hybridsec_report_{ts}.html"
        out_path = out_dir / filename

        html = self._build_html(scan_data, profile or {}, incidents or [])
        out_path.write_text(html, encoding="utf-8")

        logger.info("HTML report generated: %s", out_path)
        return out_path

    # ── HTML builder ───────────────────────────────────────────

    def _build_html(self, scan: dict, profile: dict, incidents: list) -> str:
        server  = scan.get("server_info", {})
        summary = scan.get("scan_summary", {})
        vulns   = sorted(
            scan.get("vulnerabilities", []),
            key=lambda v: (
                {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(
                    str(v.get("priority", "LOW")).upper(), 4
                ),
                -float(v.get("hybrid_score") or v.get("cvss_score") or 0),
            ),
        )
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        scan_ts = scan.get("timestamp", "")[:16].replace("T", " ")
        lynis   = scan.get("lynis_score", 0)

        critical = summary.get("critical", 0)
        if critical > 0:
            risk_label, risk_cls = "CRITICAL RISK", "text-danger"
        elif summary.get("high", 0) > 0:
            risk_label, risk_cls = "HIGH RISK", "text-warning"
        elif summary.get("medium", 0) > 0:
            risk_label, risk_cls = "MEDIUM RISK", "text-info"
        else:
            risk_label, risk_cls = "LOW RISK", "text-success"

        lynis_cls = "text-success" if lynis >= 70 else ("text-warning" if lynis >= 50 else "text-danger")

        return f"""<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HybridSec Security Report — {escape(server.get('hostname','Server'))}</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.css">
<style>
  :root {{--hs-bg:#0d1117;--hs-surface:#161b22;--hs-border:#30363d;--hs-cyan:#00d4ff;}}
  body {{ background:var(--hs-bg); color:#e6edf3; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }}
  .card {{ background:var(--hs-surface)!important; border-color:var(--hs-border)!important; }}
  .card-header {{ background:#21262d!important; border-color:var(--hs-border)!important; }}
  .table-dark {{ --bs-table-bg:transparent; --bs-table-hover-bg:rgba(255,255,255,.04); }}
  .nav-tabs .nav-link.active {{ background:#21262d; border-color:var(--hs-border); color:var(--hs-cyan); }}
  .nav-tabs .nav-link {{ color:#8b949e; border-color:transparent; }}
  .text-cyan {{ color:var(--hs-cyan)!important; }}
  .score-ring {{ width:80px;height:80px;border-radius:50%;border:5px solid;display:flex;align-items:center;justify-content:center;font-size:1.4rem;font-weight:800; }}
  code {{ background:#21262d;padding:2px 6px;border-radius:4px;font-size:.85em; }}
  @media print {{
    .no-print {{ display:none!important; }}
    body {{ background:white!important; color:black!important; }}
    .card {{ border:1px solid #ccc!important; background:white!important; }}
  }}
</style>
</head>
<body>

<!-- Header -->
<div style="background:#0d1117;border-bottom:1px solid #30363d;" class="px-4 py-3 mb-4">
  <div class="d-flex justify-content-between align-items-center">
    <div class="d-flex align-items-center gap-2">
      <i class="bi bi-shield-shaded text-cyan fs-3"></i>
      <div>
        <div class="fw-bold fs-5">HybridSec Agent <span class="badge bg-secondary small">v1.0</span></div>
        <div class="text-muted small">Security Risk Assessment Report</div>
      </div>
    </div>
    <div class="text-end">
      <div class="small text-muted">Generated: {ts}</div>
      <div class="small text-muted">Server: {escape(server.get('hostname','—'))}</div>
      <button class="btn btn-sm btn-outline-secondary mt-1 no-print" onclick="window.print()">
        <i class="bi bi-printer me-1"></i>Print
      </button>
    </div>
  </div>
</div>

<div class="container-fluid px-4 pb-5">

  <!-- Risk Banner -->
  <div class="alert {'alert-danger' if critical > 0 else 'alert-warning' if summary.get('high',0) > 0 else 'alert-info'} d-flex align-items-center gap-3 mb-4">
    <i class="bi bi-{'exclamation-octagon-fill' if critical > 0 else 'exclamation-triangle-fill'} fs-3"></i>
    <div>
      <div class="fw-bold fs-5 {risk_cls}">{risk_label}</div>
      <div class="small">
        {summary.get('total',0)} vulnerabilities detected &mdash;
        {summary.get('critical',0)} Critical, {summary.get('high',0)} High,
        {summary.get('medium',0)} Medium, {summary.get('low',0)} Low
      </div>
    </div>
  </div>

  <!-- Stat cards -->
  <div class="row g-3 mb-4">
    {self._stat_card("CRITICAL", summary.get('critical',0), "danger", "exclamation-octagon-fill")}
    {self._stat_card("HIGH",     summary.get('high',0),     "warning","exclamation-triangle-fill")}
    {self._stat_card("MEDIUM",   summary.get('medium',0),   "info",   "info-circle-fill")}
    {self._stat_card("LOW",      summary.get('low',0),      "secondary","check-circle-fill")}
    <div class="col-md-2">
      <div class="card text-center h-100">
        <div class="card-body d-flex flex-column align-items-center justify-content-center py-3">
          <div class="score-ring {lynis_cls}" style="border-color:currentColor;">{lynis}</div>
          <div class="small text-muted mt-2">Lynis Score</div>
        </div>
      </div>
    </div>
  </div>

  <!-- Tabs -->
  <ul class="nav nav-tabs mb-3 no-print" id="reportTabs">
    <li class="nav-item"><a class="nav-link active" data-bs-toggle="tab" href="#tab-vulns">Vulnerabilities</a></li>
    <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#tab-scoring">Scoring</a></li>
    <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#tab-remediation">Remediation</a></li>
    <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#tab-threats">Threats</a></li>
    <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#tab-context">SME Context</a></li>
    <li class="nav-item"><a class="nav-link" data-bs-toggle="tab" href="#tab-nextsteps">Next Steps</a></li>
  </ul>

  <div class="tab-content">

    <!-- Tab: Vulnerabilities -->
    <div class="tab-pane fade show active" id="tab-vulns">
      <div class="card">
        <div class="card-header small fw-semibold text-muted">
          <i class="bi bi-exclamation-triangle me-1"></i>All Vulnerabilities ({len(vulns)})
        </div>
        <div class="table-responsive">
          <table class="table table-dark table-hover table-sm mb-0 small">
            <thead><tr class="text-muted">
              <th>#</th><th>Type</th><th>Priority</th><th>Hybrid Score</th>
              <th>CVSS</th><th>Exploit</th><th>Patch</th><th>Category</th>
            </tr></thead>
            <tbody>
              {"".join(self._vuln_row(i, v) for i, v in enumerate(vulns, 1))}
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Tab: Scoring -->
    <div class="tab-pane fade" id="tab-scoring">
      <div class="card">
        <div class="card-header small fw-semibold text-muted">
          <i class="bi bi-bar-chart me-1"></i>Triple Hybrid Scoring Breakdown
        </div>
        <div class="card-body small text-muted mb-2">
          Hybrid Score = Rule-Based ×30% + ML Random Forest ×35% + LLM GPT-4o-mini ×35%
        </div>
        <div class="table-responsive">
          <table class="table table-dark table-hover table-sm mb-0 small">
            <thead><tr class="text-muted">
              <th>Type</th><th>Rule (30%)</th><th>ML (35%)</th>
              <th>LLM (35%)</th><th>Hybrid Score</th><th>Priority</th>
            </tr></thead>
            <tbody>
              {"".join(self._scoring_row(v) for v in vulns)}
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Tab: Remediation -->
    <div class="tab-pane fade" id="tab-remediation">
      {self._remediation_section(vulns)}
    </div>

    <!-- Tab: Threats -->
    <div class="tab-pane fade" id="tab-threats">
      <div class="card">
        <div class="card-header small fw-semibold text-muted">
          <i class="bi bi-activity me-1"></i>Live Guard Incident Log ({len(incidents)} events)
        </div>
        {self._incidents_section(incidents)}
      </div>
    </div>

    <!-- Tab: SME Context -->
    <div class="tab-pane fade" id="tab-context">
      {self._context_section(profile)}
    </div>

    <!-- Tab: Next Steps -->
    <div class="tab-pane fade" id="tab-nextsteps">
      {self._nextsteps_section(scan, summary)}
    </div>

  </div><!-- /.tab-content -->

  <div class="text-center text-muted small mt-5">
    HybridSec Agent v1.0 &mdash; BSc (Hons) Computer Science Final Year Research &mdash; 2025 &mdash;
    CONFIDENTIAL: Authorised administrators only
  </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>"""

    # ── Section helpers ────────────────────────────────────────

    @staticmethod
    def _stat_card(label, count, cls, icon):
        return f"""
        <div class="col-md-2">
          <div class="card text-center h-100 border-{cls} border-opacity-50">
            <div class="card-body py-3">
              <i class="bi bi-{icon} text-{cls} fs-3 d-block mb-1"></i>
              <div class="fs-3 fw-bold text-{cls}">{count}</div>
              <div class="text-muted small">{label}</div>
            </div>
          </div>
        </div>"""

    @staticmethod
    def _vuln_row(i, v):
        priority = str(v.get("priority", "LOW")).upper()
        badge    = _PRIORITY_BADGE.get(priority, "bg-secondary")
        score    = float(v.get("hybrid_score") or v.get("cvss_score") or 0)
        score_cls = ("text-danger fw-bold" if score >= 8.5 else
                     "text-warning fw-bold" if score >= 7.0 else
                     "text-info" if score >= 5.0 else "text-secondary")
        exploit_cls = "text-danger fw-bold" if v.get("exploit_exists") else "text-muted"
        patch_cls   = "text-success" if v.get("patch_available") else "text-warning"
        return f"""<tr>
          <td class="text-muted">{i}</td>
          <td><code>{escape(v.get('type',''))}</code><div class="text-muted" style="font-size:.75em">{escape(v.get('title',''))}</div></td>
          <td><span class="badge {badge}">{priority}</span></td>
          <td class="{score_cls}">{score:.1f}</td>
          <td class="text-muted">{float(v.get('cvss_score') or 0):.1f}</td>
          <td class="{exploit_cls}">{'Yes' if v.get('exploit_exists') else 'No'}</td>
          <td class="{patch_cls}">{'Yes' if v.get('patch_available') else 'No'}</td>
          <td class="text-muted">{escape(v.get('category',''))}</td>
        </tr>"""

    @staticmethod
    def _scoring_row(v):
        priority = str(v.get("priority", "LOW")).upper()
        badge    = _PRIORITY_BADGE.get(priority, "bg-secondary")
        hybrid   = float(v.get("hybrid_score") or v.get("cvss_score") or 0)
        rule     = v.get("rule_score")
        ml       = v.get("ml_score")
        llm      = v.get("llm_score")
        h_cls    = ("text-danger" if hybrid >= 8.5 else "text-warning" if hybrid >= 7.0
                    else "text-info" if hybrid >= 5.0 else "text-secondary")
        return f"""<tr>
          <td><code>{escape(v.get('type',''))}</code></td>
          <td class="text-muted">{f'{float(rule):.1f}' if rule is not None else '—'}</td>
          <td class="text-muted">{f'{float(ml):.1f}'   if ml  is not None else '—'}</td>
          <td class="text-muted">{f'{float(llm):.1f}'  if llm is not None else '—'}</td>
          <td class="{h_cls} fw-bold">{hybrid:.1f}</td>
          <td><span class="badge {badge}">{priority}</span></td>
        </tr>"""

    @staticmethod
    def _remediation_section(vulns):
        try:
            from modules.module4_remediation.remediation_generator import RemediationGenerator
            gen = RemediationGenerator(use_llm=False)
        except Exception:
            gen = None

        cards = []
        for v in vulns[:20]:
            priority = str(v.get("priority", "LOW")).upper()
            badge    = _PRIORITY_BADGE.get(priority, "bg-secondary")

            steps_html = ""
            autofix_badge = ""
            if gen:
                try:
                    rem = gen.get_remediation(v)
                    if rem.get("autofix_available"):
                        autofix_badge = '<span class="badge bg-success ms-1"><i class="bi bi-lightning-fill me-1"></i>AUTO-FIX</span>'
                    steps = rem.get("manual_steps", [])
                    if steps:
                        steps_html = "<ul class='text-muted small mb-0'>" + \
                            "".join(f"<li>{escape(s)}</li>" for s in steps[:6] if s.strip()) + \
                            "</ul>"
                except Exception:
                    pass

            cards.append(f"""
            <div class="card mb-3 border-secondary">
              <div class="card-body py-2 px-3">
                <div class="d-flex align-items-center gap-2 mb-1">
                  <span class="badge {badge}">{priority}</span>
                  {autofix_badge}
                  <span class="fw-semibold small">{escape(v.get('title', v.get('type', '')))}</span>
                </div>
                <div class="text-muted small mb-2">{escape(v.get('description','')[:200])}</div>
                {steps_html}
              </div>
            </div>""")

        return "".join(cards) or '<div class="text-muted p-3">No vulnerabilities to remediate.</div>'

    @staticmethod
    def _incidents_section(incidents):
        if not incidents:
            return '<div class="card-body text-muted">No incidents recorded.</div>'

        rows = ""
        for inc in incidents[:50]:
            sev  = str(inc.get("severity", "low")).lower()
            badge = _SEV_BADGE.get(sev, "bg-secondary")
            blocked = inc.get("blocked", False)
            ts = str(inc.get("timestamp", ""))[:16].replace("T", " ")
            rows += f"""<tr>
              <td class="text-muted font-monospace small">{ts}</td>
              <td><code>{escape(str(inc.get('type','')).replace('_',' '))}</code></td>
              <td class="font-monospace">{escape(str(inc.get('source_ip','—')))}</td>
              <td><span class="badge {badge}">{sev.upper()}</span></td>
              <td>{'<span class="text-success fw-bold">Yes</span>' if blocked else '<span class="text-muted">No</span>'}</td>
              <td class="text-muted small">{escape(str(inc.get('detail',''))[:100])}</td>
            </tr>"""

        return f"""<div class="table-responsive">
          <table class="table table-dark table-hover table-sm mb-0 small">
            <thead><tr class="text-muted">
              <th>Time</th><th>Type</th><th>Source IP</th>
              <th>Severity</th><th>Blocked</th><th>Detail</th>
            </tr></thead>
            <tbody>{rows}</tbody>
          </table>
        </div>"""

    @staticmethod
    def _context_section(profile):
        if not profile:
            return '<div class="card"><div class="card-body text-muted">No SME profile configured.</div></div>'

        weights = profile.get("weights") or {}
        rows = ""
        fields = [
            ("Business Type",   profile.get("business_type","—")),
            ("Employee Count",  profile.get("employee_count","—")),
            ("Server Purpose",  profile.get("server_purpose","—")),
            ("Sensitive Data",  profile.get("sensitive_data","—")),
            ("Has IT Staff",    profile.get("has_it_staff","—")),
            ("Budget",          profile.get("budget","—")),
            ("Context Modifier",f"×{weights.get('context_modifier', 1.0):.2f}"),
        ]
        for label, val in fields:
            rows += f"<tr><td class='text-muted fw-semibold'>{escape(label)}</td><td class='text-cyan'>{escape(str(val))}</td></tr>"

        return f"""<div class="card">
          <div class="card-header small fw-semibold text-muted">
            <i class="bi bi-building me-1"></i>Active SME Profile
          </div>
          <div class="card-body p-0">
            <table class="table table-dark table-sm mb-0 small"><tbody>{rows}</tbody></table>
          </div>
        </div>"""

    @staticmethod
    def _nextsteps_section(scan, summary):
        lynis = scan.get("lynis_score", 0)
        steps = []
        if summary.get("critical", 0) > 0:
            steps.append(f"<strong>Immediately:</strong> Fix {summary['critical']} CRITICAL vulnerabilities using HybridSec Auto-Fix or the manual steps in the Remediation tab.")
        if summary.get("high", 0) > 0:
            steps.append(f"<strong>Within 24h:</strong> Address {summary['high']} HIGH severity vulnerabilities.")
        if lynis < 70:
            steps.append(f"<strong>This week:</strong> Improve Lynis hardening score from {lynis} to 70+. Run <code>sudo lynis audit system</code>.")
        steps.extend([
            "<strong>Enable Telegram alerts:</strong> Add <code>TELEGRAM_BOT_TOKEN</code> and <code>TELEGRAM_CHAT_ID</code> to .env for instant push notifications.",
            "<strong>Review blocked IPs:</strong> Check the Live Guard page to ensure no legitimate traffic is blocked.",
            "<strong>Re-run this report:</strong> After applying fixes, generate a new report to verify score improvement.",
        ])
        items = "".join(f"<li class='mb-2'>{s}</li>" for s in steps)
        return f"""<div class="card"><div class="card-body"><ul class="small text-muted">{items}</ul></div></div>"""


# ── Standalone test ────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")

    fake_scan = {
        "timestamp": "2025-04-17T14:00:00",
        "server_info": {"hostname": "test-server", "ip": "10.0.0.1",
                        "os": "Ubuntu 22.04 LTS", "cloud": "AWS EC2"},
        "lynis_score": 45,
        "scan_summary": {"total": 2, "critical": 1, "high": 1, "medium": 0, "low": 0},
        "vulnerabilities": [
            {"type": "ssh_root_login_enabled", "title": "SSH Root Login",
             "category": "ssh", "cvss_score": 7.5, "hybrid_score": 9.1,
             "priority": "CRITICAL", "exploit_exists": True, "patch_available": True,
             "rule_score": 8.5, "ml_score": 9.5, "llm_score": 9.3,
             "description": "Root login via SSH is enabled."},
            {"type": "firewall_disabled", "title": "Firewall Disabled",
             "category": "firewall", "cvss_score": 7.5, "hybrid_score": 7.8,
             "priority": "HIGH", "exploit_exists": False, "patch_available": True,
             "description": "UFW firewall is not active."},
        ],
    }

    gen = HTMLGenerator()
    path = gen.generate(fake_scan)
    print(f"\n[PASS] HTML report: {path}")
    print(f"       Size: {path.stat().st_size / 1024:.1f} KB")
