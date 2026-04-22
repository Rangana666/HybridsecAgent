"""
pdf_generator.py — PDF Security Report Generator  (Module 7)

Generates a professional PDF security report using ReportLab.

Report sections:
  1. Cover page       — company name, date, server info, overall risk rating
  2. Executive Summary — score chart, critical/high/medium/low counts
  3. SME Business Context — Module 2 profile table
  4. Vulnerability Table  — all vulns sorted by hybrid score
  5. Triple Hybrid Scoring Breakdown — Rule / ML / LLM per vuln
  6. Remediation Priority List — auto-fixable first, with commands
  7. Threat Incident Log — Live Guard blocked attacks
  8. Recommended Next Steps

Usage:
    gen = PDFGenerator()
    path = gen.generate(scan_data, profile, incidents, output_dir)
    # returns Path to the generated .pdf file
"""

import logging
import sys
from datetime import datetime, timezone
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

# ── ReportLab imports ─────────────────────────────────────────────
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether,
)
from reportlab.platypus.flowables import HRFlowable

# ── Colour palette (dark security theme adapted for print) ────────
C_DARK    = colors.HexColor("#0d1117")
C_SURFACE = colors.HexColor("#161b22")
C_CYAN    = colors.HexColor("#00d4ff")
C_RED     = colors.HexColor("#f85149")
C_ORANGE  = colors.HexColor("#e3b341")
C_BLUE    = colors.HexColor("#58a6ff")
C_GREEN   = colors.HexColor("#3fb950")
C_GREY    = colors.HexColor("#8b949e")
C_WHITE   = colors.white
C_BLACK   = colors.black
C_LIGHT   = colors.HexColor("#f0f6fc")

_PRIORITY_COLORS = {
    "CRITICAL": C_RED,
    "HIGH":     C_ORANGE,
    "MEDIUM":   C_BLUE,
    "LOW":      C_GREEN,
}


def _priority_color(priority: str):
    return _PRIORITY_COLORS.get(str(priority).upper(), C_GREY)


class PDFGenerator:
    """Generates a multi-section PDF security report."""

    def __init__(self):
        _REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        self._styles = self._build_styles()

    # ── Public API ─────────────────────────────────────────────

    def generate(
        self,
        scan_data: dict,
        profile: Optional[dict] = None,
        incidents: Optional[list] = None,
        output_dir: Optional[Path] = None,
    ) -> Path:
        """
        Generate the full PDF report.

        Args:
            scan_data:  dict from scanner (vulnerabilities, scan_summary, server_info, lynis_score)
            profile:    SME context profile dict (Module 2), or None
            incidents:  list of Live Guard incidents, or None
            output_dir: where to save the PDF (defaults to data/reports/)

        Returns:
            Path to the generated PDF file.
        """
        out_dir = Path(output_dir) if output_dir else _REPORTS_DIR
        out_dir.mkdir(parents=True, exist_ok=True)

        ts       = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"hybridsec_report_{ts}.pdf"
        out_path = out_dir / filename

        doc = SimpleDocTemplate(
            str(out_path),
            pagesize=A4,
            rightMargin=2 * cm,
            leftMargin=2 * cm,
            topMargin=2.5 * cm,
            bottomMargin=2 * cm,
            title="HybridSec Security Report",
            author="HybridSec Agent v1.0",
        )

        story = []
        story += self._cover_page(scan_data, profile)
        story += self._executive_summary(scan_data)
        story += self._sme_context(profile)
        story += self._vulnerability_table(scan_data)
        story += self._hybrid_scoring_breakdown(scan_data)
        story += self._remediation_list(scan_data)
        story += self._incident_log(incidents or [])
        story += self._next_steps(scan_data)

        doc.build(story, onFirstPage=self._page_header_footer,
                  onLaterPages=self._page_header_footer)

        logger.info("PDF report generated: %s", out_path)
        return out_path

    # ── Page header / footer callback ─────────────────────────

    @staticmethod
    def _page_header_footer(canvas, doc):
        canvas.saveState()
        w, h = A4

        # Top bar
        canvas.setFillColor(C_DARK)
        canvas.rect(0, h - 1.2 * cm, w, 1.2 * cm, fill=1, stroke=0)
        canvas.setFillColor(C_CYAN)
        canvas.setFont("Helvetica-Bold", 9)
        canvas.drawString(2 * cm, h - 0.8 * cm, "HybridSec Agent v1.0")
        canvas.setFillColor(C_GREY)
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(w - 2 * cm, h - 0.8 * cm,
                               "CONFIDENTIAL — Authorised Administrators Only")

        # Bottom bar
        canvas.setFillColor(C_DARK)
        canvas.rect(0, 0, w, 0.9 * cm, fill=1, stroke=0)
        canvas.setFillColor(C_GREY)
        canvas.setFont("Helvetica", 8)
        canvas.drawString(2 * cm, 0.3 * cm,
                          f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
        canvas.drawCentredString(w / 2, 0.3 * cm, "HybridSec Security Report")
        canvas.drawRightString(w - 2 * cm, 0.3 * cm, f"Page {doc.page}")

        canvas.restoreState()

    # ── Section builders ───────────────────────────────────────

    def _cover_page(self, scan_data: dict, profile: Optional[dict]) -> list:
        S = self._styles
        story = []

        story.append(Spacer(1, 3 * cm))

        # Title block
        story.append(Paragraph("🛡 HybridSec Agent", S["cover_title"]))
        story.append(Paragraph("Security Risk Assessment Report", S["cover_subtitle"]))
        story.append(Spacer(1, 0.5 * cm))
        story.append(HRFlowable(width="100%", thickness=2, color=C_CYAN))
        story.append(Spacer(1, 1 * cm))

        # Server info table
        server = scan_data.get("server_info", {})
        summary = scan_data.get("scan_summary", {})
        scan_ts = scan_data.get("timestamp", "")[:16].replace("T", " ")

        lynis = scan_data.get("lynis_score", 0)
        total = summary.get("total", 0)
        critical = summary.get("critical", 0)

        # Overall risk rating
        if critical > 0:
            risk_rating, risk_color = "CRITICAL RISK", C_RED
        elif summary.get("high", 0) > 0:
            risk_rating, risk_color = "HIGH RISK", C_ORANGE
        elif summary.get("medium", 0) > 0:
            risk_rating, risk_color = "MEDIUM RISK", C_BLUE
        else:
            risk_rating, risk_color = "LOW RISK", C_GREEN

        biz = profile.get("business_type", "N/A") if profile else "N/A"

        cover_data = [
            ["Server",       server.get("hostname", "Unknown")],
            ["IP Address",   server.get("ip", "Unknown")],
            ["OS",           server.get("os", "Unknown")],
            ["Cloud / Env",  server.get("cloud", "On-Premise")],
            ["Scan Date",    scan_ts],
            ["Business",     biz],
            ["Lynis Score",  f"{lynis} / 100"],
            ["Total Vulns",  str(total)],
            ["Risk Rating",  risk_rating],
        ]

        tbl = Table(cover_data, colWidths=[4.5 * cm, 11 * cm])
        style = TableStyle([
            ("BACKGROUND",  (0, 0), (0, -1), C_DARK),
            ("TEXTCOLOR",   (0, 0), (0, -1), C_CYAN),
            ("BACKGROUND",  (1, 0), (1, -1), C_SURFACE),
            ("TEXTCOLOR",   (1, 0), (1, -1), C_LIGHT),
            ("FONTNAME",    (0, 0), (-1, -1), "Helvetica"),
            ("FONTSIZE",    (0, 0), (-1, -1), 10),
            ("FONTNAME",    (0, 0), (0, -1), "Helvetica-Bold"),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_DARK, C_SURFACE]),
            ("GRID",        (0, 0), (-1, -1), 0.5, C_GREY),
            ("PADDING",     (0, 0), (-1, -1), 8),
            # Risk rating row — highlight
            ("BACKGROUND",  (1, -1), (1, -1), risk_color),
            ("TEXTCOLOR",   (1, -1), (1, -1), C_WHITE),
            ("FONTNAME",    (1, -1), (1, -1), "Helvetica-Bold"),
        ])
        tbl.setStyle(style)
        story.append(tbl)
        story.append(Spacer(1, 1 * cm))

        story.append(Paragraph(
            "This report was generated by <b>HybridSec Agent v1.0</b> — "
            "a Hybrid Context-Aware Agentic AI Framework for Linux Server Security Risk "
            "Prioritization and Remediation Recommendation, designed for Sri Lankan SMEs.",
            S["body_small"],
        ))
        story.append(PageBreak())
        return story

    def _executive_summary(self, scan_data: dict) -> list:
        S = self._styles
        summary = scan_data.get("scan_summary", {})
        lynis   = scan_data.get("lynis_score", 0)
        story   = []

        story.append(Paragraph("Executive Summary", S["h1"]))
        story.append(HRFlowable(width="100%", thickness=1, color=C_CYAN))
        story.append(Spacer(1, 0.4 * cm))

        # Count summary table
        counts = [
            ["Priority", "Count", "Action Required"],
            ["CRITICAL", str(summary.get("critical", 0)), "Fix immediately"],
            ["HIGH",     str(summary.get("high",     0)), "Fix within 24 hours"],
            ["MEDIUM",   str(summary.get("medium",   0)), "Fix this week"],
            ["LOW",      str(summary.get("low",      0)), "Fix this month"],
            ["TOTAL",    str(summary.get("total",    0)), ""],
        ]

        tbl = Table(counts, colWidths=[4 * cm, 3 * cm, 9.5 * cm])
        sty = TableStyle([
            ("BACKGROUND",  (0, 0), (-1, 0), C_DARK),
            ("TEXTCOLOR",   (0, 0), (-1, 0), C_CYAN),
            ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, -1), 10),
            ("ALIGN",       (1, 0), (1, -1), "CENTER"),
            ("GRID",        (0, 0), (-1, -1), 0.5, C_GREY),
            ("PADDING",     (0, 0), (-1, -1), 7),
            ("BACKGROUND",  (0, 1), (-1, 1), colors.HexColor("#2d1515")),
            ("TEXTCOLOR",   (0, 1), (-1, 1), C_RED),
            ("FONTNAME",    (0, 1), (-1, 1), "Helvetica-Bold"),
            ("BACKGROUND",  (0, 2), (-1, 2), colors.HexColor("#2d2415")),
            ("TEXTCOLOR",   (0, 2), (-1, 2), C_ORANGE),
            ("FONTNAME",    (0, 2), (-1, 2), "Helvetica-Bold"),
            ("BACKGROUND",  (0, 3), (-1, 3), colors.HexColor("#15202d")),
            ("TEXTCOLOR",   (0, 3), (-1, 3), C_BLUE),
            ("BACKGROUND",  (0, 4), (-1, 4), colors.HexColor("#152d19")),
            ("TEXTCOLOR",   (0, 4), (-1, 4), C_GREEN),
            ("BACKGROUND",  (0, 5), (-1, 5), C_DARK),
            ("TEXTCOLOR",   (0, 5), (-1, 5), C_LIGHT),
            ("FONTNAME",    (0, 5), (-1, 5), "Helvetica-Bold"),
        ])
        tbl.setStyle(sty)
        story.append(tbl)
        story.append(Spacer(1, 0.6 * cm))

        # Lynis hardening score
        lynis_label = "Good" if lynis >= 70 else ("Fair" if lynis >= 50 else "Poor")
        lynis_color_str = "green" if lynis >= 70 else ("orange" if lynis >= 50 else "red")
        story.append(Paragraph(
            f"<b>Lynis Hardening Score:</b> "
            f'<font color="{lynis_color_str}"><b>{lynis}/100 ({lynis_label})</b></font>  '
            f"— Target: 70+ (Good), 85+ (Excellent)",
            S["body"],
        ))
        story.append(Spacer(1, 0.4 * cm))

        # Key findings paragraph
        vulns = scan_data.get("vulnerabilities", [])
        critical_vulns = [v for v in vulns if v.get("priority") == "CRITICAL"]
        auto_fixable   = [v for v in vulns if v.get("fix_type") == "auto" or
                          v.get("autofix_available")]

        findings = (
            f"The scan identified <b>{len(vulns)} vulnerabilities</b> on this server. "
        )
        if critical_vulns:
            findings += (
                f"<b>{len(critical_vulns)} CRITICAL</b> findings require immediate attention: "
                + ", ".join(v.get("type", "").replace("_", " ") for v in critical_vulns[:3])
                + (f" and {len(critical_vulns) - 3} more." if len(critical_vulns) > 3 else ". ")
            )
        if auto_fixable:
            findings += (
                f"<b>{len(auto_fixable)} vulnerabilities</b> can be resolved with the "
                "HybridSec one-click Auto-Fix feature. "
            )
        findings += (
            "Refer to the Remediation Priority List (Section 6) for step-by-step fix instructions."
        )
        story.append(Paragraph(findings, S["body"]))
        story.append(PageBreak())
        return story

    def _sme_context(self, profile: Optional[dict]) -> list:
        S = self._styles
        story = []

        story.append(Paragraph("SME Business Context", S["h1"]))
        story.append(HRFlowable(width="100%", thickness=1, color=C_CYAN))
        story.append(Spacer(1, 0.4 * cm))

        if not profile:
            story.append(Paragraph(
                "No SME profile configured. Risk scores use generic CVSS weights. "
                "Configure your business profile in the HybridSec web dashboard to get "
                "context-aware prioritisation.",
                S["body"],
            ))
            story.append(Spacer(1, 1 * cm))
            return story

        story.append(Paragraph(
            "The following business context was used to amplify vulnerability scores "
            "via the Triple Hybrid Scoring Engine:",
            S["body"],
        ))
        story.append(Spacer(1, 0.3 * cm))

        weights = profile.get("weights") or {}
        rows = [
            ["Field",            "Value",                           "Risk Impact"],
            ["Business Type",    profile.get("business_type","—"),  _multiplier_label(profile.get("business_type",""))],
            ["Employee Count",   profile.get("employee_count","—"), ""],
            ["Server Purpose",   profile.get("server_purpose","—"), ""],
            ["Sensitive Data",   profile.get("sensitive_data","—"), "+0.4 addition" if profile.get("sensitive_data") == "Yes" else "No addition"],
            ["Has IT Staff",     profile.get("has_it_staff","—"),   "+0.3 addition" if profile.get("has_it_staff") == "No" else "No addition"],
            ["Security Budget",  profile.get("budget","—"),         ""],
            ["Context Modifier", f"×{weights.get('context_modifier', 1.0):.2f}", "Applied to all hybrid scores"],
        ]

        tbl = Table(rows, colWidths=[4.5 * cm, 5.5 * cm, 6.5 * cm])
        sty = TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), C_DARK),
            ("TEXTCOLOR",  (0, 0), (-1, 0), C_CYAN),
            ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",   (0, 0), (-1, -1), 10),
            ("GRID",       (0, 0), (-1, -1), 0.5, C_GREY),
            ("PADDING",    (0, 0), (-1, -1), 7),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_SURFACE, C_DARK]),
            ("TEXTCOLOR",  (0, 1), (-1, -1), C_LIGHT),
            ("FONTNAME",   (0, 1), (0, -1), "Helvetica-Bold"),
            ("TEXTCOLOR",  (0, 1), (0, -1), C_CYAN),
            # Last row highlight
            ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#0d2030")),
            ("TEXTCOLOR",  (1, -1), (1, -1), C_CYAN),
            ("FONTNAME",   (1, -1), (1, -1), "Helvetica-Bold"),
        ])
        tbl.setStyle(sty)
        story.append(tbl)
        story.append(Spacer(1, 0.5 * cm))

        story.append(Paragraph(
            "Scores were calculated using the <b>Triple Hybrid Engine</b>: "
            "Rule-Based (30%) + Random Forest ML (35%) + LLM GPT-4o-mini (35%), "
            "with the context modifier applied as a final multiplier.",
            S["body_small"],
        ))
        story.append(PageBreak())
        return story

    def _vulnerability_table(self, scan_data: dict) -> list:
        S = self._styles
        vulns = sorted(
            scan_data.get("vulnerabilities", []),
            key=lambda v: (
                {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(
                    str(v.get("priority", "LOW")).upper(), 4
                ),
                -float(v.get("hybrid_score") or v.get("cvss_score") or 0),
            ),
        )
        story = []

        story.append(Paragraph(f"Vulnerability Table ({len(vulns)} findings)", S["h1"]))
        story.append(HRFlowable(width="100%", thickness=1, color=C_CYAN))
        story.append(Spacer(1, 0.4 * cm))

        if not vulns:
            story.append(Paragraph("No vulnerabilities detected in this scan.", S["body"]))
            story.append(PageBreak())
            return story

        header = ["#", "Type", "Priority", "Hybrid\nScore", "CVSS", "Exploit?", "Patch?"]
        rows = [header]
        for i, v in enumerate(vulns, 1):
            rows.append([
                str(i),
                Paragraph(_wrap(v.get("type", ""), 30), S["cell_small"]),
                str(v.get("priority", "—")),
                f"{float(v.get('hybrid_score') or v.get('cvss_score') or 0):.1f}",
                f"{float(v.get('cvss_score') or 0):.1f}",
                "Yes" if v.get("exploit_exists") else "No",
                "Yes" if v.get("patch_available") else "No",
            ])

        col_widths = [0.8*cm, 7*cm, 2.2*cm, 1.8*cm, 1.5*cm, 1.8*cm, 1.8*cm]
        tbl = Table(rows, colWidths=col_widths, repeatRows=1)

        sty = [
            ("BACKGROUND",  (0, 0), (-1, 0), C_DARK),
            ("TEXTCOLOR",   (0, 0), (-1, 0), C_CYAN),
            ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, -1), 8),
            ("ALIGN",       (0, 0), (-1, -1), "CENTER"),
            ("ALIGN",       (1, 1), (1, -1), "LEFT"),
            ("GRID",        (0, 0), (-1, -1), 0.3, C_GREY),
            ("PADDING",     (0, 0), (-1, -1), 5),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_SURFACE, C_DARK]),
            ("TEXTCOLOR",   (0, 1), (-1, -1), C_LIGHT),
        ]

        # Color the priority column per row
        for i, v in enumerate(vulns, 1):
            col = _priority_color(v.get("priority", "LOW"))
            sty.append(("TEXTCOLOR",   (2, i), (2, i), col))
            sty.append(("FONTNAME",    (2, i), (2, i), "Helvetica-Bold"))
            # Score column
            score = float(v.get("hybrid_score") or v.get("cvss_score") or 0)
            score_col = (C_RED if score >= 8.5 else C_ORANGE if score >= 7.0
                         else C_BLUE if score >= 5.0 else C_GREEN)
            sty.append(("TEXTCOLOR",   (3, i), (3, i), score_col))
            sty.append(("FONTNAME",    (3, i), (3, i), "Helvetica-Bold"))
            # Exploit
            if v.get("exploit_exists"):
                sty.append(("TEXTCOLOR", (5, i), (5, i), C_RED))
                sty.append(("FONTNAME",  (5, i), (5, i), "Helvetica-Bold"))
            # No patch
            if not v.get("patch_available"):
                sty.append(("TEXTCOLOR", (6, i), (6, i), C_ORANGE))

        tbl.setStyle(TableStyle(sty))
        story.append(tbl)
        story.append(PageBreak())
        return story

    def _hybrid_scoring_breakdown(self, scan_data: dict) -> list:
        S = self._styles
        vulns = [v for v in scan_data.get("vulnerabilities", [])
                 if v.get("hybrid_score") or v.get("rule_score") or v.get("ml_score")][:20]
        story = []

        story.append(Paragraph("Triple Hybrid Scoring Breakdown", S["h1"]))
        story.append(HRFlowable(width="100%", thickness=1, color=C_CYAN))
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph(
            "Hybrid Score = Rule-Based (30%) + ML Random Forest (35%) + LLM GPT-4o-mini (35%)",
            S["body_small"],
        ))
        story.append(Spacer(1, 0.3 * cm))

        if not vulns:
            story.append(Paragraph(
                "Detailed scoring breakdown requires at least one scan with hybrid scoring active.",
                S["body"],
            ))
            story.append(PageBreak())
            return story

        header = ["Vulnerability Type", "Rule\n(30%)", "ML\n(35%)", "LLM\n(35%)", "Hybrid\nScore", "Priority"]
        rows = [header]
        for v in vulns:
            hybrid = float(v.get("hybrid_score") or v.get("cvss_score") or 0)
            rule   = float(v.get("rule_score")   or 0)
            ml     = float(v.get("ml_score")     or 0)
            llm    = float(v.get("llm_score")    or 0)
            rows.append([
                Paragraph(_wrap(v.get("type", ""), 35), S["cell_small"]),
                f"{rule:.1f}" if rule else "—",
                f"{ml:.1f}"   if ml   else "—",
                f"{llm:.1f}"  if llm  else "—",
                f"{hybrid:.1f}",
                str(v.get("priority", "—")),
            ])

        tbl = Table(rows, colWidths=[7*cm, 2*cm, 2*cm, 2*cm, 2*cm, 2.5*cm], repeatRows=1)
        sty = [
            ("BACKGROUND",     (0, 0), (-1, 0), C_DARK),
            ("TEXTCOLOR",      (0, 0), (-1, 0), C_CYAN),
            ("FONTNAME",       (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",       (0, 0), (-1, -1), 9),
            ("ALIGN",          (1, 0), (-1, -1), "CENTER"),
            ("ALIGN",          (0, 1), (0, -1), "LEFT"),
            ("GRID",           (0, 0), (-1, -1), 0.3, C_GREY),
            ("PADDING",        (0, 0), (-1, -1), 5),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_SURFACE, C_DARK]),
            ("TEXTCOLOR",      (0, 1), (-1, -1), C_LIGHT),
        ]
        for i, v in enumerate(vulns, 1):
            col = _priority_color(v.get("priority", "LOW"))
            sty.append(("TEXTCOLOR",  (-1, i), (-1, i), col))
            sty.append(("FONTNAME",   (-1, i), (-1, i), "Helvetica-Bold"))
            hybrid = float(v.get("hybrid_score") or v.get("cvss_score") or 0)
            h_col = (C_RED if hybrid >= 8.5 else C_ORANGE if hybrid >= 7.0
                     else C_BLUE if hybrid >= 5.0 else C_GREEN)
            sty.append(("TEXTCOLOR",  (-2, i), (-2, i), h_col))
            sty.append(("FONTNAME",   (-2, i), (-2, i), "Helvetica-Bold"))
        tbl.setStyle(TableStyle(sty))
        story.append(tbl)
        story.append(PageBreak())
        return story

    def _remediation_list(self, scan_data: dict) -> list:
        S = self._styles
        story = []

        story.append(Paragraph("Remediation Priority List", S["h1"]))
        story.append(HRFlowable(width="100%", thickness=1, color=C_CYAN))
        story.append(Spacer(1, 0.4 * cm))

        vulns = sorted(
            scan_data.get("vulnerabilities", []),
            key=lambda v: (
                {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(
                    str(v.get("priority", "LOW")).upper(), 4
                ),
            ),
        )

        if not vulns:
            story.append(Paragraph("No vulnerabilities to remediate.", S["body"]))
            story.append(PageBreak())
            return story

        try:
            from modules.module4_remediation.remediation_generator import RemediationGenerator
            gen = RemediationGenerator(use_llm=False)
        except Exception:
            gen = None

        for i, vuln in enumerate(vulns[:25], 1):   # cap at 25 for page length
            priority = str(vuln.get("priority", "LOW")).upper()
            p_color = _priority_color(priority)

            block = []

            # Title row
            title_text = (
                f'<font color="#{_hex(p_color)}"><b>[{priority}]</b></font>  '
                f'<b>{i}. {vuln.get("title", vuln.get("type", ""))}</b>'
            )
            block.append(Paragraph(title_text, S["body"]))
            block.append(Paragraph(
                f'<font color="#8b949e">Type: {vuln.get("type", "—")} | '
                f'Hybrid Score: {float(vuln.get("hybrid_score") or vuln.get("cvss_score") or 0):.1f}</font>',
                S["body_small"],
            ))

            # Fix steps
            if gen:
                try:
                    rem = gen.get_remediation(vuln)
                    if rem.get("autofix_available"):
                        block.append(Paragraph(
                            '✅ <font color="green"><b>AUTO-FIX available</b></font> via HybridSec dashboard.',
                            S["body_small"],
                        ))
                    steps = rem.get("manual_steps", [])
                    for step in steps[:6]:
                        if step.strip():
                            block.append(Paragraph(f"  {step}", S["mono_small"]))
                except Exception:
                    pass

            block.append(Spacer(1, 0.3 * cm))
            block.append(HRFlowable(width="100%", thickness=0.5, color=C_GREY))
            block.append(Spacer(1, 0.2 * cm))
            story.append(KeepTogether(block))

        story.append(PageBreak())
        return story

    def _incident_log(self, incidents: list) -> list:
        S = self._styles
        story = []

        story.append(Paragraph("Live Guard — Threat Incident Log", S["h1"]))
        story.append(HRFlowable(width="100%", thickness=1, color=C_CYAN))
        story.append(Spacer(1, 0.4 * cm))

        if not incidents:
            story.append(Paragraph(
                "No threat incidents recorded during this period. "
                "Live Guard is monitoring SSH, web, and port scan activity 24/7.",
                S["body"],
            ))
            story.append(PageBreak())
            return story

        header = ["Timestamp", "Type", "Source IP", "Severity", "Blocked?", "Detail"]
        rows = [header]
        for inc in incidents[:50]:
            rows.append([
                str(inc.get("timestamp", ""))[:16].replace("T", " "),
                str(inc.get("type", "")).replace("_", " "),
                str(inc.get("source_ip", "—")),
                str(inc.get("severity", "—")).upper(),
                "Yes" if inc.get("blocked") else "No",
                Paragraph(_wrap(str(inc.get("detail", "")), 40), S["cell_small"]),
            ])

        col_widths = [3*cm, 3.2*cm, 2.8*cm, 2*cm, 1.8*cm, 4.7*cm]
        tbl = Table(rows, colWidths=col_widths, repeatRows=1)
        sty = [
            ("BACKGROUND",     (0, 0), (-1, 0), C_DARK),
            ("TEXTCOLOR",      (0, 0), (-1, 0), C_CYAN),
            ("FONTNAME",       (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",       (0, 0), (-1, -1), 8),
            ("GRID",           (0, 0), (-1, -1), 0.3, C_GREY),
            ("PADDING",        (0, 0), (-1, -1), 5),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [C_SURFACE, C_DARK]),
            ("TEXTCOLOR",      (0, 1), (-1, -1), C_LIGHT),
        ]
        for i, inc in enumerate(incidents[:50], 1):
            sev = str(inc.get("severity", "")).lower()
            col = (C_RED if sev == "critical" else C_ORANGE if sev == "high"
                   else C_BLUE if sev == "medium" else C_GREEN)
            sty.append(("TEXTCOLOR", (3, i), (3, i), col))
            sty.append(("FONTNAME",  (3, i), (3, i), "Helvetica-Bold"))
            if inc.get("blocked"):
                sty.append(("TEXTCOLOR", (4, i), (4, i), C_GREEN))
                sty.append(("FONTNAME",  (4, i), (4, i), "Helvetica-Bold"))
        tbl.setStyle(TableStyle(sty))
        story.append(tbl)
        story.append(PageBreak())
        return story

    def _next_steps(self, scan_data: dict) -> list:
        S = self._styles
        vulns   = scan_data.get("vulnerabilities", [])
        summary = scan_data.get("scan_summary", {})
        story   = []

        story.append(Paragraph("Recommended Next Steps", S["h1"]))
        story.append(HRFlowable(width="100%", thickness=1, color=C_CYAN))
        story.append(Spacer(1, 0.4 * cm))

        steps = []

        if summary.get("critical", 0) > 0:
            steps.append(
                f"<b>IMMEDIATE (today):</b> Fix {summary['critical']} CRITICAL "
                "vulnerabilities using the HybridSec Auto-Fix feature or manual steps in Section 6."
            )
        if summary.get("high", 0) > 0:
            steps.append(
                f"<b>Within 24 hours:</b> Address {summary['high']} HIGH severity findings. "
                "These represent significant attack vectors."
            )

        lynis = scan_data.get("lynis_score", 0)
        if lynis < 70:
            steps.append(
                f"<b>This week:</b> Improve Lynis hardening score from {lynis} to 70+. "
                "Run: <font face='Courier'>sudo lynis audit system</font> for detailed guidance."
            )

        steps.extend([
            "<b>Enable automatic scans:</b> HybridSec Quick Scan runs every 6 hours automatically. "
            "Ensure the service is running: <font face='Courier'>python3 run.py</font>",
            "<b>Configure Telegram alerts:</b> Add TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID "
            "to your .env file to receive instant push notifications of new attacks.",
            "<b>Review blocked IPs:</b> Check the Live Guard page regularly and verify "
            "that no legitimate traffic has been blocked.",
            "<b>Schedule a Deep Scan:</b> Runs automatically at 3:00 AM UTC. "
            "For immediate deep analysis, use the HybridSec Scan page → Deep Scan.",
            "<b>Re-run this report:</b> After applying fixes, generate a new report "
            "to verify your risk score has improved.",
        ])

        for step in steps:
            story.append(Paragraph(f"▸  {step}", S["body"]))
            story.append(Spacer(1, 0.2 * cm))

        story.append(Spacer(1, 1 * cm))
        story.append(Paragraph(
            "Report generated by <b>HybridSec Agent v1.0</b> — "
            "BSc (Hons) Computer Science Final Year Research Project, 2025.<br/>"
            "For authorised administrators only. Do not distribute.",
            S["body_small"],
        ))
        return story

    # ── Styles ─────────────────────────────────────────────────

    @staticmethod
    def _build_styles() -> dict:
        base = getSampleStyleSheet()

        def _ps(name, **kw):
            return ParagraphStyle(name, parent=base["Normal"], **kw)

        return {
            "cover_title": _ps(
                "cover_title",
                fontSize=28, textColor=C_CYAN, fontName="Helvetica-Bold",
                alignment=TA_CENTER, spaceAfter=6,
            ),
            "cover_subtitle": _ps(
                "cover_subtitle",
                fontSize=14, textColor=C_LIGHT, fontName="Helvetica",
                alignment=TA_CENTER, spaceAfter=4,
            ),
            "h1": _ps(
                "h1",
                fontSize=14, textColor=C_CYAN, fontName="Helvetica-Bold",
                spaceBefore=6, spaceAfter=4,
            ),
            "h2": _ps(
                "h2",
                fontSize=11, textColor=C_LIGHT, fontName="Helvetica-Bold",
                spaceBefore=4, spaceAfter=3,
            ),
            "body": _ps(
                "body",
                fontSize=10, textColor=C_LIGHT, fontName="Helvetica",
                spaceBefore=2, spaceAfter=2, leading=14,
            ),
            "body_small": _ps(
                "body_small",
                fontSize=8, textColor=C_GREY, fontName="Helvetica",
                spaceBefore=1, spaceAfter=1, leading=11,
            ),
            "cell_small": _ps(
                "cell_small",
                fontSize=8, textColor=C_LIGHT, fontName="Helvetica",
                leading=10,
            ),
            "mono_small": _ps(
                "mono_small",
                fontSize=8, textColor=C_GREY, fontName="Courier",
                spaceBefore=1, spaceAfter=1, leftIndent=10,
            ),
        }


# ── Helpers ────────────────────────────────────────────────────

def _wrap(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    return text[:max_chars - 1] + "…"


def _hex(color) -> str:
    """Convert ReportLab Color to hex string for Paragraph markup."""
    try:
        r = int(color.red * 255)
        g = int(color.green * 255)
        b = int(color.blue * 255)
        return f"{r:02x}{g:02x}{b:02x}"
    except Exception:
        return "ffffff"


def _multiplier_label(business_type: str) -> str:
    m = {"E-commerce": "1.8×", "Healthcare": "1.8×", "Finance": "1.8×",
         "IT Services": "1.4×"}.get(business_type, "1.0×")
    return f"{m} risk multiplier"


# ── Standalone test ────────────────────────────────────────────
if __name__ == "__main__":
    import json
    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")

    fake_scan = {
        "scan_id": "scan_test_001",
        "timestamp": "2025-04-17T14:00:00",
        "server_info": {"hostname": "test-server", "ip": "10.0.0.1",
                        "os": "Ubuntu 22.04 LTS", "cloud": "AWS EC2"},
        "lynis_score": 45,
        "scan_summary": {"total": 4, "critical": 1, "high": 1, "medium": 1, "low": 1},
        "vulnerabilities": [
            {"id": "V1", "type": "ssh_root_login_enabled", "title": "SSH Root Login Enabled",
             "category": "ssh", "cvss_score": 7.5, "hybrid_score": 9.1,
             "priority": "CRITICAL", "exploit_exists": True, "patch_available": True,
             "rule_score": 8.5, "ml_score": 9.5, "llm_score": 9.3,
             "description": "Root login via SSH is enabled, allowing attackers full access."},
            {"id": "V2", "type": "firewall_disabled", "title": "Firewall Disabled",
             "category": "firewall", "cvss_score": 7.5, "hybrid_score": 7.8,
             "priority": "HIGH", "exploit_exists": False, "patch_available": True,
             "rule_score": 7.0, "ml_score": 8.0, "llm_score": 8.3,
             "description": "UFW firewall is not active."},
            {"id": "V3", "type": "weak_password_policy", "title": "Weak Password Policy",
             "category": "users", "cvss_score": 5.0, "hybrid_score": 5.2,
             "priority": "MEDIUM", "exploit_exists": False, "patch_available": True,
             "description": "No minimum password length enforced."},
            {"id": "V4", "type": "ntp_not_configured", "title": "NTP Not Configured",
             "category": "system", "cvss_score": 2.0, "hybrid_score": 2.1,
             "priority": "LOW", "exploit_exists": False, "patch_available": True,
             "description": "System clock is not synchronized."},
        ],
    }

    fake_profile = {
        "business_type": "E-commerce", "employee_count": "11-50",
        "server_purpose": "Web Server", "sensitive_data": "Yes",
        "has_it_staff": "No", "budget": "Under $50",
        "weights": {"context_modifier": 1.45},
    }

    fake_incidents = [
        {"type": "ssh_brute_force", "source_ip": "185.220.101.47",
         "severity": "critical", "detail": "8 failed SSH logins in 60s",
         "blocked": True, "timestamp": "2025-04-17T13:45:00"},
    ]

    gen = PDFGenerator()
    path = gen.generate(fake_scan, fake_profile, fake_incidents)
    print(f"\n[PASS] PDF generated: {path}")
    print(f"       Size: {path.stat().st_size / 1024:.1f} KB")
