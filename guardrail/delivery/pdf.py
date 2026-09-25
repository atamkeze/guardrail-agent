"""Professional PDF Report Generator using ReportLab for GuardRail-Agent."""

from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from guardrail.agent.models import PentestReport
from guardrail.models import Severity


class ReportGenerator:
    """Generates enterprise-grade penetration testing reports in PDF format."""

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = Path(output_dir or os.environ.get("GUARDRAIL_REPORTS_DIR", "./guardrail-reports"))
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_pdf(self, report: PentestReport) -> Path:
        safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", report.repo_name).strip("_") or "security_audit"
        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"{safe_name}_guardrail_report_{timestamp_str}.pdf"
        self.output_dir = Path(self.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        output_path = self.output_dir / filename

        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=letter,
            rightMargin=40,
            leftMargin=40,
            topMargin=40,
            bottomMargin=40,
        )

        styles = getSampleStyleSheet()

        # Custom styles
        title_style = ParagraphStyle(
            "ReportTitle",
            parent=styles["Heading1"],
            fontSize=22,
            leading=26,
            textColor=colors.HexColor("#0f172a"),
            spaceAfter=6,
        )

        subtitle_style = ParagraphStyle(
            "ReportSubtitle",
            parent=styles["Normal"],
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#475569"),
            spaceAfter=15,
        )

        section_heading = ParagraphStyle(
            "SectionHeading",
            parent=styles["Heading2"],
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#1e293b"),
            spaceBefore=12,
            spaceAfter=6,
        )

        body_style = ParagraphStyle(
            "BodyDark",
            parent=styles["Normal"],
            fontSize=9.5,
            leading=14,
            textColor=colors.HexColor("#334155"),
            spaceAfter=8,
        )

        code_style = ParagraphStyle(
            "SnippetCode",
            parent=styles["Code"],
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#0f172a"),
            backColor=colors.HexColor("#f1f5f9"),
        )

        story = []

        # 1. Header Banner
        header_text = "<b>GuardRail-Agent</b> | Autonomous Penetration Testing & Drift Gate"
        story.append(Paragraph(header_text, title_style))
        story.append(Paragraph("Enterprise AI Security Audit & Codebase Vulnerability Report", subtitle_style))
        story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#cbd5e1"), spaceAfter=12))

        # 2. Executive Overview / Risk Score Table
        risk_color = colors.HexColor("#dc2626")  # CRITICAL
        if report.overall_risk_score == "HIGH":
            risk_color = colors.HexColor("#ea580c")
        elif report.overall_risk_score == "MEDIUM":
            risk_color = colors.HexColor("#d97706")
        elif report.overall_risk_score == "LOW":
            risk_color = colors.HexColor("#2563eb")
        elif report.overall_risk_score == "INFORMATIONAL":
            risk_color = colors.HexColor("#059669")

        meta_data = [
            [
                Paragraph("<b>Target System:</b>", body_style),
                Paragraph(report.repo_name, body_style),
                Paragraph("<b>Overall Risk Rating:</b>", body_style),
                Paragraph(f"<b><font color='white'>{report.overall_risk_score}</font></b>", ParagraphStyle("RiskBadge", parent=body_style, backColor=risk_color, alignment=1)),
            ],
            [
                Paragraph("<b>Scan Timestamp:</b>", body_style),
                Paragraph(report.scan_timestamp, body_style),
                Paragraph("<b>Total Findings:</b>", body_style),
                Paragraph(f"{report.total_findings} (Critical/Err: {report.critical_or_error_count}, Warn: {report.warning_count})", body_style),
            ],
            [
                Paragraph("<b>Source Path / URL:</b>", body_style),
                Paragraph(report.target_path_or_url[:40], body_style),
                Paragraph("<b>Audit Engine:</b>", body_style),
                Paragraph("GuardRail Autonomous Agent v2.0", body_style),
            ],
        ]

        meta_table = Table(meta_data, colWidths=[110, 160, 120, 140])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#e2e8f0")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 14))

        # 3. Agent Reasoning & Profiling
        if report.execution_plan:
            story.append(Paragraph("1. Agent Threat Modeling & Reasoning", section_heading))
            story.append(Paragraph(report.execution_plan.reasoning_narrative, body_style))
            story.append(Spacer(1, 10))

        # 4. Executive Summary
        story.append(Paragraph("2. Executive Summary & Impact Analysis", section_heading))
        story.append(Paragraph(report.executive_summary, body_style))
        story.append(Spacer(1, 10))

        # 5. Strategic Remediation Recommendations
        if report.remediation_recommendations:
            story.append(Paragraph("3. Prioritized Remediation Roadmap", section_heading))
            for idx, rec in enumerate(report.remediation_recommendations, start=1):
                story.append(Paragraph(f"<b>{idx}.</b> {rec}", body_style))
            story.append(Spacer(1, 12))

        # 6. Detailed Technical Findings Table
        story.append(Paragraph("4. Detailed Technical Findings", section_heading))

        if not report.findings:
            story.append(Paragraph("No security violations or vulnerabilities identified during this scan.", body_style))
        else:
            findings_data = [
                [
                    Paragraph("<b>Severity</b>", body_style),
                    Paragraph("<b>Rule & Analyzer</b>", body_style),
                    Paragraph("<b>Location</b>", body_style),
                    Paragraph("<b>Description & Snippet</b>", body_style),
                ]
            ]

            for f in report.findings:
                sev_color = colors.HexColor("#dc2626") if f.severity == Severity.ERROR else colors.HexColor("#d97706") if f.severity == Severity.WARNING else colors.HexColor("#2563eb")
                sev_p = Paragraph(f"<b><font color='white'>{f.severity.value.upper()}</font></b>", ParagraphStyle("SevCol", parent=body_style, backColor=sev_color, alignment=1))
                rule_p = Paragraph(f"<b>{f.rule_id}</b><br/><font color='#64748b' size='7'>{f.analyzer}</font>", body_style)
                loc_p = Paragraph(f"<font size='8'>{f.file_path}:{f.line_number or 1}</font>", body_style)

                desc_text = f"{f.message}"
                if f.snippet:
                    desc_text += f"<br/><font color='#0f172a' size='7'><b>Code:</b> <code>{f.snippet[:120]}</code></font>"
                desc_p = Paragraph(desc_text, body_style)

                findings_data.append([sev_p, rule_p, loc_p, desc_p])

            table = Table(findings_data, colWidths=[70, 110, 110, 240])
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]))
            story.append(table)

        doc.build(story)
        report.pdf_report_path = str(output_path)
        return output_path
