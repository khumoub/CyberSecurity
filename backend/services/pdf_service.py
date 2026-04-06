from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    PageBreak,
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
import io
from datetime import datetime

# Severity color map (RGB tuples normalized 0-1)
SEVERITY_COLORS = {
    "critical": colors.HexColor("#DC2626"),   # red-600
    "high": colors.HexColor("#EA580C"),       # orange-600
    "medium": colors.HexColor("#D97706"),     # amber-600
    "low": colors.HexColor("#2563EB"),        # blue-600
    "info": colors.HexColor("#6B7280"),       # gray-500
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _sev_color(sev: str) -> colors.Color:
    return SEVERITY_COLORS.get(sev.lower(), colors.gray)


class PDFReportService:
    """Generates executive and technical PDF security reports using ReportLab."""

    def _base_styles(self):
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(
            name="CoverTitle",
            fontSize=28,
            leading=34,
            textColor=colors.HexColor("#111827"),
            spaceAfter=12,
            alignment=TA_LEFT,
        ))
        styles.add(ParagraphStyle(
            name="CoverSubtitle",
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#374151"),
            spaceAfter=6,
            alignment=TA_LEFT,
        ))
        styles.add(ParagraphStyle(
            name="SectionHeading",
            fontSize=16,
            leading=20,
            textColor=colors.HexColor("#111827"),
            spaceBefore=18,
            spaceAfter=8,
            fontName="Helvetica-Bold",
        ))
        styles.add(ParagraphStyle(
            name="SubHeading",
            fontSize=12,
            leading=16,
            textColor=colors.HexColor("#374151"),
            spaceBefore=10,
            spaceAfter=4,
            fontName="Helvetica-Bold",
        ))
        styles.add(ParagraphStyle(
            name="BodyText2",
            fontSize=10,
            leading=14,
            textColor=colors.HexColor("#374151"),
            spaceAfter=4,
        ))
        styles.add(ParagraphStyle(
            name="SmallText",
            fontSize=8,
            leading=12,
            textColor=colors.HexColor("#6B7280"),
        ))
        styles.add(ParagraphStyle(
            name="TableCell",
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#111827"),
        ))
        styles.add(ParagraphStyle(
            name="SeverityBadge",
            fontSize=9,
            leading=12,
            fontName="Helvetica-Bold",
        ))
        return styles

    def _severity_badge_cell(self, severity: str, styles) -> Paragraph:
        color = _sev_color(severity)
        return Paragraph(
            f'<font color="{color.hexval()}">{severity.upper()}</font>',
            styles["SeverityBadge"],
        )

    def generate_executive_report(
        self,
        org_name: str,
        findings_summary: dict,
        scan_date: str,
    ) -> bytes:
        """
        Executive PDF: cover page, risk overview, critical findings summary,
        remediation recommendations. Board-readable, 5-10 pages.
        Returns bytes of PDF.
        """
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            leftMargin=2.5 * cm,
            rightMargin=2.5 * cm,
            topMargin=2.5 * cm,
            bottomMargin=2.5 * cm,
        )
        styles = self._base_styles()
        story = []

        # ---- Cover Page ----
        story.append(Spacer(1, 3 * cm))
        story.append(Paragraph("SECURITY ASSESSMENT REPORT", styles["CoverTitle"]))
        story.append(Paragraph(f"<b>{org_name}</b>", styles["CoverSubtitle"]))
        story.append(Paragraph(f"Executive Summary — {scan_date}", styles["CoverSubtitle"]))
        story.append(Spacer(1, 1 * cm))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#111827")))
        story.append(Spacer(1, 1 * cm))

        story.append(Paragraph(
            "CONFIDENTIAL — FOR AUTHORIZED RECIPIENTS ONLY",
            ParagraphStyle(
                "Confidential",
                fontSize=10,
                textColor=colors.HexColor("#DC2626"),
                fontName="Helvetica-Bold",
            ),
        ))
        story.append(Spacer(1, 0.5 * cm))
        story.append(Paragraph(
            f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
            styles["SmallText"],
        ))
        story.append(PageBreak())

        # ---- Executive Summary ----
        story.append(Paragraph("1. Executive Summary", styles["SectionHeading"]))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#E5E7EB")))
        story.append(Spacer(1, 0.3 * cm))

        total_findings = findings_summary.get("total", 0)
        risk_score = findings_summary.get("risk_score", 0)

        risk_level = "Low"
        risk_color = colors.HexColor("#2563EB")
        if risk_score >= 75:
            risk_level = "Critical"
            risk_color = colors.HexColor("#DC2626")
        elif risk_score >= 50:
            risk_level = "High"
            risk_color = colors.HexColor("#EA580C")
        elif risk_score >= 25:
            risk_level = "Medium"
            risk_color = colors.HexColor("#D97706")

        story.append(Paragraph(
            f"This report presents the findings from the security assessment of <b>{org_name}</b> "
            f"conducted on <b>{scan_date}</b>. A total of <b>{total_findings}</b> security findings "
            f"were identified across the assessed scope.",
            styles["BodyText2"],
        ))
        story.append(Spacer(1, 0.5 * cm))

        story.append(Paragraph(
            f'Overall Risk Score: <font color="{risk_color.hexval()}"><b>{risk_score}/100 ({risk_level} Risk)</b></font>',
            styles["SubHeading"],
        ))
        story.append(Spacer(1, 0.5 * cm))

        # ---- Risk Overview Table ----
        story.append(Paragraph("2. Risk Overview", styles["SectionHeading"]))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#E5E7EB")))
        story.append(Spacer(1, 0.3 * cm))

        by_severity = findings_summary.get("findings", findings_summary)
        sev_data = [
            ["Severity", "Count", "SLA Target", "Immediate Action Required"],
            [
                Paragraph('<font color="#DC2626"><b>Critical</b></font>', styles["TableCell"]),
                str(by_severity.get("critical", 0)),
                "7 days",
                "Yes — escalate immediately",
            ],
            [
                Paragraph('<font color="#EA580C"><b>High</b></font>', styles["TableCell"]),
                str(by_severity.get("high", 0)),
                "30 days",
                "Yes — prioritize this sprint",
            ],
            [
                Paragraph('<font color="#D97706"><b>Medium</b></font>', styles["TableCell"]),
                str(by_severity.get("medium", 0)),
                "90 days",
                "Schedule remediation",
            ],
            [
                Paragraph('<font color="#2563EB"><b>Low</b></font>', styles["TableCell"]),
                str(by_severity.get("low", 0)),
                "180 days",
                "Include in next hardening cycle",
            ],
            [
                Paragraph('<font color="#6B7280">Info</font>', styles["TableCell"]),
                str(by_severity.get("info", 0)),
                "N/A",
                "Review for awareness",
            ],
        ]

        sev_table = Table(sev_data, colWidths=[4 * cm, 2 * cm, 3 * cm, 7 * cm])
        sev_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F3F4F6")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#111827")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F9FAFB")]),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(sev_table)
        story.append(Spacer(1, 0.5 * cm))

        # ---- Critical Findings Summary ----
        critical_findings = findings_summary.get("critical_findings", [])
        if critical_findings:
            story.append(Paragraph("3. Critical Findings Summary", styles["SectionHeading"]))
            story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#E5E7EB")))
            story.append(Spacer(1, 0.3 * cm))

            for i, f in enumerate(critical_findings[:10], 1):
                story.append(Paragraph(
                    f"{i}. {f.get('title', 'Unknown Finding')}",
                    styles["SubHeading"],
                ))
                story.append(Paragraph(
                    f"<b>Affected:</b> {f.get('affected_component', 'N/A')} &nbsp;&nbsp; "
                    f"<b>CVE:</b> {f.get('cve_id', 'N/A')} &nbsp;&nbsp; "
                    f"<b>CVSS:</b> {f.get('cvss_score', 'N/A')}",
                    styles["BodyText2"],
                ))
                if f.get("remediation"):
                    story.append(Paragraph(
                        f"<b>Remediation:</b> {f['remediation'][:300]}",
                        styles["BodyText2"],
                    ))
                story.append(Spacer(1, 0.3 * cm))

        # ---- Remediation Recommendations ----
        story.append(PageBreak())
        story.append(Paragraph("4. Remediation Recommendations", styles["SectionHeading"]))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#E5E7EB")))
        story.append(Spacer(1, 0.3 * cm))

        recommendations = [
            ("Immediate (0-7 days)", [
                "Patch or mitigate all Critical severity findings.",
                "Revoke and rotate any exposed credentials immediately.",
                "Isolate systems with critical vulnerabilities from production.",
                "Notify relevant stakeholders and incident response team.",
            ]),
            ("Short-term (7-30 days)", [
                "Remediate all High severity findings.",
                "Implement compensating controls where immediate patching is not possible.",
                "Conduct access reviews for affected systems.",
                "Deploy WAF rules for known web application vulnerabilities.",
            ]),
            ("Medium-term (30-90 days)", [
                "Address all Medium severity findings.",
                "Review and harden network segmentation.",
                "Implement security logging and monitoring improvements.",
                "Conduct security awareness training for development teams.",
            ]),
            ("Long-term (90+ days)", [
                "Address Low severity and informational findings.",
                "Establish a regular vulnerability management programme.",
                "Implement CI/CD security scanning.",
                "Schedule quarterly penetration testing.",
            ]),
        ]

        for phase, items in recommendations:
            story.append(Paragraph(f"<b>{phase}</b>", styles["SubHeading"]))
            for item in items:
                story.append(Paragraph(f"• {item}", styles["BodyText2"]))
            story.append(Spacer(1, 0.3 * cm))

        # ---- Appendix: Status Overview ----
        story.append(PageBreak())
        story.append(Paragraph("5. Findings Status Overview", styles["SectionHeading"]))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#E5E7EB")))
        story.append(Spacer(1, 0.3 * cm))

        by_status = findings_summary.get("by_status", findings_summary.get("findings_by_status", {}))
        status_data = [
            ["Status", "Count"],
            ["Open", str(by_status.get("open", 0))],
            ["In Remediation", str(by_status.get("in_remediation", 0))],
            ["Resolved", str(by_status.get("resolved", 0))],
            ["Accepted Risk", str(by_status.get("accepted_risk", 0))],
            ["Known Exploited (KEV)", str(findings_summary.get("known_exploited_count", 0))],
            ["SLA Breaches", str(findings_summary.get("sla_breaches", 0))],
        ]

        status_table = Table(status_data, colWidths=[10 * cm, 3 * cm])
        status_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F3F4F6")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F9FAFB")]),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(status_table)

        doc.build(story)
        return buffer.getvalue()

    def generate_technical_report(
        self,
        org_name: str,
        findings: list,
        scan_jobs: list,
    ) -> bytes:
        """
        Technical PDF: full per-finding detail table, CVE IDs, CVSS scores,
        affected components, step-by-step remediation.
        Returns bytes of PDF.
        """
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            leftMargin=2 * cm,
            rightMargin=2 * cm,
            topMargin=2 * cm,
            bottomMargin=2 * cm,
        )
        styles = self._base_styles()
        story = []

        # ---- Cover ----
        story.append(Spacer(1, 2 * cm))
        story.append(Paragraph("TECHNICAL SECURITY REPORT", styles["CoverTitle"]))
        story.append(Paragraph(f"<b>{org_name}</b>", styles["CoverSubtitle"]))
        story.append(Paragraph(
            f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
            styles["CoverSubtitle"],
        ))
        story.append(Spacer(1, 0.5 * cm))
        story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#111827")))
        story.append(Spacer(1, 0.5 * cm))
        story.append(Paragraph(
            "CONFIDENTIAL — FOR TECHNICAL TEAMS ONLY",
            ParagraphStyle(
                "ConfTech",
                fontSize=10,
                textColor=colors.HexColor("#DC2626"),
                fontName="Helvetica-Bold",
            ),
        ))
        story.append(PageBreak())

        # ---- Scan Jobs Summary ----
        story.append(Paragraph("1. Scan Jobs", styles["SectionHeading"]))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#E5E7EB")))
        story.append(Spacer(1, 0.3 * cm))

        if scan_jobs:
            job_data = [["Scan ID", "Type", "Target", "Status", "Findings", "Date"]]
            for job in scan_jobs[:50]:
                job_data.append([
                    str(job.get("id", ""))[:8] + "...",
                    job.get("scan_type", "N/A"),
                    str(job.get("target", "N/A"))[:30],
                    job.get("status", "N/A"),
                    str(job.get("findings_count", 0)),
                    str(job.get("created_at", "N/A"))[:10],
                ])

            job_table = Table(
                job_data,
                colWidths=[2.5 * cm, 2.5 * cm, 4.5 * cm, 2.5 * cm, 2 * cm, 2.5 * cm],
            )
            job_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F3F4F6")),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F9FAFB")]),
                ("PADDING", (0, 0), (-1, -1), 4),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]))
            story.append(job_table)
        else:
            story.append(Paragraph("No scan jobs provided.", styles["BodyText2"]))

        story.append(Spacer(1, 0.5 * cm))

        # ---- Findings Summary Table ----
        story.append(Paragraph("2. Findings Summary", styles["SectionHeading"]))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#E5E7EB")))
        story.append(Spacer(1, 0.3 * cm))

        # Count by severity
        sev_counts = {s: 0 for s in SEVERITY_ORDER}
        for f in findings:
            sev = (f.get("severity") or "info").lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        summary_data = [["Severity", "Count"]]
        for sev in SEVERITY_ORDER:
            summary_data.append([sev.capitalize(), str(sev_counts.get(sev, 0))])
        summary_data.append(["Total", str(len(findings))])

        summary_table = Table(summary_data, colWidths=[6 * cm, 3 * cm])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F3F4F6")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -2), [colors.white, colors.HexColor("#F9FAFB")]),
            ("PADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(summary_table)
        story.append(PageBreak())

        # ---- Per-Finding Detail Table ----
        story.append(Paragraph("3. Detailed Findings", styles["SectionHeading"]))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#E5E7EB")))
        story.append(Spacer(1, 0.3 * cm))

        # Sort by severity
        sev_rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
        sorted_findings = sorted(
            findings,
            key=lambda f: sev_rank.get((f.get("severity") or "info").lower(), 99),
        )

        for idx, f in enumerate(sorted_findings, 1):
            sev = (f.get("severity") or "info").lower()
            sev_col = _sev_color(sev)

            # Finding header
            story.append(Paragraph(
                f'<font color="{sev_col.hexval()}">[{sev.upper()}]</font> '
                f'{idx}. {f.get("title", "Unknown Finding")}',
                styles["SubHeading"],
            ))

            # Metadata row
            meta_parts = []
            if f.get("cve_id"):
                meta_parts.append(f"<b>CVE:</b> {f['cve_id']}")
            if f.get("cvss_score"):
                meta_parts.append(f"<b>CVSS:</b> {f['cvss_score']}")
            if f.get("cwe_id"):
                meta_parts.append(f"<b>CWE:</b> {f['cwe_id']}")
            if f.get("affected_component"):
                meta_parts.append(f"<b>Component:</b> {f['affected_component'][:60]}")
            if f.get("affected_port"):
                meta_parts.append(f"<b>Port:</b> {f['affected_port']}")
            if f.get("mitre_technique"):
                meta_parts.append(f"<b>MITRE:</b> {f['mitre_technique']}")

            if meta_parts:
                story.append(Paragraph(" &nbsp; | &nbsp; ".join(meta_parts), styles["SmallText"]))

            if f.get("description"):
                desc_text = str(f["description"])[:800]
                story.append(Paragraph(
                    f"<b>Description:</b> {desc_text}",
                    styles["BodyText2"],
                ))

            if f.get("remediation"):
                story.append(Paragraph(
                    f"<b>Remediation:</b> {str(f['remediation'])[:600]}",
                    styles["BodyText2"],
                ))

            refs = f.get("references", [])
            if refs:
                refs_text = ", ".join(str(r) for r in refs[:5])
                story.append(Paragraph(
                    f"<b>References:</b> {refs_text}",
                    styles["SmallText"],
                ))

            story.append(HRFlowable(
                width="100%", thickness=0.5, color=colors.HexColor("#E5E7EB")
            ))
            story.append(Spacer(1, 0.2 * cm))

            # Page break every 5 findings to avoid overflow
            if idx % 5 == 0 and idx < len(sorted_findings):
                story.append(PageBreak())

        doc.build(story)
        return buffer.getvalue()
