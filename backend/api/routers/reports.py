import uuid
import base64
import json
from datetime import datetime, timezone
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, case, and_
from core.database import get_db
from core.security import get_current_user
from core.config import settings
from models.finding import Finding
from models.scan_job import ScanJob
from models.asset import Asset
from models.organization import Organization
from models.user import User

router = APIRouter()

# In-memory scheduled report store (replace with DB table in production)
_scheduled_reports: dict = {}


class ReportRequest(BaseModel):
    title: Optional[str] = None
    include_resolved: bool = False
    asset_ids: Optional[List[uuid.UUID]] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None


class ScheduledReportRequest(BaseModel):
    name: str
    frequency: str  # weekly/monthly
    recipients: List[str]
    include_resolved: bool = False
    report_type: str = "executive"  # executive/technical


def _severity_order(sev: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(sev, 5)


async def _fetch_report_data(
    current_user: User,
    db: AsyncSession,
    request: ReportRequest,
):
    filters = [Finding.org_id == current_user.org_id]
    if not request.include_resolved:
        filters.append(Finding.status.notin_(["resolved", "false_positive"]))
    if request.asset_ids:
        filters.append(Finding.asset_id.in_([str(a) for a in request.asset_ids]))
    if request.date_from:
        filters.append(Finding.created_at >= request.date_from)
    if request.date_to:
        filters.append(Finding.created_at <= request.date_to)

    result = await db.execute(
        select(Finding).where(and_(*filters)).order_by(Finding.severity, Finding.created_at.desc())
    )
    findings = result.scalars().all()

    org_result = await db.execute(
        select(Organization).where(Organization.id == current_user.org_id)
    )
    org = org_result.scalar_one_or_none()

    stats = {
        "total": len(findings),
        "critical": sum(1 for f in findings if f.severity == "critical"),
        "high": sum(1 for f in findings if f.severity == "high"),
        "medium": sum(1 for f in findings if f.severity == "medium"),
        "low": sum(1 for f in findings if f.severity == "low"),
        "info": sum(1 for f in findings if f.severity == "info"),
        "known_exploited": sum(1 for f in findings if f.is_known_exploited),
    }

    return org, findings, stats


def _build_executive_html(org, findings, stats, title: str) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    critical_findings = [f for f in findings if f.severity == "critical"]
    high_findings = [f for f in findings if f.severity == "high"]

    critical_rows = "".join(
        f"<tr><td>{f.title}</td><td style='color:red'>CRITICAL</td><td>{f.status}</td><td>{f.cve_id or ''}</td></tr>"
        for f in critical_findings[:20]
    )
    high_rows = "".join(
        f"<tr><td>{f.title}</td><td style='color:orange'>HIGH</td><td>{f.status}</td><td>{f.cve_id or ''}</td></tr>"
        for f in high_findings[:20]
    )

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
body {{ font-family: Arial, sans-serif; margin: 40px; color: #333; }}
h1 {{ color: #1a1a2e; border-bottom: 3px solid #e63946; padding-bottom: 10px; }}
h2 {{ color: #457b9d; margin-top: 30px; }}
.stat-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin: 20px 0; }}
.stat-card {{ border: 1px solid #ddd; border-radius: 8px; padding: 20px; text-align: center; }}
.stat-number {{ font-size: 36px; font-weight: bold; }}
.critical {{ color: #dc2626; }}
.high {{ color: #ea580c; }}
.medium {{ color: #d97706; }}
.low {{ color: #16a34a; }}
.info {{ color: #6b7280; }}
table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
th {{ background: #1a1a2e; color: white; }}
tr:nth-child(even) {{ background: #f8f9fa; }}
.footer {{ margin-top: 40px; border-top: 1px solid #ddd; padding-top: 20px; color: #666; font-size: 12px; }}
</style>
</head>
<body>
<h1>{title or "Executive Security Report"}</h1>
<p><strong>Organization:</strong> {org.name if org else "N/A"} &nbsp;|&nbsp; <strong>Generated:</strong> {now}</p>

<h2>Executive Summary</h2>
<p>This report summarizes the current security posture of {org.name if org else "your organization"}.
A total of <strong>{stats['total']}</strong> findings were identified across all monitored assets.</p>

<div class="stat-grid">
  <div class="stat-card"><div class="stat-number critical">{stats['critical']}</div><div>Critical</div></div>
  <div class="stat-card"><div class="stat-number high">{stats['high']}</div><div>High</div></div>
  <div class="stat-card"><div class="stat-number medium">{stats['medium']}</div><div>Medium</div></div>
  <div class="stat-card"><div class="stat-number low">{stats['low']}</div><div>Low</div></div>
  <div class="stat-card"><div class="stat-number info">{stats['info']}</div><div>Informational</div></div>
  <div class="stat-card"><div class="stat-number" style="color:#7c3aed">{stats['known_exploited']}</div><div>Known Exploited</div></div>
</div>

<h2>Critical Findings</h2>
<table>
  <tr><th>Title</th><th>Severity</th><th>Status</th><th>CVE</th></tr>
  {critical_rows if critical_rows else "<tr><td colspan='4'>No critical findings</td></tr>"}
</table>

<h2>High Severity Findings</h2>
<table>
  <tr><th>Title</th><th>Severity</th><th>Status</th><th>CVE</th></tr>
  {high_rows if high_rows else "<tr><td colspan='4'>No high severity findings</td></tr>"}
</table>

<div class="footer">
  <p>Leruo Security Platform &copy; {datetime.now().year} | Confidential — For Authorized Recipients Only</p>
</div>
</body>
</html>"""


def _build_technical_html(org, findings, stats, title: str) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    all_rows = "".join(
        f"""<tr>
<td>{f.title}</td>
<td class='{f.severity}'>{f.severity.upper()}</td>
<td>{f.status}</td>
<td>{f.cve_id or ''}</td>
<td>{f.cwe_id or ''}</td>
<td>{f.cvss_score or ''}</td>
<td>{f.affected_component or ''}</td>
<td>{f.affected_port or ''}</td>
<td>{f.is_known_exploited}</td>
</tr>"""
        for f in findings
    )

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
body {{ font-family: monospace; margin: 40px; color: #333; font-size: 13px; }}
h1 {{ font-family: Arial, sans-serif; color: #1a1a2e; border-bottom: 3px solid #e63946; padding-bottom: 10px; }}
h2 {{ font-family: Arial, sans-serif; color: #457b9d; }}
table {{ width: 100%; border-collapse: collapse; margin: 20px 0; font-size: 12px; }}
th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
th {{ background: #1a1a2e; color: white; }}
tr:nth-child(even) {{ background: #f8f9fa; }}
.critical {{ color: #dc2626; font-weight: bold; }}
.high {{ color: #ea580c; font-weight: bold; }}
.medium {{ color: #d97706; }}
.low {{ color: #16a34a; }}
.info {{ color: #6b7280; }}
.footer {{ margin-top: 40px; border-top: 1px solid #ddd; padding-top: 20px; color: #666; font-size: 11px; }}
</style>
</head>
<body>
<h1>{title or "Technical Security Report"}</h1>
<p><strong>Organization:</strong> {org.name if org else "N/A"} &nbsp;|&nbsp; <strong>Generated:</strong> {now}</p>
<p>Total findings: <strong>{stats['total']}</strong> |
Critical: <strong class='critical'>{stats['critical']}</strong> |
High: <strong class='high'>{stats['high']}</strong> |
Medium: <strong>{stats['medium']}</strong> |
Low: <strong>{stats['low']}</strong></p>

<h2>All Findings</h2>
<table>
  <tr>
    <th>Title</th><th>Severity</th><th>Status</th><th>CVE</th><th>CWE</th>
    <th>CVSS</th><th>Component</th><th>Port</th><th>KEV</th>
  </tr>
  {all_rows if all_rows else "<tr><td colspan='9'>No findings</td></tr>"}
</table>

<div class="footer">
  <p>Leruo Security Platform &copy; {datetime.now().year} | Technical Report — Confidential</p>
</div>
</body>
</html>"""


@router.post("/executive-pdf")
async def generate_executive_pdf(
    request: ReportRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    org, findings, stats = await _fetch_report_data(current_user, db, request)
    html_content = _build_executive_html(org, findings, stats, request.title or "Executive Security Report")

    # Return as base64-encoded HTML (PDF generation requires WeasyPrint/pdfkit in prod)
    encoded = base64.b64encode(html_content.encode()).decode()
    return {
        "format": "html",
        "filename": f"executive_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
        "content_base64": encoded,
        "stats": stats,
        "note": "Add WeasyPrint to requirements.txt for PDF output",
    }


@router.post("/technical-pdf")
async def generate_technical_pdf(
    request: ReportRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    org, findings, stats = await _fetch_report_data(current_user, db, request)
    html_content = _build_technical_html(org, findings, stats, request.title or "Technical Security Report")

    encoded = base64.b64encode(html_content.encode()).decode()
    return {
        "format": "html",
        "filename": f"technical_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
        "content_base64": encoded,
        "stats": stats,
        "findings_count": len(findings),
        "note": "Add WeasyPrint to requirements.txt for PDF output",
    }


@router.get("/scheduled", response_model=list)
async def list_scheduled_reports(
    current_user: User = Depends(get_current_user),
):
    org_reports = [
        r for r in _scheduled_reports.values()
        if r.get("org_id") == str(current_user.org_id)
    ]
    return org_reports


@router.post("/scheduled", response_model=dict, status_code=201)
async def create_scheduled_report(
    request: ScheduledReportRequest,
    current_user: User = Depends(get_current_user),
):
    if current_user.role not in ("admin", "analyst"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    schedule_id = str(uuid.uuid4())
    record = {
        "id": schedule_id,
        "org_id": str(current_user.org_id),
        "name": request.name,
        "frequency": request.frequency,
        "recipients": request.recipients,
        "include_resolved": request.include_resolved,
        "report_type": request.report_type,
        "created_by": str(current_user.id),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _scheduled_reports[schedule_id] = record
    return record


@router.delete("/scheduled/{schedule_id}", status_code=204)
async def delete_scheduled_report(
    schedule_id: str,
    current_user: User = Depends(get_current_user),
):
    record = _scheduled_reports.get(schedule_id)
    if not record or record.get("org_id") != str(current_user.org_id):
        raise HTTPException(status_code=404, detail="Scheduled report not found")

    del _scheduled_reports[schedule_id]


# ── Compliance Report Templates ──────────────────────────────────────────────

COMPLIANCE_FRAMEWORKS = {
    "pci-dss": {
        "name": "PCI DSS v4.0",
        "requirements": {
            "1": "Install and maintain network security controls",
            "2": "Apply secure configurations to all system components",
            "3": "Protect stored account data",
            "4": "Protect cardholder data with strong cryptography during transmission",
            "5": "Protect all systems and networks from malicious software",
            "6": "Develop and maintain secure systems and software",
            "7": "Restrict access to system components and cardholder data",
            "8": "Identify users and authenticate access to system components",
            "9": "Restrict physical access to cardholder data",
            "10": "Log and monitor all access to system components and cardholder data",
            "11": "Test security of systems and networks regularly",
            "12": "Support information security with organizational policies and programs",
        },
        "severity_to_requirement": {
            "critical": ["6", "11"],
            "high": ["5", "6", "11"],
            "medium": ["2", "4", "5"],
            "low": ["2", "10"],
            "info": ["10", "12"],
        },
    },
    "hipaa": {
        "name": "HIPAA Security Rule",
        "requirements": {
            "164.308(a)(1)": "Security Management Process",
            "164.308(a)(3)": "Workforce Security",
            "164.308(a)(4)": "Information Access Management",
            "164.308(a)(5)": "Security Awareness and Training",
            "164.308(a)(6)": "Security Incident Procedures",
            "164.308(a)(7)": "Contingency Plan",
            "164.310(a)": "Facility Access Controls",
            "164.312(a)": "Access Control",
            "164.312(b)": "Audit Controls",
            "164.312(c)": "Integrity",
            "164.312(d)": "Person or Entity Authentication",
            "164.312(e)": "Transmission Security",
        },
        "severity_to_requirement": {
            "critical": ["164.308(a)(1)", "164.308(a)(6)", "164.312(a)"],
            "high": ["164.308(a)(1)", "164.312(a)", "164.312(e)"],
            "medium": ["164.308(a)(5)", "164.312(b)", "164.312(c)"],
            "low": ["164.308(a)(5)", "164.312(b)"],
            "info": ["164.308(a)(5)"],
        },
    },
    "nist-800-53": {
        "name": "NIST SP 800-53 Rev 5",
        "requirements": {
            "AC": "Access Control",
            "AT": "Awareness and Training",
            "AU": "Audit and Accountability",
            "CA": "Assessment, Authorization, and Monitoring",
            "CM": "Configuration Management",
            "CP": "Contingency Planning",
            "IA": "Identification and Authentication",
            "IR": "Incident Response",
            "MA": "Maintenance",
            "MP": "Media Protection",
            "PE": "Physical and Environmental Protection",
            "PL": "Planning",
            "PM": "Program Management",
            "PS": "Personnel Security",
            "RA": "Risk Assessment",
            "SA": "System and Services Acquisition",
            "SC": "System and Communications Protection",
            "SI": "System and Information Integrity",
        },
        "severity_to_requirement": {
            "critical": ["SI", "IR", "RA"],
            "high": ["CM", "SC", "SI"],
            "medium": ["AC", "IA", "CM"],
            "low": ["AU", "AT", "AC"],
            "info": ["AU", "AT"],
        },
    },
    "soc2": {
        "name": "SOC 2 Type II (Trust Service Criteria)",
        "requirements": {
            "CC1": "Control Environment",
            "CC2": "Communication and Information",
            "CC3": "Risk Assessment",
            "CC4": "Monitoring Activities",
            "CC5": "Control Activities",
            "CC6": "Logical and Physical Access Controls",
            "CC7": "System Operations",
            "CC8": "Change Management",
            "CC9": "Risk Mitigation",
            "A1": "Availability",
            "C1": "Confidentiality",
            "PI1": "Processing Integrity",
        },
        "severity_to_requirement": {
            "critical": ["CC6", "CC7", "C1"],
            "high": ["CC5", "CC6", "CC7"],
            "medium": ["CC3", "CC5", "CC8"],
            "low": ["CC3", "CC4"],
            "info": ["CC2", "CC4"],
        },
    },
    "iso27001": {
        "name": "ISO/IEC 27001:2022",
        "requirements": {
            "A.5": "Organizational Controls",
            "A.6": "People Controls",
            "A.7": "Physical Controls",
            "A.8": "Technological Controls",
        },
        "severity_to_requirement": {
            "critical": ["A.8"],
            "high": ["A.8", "A.5"],
            "medium": ["A.8", "A.5"],
            "low": ["A.5", "A.6"],
            "info": ["A.5"],
        },
    },
}


class ComplianceReportRequest(BaseModel):
    framework: str  # pci-dss, hipaa, nist-800-53, soc2, iso27001
    include_resolved: bool = False
    asset_ids: Optional[List[uuid.UUID]] = None
    title: Optional[str] = None


@router.post("/compliance/{framework}", response_model=dict)
async def generate_compliance_report(
    framework: str,
    request: ComplianceReportRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate a compliance gap report mapped to a specific framework."""
    fw = COMPLIANCE_FRAMEWORKS.get(framework)
    if not fw:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown framework '{framework}'. Valid: {list(COMPLIANCE_FRAMEWORKS.keys())}"
        )

    report_data = await _fetch_report_data(current_user, db, ReportRequest(
        include_resolved=request.include_resolved,
        asset_ids=request.asset_ids,
    ))

    findings = report_data["findings"]
    fw_name = fw["name"]
    req_map = fw["requirements"]
    sev_to_req = fw["severity_to_requirement"]

    # Map findings to requirements
    requirement_findings = {req: [] for req in req_map}
    for f in findings:
        reqs = sev_to_req.get(f.severity or "info", [])
        for req in reqs:
            if req in requirement_findings:
                requirement_findings[req].append(f)

    # Calculate compliance status per requirement
    compliance_status = {}
    for req, req_findings in requirement_findings.items():
        open_findings = [f for f in req_findings if f.status not in ("resolved", "false_positive", "accepted_risk")]
        critical_open = [f for f in open_findings if f.severity == "critical"]
        compliance_status[req] = {
            "requirement": req,
            "name": req_map[req],
            "status": "FAIL" if critical_open else ("PARTIAL" if open_findings else "PASS"),
            "open_findings": len(open_findings),
            "critical_findings": len(critical_open),
            "findings": [
                {"id": str(f.id), "title": f.title, "severity": f.severity, "status": f.status, "cve_id": f.cve_id}
                for f in open_findings[:10]
            ],
        }

    total_reqs = len(req_map)
    passing = sum(1 for s in compliance_status.values() if s["status"] == "PASS")
    partial = sum(1 for s in compliance_status.values() if s["status"] == "PARTIAL")
    failing = sum(1 for s in compliance_status.values() if s["status"] == "FAIL")
    score = round(passing / total_reqs * 100, 1)

    # Generate HTML report
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    STATUS_COLOR = {"PASS": "#22c55e", "PARTIAL": "#f59e0b", "FAIL": "#ef4444"}

    rows_html = ""
    for req, info in compliance_status.items():
        color = STATUS_COLOR[info["status"]]
        findings_preview = ", ".join(f["title"][:50] for f in info["findings"][:3])
        rows_html += f"""
        <tr>
            <td style="padding:8px;border:1px solid #ddd;font-family:monospace">{req}</td>
            <td style="padding:8px;border:1px solid #ddd">{info['name']}</td>
            <td style="padding:8px;border:1px solid #ddd;text-align:center">
                <span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px">{info['status']}</span>
            </td>
            <td style="padding:8px;border:1px solid #ddd;text-align:center">{info['open_findings']}</td>
            <td style="padding:8px;border:1px solid #ddd;font-size:12px;color:#666">{findings_preview}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html>
<head><title>{fw_name} Compliance Report</title>
<style>body{{font-family:Arial,sans-serif;margin:40px;color:#1a1a2e}}
h1{{color:#2d3748}}
.stat{{display:inline-block;background:#f8f9fa;border:1px solid #e2e8f0;border-radius:8px;padding:16px 24px;margin:8px;text-align:center}}
.stat-num{{font-size:32px;font-weight:bold;color:#2d3748}}
.stat-lbl{{font-size:13px;color:#718096}}
table{{border-collapse:collapse;width:100%;margin-top:24px}}
th{{background:#2d3748;color:#fff;padding:10px;text-align:left}}</style>
</head>
<body>
<h1>{fw_name} Compliance Report</h1>
<p style="color:#718096">Generated: {now} | Organization: {report_data['org_name']}</p>
<hr/>

<h2>Compliance Summary</h2>
<div>
  <div class="stat"><div class="stat-num" style="color:#22c55e">{score}%</div><div class="stat-lbl">Overall Score</div></div>
  <div class="stat"><div class="stat-num" style="color:#22c55e">{passing}</div><div class="stat-lbl">Passing</div></div>
  <div class="stat"><div class="stat-num" style="color:#f59e0b">{partial}</div><div class="stat-lbl">Partial</div></div>
  <div class="stat"><div class="stat-num" style="color:#ef4444">{failing}</div><div class="stat-lbl">Failing</div></div>
  <div class="stat"><div class="stat-num">{len(findings)}</div><div class="stat-lbl">Total Findings</div></div>
</div>

<h2>Requirement Status</h2>
<table>
<tr>
  <th>Control</th><th>Requirement</th><th>Status</th><th>Open Findings</th><th>Sample Findings</th>
</tr>
{rows_html}
</table>

<p style="margin-top:40px;font-size:12px;color:#999">
Generated by Leruo Security Platform. This report reflects findings as of {now}.
For audit purposes, retain this report per your {fw_name} documentation requirements.
</p>
</body>
</html>"""

    encoded = base64.b64encode(html.encode()).decode()
    title = request.title or f"{fw_name} Compliance Report"

    return {
        "title": title,
        "framework": framework,
        "framework_name": fw_name,
        "generated_at": now,
        "compliance_score": score,
        "summary": {"passing": passing, "partial": partial, "failing": failing, "total": total_reqs},
        "requirement_status": compliance_status,
        "html_base64": encoded,
        "filename": f"compliance_{framework}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M')}.html",
    }


@router.get("/compliance/frameworks", response_model=list)
async def list_compliance_frameworks():
    """List available compliance frameworks for reporting."""
    return [
        {"id": k, "name": v["name"], "requirement_count": len(v["requirements"])}
        for k, v in COMPLIANCE_FRAMEWORKS.items()
    ]
