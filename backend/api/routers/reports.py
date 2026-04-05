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
