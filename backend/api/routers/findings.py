import uuid
import csv
import io
from datetime import datetime, timezone
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, case, text
from core.database import get_db
from core.security import get_current_user
from models.finding import Finding
from models.user import User
from api.schemas.finding import FindingResponse, UpdateFindingRequest, FindingStats

router = APIRouter()


@router.get("/stats", response_model=FindingStats)
async def get_finding_stats(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    base_filter = and_(
        Finding.org_id == current_user.org_id,
        Finding.status.notin_(["false_positive"]),
    )

    result = await db.execute(
        select(
            func.count(Finding.id).label("total"),
            func.sum(case((Finding.severity == "critical", 1), else_=0)).label("critical"),
            func.sum(case((Finding.severity == "high", 1), else_=0)).label("high"),
            func.sum(case((Finding.severity == "medium", 1), else_=0)).label("medium"),
            func.sum(case((Finding.severity == "low", 1), else_=0)).label("low"),
            func.sum(case((Finding.severity == "info", 1), else_=0)).label("info"),
            func.sum(case((Finding.status == "open", 1), else_=0)).label("open"),
            func.sum(case((Finding.status == "in_remediation", 1), else_=0)).label("in_remediation"),
            func.sum(case((Finding.status == "resolved", 1), else_=0)).label("resolved"),
            func.sum(case((Finding.status == "accepted_risk", 1), else_=0)).label("accepted_risk"),
            func.sum(case((Finding.status == "false_positive", 1), else_=0)).label("false_positive"),
            func.sum(case((Finding.is_known_exploited == True, 1), else_=0)).label("known_exploited"),
        ).where(Finding.org_id == current_user.org_id)
    )
    row = result.one()

    return FindingStats(
        total=row.total or 0,
        by_severity={
            "critical": row.critical or 0,
            "high": row.high or 0,
            "medium": row.medium or 0,
            "low": row.low or 0,
            "info": row.info or 0,
        },
        by_status={
            "open": row.open or 0,
            "in_remediation": row.in_remediation or 0,
            "resolved": row.resolved or 0,
            "accepted_risk": row.accepted_risk or 0,
            "false_positive": row.false_positive or 0,
        },
        critical=row.critical or 0,
        high=row.high or 0,
        medium=row.medium or 0,
        low=row.low or 0,
        info=row.info or 0,
        open=row.open or 0,
        in_remediation=row.in_remediation or 0,
        resolved=row.resolved or 0,
        accepted_risk=row.accepted_risk or 0,
        false_positive=row.false_positive or 0,
        known_exploited=row.known_exploited or 0,
    )


@router.get("/", response_model=dict)
async def list_findings(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: Optional[str] = Query(None),
    finding_status: Optional[str] = Query(None, alias="status"),
    asset_id: Optional[uuid.UUID] = Query(None),
    scan_id: Optional[uuid.UUID] = Query(None),
    cve_id: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    is_known_exploited: Optional[bool] = Query(None),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    filters = [Finding.org_id == current_user.org_id]
    if severity:
        filters.append(Finding.severity == severity)
    if finding_status:
        filters.append(Finding.status == finding_status)
    if asset_id:
        filters.append(Finding.asset_id == asset_id)
    if scan_id:
        filters.append(Finding.scan_id == scan_id)
    if cve_id:
        filters.append(Finding.cve_id == cve_id)
    if search:
        filters.append(
            Finding.title.ilike(f"%{search}%") | Finding.description.ilike(f"%{search}%")
        )
    if is_known_exploited is not None:
        filters.append(Finding.is_known_exploited == is_known_exploited)

    count_q = await db.execute(select(func.count(Finding.id)).where(and_(*filters)))
    total = count_q.scalar_one()

    result = await db.execute(
        select(Finding)
        .where(and_(*filters))
        .order_by(
            Finding.severity.asc(),  # critical first when using case ordering
            Finding.created_at.desc(),
        )
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    findings = result.scalars().all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [FindingResponse.model_validate(f) for f in findings],
    }


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Finding).where(
            Finding.id == finding_id, Finding.org_id == current_user.org_id
        )
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return FindingResponse.model_validate(finding)


@router.patch("/{finding_id}", response_model=FindingResponse)
async def update_finding(
    finding_id: uuid.UUID,
    request: UpdateFindingRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Finding).where(
            Finding.id == finding_id, Finding.org_id == current_user.org_id
        )
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    update_data = request.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        if field == "status" and value is not None:
            status_val = value.value if hasattr(value, "value") else value
            setattr(finding, "status", status_val)
            if status_val == "resolved" and not finding.resolved_at:
                finding.resolved_at = datetime.now(timezone.utc)
        elif field == "severity" and value is not None:
            setattr(finding, "severity", value.value if hasattr(value, "value") else value)
        else:
            setattr(finding, field, value)

    await db.commit()
    await db.refresh(finding)
    return FindingResponse.model_validate(finding)


@router.post("/deduplicate", response_model=dict)
async def deduplicate_findings(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Deduplicate findings by (asset_id, title, severity, affected_port).
    Keeps the most recent and marks older duplicates as false_positive.
    """
    result = await db.execute(
        select(Finding).where(
            Finding.org_id == current_user.org_id,
            Finding.status == "open",
        ).order_by(Finding.asset_id, Finding.title, Finding.affected_port, Finding.created_at.desc())
    )
    findings = result.scalars().all()

    seen = {}
    deduplicated = 0

    for finding in findings:
        key = (
            str(finding.asset_id),
            finding.title,
            finding.severity,
            finding.affected_port,
        )
        if key in seen:
            # Mark as false_positive (duplicate)
            finding.status = "false_positive"
            deduplicated += 1
        else:
            seen[key] = finding.id

    await db.commit()
    return {"deduplicated": deduplicated, "message": f"Marked {deduplicated} duplicate findings"}


# ── CSV Export ────────────────────────────────────────────────────────────────

@router.get("/export/csv")
async def export_findings_csv(
    severity: Optional[str] = Query(None),
    finding_status: Optional[str] = Query(None, alias="status"),
    search: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Export findings as a CSV file."""
    filters = [Finding.org_id == current_user.org_id]
    if severity:
        filters.append(Finding.severity == severity)
    if finding_status:
        filters.append(Finding.status == finding_status)
    if search:
        filters.append(
            Finding.title.ilike(f"%{search}%") | Finding.description.ilike(f"%{search}%")
        )

    result = await db.execute(
        select(Finding).where(and_(*filters)).order_by(Finding.severity, Finding.created_at.desc())
    )
    findings = result.scalars().all()

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "id", "title", "severity", "status", "cve_id", "cvss_score",
        "affected_component", "affected_port", "affected_service",
        "is_known_exploited", "exploit_available",
        "first_seen_at", "last_seen_at", "sla_due_date", "resolved_at",
        "description", "remediation",
    ])
    writer.writeheader()
    for f in findings:
        writer.writerow({
            "id": str(f.id),
            "title": f.title,
            "severity": f.severity,
            "status": f.status,
            "cve_id": f.cve_id or "",
            "cvss_score": f.cvss_score or "",
            "affected_component": f.affected_component or "",
            "affected_port": f.affected_port or "",
            "affected_service": f.affected_service or "",
            "is_known_exploited": f.is_known_exploited,
            "exploit_available": f.exploit_available,
            "first_seen_at": f.first_seen_at.isoformat() if f.first_seen_at else "",
            "last_seen_at": f.last_seen_at.isoformat() if f.last_seen_at else "",
            "sla_due_date": f.sla_due_date.isoformat() if f.sla_due_date else "",
            "resolved_at": f.resolved_at.isoformat() if f.resolved_at else "",
            "description": (f.description or "").replace("\n", " "),
            "remediation": (f.remediation or "").replace("\n", " "),
        })

    output.seek(0)
    filename = f"findings-export-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ── Bulk Update ───────────────────────────────────────────────────────────────

class BulkUpdateRequest(BaseModel):
    finding_ids: List[uuid.UUID]
    status: Optional[str] = None
    assigned_to: Optional[uuid.UUID] = None


@router.post("/bulk-update", response_model=dict)
async def bulk_update_findings(
    request: BulkUpdateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Bulk update status or assignment for multiple findings."""
    if not request.finding_ids:
        raise HTTPException(status_code=400, detail="No finding IDs provided")

    valid_statuses = {"open", "in_remediation", "resolved", "accepted_risk", "false_positive"}
    if request.status and request.status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {valid_statuses}")

    result = await db.execute(
        select(Finding).where(
            Finding.id.in_(request.finding_ids),
            Finding.org_id == current_user.org_id,
        )
    )
    findings = result.scalars().all()
    if not findings:
        raise HTTPException(status_code=404, detail="No matching findings found")

    updated = 0
    now = datetime.now(timezone.utc)
    for finding in findings:
        if request.status:
            finding.status = request.status
            if request.status == "resolved" and not finding.resolved_at:
                finding.resolved_at = now
        if request.assigned_to is not None:
            finding.assigned_to = request.assigned_to
        finding.updated_at = now
        updated += 1

    await db.commit()
    return {"updated": updated, "message": f"Updated {updated} findings"}


# ── SLA Summary ───────────────────────────────────────────────────────────────

@router.get("/sla-summary", response_model=dict)
async def get_sla_summary(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return counts of findings by SLA status: overdue, due_this_week, on_track."""
    now = datetime.now(timezone.utc)
    result = await db.execute(
        select(Finding).where(
            Finding.org_id == current_user.org_id,
            Finding.status.in_(["open", "in_remediation"]),
            Finding.sla_due_date.isnot(None),
        )
    )
    findings = result.scalars().all()

    overdue = 0
    due_this_week = 0
    on_track = 0
    from datetime import timedelta
    week_out = now + timedelta(days=7)

    for f in findings:
        due = f.sla_due_date.replace(tzinfo=timezone.utc) if f.sla_due_date.tzinfo is None else f.sla_due_date
        if due < now:
            overdue += 1
        elif due <= week_out:
            due_this_week += 1
        else:
            on_track += 1

    return {
        "overdue": overdue,
        "due_this_week": due_this_week,
        "on_track": on_track,
        "total_with_sla": len(findings),
    }
