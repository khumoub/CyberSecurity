import uuid
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, case
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
