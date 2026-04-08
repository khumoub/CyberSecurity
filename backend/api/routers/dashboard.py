import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, case, text, literal_column
from core.database import get_db
from core.security import get_current_user
from models.finding import Finding
from models.asset import Asset
from models.scan_job import ScanJob
from models.user import User

router = APIRouter()

SEVERITY_WEIGHTS = {
    "critical": 10.0,
    "high": 5.0,
    "medium": 2.0,
    "low": 0.5,
    "info": 0.0,
}


def _calculate_risk_score(critical: int, high: int, medium: int, low: int, total: int) -> float:
    """Weighted risk score normalized 0-100."""
    if total == 0:
        return 0.0
    raw = (
        critical * SEVERITY_WEIGHTS["critical"]
        + high * SEVERITY_WEIGHTS["high"]
        + medium * SEVERITY_WEIGHTS["medium"]
        + low * SEVERITY_WEIGHTS["low"]
    )
    return round(min(100.0, (raw / (total * 10.0)) * 100), 1)


@router.get("/stats")
async def get_dashboard_stats(
    org_id: Optional[uuid.UUID] = Query(None),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Comprehensive dashboard statistics for an organization."""
    effective_org_id = org_id or current_user.org_id
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    # ---- Asset counts ----
    assets_result = await db.execute(
        select(
            func.count(Asset.id).label("total"),
            func.sum(case((Asset.is_active == True, 1), else_=0)).label("active"),
        ).where(Asset.org_id == effective_org_id)
    )
    asset_row = assets_result.one()

    # ---- Finding counts by severity and status ----
    findings_result = await db.execute(
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
            func.sum(case((Finding.is_known_exploited == True, 1), else_=0)).label("kev_count"),
        ).where(
            and_(
                Finding.org_id == effective_org_id,
                Finding.status != "false_positive",
            )
        )
    )
    f_row = findings_result.one()

    # ---- SLA breaches ----
    sla_result = await db.execute(
        select(func.count(Finding.id)).where(
            and_(
                Finding.org_id == effective_org_id,
                Finding.sla_due_date < now,
                Finding.status.notin_(["resolved", "false_positive", "accepted_risk"]),
            )
        )
    )
    sla_breaches = sla_result.scalar_one() or 0

    # ---- Scan counts ----
    scans_result = await db.execute(
        select(
            func.sum(case((ScanJob.status == "running", 1), else_=0)).label("active"),
            func.sum(
                case(
                    (
                        and_(
                            ScanJob.status == "completed",
                            ScanJob.completed_at >= today_start,
                        ),
                        1,
                    ),
                    else_=0,
                )
            ).label("completed_today"),
        ).where(ScanJob.org_id == effective_org_id)
    )
    scan_row = scans_result.one()

    # ---- Top affected assets (top 5 by critical+high count) ----
    top_assets_result = await db.execute(
        select(
            Asset.value.label("asset_value"),
            func.sum(case((Finding.severity == "critical", 1), else_=0)).label("critical"),
            func.sum(case((Finding.severity == "high", 1), else_=0)).label("high"),
        )
        .join(Asset, Asset.id == Finding.asset_id)
        .where(
            and_(
                Finding.org_id == effective_org_id,
                Finding.status.notin_(["false_positive", "resolved"]),
            )
        )
        .group_by(Asset.value)
        .order_by(
            (
                func.sum(case((Finding.severity == "critical", 1), else_=0)) * 10
                + func.sum(case((Finding.severity == "high", 1), else_=0)) * 5
            ).desc()
        )
        .limit(5)
    )
    top_assets = [
        {
            "asset_value": row.asset_value,
            "critical": row.critical or 0,
            "high": row.high or 0,
        }
        for row in top_assets_result.all()
    ]

    # ---- Recent findings (last 10) ----
    recent_result = await db.execute(
        select(
            Finding.id,
            Finding.title,
            Finding.severity,
            Finding.cve_id,
            Finding.created_at,
            Asset.value.label("asset_value"),
        )
        .join(Asset, Asset.id == Finding.asset_id, isouter=True)
        .where(Finding.org_id == effective_org_id)
        .order_by(Finding.created_at.desc())
        .limit(10)
    )
    recent_findings = [
        {
            "id": str(row.id),
            "title": row.title,
            "severity": row.severity,
            "cve_id": row.cve_id,
            "asset_value": row.asset_value,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }
        for row in recent_result.all()
    ]

    # ---- Scan trend (last 30 days) ----
    thirty_days_ago = now - timedelta(days=30)
    scan_trend_result = await db.execute(
        select(
            literal_column("date_trunc('day', scan_jobs.created_at)").label("date"),
            func.count(ScanJob.id).label("count"),
        )
        .where(
            and_(
                ScanJob.org_id == effective_org_id,
                ScanJob.created_at >= thirty_days_ago,
            )
        )
        .group_by(literal_column("date_trunc('day', scan_jobs.created_at)"))
        .order_by(literal_column("date_trunc('day', scan_jobs.created_at)"))
    )
    scan_trend = [
        {"date": row.date.date().isoformat(), "count": row.count}
        for row in scan_trend_result.all()
    ]

    # ---- Findings trend (last 30 days, by severity) ----
    findings_trend_result = await db.execute(
        select(
            literal_column("date_trunc('day', findings.created_at)").label("date"),
            func.sum(case((Finding.severity == "critical", 1), else_=0)).label("critical"),
            func.sum(case((Finding.severity == "high", 1), else_=0)).label("high"),
            func.sum(case((Finding.severity == "medium", 1), else_=0)).label("medium"),
            func.sum(case((Finding.severity == "low", 1), else_=0)).label("low"),
        )
        .where(
            and_(
                Finding.org_id == effective_org_id,
                Finding.created_at >= thirty_days_ago,
            )
        )
        .group_by(literal_column("date_trunc('day', findings.created_at)"))
        .order_by(literal_column("date_trunc('day', findings.created_at)"))
    )
    findings_trend = [
        {
            "date": row.date.date().isoformat(),
            "critical": row.critical or 0,
            "high": row.high or 0,
            "medium": row.medium or 0,
            "low": row.low or 0,
        }
        for row in findings_trend_result.all()
    ]

    total_findings = f_row.total or 0
    critical = f_row.critical or 0
    high = f_row.high or 0
    medium = f_row.medium or 0
    low = f_row.low or 0

    return {
        "total_assets": asset_row.total or 0,
        "active_assets": asset_row.active or 0,
        "findings": {
            "total": total_findings,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "info": f_row.info or 0,
        },
        "findings_by_status": {
            "open": f_row.open or 0,
            "in_remediation": f_row.in_remediation or 0,
            "resolved": f_row.resolved or 0,
            "accepted_risk": f_row.accepted_risk or 0,
        },
        "active_scans": scan_row.active or 0,
        "completed_scans_today": scan_row.completed_today or 0,
        "risk_score": _calculate_risk_score(critical, high, medium, low, total_findings),
        "sla_breaches": sla_breaches,
        "known_exploited_count": f_row.kev_count or 0,
        "top_affected_assets": top_assets,
        "recent_findings": recent_findings,
        "scan_trend": scan_trend,
        "findings_trend": findings_trend,
    }


@router.get("/scan-history")
async def get_scan_history(
    org_id: Optional[uuid.UUID] = Query(None),
    asset_id: Optional[uuid.UUID] = Query(None),
    days: int = Query(30, ge=1, le=365),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return scan history for trending charts."""
    effective_org_id = org_id or current_user.org_id
    since = datetime.now(timezone.utc) - timedelta(days=days)

    filters = [
        ScanJob.org_id == effective_org_id,
        ScanJob.created_at >= since,
    ]
    if asset_id:
        filters.append(ScanJob.asset_id == asset_id)

    result = await db.execute(
        select(
            ScanJob.id,
            ScanJob.scan_type,
            ScanJob.status,
            ScanJob.findings_count,
            ScanJob.created_at,
            ScanJob.completed_at,
            Asset.value.label("asset_value"),
        )
        .join(Asset, Asset.id == ScanJob.asset_id, isouter=True)
        .where(and_(*filters))
        .order_by(ScanJob.created_at.desc())
        .limit(500)
    )

    scans = [
        {
            "id": str(row.id),
            "scan_type": row.scan_type,
            "status": row.status,
            "findings_count": row.findings_count or 0,
            "asset_value": row.asset_value,
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "completed_at": row.completed_at.isoformat() if row.completed_at else None,
            "duration_seconds": (
                int((row.completed_at - row.created_at).total_seconds())
                if row.completed_at and row.created_at
                else None
            ),
        }
        for row in result.all()
    ]

    return {
        "org_id": str(effective_org_id),
        "days": days,
        "total": len(scans),
        "scans": scans,
    }


@router.get("/mttr")
async def get_mttr(
    org_id: Optional[uuid.UUID] = Query(None),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Mean Time to Remediate (MTTR) per severity, in hours."""
    effective_org_id = org_id or current_user.org_id

    result = await db.execute(
        select(
            Finding.severity,
            func.avg(
                func.extract(
                    "epoch",
                    Finding.resolved_at - Finding.first_seen_at,
                )
            ).label("avg_seconds"),
            func.count(Finding.id).label("resolved_count"),
        )
        .where(
            and_(
                Finding.org_id == effective_org_id,
                Finding.status == "resolved",
                Finding.resolved_at.isnot(None),
                Finding.first_seen_at.isnot(None),
            )
        )
        .group_by(Finding.severity)
    )

    mttr_data = {}
    for row in result.all():
        avg_hours = round(float(row.avg_seconds or 0) / 3600, 1)
        mttr_data[row.severity] = {
            "avg_hours": avg_hours,
            "avg_days": round(avg_hours / 24, 1),
            "resolved_count": row.resolved_count,
        }

    # Fill in zeros for missing severities
    for sev in ("critical", "high", "medium", "low", "info"):
        if sev not in mttr_data:
            mttr_data[sev] = {"avg_hours": 0.0, "avg_days": 0.0, "resolved_count": 0}

    return {
        "org_id": str(effective_org_id),
        "mttr_by_severity": mttr_data,
    }
