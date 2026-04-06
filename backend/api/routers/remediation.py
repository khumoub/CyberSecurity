import uuid
from datetime import datetime, timezone
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, and_
from sqlalchemy.orm import selectinload
from core.database import get_db
from core.security import get_current_user
from models.user import User
from models.finding import Finding

router = APIRouter()


# ── Pydantic schemas ───────────────────────────────────────────────────────────

class RemediationTaskCreate(BaseModel):
    finding_id: uuid.UUID
    title: str
    description: Optional[str] = None
    assigned_to: Optional[uuid.UUID] = None
    due_date: Optional[datetime] = None
    notes: Optional[str] = None


class RemediationTaskUpdate(BaseModel):
    title: Optional[str] = None
    assigned_to: Optional[uuid.UUID] = None
    due_date: Optional[datetime] = None
    status: Optional[str] = None   # open | in_progress | completed | overdue
    notes: Optional[str] = None


class RemediationTaskResponse(BaseModel):
    id: str
    org_id: str
    finding_id: str
    title: str
    description: Optional[str]
    assigned_to: Optional[str]
    due_date: Optional[datetime]
    status: str
    notes: Optional[str]
    created_at: datetime
    updated_at: datetime


# ── SLA due-date policy (days from first_seen_at by severity) ─────────────────
SLA_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180, "info": 365}


def _compute_sla(severity: str, first_seen: datetime) -> datetime:
    from datetime import timedelta
    days = SLA_DAYS.get(severity, 90)
    return first_seen + timedelta(days=days)


# ── Endpoints ──────────────────────────────────────────────────────────────────

@router.get("/", response_model=dict)
async def list_remediation_tasks(
    org_id: Optional[uuid.UUID] = Query(None),
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    assigned_to: Optional[uuid.UUID] = Query(None),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List remediation tasks for the organisation with optional filters."""
    from sqlalchemy import text
    effective_org = str(org_id or current_user.org_id)

    where_clauses = ["rt.org_id = :org_id"]
    params: dict = {"org_id": effective_org, "limit": limit, "offset": (page - 1) * limit}

    if status:
        where_clauses.append("rt.status = :status")
        params["status"] = status
    if assigned_to:
        where_clauses.append("rt.assigned_to = :assigned_to")
        params["assigned_to"] = str(assigned_to)

    severity_join = ""
    if severity:
        severity_join = "JOIN findings f ON f.id = rt.finding_id"
        where_clauses.append("f.severity = :severity")
        params["severity"] = severity

    where_sql = " AND ".join(where_clauses)
    result = await db.execute(
        text(f"""
            SELECT rt.id, rt.org_id, rt.finding_id, rt.title, rt.description,
                   rt.assigned_to, rt.due_date, rt.status, rt.notes,
                   rt.created_at, rt.updated_at,
                   f.severity, f.title AS finding_title, a.value AS asset_value
            FROM remediation_tasks rt
            {severity_join}
            LEFT JOIN findings f ON f.id = rt.finding_id
            LEFT JOIN assets a ON a.id = f.asset_id
            WHERE {where_sql}
            ORDER BY
                CASE rt.status WHEN 'overdue' THEN 0 WHEN 'open' THEN 1 WHEN 'in_progress' THEN 2 ELSE 3 END,
                rt.due_date ASC NULLS LAST
            LIMIT :limit OFFSET :offset
        """),
        params,
    )
    rows = result.fetchall()

    count_result = await db.execute(
        text(f"SELECT COUNT(*) FROM remediation_tasks rt {severity_join} WHERE {where_sql}"),
        {k: v for k, v in params.items() if k not in ("limit", "offset")},
    )
    total = count_result.scalar()

    tasks = []
    now = datetime.now(timezone.utc)
    for row in rows:
        task = {
            "id": str(row[0]),
            "org_id": str(row[1]),
            "finding_id": str(row[2]),
            "title": row[3],
            "description": row[4],
            "assigned_to": str(row[5]) if row[5] else None,
            "due_date": row[6].isoformat() if row[6] else None,
            "status": row[7],
            "notes": row[8],
            "created_at": row[9].isoformat(),
            "updated_at": row[10].isoformat(),
            "finding_severity": row[11],
            "finding_title": row[12],
            "asset_value": row[13],
            "overdue": bool(row[6] and row[6].replace(tzinfo=timezone.utc) < now and row[7] != "completed"),
        }
        tasks.append(task)

    return {"tasks": tasks, "total": total, "page": page, "limit": limit}


@router.post("/", response_model=dict, status_code=201)
async def create_remediation_task(
    payload: RemediationTaskCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a remediation task for a finding."""
    from sqlalchemy import text
    task_id = str(uuid.uuid4())
    org_id = str(current_user.org_id)
    now = datetime.now(timezone.utc)

    await db.execute(
        text("""
            INSERT INTO remediation_tasks
              (id, org_id, finding_id, title, description, assigned_to, due_date, status, notes, created_at, updated_at)
            VALUES
              (:id, :org_id, :finding_id, :title, :description, :assigned_to, :due_date, 'open', :notes, :now, :now)
        """),
        {
            "id": task_id,
            "org_id": org_id,
            "finding_id": str(payload.finding_id),
            "title": payload.title,
            "description": payload.description,
            "assigned_to": str(payload.assigned_to) if payload.assigned_to else None,
            "due_date": payload.due_date,
            "notes": payload.notes,
            "now": now,
        },
    )
    await db.commit()
    return {"id": task_id, "status": "open", "message": "Remediation task created"}


@router.get("/{task_id}", response_model=dict)
async def get_remediation_task(
    task_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    from sqlalchemy import text
    result = await db.execute(
        text("SELECT * FROM remediation_tasks WHERE id = :id AND org_id = :org_id"),
        {"id": str(task_id), "org_id": str(current_user.org_id)},
    )
    row = result.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Remediation task not found")
    return dict(zip(result.keys(), row))


@router.patch("/{task_id}", response_model=dict)
async def update_remediation_task(
    task_id: uuid.UUID,
    payload: RemediationTaskUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    from sqlalchemy import text
    now = datetime.now(timezone.utc)
    updates = {"updated_at": now}
    if payload.title is not None:
        updates["title"] = payload.title
    if payload.assigned_to is not None:
        updates["assigned_to"] = str(payload.assigned_to)
    if payload.due_date is not None:
        updates["due_date"] = payload.due_date
    if payload.status is not None:
        updates["status"] = payload.status
    if payload.notes is not None:
        updates["notes"] = payload.notes

    set_clause = ", ".join(f"{k} = :{k}" for k in updates)
    await db.execute(
        text(f"UPDATE remediation_tasks SET {set_clause} WHERE id = :task_id AND org_id = :org_id"),
        {**updates, "task_id": str(task_id), "org_id": str(current_user.org_id)},
    )
    await db.commit()
    return {"id": str(task_id), "updated": True}


@router.delete("/{task_id}", status_code=204)
async def delete_remediation_task(
    task_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    from sqlalchemy import text
    await db.execute(
        text("DELETE FROM remediation_tasks WHERE id = :id AND org_id = :org_id"),
        {"id": str(task_id), "org_id": str(current_user.org_id)},
    )
    await db.commit()


@router.post("/auto-create", response_model=dict)
async def auto_create_for_open_findings(
    org_id: Optional[uuid.UUID] = Query(None),
    severity: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Auto-create remediation tasks for open findings that don't have one yet."""
    from sqlalchemy import text
    effective_org = str(org_id or current_user.org_id)

    sev_filter = "AND f.severity = :severity" if severity else ""
    result = await db.execute(
        text(f"""
            SELECT f.id, f.title, f.severity, f.first_seen_at
            FROM findings f
            LEFT JOIN remediation_tasks rt ON rt.finding_id = f.id
            WHERE f.org_id = :org_id
              AND f.status = 'open'
              AND rt.id IS NULL
              {sev_filter}
            LIMIT 100
        """),
        {"org_id": effective_org, **({"severity": severity} if severity else {})},
    )
    rows = result.fetchall()

    created = 0
    now = datetime.now(timezone.utc)
    for row in rows:
        fid, title, sev, first_seen = row
        due = _compute_sla(sev, first_seen.replace(tzinfo=timezone.utc))
        await db.execute(
            text("""
                INSERT INTO remediation_tasks
                  (id, org_id, finding_id, title, status, due_date, created_at, updated_at)
                VALUES
                  (:id, :org_id, :finding_id, :title, 'open', :due_date, :now, :now)
                ON CONFLICT DO NOTHING
            """),
            {
                "id": str(uuid.uuid4()),
                "org_id": effective_org,
                "finding_id": str(fid),
                "title": f"Remediate: {title}",
                "due_date": due,
                "now": now,
            },
        )
        created += 1

    await db.commit()
    return {"created": created, "message": f"Auto-created {created} remediation tasks"}


@router.get("/stats/summary", response_model=dict)
async def remediation_stats(
    org_id: Optional[uuid.UUID] = Query(None),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Summary stats: counts by status, overdue count, completion rate, MTTR."""
    from sqlalchemy import text
    effective_org = str(org_id or current_user.org_id)
    result = await db.execute(
        text("""
            SELECT
                COUNT(*) FILTER (WHERE status = 'open') AS open_count,
                COUNT(*) FILTER (WHERE status = 'in_progress') AS in_progress,
                COUNT(*) FILTER (WHERE status = 'completed') AS completed,
                COUNT(*) FILTER (WHERE status = 'overdue' OR (due_date < NOW() AND status != 'completed')) AS overdue,
                COUNT(*) AS total,
                AVG(EXTRACT(EPOCH FROM (updated_at - created_at))/86400.0)
                    FILTER (WHERE status = 'completed') AS avg_days_to_complete
            FROM remediation_tasks
            WHERE org_id = :org_id
        """),
        {"org_id": effective_org},
    )
    row = result.fetchone()
    return {
        "open": int(row[0] or 0),
        "in_progress": int(row[1] or 0),
        "completed": int(row[2] or 0),
        "overdue": int(row[3] or 0),
        "total": int(row[4] or 0),
        "avg_days_to_complete": round(float(row[5] or 0), 1),
        "completion_rate": round(int(row[2] or 0) / max(int(row[4] or 1), 1) * 100, 1),
    }
