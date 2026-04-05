import uuid
import json
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
import redis as redis_lib
from core.database import get_db
from core.security import get_current_user, verify_token
from core.config import settings
from models.scan_job import ScanJob
from models.finding import Finding
from models.user import User
from api.schemas.scan import CreateScanRequest, ScanJobResponse, ScanOutputResponse
from api.schemas.finding import FindingResponse

router = APIRouter()

TASK_MAP = {
    "nmap": "worker.tasks.nmap_task.run_nmap",
    "nuclei": "worker.tasks.nuclei_task.run_nuclei",
    "nikto": "worker.tasks.nikto_task.run_nikto",
    "ssl": "worker.tasks.ssl_task.run_sslscan",
    "subdomain": "worker.tasks.subdomain_task.run_subdomain_enum",
    "dns": "worker.tasks.dns_task.run_dns_analysis",
    "headers": "worker.tasks.headers_task.check_headers",
    "sqlmap": "worker.tasks.sqlmap_task.run_sqlmap",
    "gobuster": "worker.tasks.gobuster_task.run_gobuster",
    "masscan": "worker.tasks.masscan_task.run_masscan",
    "whatweb": "worker.tasks.whatweb_task.run_whatweb",
    "wpscan": "worker.tasks.wpscan_task.run_wpscan",
}


@router.post("/", response_model=ScanJobResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    request: CreateScanRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    from worker.celery_app import celery_app

    scan_id = uuid.uuid4()
    scan_job = ScanJob(
        id=scan_id,
        org_id=current_user.org_id,
        asset_id=request.asset_id,
        scan_type=request.scan_type.value,
        status="pending",
        target=request.target,
        options=request.options or {},
        initiated_by=current_user.id,
    )
    db.add(scan_job)
    await db.flush()

    task_name = TASK_MAP.get(request.scan_type.value)
    if not task_name:
        raise HTTPException(status_code=400, detail=f"Unknown scan type: {request.scan_type}")

    task = celery_app.send_task(
        task_name,
        args=[
            str(scan_id),
            str(current_user.org_id),
            str(request.asset_id) if request.asset_id else None,
            request.target,
            request.options or {},
        ],
        queue="scans",
    )

    scan_job.celery_task_id = task.id
    await db.commit()
    await db.refresh(scan_job)
    return ScanJobResponse.model_validate(scan_job)


@router.get("/", response_model=dict)
async def list_scans(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    scan_status: Optional[str] = Query(None, alias="status"),
    scan_type: Optional[str] = Query(None),
    asset_id: Optional[uuid.UUID] = Query(None),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    filters = [ScanJob.org_id == current_user.org_id]
    if scan_status:
        filters.append(ScanJob.status == scan_status)
    if scan_type:
        filters.append(ScanJob.scan_type == scan_type)
    if asset_id:
        filters.append(ScanJob.asset_id == asset_id)

    count_q = await db.execute(select(func.count(ScanJob.id)).where(and_(*filters)))
    total = count_q.scalar_one()

    result = await db.execute(
        select(ScanJob)
        .where(and_(*filters))
        .order_by(ScanJob.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    scans = result.scalars().all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [ScanJobResponse.model_validate(s) for s in scans],
    }


@router.get("/{scan_id}", response_model=ScanJobResponse)
async def get_scan(
    scan_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ScanJob).where(
            ScanJob.id == scan_id, ScanJob.org_id == current_user.org_id
        )
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return ScanJobResponse.model_validate(scan)


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def cancel_scan(
    scan_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    from worker.celery_app import celery_app

    result = await db.execute(
        select(ScanJob).where(
            ScanJob.id == scan_id, ScanJob.org_id == current_user.org_id
        )
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan job not found")

    if scan.celery_task_id:
        celery_app.control.revoke(scan.celery_task_id, terminate=True)

    scan.status = "cancelled"
    await db.commit()


@router.get("/{scan_id}/findings", response_model=dict)
async def get_scan_findings(
    scan_id: uuid.UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # Verify scan belongs to org
    scan_result = await db.execute(
        select(ScanJob).where(
            ScanJob.id == scan_id, ScanJob.org_id == current_user.org_id
        )
    )
    if not scan_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Scan job not found")

    filters = [Finding.scan_id == scan_id, Finding.org_id == current_user.org_id]
    if severity:
        filters.append(Finding.severity == severity)

    count_q = await db.execute(select(func.count(Finding.id)).where(and_(*filters)))
    total = count_q.scalar_one()

    result = await db.execute(
        select(Finding)
        .where(and_(*filters))
        .order_by(Finding.severity, Finding.created_at.desc())
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


@router.get("/{scan_id}/output", response_model=ScanOutputResponse)
async def get_scan_output(
    scan_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ScanJob).where(
            ScanJob.id == scan_id, ScanJob.org_id == current_user.org_id
        )
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return ScanOutputResponse(scan_id=scan_id, raw_output=scan.raw_output)


@router.websocket("/{scan_id}/stream")
async def stream_scan_output(
    websocket: WebSocket,
    scan_id: str,
):
    """WebSocket endpoint to stream live scan output via Redis pub/sub."""
    await websocket.accept()

    # Authenticate via query param token
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=4001, reason="Missing token")
        return

    try:
        payload = verify_token(token)
        if payload.get("type") != "access":
            await websocket.close(code=4001, reason="Invalid token")
            return
    except Exception:
        await websocket.close(code=4001, reason="Invalid token")
        return

    r = redis_lib.Redis.from_url(settings.REDIS_URL, decode_responses=True)
    pubsub = r.pubsub()
    channel = f"scan_output:{scan_id}"
    pubsub.subscribe(channel)

    try:
        for message in pubsub.listen():
            if message["type"] == "message":
                data = message["data"]
                await websocket.send_text(data)
                try:
                    parsed = json.loads(data)
                    if parsed.get("type") == "status" and parsed.get("status") in (
                        "completed",
                        "failed",
                        "cancelled",
                    ):
                        break
                except Exception:
                    pass
    except WebSocketDisconnect:
        pass
    finally:
        pubsub.unsubscribe(channel)
        pubsub.close()
        r.close()

    await websocket.close()
