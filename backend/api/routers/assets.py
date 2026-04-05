import uuid
import ipaddress
import csv
import io
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from core.database import get_db
from core.security import get_current_user
from models.asset import Asset
from models.finding import Finding
from models.user import User
from api.schemas.asset import (
    CreateAssetRequest,
    UpdateAssetRequest,
    AssetResponse,
    BulkImportRequest,
)
from api.schemas.finding import FindingResponse

router = APIRouter()


@router.get("/", response_model=dict)
async def list_assets(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    type: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(None),
    search: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    filters = [Asset.org_id == current_user.org_id]
    if type:
        filters.append(Asset.type == type)
    if is_active is not None:
        filters.append(Asset.is_active == is_active)
    if search:
        filters.append(
            Asset.name.ilike(f"%{search}%") | Asset.value.ilike(f"%{search}%")
        )

    count_q = await db.execute(select(func.count(Asset.id)).where(and_(*filters)))
    total = count_q.scalar_one()

    result = await db.execute(
        select(Asset)
        .where(and_(*filters))
        .order_by(Asset.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    assets = result.scalars().all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [AssetResponse.model_validate(a) for a in assets],
    }


@router.post("/", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
async def create_asset(
    request: CreateAssetRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    asset = Asset(
        id=uuid.uuid4(),
        org_id=current_user.org_id,
        name=request.name,
        type=request.type.value,
        value=request.value,
        os=request.os,
        os_version=request.os_version,
        tags=request.tags or [],
        metadata_=request.metadata or {},
        is_active=True,
    )
    db.add(asset)
    await db.commit()
    await db.refresh(asset)
    return AssetResponse.model_validate(asset)


@router.post("/import", response_model=dict, status_code=status.HTTP_201_CREATED)
async def bulk_import_assets(
    request: BulkImportRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    created = []

    if request.cidr:
        try:
            network = ipaddress.ip_network(request.cidr, strict=False)
            for ip in network.hosts():
                asset = Asset(
                    id=uuid.uuid4(),
                    org_id=current_user.org_id,
                    name=str(ip),
                    type="ip",
                    value=str(ip),
                    tags=request.tags or [],
                    is_active=True,
                )
                db.add(asset)
                created.append(str(ip))
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"Invalid CIDR: {e}")

    elif request.targets:
        for target in request.targets:
            asset = Asset(
                id=uuid.uuid4(),
                org_id=current_user.org_id,
                name=target,
                type=request.type.value,
                value=target,
                tags=request.tags or [],
                is_active=True,
            )
            db.add(asset)
            created.append(target)

    elif request.csv_data:
        reader = csv.DictReader(io.StringIO(request.csv_data))
        for row in reader:
            name = row.get("name") or row.get("value", "")
            value = row.get("value") or row.get("ip") or row.get("domain", "")
            asset_type = row.get("type", request.type.value)
            if not value:
                continue
            asset = Asset(
                id=uuid.uuid4(),
                org_id=current_user.org_id,
                name=name or value,
                type=asset_type,
                value=value,
                tags=request.tags or [],
                is_active=True,
            )
            db.add(asset)
            created.append(value)

    await db.commit()
    return {"created": len(created), "targets": created}


@router.get("/{asset_id}", response_model=AssetResponse)
async def get_asset(
    asset_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Asset).where(Asset.id == asset_id, Asset.org_id == current_user.org_id)
    )
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    # Get findings counts
    count_result = await db.execute(
        select(func.count(Finding.id)).where(Finding.asset_id == asset_id)
    )
    findings_count = count_result.scalar_one()

    response = AssetResponse.model_validate(asset)
    response.findings_count = findings_count
    return response


@router.put("/{asset_id}", response_model=AssetResponse)
async def update_asset(
    asset_id: uuid.UUID,
    request: UpdateAssetRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Asset).where(Asset.id == asset_id, Asset.org_id == current_user.org_id)
    )
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    update_data = request.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        if field == "metadata":
            setattr(asset, "metadata_", value)
        elif field == "type" and value is not None:
            setattr(asset, "type", value.value if hasattr(value, "value") else value)
        else:
            setattr(asset, field, value)

    await db.commit()
    await db.refresh(asset)
    return AssetResponse.model_validate(asset)


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_asset(
    asset_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Asset).where(Asset.id == asset_id, Asset.org_id == current_user.org_id)
    )
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    # Soft delete
    asset.is_active = False
    await db.commit()


@router.get("/{asset_id}/findings", response_model=dict)
async def get_asset_findings(
    asset_id: uuid.UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # Verify asset belongs to org
    asset_result = await db.execute(
        select(Asset).where(Asset.id == asset_id, Asset.org_id == current_user.org_id)
    )
    if not asset_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Asset not found")

    filters = [Finding.asset_id == asset_id, Finding.org_id == current_user.org_id]
    if severity:
        filters.append(Finding.severity == severity)
    if status:
        filters.append(Finding.status == status)

    count_q = await db.execute(select(func.count(Finding.id)).where(and_(*filters)))
    total = count_q.scalar_one()

    result = await db.execute(
        select(Finding)
        .where(and_(*filters))
        .order_by(Finding.created_at.desc())
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
