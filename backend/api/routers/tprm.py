"""TPRM (Third-Party Risk Management) router — vendor management and AI questionnaires."""
import uuid
from datetime import datetime, timezone
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from core.database import get_db
from core.security import get_current_user
from models.user import User
from core.config import settings

router = APIRouter()


class VendorCreate(BaseModel):
    name: str
    domain: Optional[str] = None
    contact_email: Optional[str] = None
    risk_tier: str = "medium"


class VendorUpdate(BaseModel):
    name: Optional[str] = None
    domain: Optional[str] = None
    contact_email: Optional[str] = None
    risk_tier: Optional[str] = None


@router.get("/vendors", response_model=dict)
async def list_vendors(
    org_id: Optional[uuid.UUID] = Query(None),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    effective_org = str(org_id or current_user.org_id)
    result = await db.execute(
        text("""
            SELECT v.*,
                   COUNT(DISTINCT sj.id) AS scan_count,
                   COUNT(DISTINCT f.id) FILTER (WHERE f.severity = 'critical') AS critical_findings,
                   COUNT(DISTINCT f.id) FILTER (WHERE f.severity = 'high') AS high_findings
            FROM vendors v
            LEFT JOIN assets a ON a.org_id = v.org_id AND a.value LIKE '%' || COALESCE(v.domain, '') || '%'
            LEFT JOIN scan_jobs sj ON sj.asset_id = a.id
            LEFT JOIN findings f ON f.asset_id = a.id AND f.status = 'open'
            WHERE v.org_id = :org_id
            GROUP BY v.id
            ORDER BY v.technical_risk_score DESC NULLS LAST, v.name
            LIMIT :limit OFFSET :offset
        """),
        {"org_id": effective_org, "limit": limit, "offset": (page - 1) * limit},
    )
    rows = result.fetchall()
    cols = result.keys()
    vendors = [dict(zip(cols, row)) for row in rows]
    for v in vendors:
        for k, val in v.items():
            if hasattr(val, 'isoformat'):
                v[k] = val.isoformat()
            elif isinstance(val, uuid.UUID):
                v[k] = str(val)
    count_res = await db.execute(
        text("SELECT COUNT(*) FROM vendors WHERE org_id = :org_id"),
        {"org_id": effective_org},
    )
    return {"vendors": vendors, "total": count_res.scalar(), "page": page, "limit": limit}


@router.post("/vendors", response_model=dict, status_code=201)
async def create_vendor(
    payload: VendorCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    vid = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    await db.execute(
        text("""
            INSERT INTO vendors (id, org_id, name, domain, contact_email, risk_tier, created_at, updated_at)
            VALUES (:id, :org_id, :name, :domain, :email, :risk_tier, :now, :now)
        """),
        {"id": vid, "org_id": str(current_user.org_id), "name": payload.name,
         "domain": payload.domain, "email": payload.contact_email,
         "risk_tier": payload.risk_tier, "now": now},
    )
    await db.commit()
    return {"id": vid, "message": "Vendor created"}


@router.get("/vendors/{vendor_id}", response_model=dict)
async def get_vendor(
    vendor_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        text("SELECT * FROM vendors WHERE id = :id AND org_id = :org_id"),
        {"id": str(vendor_id), "org_id": str(current_user.org_id)},
    )
    row = result.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Vendor not found")
    return {k: (str(v) if isinstance(v, uuid.UUID) else (v.isoformat() if hasattr(v, 'isoformat') else v))
            for k, v in zip(result.keys(), row)}


@router.patch("/vendors/{vendor_id}", response_model=dict)
async def update_vendor(
    vendor_id: uuid.UUID,
    payload: VendorUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    updates = {k: v for k, v in payload.dict(exclude_none=True).items()}
    if not updates:
        return {"id": str(vendor_id), "updated": False}
    updates["updated_at"] = datetime.now(timezone.utc)
    set_clause = ", ".join(f"{k} = :{k}" for k in updates)
    await db.execute(
        text(f"UPDATE vendors SET {set_clause} WHERE id = :vid AND org_id = :org_id"),
        {**updates, "vid": str(vendor_id), "org_id": str(current_user.org_id)},
    )
    await db.commit()
    return {"id": str(vendor_id), "updated": True}


@router.delete("/vendors/{vendor_id}", status_code=204)
async def delete_vendor(
    vendor_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    await db.execute(
        text("DELETE FROM vendors WHERE id = :id AND org_id = :org_id"),
        {"id": str(vendor_id), "org_id": str(current_user.org_id)},
    )
    await db.commit()


@router.post("/vendors/{vendor_id}/generate-questionnaire", response_model=dict)
async def generate_questionnaire(
    vendor_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate AI-powered security questionnaire based on vendor scan findings."""
    vendor_res = await db.execute(
        text("SELECT name, domain FROM vendors WHERE id = :id AND org_id = :org_id"),
        {"id": str(vendor_id), "org_id": str(current_user.org_id)},
    )
    vendor = vendor_res.fetchone()
    if not vendor:
        raise HTTPException(status_code=404, detail="Vendor not found")

    # Fetch findings for this vendor's domain
    findings_res = await db.execute(
        text("""
            SELECT f.title, f.severity, f.cve_id, f.affected_component, f.description
            FROM findings f
            JOIN assets a ON a.id = f.asset_id
            WHERE f.org_id = :org_id
              AND a.value LIKE :domain_pattern
              AND f.status NOT IN ('resolved', 'false_positive')
            ORDER BY f.severity DESC
            LIMIT 20
        """),
        {"org_id": str(current_user.org_id), "domain_pattern": f"%{vendor[1] or vendor[0]}%"},
    )
    findings = [
        {"title": r[0], "severity": r[1], "cve_id": r[2], "affected_component": r[3], "description": r[4]}
        for r in findings_res.fetchall()
    ]

    from services.claude_service import generate_vendor_questionnaire
    questions = await generate_vendor_questionnaire(vendor[0], findings)

    return {
        "vendor_id": str(vendor_id),
        "vendor_name": vendor[0],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "based_on_findings": len(findings),
        "questions": questions,
        "ai_powered": bool(settings.CLAUDE_API_KEY),
    }


@router.post("/vendors/{vendor_id}/evidence", response_model=dict)
async def upload_evidence(
    vendor_id: uuid.UUID,
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Upload evidence file (scan report, certificate) for vendor assessment."""
    import os, shutil
    evidence_dir = os.path.join(settings.SCAN_OUTPUT_DIR, "evidence", str(vendor_id))
    os.makedirs(evidence_dir, exist_ok=True)

    safe_name = file.filename.replace("..", "").replace("/", "_")
    dest = os.path.join(evidence_dir, safe_name)

    with open(dest, "wb") as f:
        shutil.copyfileobj(file.file, f)

    file_size = os.path.getsize(dest)
    return {
        "vendor_id": str(vendor_id),
        "filename": safe_name,
        "size_bytes": file_size,
        "path": dest,
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
        "message": "Evidence uploaded successfully",
    }


@router.get("/vendors/{vendor_id}/evidence", response_model=dict)
async def list_evidence(
    vendor_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    import os
    evidence_dir = os.path.join(settings.SCAN_OUTPUT_DIR, "evidence", str(vendor_id))
    if not os.path.exists(evidence_dir):
        return {"files": []}
    files = []
    for fname in os.listdir(evidence_dir):
        fpath = os.path.join(evidence_dir, fname)
        files.append({
            "filename": fname,
            "size_bytes": os.path.getsize(fpath),
            "uploaded_at": datetime.fromtimestamp(os.path.getmtime(fpath), tz=timezone.utc).isoformat(),
        })
    return {"vendor_id": str(vendor_id), "files": files}


# NIST CSF 2.0 / ISO 27001 compliance mapping
NIST_MAPPING = {
    "critical": {"function": "RS", "category": "RS.MI-1", "name": "Incidents are contained"},
    "high": {"function": "DE", "category": "DE.CM-8", "name": "Vulnerability scans are performed"},
    "medium": {"function": "PR", "category": "PR.IP-12", "name": "A vulnerability management plan is developed and implemented"},
    "low": {"function": "ID", "category": "ID.RA-1", "name": "Asset vulnerabilities are identified and documented"},
    "info": {"function": "ID", "category": "ID.AM-2", "name": "Software platforms and applications within the organization are inventoried"},
}

ISO_MAPPING = {
    "critical": {"control": "A.16.1.5", "name": "Response to information security incidents"},
    "high": {"control": "A.12.6.1", "name": "Management of technical vulnerabilities"},
    "medium": {"control": "A.14.2.3", "name": "Technical review of applications after OS changes"},
    "low": {"control": "A.18.2.3", "name": "Technical compliance review"},
    "info": {"control": "A.8.1.1", "name": "Inventory of assets"},
}


@router.get("/compliance/mapping", response_model=dict)
async def get_compliance_mapping(
    org_id: Optional[uuid.UUID] = Query(None),
    framework: str = Query("nist", regex="^(nist|iso|bob|dpa)$"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Map org findings to compliance framework controls."""
    effective_org = str(org_id or current_user.org_id)
    result = await db.execute(
        text("""
            SELECT f.id, f.title, f.severity, f.status, f.cve_id, a.value AS asset
            FROM findings f
            JOIN assets a ON a.id = f.asset_id
            WHERE f.org_id = :org_id
            ORDER BY f.severity DESC
            LIMIT 200
        """),
        {"org_id": effective_org},
    )
    rows = result.fetchall()

    mapped = []
    for row in rows:
        fid, title, severity, fstatus, cve, asset = row
        if framework == "nist":
            ctrl = NIST_MAPPING.get(severity, NIST_MAPPING["info"])
            mapped.append({
                "finding_id": str(fid), "title": title, "severity": severity,
                "status": fstatus, "asset": asset, "cve_id": cve,
                "function": ctrl["function"], "category": ctrl["category"],
                "control_name": ctrl["name"],
                "compliance_status": "non-compliant" if fstatus == "open" else "compliant",
            })
        elif framework == "iso":
            ctrl = ISO_MAPPING.get(severity, ISO_MAPPING["info"])
            mapped.append({
                "finding_id": str(fid), "title": title, "severity": severity,
                "status": fstatus, "asset": asset, "cve_id": cve,
                "annex_control": ctrl["control"], "control_name": ctrl["name"],
                "compliance_status": "non-compliant" if fstatus == "open" else "compliant",
            })

    return {
        "framework": framework,
        "total_findings": len(mapped),
        "non_compliant": sum(1 for m in mapped if m.get("compliance_status") == "non-compliant"),
        "mappings": mapped,
    }
