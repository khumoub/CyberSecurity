"""User management and API key endpoints."""
import uuid, secrets, hashlib
from datetime import datetime, timezone
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text
from core.database import get_db
from core.security import get_current_user, get_password_hash
from models.user import User

router = APIRouter()

VALID_ROLES = ("admin", "analyst", "junior_analyst", "tprm_manager", "read_only")


# ── Schemas ────────────────────────────────────────────────────────────────────

class InviteUserRequest(BaseModel):
    email: str
    full_name: str
    role: str = "analyst"
    send_email: bool = True


class UpdateRoleRequest(BaseModel):
    role: str


class UpdateActiveRequest(BaseModel):
    is_active: bool


class CreateApiKeyRequest(BaseModel):
    name: str
    scopes: List[str] = ["scan:read", "finding:read"]


# ── Users ──────────────────────────────────────────────────────────────────────

@router.get("/")
async def list_users(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all users in the organization."""
    result = await db.execute(
        select(User)
        .where(User.org_id == current_user.org_id)
        .order_by(User.created_at)
    )
    users = result.scalars().all()
    return {
        "users": [
            {
                "id": str(u.id),
                "email": u.email,
                "full_name": u.full_name,
                "role": u.role,
                "is_active": u.is_active,
                "last_login": u.last_login.isoformat() if u.last_login else None,
                "created_at": u.created_at.isoformat(),
            }
            for u in users
        ]
    }


@router.post("/invite", status_code=201)
async def invite_user(
    req: InviteUserRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Invite a new user to the organization (creates account with temp password)."""
    if current_user.role not in ("admin",):
        raise HTTPException(status_code=403, detail="Only admins can invite users")
    if req.role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail=f"Invalid role. Must be one of: {VALID_ROLES}")

    existing = await db.execute(select(User).where(User.email == req.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="User with this email already exists")

    temp_password = secrets.token_urlsafe(12)
    new_user = User(
        org_id=current_user.org_id,
        email=req.email,
        full_name=req.full_name,
        role=req.role,
        hashed_password=get_password_hash(temp_password),
        is_active=True,
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    # Send invitation email if Resend configured
    if req.send_email:
        try:
            from core.config import settings
            if settings.RESEND_API_KEY:
                import resend
                resend.api_key = settings.RESEND_API_KEY
                resend.Emails.send({
                    "from": settings.EMAIL_FROM,
                    "to": [req.email],
                    "subject": "You've been invited to Leruo Security Platform",
                    "html": f"""
                        <h2>Welcome to Leruo Security Platform</h2>
                        <p>You have been invited by {current_user.full_name}.</p>
                        <p><b>Email:</b> {req.email}<br>
                        <b>Temporary Password:</b> {temp_password}</p>
                        <p>Please log in and change your password immediately.</p>
                    """,
                })
        except Exception:
            pass  # Don't fail invitation if email fails

    return {
        "id": str(new_user.id),
        "email": new_user.email,
        "full_name": new_user.full_name,
        "role": new_user.role,
        "temp_password": temp_password,
        "message": "User invited successfully",
    }


@router.patch("/{user_id}/role")
async def update_user_role(
    user_id: uuid.UUID,
    req: UpdateRoleRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update a user's role (admin only)."""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admins can change roles")
    if req.role not in VALID_ROLES:
        raise HTTPException(status_code=400, detail=f"Invalid role")

    result = await db.execute(
        select(User).where(User.id == user_id, User.org_id == current_user.org_id)
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.role = req.role
    user.updated_at = datetime.now(timezone.utc)
    await db.commit()
    return {"id": str(user.id), "role": user.role}


@router.patch("/{user_id}/active")
async def toggle_user_active(
    user_id: uuid.UUID,
    req: UpdateActiveRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Enable or disable a user (admin only)."""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admins can enable/disable users")

    result = await db.execute(
        select(User).where(User.id == user_id, User.org_id == current_user.org_id)
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot disable your own account")

    user.is_active = req.is_active
    user.updated_at = datetime.now(timezone.utc)
    await db.commit()
    return {"id": str(user.id), "is_active": user.is_active}


@router.delete("/{user_id}")
async def remove_user(
    user_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove a user from the organization (admin only)."""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admins can remove users")
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot remove your own account")

    result = await db.execute(
        select(User).where(User.id == user_id, User.org_id == current_user.org_id)
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    await db.delete(user)
    await db.commit()
    return {"message": "User removed"}


# ── API Keys ───────────────────────────────────────────────────────────────────

@router.get("/api-keys")
async def list_api_keys(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List API keys for the organization."""
    result = await db.execute(
        text("""
            SELECT id, name, key_prefix, scopes, created_at, last_used_at, is_active
              FROM api_keys
             WHERE org_id = :org_id
          ORDER BY created_at DESC
        """),
        {"org_id": str(current_user.org_id)},
    )
    rows = result.mappings().all()
    return {
        "api_keys": [
            {
                "id": str(r["id"]),
                "name": r["name"],
                "prefix": r["key_prefix"],
                "scopes": r["scopes"] or [],
                "created_at": r["created_at"].isoformat() if r["created_at"] else None,
                "last_used_at": r["last_used_at"].isoformat() if r["last_used_at"] else None,
                "is_active": r["is_active"],
            }
            for r in rows
        ]
    }


@router.post("/api-keys", status_code=201)
async def create_api_key(
    req: CreateApiKeyRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a new API key (shown once, then only prefix stored)."""
    raw_key   = f"lrsk_live_{secrets.token_urlsafe(32)}"
    key_hash  = hashlib.sha256(raw_key.encode()).hexdigest()
    key_prefix = raw_key[:20] + "..."

    # Ensure table exists (graceful degradation)
    await db.execute(text("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            org_id UUID NOT NULL,
            user_id UUID NOT NULL,
            name VARCHAR(255) NOT NULL,
            key_hash VARCHAR(64) UNIQUE NOT NULL,
            key_prefix VARCHAR(30) NOT NULL,
            scopes TEXT[],
            is_active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            last_used_at TIMESTAMPTZ
        )
    """))
    await db.execute(
        text("""
            INSERT INTO api_keys (org_id, user_id, name, key_hash, key_prefix, scopes)
            VALUES (:org_id, :user_id, :name, :key_hash, :key_prefix, :scopes)
        """),
        {
            "org_id":     str(current_user.org_id),
            "user_id":    str(current_user.id),
            "name":       req.name,
            "key_hash":   key_hash,
            "key_prefix": key_prefix,
            "scopes":     req.scopes,
        },
    )
    await db.commit()
    return {
        "key": raw_key,
        "prefix": key_prefix,
        "name": req.name,
        "scopes": req.scopes,
        "message": "Save this key — it will not be shown again.",
    }


@router.delete("/api-keys/{key_id}")
async def revoke_api_key(
    key_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Revoke (delete) an API key."""
    await db.execute(
        text("DELETE FROM api_keys WHERE id = :id AND org_id = :org_id"),
        {"id": key_id, "org_id": str(current_user.org_id)},
    )
    await db.commit()
    return {"message": "API key revoked"}
