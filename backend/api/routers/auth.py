import uuid
import re
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from core.database import get_db
from core.security import (
    get_password_hash,
    verify_password,
    create_access_token,
    create_refresh_token,
    verify_token,
    get_current_user,
)
from models.organization import Organization
from models.user import User
from api.schemas.auth import (
    LoginRequest,
    LoginResponse,
    RegisterRequest,
    TokenRefresh,
    TokenResponse,
    UserResponse,
)

router = APIRouter()


@router.post("/login", response_model=LoginResponse)
async def login(request: LoginRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == request.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(request.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )

    user.last_login = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(user)

    access_token = create_access_token(data={"sub": str(user.id), "org_id": str(user.org_id)})
    refresh_token = create_refresh_token(data={"sub": str(user.id), "org_id": str(user.org_id)})

    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user=UserResponse.model_validate(user),
    )


@router.post("/register", response_model=LoginResponse, status_code=status.HTTP_201_CREATED)
async def register(request: RegisterRequest, db: AsyncSession = Depends(get_db)):
    # Check email uniqueness
    existing = await db.execute(select(User).where(User.email == request.email))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    # Check slug uniqueness
    slug_check = await db.execute(
        select(Organization).where(Organization.slug == request.org_slug)
    )
    if slug_check.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Organization slug already taken",
        )

    # Create organization
    org = Organization(
        id=uuid.uuid4(),
        name=request.org_name,
        slug=request.org_slug,
        plan="community",
    )
    db.add(org)
    await db.flush()

    # Create admin user
    user = User(
        id=uuid.uuid4(),
        org_id=org.id,
        email=request.email,
        hashed_password=get_password_hash(request.password),
        full_name=request.full_name,
        role="admin",
        is_active=True,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    access_token = create_access_token(data={"sub": str(user.id), "org_id": str(user.org_id)})
    refresh_token = create_refresh_token(data={"sub": str(user.id), "org_id": str(user.org_id)})

    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user=UserResponse.model_validate(user),
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(request: TokenRefresh, db: AsyncSession = Depends(get_db)):
    payload = verify_token(request.refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
        )

    user_id = payload.get("sub")
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    access_token = create_access_token(data={"sub": str(user.id), "org_id": str(user.org_id)})
    return TokenResponse(access_token=access_token)


@router.post("/logout")
async def logout(current_user: User = Depends(get_current_user)):
    # In a production system, you would add the token to a blocklist in Redis
    # For now we return a success response — client should discard tokens
    return {"message": "Successfully logged out"}


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    return UserResponse.model_validate(current_user)


class OrgUpdateRequest(BaseModel):
    name: Optional[str] = None
    domain: Optional[str] = None
    timezone: Optional[str] = None


from pydantic import BaseModel
from typing import Optional


@router.patch("/organization")
async def update_organization(
    body: OrgUpdateRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update organization settings (name, domain, timezone)."""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")

    result = await db.execute(
        select(Organization).where(Organization.id == current_user.org_id)
    )
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    if body.name is not None:
        org.name = body.name
    if body.domain is not None:
        org.domain = body.domain
    if body.timezone is not None:
        org.timezone = body.timezone

    await db.commit()
    await db.refresh(org)
    return {"id": str(org.id), "name": org.name, "domain": getattr(org, "domain", None), "timezone": getattr(org, "timezone", None)}
