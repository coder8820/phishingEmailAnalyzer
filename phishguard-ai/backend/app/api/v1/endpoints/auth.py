"""
PhishGuard AI — Authentication API Endpoint
"""
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, field_validator
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.models import User, RefreshToken, AuditLog, Organization
from app.security.auth import (
    create_access_token,
    create_refresh_token,
    get_current_user,
    hash_password,
    verify_password,
)

router = APIRouter()
logger = structlog.get_logger(__name__)


class LoginRequest(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def sanitize_email(cls, v: str) -> str:
        return v.strip().lower()


class RegisterRequest(BaseModel):
    email: str
    password: str
    username: Optional[str] = None
    display_name: Optional[str] = None
    organization_name: Optional[str] = None

    @field_validator("email")
    @classmethod
    def sanitize_email(cls, v: str) -> str:
        cleaned = v.strip().lower()
        if "@" not in cleaned or len(cleaned) < 3:
            raise ValueError("Invalid email format")
        return cleaned

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v


class RefreshRequest(BaseModel):
    refresh_token: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v


async def _write_audit_log(
    db: AsyncSession,
    action: str,
    user: Optional[User],
    request: Request,
    details: dict,
    severity: str = "info",
) -> None:
    try:
        log = AuditLog(
            organization_id=user.organization_id if user else None,
            user_id=user.id if user else None,
            action=action,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("User-Agent"),
            request_id=getattr(request.state, "request_id", None),
            details=details,
            severity=severity,
        )
        db.add(log)
        await db.flush()
    except Exception as e:
        logger.warning("audit_log_failed", error=str(e), action=action)


@router.post("/register", response_model=dict, summary="Register a new analyst account")
async def register(
    request: Request,
    body: RegisterRequest,
    db: AsyncSession = Depends(get_db),
) -> dict:
    existing = await db.execute(
        select(User).where(User.email == body.email)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email address already exists"
        )

    # Derive username if omitted
    username = body.username.strip() if body.username else body.email.split("@")[0]
    uname_check = await db.execute(select(User).where(User.username == username))
    if uname_check.scalar_one_or_none():
        import secrets
        username = f"{username}_{secrets.token_hex(3)}"

    display_name = body.display_name.strip() if body.display_name else username

    # Get or create organization
    org_name = body.organization_name.strip() if body.organization_name else "Default SOC Team"
    org_slug = org_name.lower().replace(" ", "-")[:50]
    org_result = await db.execute(select(Organization).where(Organization.slug == org_slug))
    org = org_result.scalar_one_or_none()
    if not org:
        any_org = await db.execute(select(Organization).limit(1))
        org = any_org.scalar_one_or_none()
        if not org:
            org = Organization(
                name=org_name,
                slug=org_slug,
                plan="free",
                is_active=True,
            )
            db.add(org)
            await db.flush()

    new_user = User(
        organization_id=org.id,
        email=body.email,
        username=username,
        display_name=display_name,
        hashed_password=hash_password(body.password),
        role="analyst",
        is_active=True,
        is_email_verified=True,
    )
    db.add(new_user)
    await db.flush()

    raw_refresh, hashed_refresh = create_refresh_token()
    refresh_expires = datetime.now(timezone.utc) + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)

    db.add(RefreshToken(
        user_id=new_user.id,
        token_hash=hashed_refresh,
        expires_at=refresh_expires,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("User-Agent"),
    ))

    access_token = create_access_token(str(new_user.id), str(new_user.organization_id), new_user.role)
    await _write_audit_log(db, "user.registered", new_user, request, {"email": body.email})

    return {
        "success": True,
        "data": {
            "access_token": access_token,
            "refresh_token": raw_refresh,
            "token_type": "bearer",
            "user": {
                "id": str(new_user.id),
                "email": new_user.email,
                "username": new_user.username,
                "display_name": new_user.display_name,
                "role": new_user.role,
                "organization_id": str(new_user.organization_id),
            }
        },
        "error": None,
    }


@router.post("/login", response_model=dict, summary="Authenticate user")
async def login(
    request: Request,
    body: LoginRequest,
    db: AsyncSession = Depends(get_db),
) -> dict:
    result = await db.execute(
        select(User).where(User.email == body.email, User.deleted_at.is_(None))
    )
    user = result.scalar_one_or_none()

    if user and user.locked_until:
        locked_until = user.locked_until
        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)
        if locked_until > datetime.now(timezone.utc):
            await _write_audit_log(db, "user.login_locked", user, request, {"email": body.email}, "warning")
            raise HTTPException(status_code=status.HTTP_423_LOCKED, detail="Account temporarily locked")

    password_ok = user is not None and verify_password(body.password, user.hashed_password)

    if not password_ok:
        if user:
            new_count = (user.failed_login_count or 0) + 1
            updates: dict = {"failed_login_count": new_count}
            if new_count >= settings.ACCOUNT_LOCKOUT_ATTEMPTS:
                lock_until = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCOUNT_LOCKOUT_DURATION_MINUTES)
                updates["locked_until"] = lock_until
            await db.execute(update(User).where(User.id == user.id).values(**updates))
            await _write_audit_log(db, "user.login_failed", user, request, {"attempts": new_count}, "warning")
            await db.commit()

        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Account disabled")

    raw_refresh, hashed_refresh = create_refresh_token()
    refresh_expires = datetime.now(timezone.utc) + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)

    await db.execute(
        update(User).where(User.id == user.id).values(
            failed_login_count=0, locked_until=None, last_login_at=datetime.now(timezone.utc)
        )
    )

    db.add(RefreshToken(
        user_id=user.id,
        token_hash=hashed_refresh,
        expires_at=refresh_expires,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("User-Agent"),
    ))

    access_token = create_access_token(str(user.id), str(user.organization_id), user.role)
    await _write_audit_log(db, "user.login_success", user, request, {})

    return {
        "success": True,
        "data": {"access_token": access_token, "refresh_token": raw_refresh, "token_type": "bearer"},
        "error": None,
    }


@router.post("/refresh", response_model=dict, summary="Rotate refresh token")
async def refresh_token(request: Request, body: RefreshRequest, db: AsyncSession = Depends(get_db)) -> dict:
    token_hash = hashlib.sha256(body.refresh_token.encode()).hexdigest()
    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.token_hash == token_hash,
            RefreshToken.revoked_at.is_(None),
            RefreshToken.expires_at > datetime.now(timezone.utc),
        )
    )
    token_record = result.scalar_one_or_none()
    if not token_record:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token")

    await db.execute(
        update(RefreshToken).where(RefreshToken.id == token_record.id).values(revoked_at=datetime.now(timezone.utc))
    )

    user_result = await db.execute(select(User).where(User.id == token_record.user_id, User.is_active == True))
    user = user_result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    raw_refresh, hashed_refresh = create_refresh_token()
    db.add(RefreshToken(
        user_id=user.id,
        token_hash=hashed_refresh,
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS),
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("User-Agent"),
    ))

    access_token = create_access_token(str(user.id), str(user.organization_id), user.role)
    return {"success": True, "data": {"access_token": access_token, "refresh_token": raw_refresh, "token_type": "bearer"}, "error": None}


@router.post("/logout", response_model=dict, summary="Revoke refresh token")
async def logout(request: Request, body: RefreshRequest, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)) -> dict:
    token_hash = hashlib.sha256(body.refresh_token.encode()).hexdigest()
    await db.execute(
        update(RefreshToken).where(
            RefreshToken.token_hash == token_hash, RefreshToken.user_id == current_user.id
        ).values(revoked_at=datetime.now(timezone.utc))
    )
    await _write_audit_log(db, "user.logout", current_user, request, {})
    return {"success": True, "data": {"message": "Logged out successfully"}, "error": None}


@router.get("/me", response_model=dict, summary="Get current user profile")
async def get_me(current_user: User = Depends(get_current_user)) -> dict:
    return {
        "success": True,
        "data": {
            "id": str(current_user.id), "email": current_user.email, "username": current_user.username,
            "display_name": current_user.display_name, "role": current_user.role,
            "organization_id": str(current_user.organization_id),
            "last_login_at": current_user.last_login_at.isoformat() if current_user.last_login_at else None,
            "created_at": current_user.created_at.isoformat(),
        },
        "error": None,
    }


@router.put("/me/password", response_model=dict, summary="Change own password")
async def change_password(request: Request, body: ChangePasswordRequest, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)) -> dict:
    if not verify_password(body.current_password, current_user.hashed_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect")
    await db.execute(
        update(User).where(User.id == current_user.id).values(
            hashed_password=hash_password(body.new_password),
            password_changed_at=datetime.now(timezone.utc),
        )
    )
    await _write_audit_log(db, "user.password_changed", current_user, request, {})
    return {"success": True, "data": {"message": "Password updated successfully"}, "error": None}


@router.post("/forgot-password", response_model=dict, summary="Initiate password reset")
async def forgot_password(body: dict) -> dict:
    # Always return 200 to prevent email enumeration
    return {"success": True, "data": {"message": "If that email exists, a reset link has been sent."}, "error": None}


@router.post("/reset-password", response_model=dict)
async def reset_password(body: dict) -> dict:
    raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Configure SMTP to enable password reset")
