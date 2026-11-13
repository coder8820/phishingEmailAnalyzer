"""
PhishGuard AI — Security Core
JWT, password hashing (Argon2id), RBAC enforcement.
"""
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

import structlog
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.models import User

logger = structlog.get_logger(__name__)

# ---- Password Hashing ----
try:
    import argon2  # noqa: F401
    pwd_context = CryptContext(
        schemes=["argon2", "bcrypt"],
        deprecated="auto",
        argon2__memory_cost=65536,  # 64 MB
        argon2__time_cost=3,
        argon2__parallelism=4,
    )
except ImportError:
    pwd_context = CryptContext(
        schemes=["bcrypt"],
        deprecated="auto",
    )

bearer_scheme = HTTPBearer(auto_error=False)

# ---- Role Hierarchy ----
ROLE_WEIGHTS = {
    "viewer": 0,
    "analyst": 1,
    "security_admin": 2,
    "super_admin": 3,
}


def hash_password(password: str) -> str:
    """Hash password using Argon2id."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against Argon2id hash."""
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(user_id: str, organization_id: str, role: str) -> str:
    """Create a short-lived JWT access token (15 min default)."""
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": user_id,
        "org": organization_id,
        "role": role,
        "type": "access",
        "iat": now,
        "exp": expire,
    }
    return jwt.encode(payload, settings.APP_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token() -> tuple[str, str]:
    """Create a secure refresh token. Returns (raw_token, hashed_token)."""
    raw = secrets.token_urlsafe(64)
    hashed = hashlib.sha256(raw.encode()).hexdigest()
    return raw, hashed


def decode_access_token(token: str) -> dict:
    """Decode and validate a JWT access token. Raises JWTError on failure."""
    return jwt.decode(token, settings.APP_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])


# ---- FastAPI Dependencies ----

async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Extract and validate the current user from Bearer token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not credentials:
        raise credentials_exception

    try:
        payload = decode_access_token(credentials.credentials)
        user_id: str = payload.get("sub")
        token_type: str = payload.get("type")
        if not user_id or token_type != "access":
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    # Fetch user from DB (validates they still exist and are active)
    result = await db.execute(
        select(User).where(
            User.id == UUID(user_id),
            User.is_active == True,
            User.deleted_at == None,
        )
    )
    user = result.scalar_one_or_none()
    if not user:
        raise credentials_exception

    # Inject for audit middleware
    request.state.current_user = user
    return user


def require_role(minimum_role: str):
    """
    FastAPI dependency factory: require a minimum role level.
    Enforces authorization on the BACKEND — never trust frontend claims.
    """
    async def role_checker(current_user: User = Depends(get_current_user)) -> User:
        user_weight = ROLE_WEIGHTS.get(current_user.role, -1)
        required_weight = ROLE_WEIGHTS.get(minimum_role, 999)
        if user_weight < required_weight:
            logger.warning(
                "authorization_denied",
                user_id=str(current_user.id),
                user_role=current_user.role,
                required_role=minimum_role,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires role: {minimum_role}",
            )
        return current_user
    return role_checker


# Convenience dependencies
require_viewer = require_role("viewer")
require_analyst = require_role("analyst")
require_admin = require_role("security_admin")
require_super_admin = require_role("super_admin")
