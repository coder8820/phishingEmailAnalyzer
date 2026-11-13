"""
User Management API Endpoints for PhishGuard AI.
Admin-only controls: listing organization users, creating users, toggling active status, and account lockout.
"""
import uuid
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models import User
from app.security.auth import get_current_user, require_role, hash_password
from app.utils.response import success_response, paginated_response

router = APIRouter()


class CreateUserRequest(BaseModel):
    email: EmailStr
    username: str
    password: str
    display_name: Optional[str] = None
    role: str = "analyst"  # viewer | analyst | security_admin | super_admin


class UpdateUserRequest(BaseModel):
    display_name: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None


@router.get("", summary="List users in current organization")
async def list_users(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: User = Depends(require_role("security_admin")),
    db: AsyncSession = Depends(get_db),
):
    query = (
        select(User)
        .where(
            User.organization_id == current_user.organization_id,
            User.deleted_at.is_(None),
        )
        .order_by(desc(User.created_at))
    )
    count_res = await db.execute(
        select(User).where(
            User.organization_id == current_user.organization_id,
            User.deleted_at.is_(None),
        )
    )
    total = len(count_res.scalars().all())

    query = query.offset((page - 1) * page_size).limit(page_size)
    res = await db.execute(query)
    users = res.scalars().all()

    items = [
        {
            "id": str(u.id),
            "email": u.email,
            "username": u.username,
            "display_name": u.display_name,
            "role": u.role,
            "is_active": u.is_active,
            "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
            "created_at": u.created_at.isoformat() if u.created_at else None,
        }
        for u in users
    ]
    return paginated_response(items, total, page, page_size)


@router.post("", summary="Create a new user in organization")
async def create_user(
    body: CreateUserRequest,
    current_user: User = Depends(require_role("security_admin")),
    db: AsyncSession = Depends(get_db),
):
    # Check duplicate email
    existing_res = await db.execute(select(User).where(User.email == body.email))
    if existing_res.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

    new_user = User(
        organization_id=current_user.organization_id,
        email=body.email,
        username=body.username,
        display_name=body.display_name or body.username,
        hashed_password=hash_password(body.password),
        role=body.role,
        is_active=True,
    )
    db.add(new_user)
    await db.commit()
    return success_response({
        "id": str(new_user.id),
        "email": new_user.email,
        "username": new_user.username,
        "role": new_user.role,
    }, status_code=status.HTTP_201_CREATED)


@router.put("/{id}", summary="Update user profile or status")
async def update_user(
    id: uuid.UUID,
    body: UpdateUserRequest,
    current_user: User = Depends(require_role("security_admin")),
    db: AsyncSession = Depends(get_db),
):
    res = await db.execute(
        select(User).where(
            User.id == id,
            User.organization_id == current_user.organization_id,
            User.deleted_at.is_(None),
        )
    )
    user = res.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if body.display_name is not None:
        user.display_name = body.display_name
    if body.role is not None:
        user.role = body.role
    if body.is_active is not None:
        user.is_active = body.is_active

    await db.commit()
    return success_response({"id": str(user.id), "is_active": user.is_active, "role": user.role})


@router.delete("/{id}", summary="Soft delete a user")
async def delete_user(
    id: uuid.UUID,
    current_user: User = Depends(require_role("super_admin")),
    db: AsyncSession = Depends(get_db),
):
    if id == current_user.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot delete your own user account")

    res = await db.execute(
        select(User).where(
            User.id == id,
            User.organization_id == current_user.organization_id,
        )
    )
    user = res.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    user.deleted_at = func.now()
    user.is_active = False
    await db.commit()
    return success_response({"message": "User deleted successfully"})
