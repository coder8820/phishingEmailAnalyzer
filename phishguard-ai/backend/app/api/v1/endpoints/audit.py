"""
Audit Logs API Endpoints for PhishGuard AI.
Provides immutable, tamper-resistant access to administrative, authentication,
and email analysis audit events for security administrators.
"""
from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models import AuditLog, User
from app.security.auth import require_role
from app.utils.response import paginated_response

router = APIRouter()


@router.get("", summary="List audit logs for organization")
async def list_audit_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    action: Optional[str] = None,
    severity: Optional[str] = None,
    current_user: User = Depends(require_role("security_admin")),
    db: AsyncSession = Depends(get_db),
):
    query = select(AuditLog).where(AuditLog.organization_id == current_user.organization_id)

    if action:
        query = query.where(AuditLog.action.ilike(f"%{action}%"))
    if severity:
        query = query.where(AuditLog.severity == severity)

    query = query.order_by(desc(AuditLog.created_at))

    count_res = await db.execute(
        select(func.count(AuditLog.id)).where(AuditLog.organization_id == current_user.organization_id)
    )
    total = count_res.scalar() or 0

    query = query.offset((page - 1) * page_size).limit(page_size)
    res = await db.execute(query)
    logs = res.scalars().all()

    items = [
        {
            "id": str(log.id),
            "action": log.action,
            "resource_type": log.resource_type,
            "resource_id": str(log.resource_id) if log.resource_id else None,
            "ip_address": str(log.ip_address) if log.ip_address else None,
            "user_id": str(log.user_id) if log.user_id else None,
            "severity": log.severity,
            "details": log.details or {},
            "created_at": log.created_at.isoformat() if log.created_at else None,
        }
        for log in logs
    ]
    return paginated_response(items, total, page, page_size)
