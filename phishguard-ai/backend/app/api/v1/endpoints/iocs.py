"""
IOC Management API Endpoints for PhishGuard AI.
Tenant-scoped listing, filtering, false-positive toggling, and export (CSV/JSON).
"""
import csv
import io
import json
import uuid
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models import IOC, User
from app.security.auth import get_current_user
from app.utils.response import success_response, error_response, paginated_response

router = APIRouter()


class UpdateIOCRequest(BaseModel):
    is_false_positive: Optional[bool] = None
    tags: Optional[list[str]] = None


@router.get("", summary="List Indicators of Compromise")
async def list_iocs(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    ioc_type: Optional[str] = None,
    risk_level: Optional[str] = None,
    search: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    query = select(IOC).where(IOC.organization_id == current_user.organization_id)

    if ioc_type:
        query = query.where(IOC.ioc_type == ioc_type)
    if risk_level:
        query = query.where(IOC.risk_level == risk_level)
    if search:
        query = query.where(IOC.ioc_value.ilike(f"%{search}%"))

    query = query.order_by(desc(IOC.created_at))

    count_res = await db.execute(select(IOC).where(IOC.organization_id == current_user.organization_id))
    total = len(count_res.scalars().all())

    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    iocs = result.scalars().all()

    items = [
        {
            "id": str(i.id),
            "ioc_type": i.ioc_type,
            "ioc_value": i.ioc_value,
            "source_location": i.source_location,
            "risk_level": i.risk_level,
            "confidence": i.confidence,
            "detection_reason": i.detection_reason,
            "is_false_positive": i.is_false_positive,
            "tags": i.tags or [],
            "first_seen_at": i.first_seen_at.isoformat() if i.first_seen_at else None,
            "created_at": i.created_at.isoformat() if i.created_at else None,
        }
        for i in iocs
    ]
    return paginated_response(items, total, page, page_size)


@router.get("/export", summary="Export IOCs as CSV or JSON")
async def export_iocs(
    format: str = Query("json", pattern="^(json|csv)$"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    res = await db.execute(
        select(IOC).where(IOC.organization_id == current_user.organization_id).order_by(desc(IOC.created_at))
    )
    iocs = res.scalars().all()

    if format == "json":
        data = [
            {
                "type": i.ioc_type,
                "value": i.ioc_value,
                "source": i.source_location,
                "risk": i.risk_level,
                "confidence": i.confidence,
                "reason": i.detection_reason,
                "is_false_positive": i.is_false_positive,
                "first_seen": i.first_seen_at.isoformat() if i.first_seen_at else None,
            }
            for i in iocs
        ]
        return Response(
            content=json.dumps(data, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=phishguard_iocs.json"},
        )

    # CSV
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Type", "Value", "Source", "Risk Level", "Confidence", "Reason", "False Positive", "First Seen"])
    for i in iocs:
        writer.writerow([
            i.ioc_type,
            i.ioc_value,
            i.source_location or "",
            i.risk_level or "",
            i.confidence or "",
            i.detection_reason or "",
            "true" if i.is_false_positive else "false",
            i.first_seen_at.isoformat() if i.first_seen_at else "",
        ])

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=phishguard_iocs.csv"},
    )


@router.get("/{id}", summary="Get IOC by ID")
async def get_ioc(
    id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    res = await db.execute(
        select(IOC).where(IOC.id == id, IOC.organization_id == current_user.organization_id)
    )
    ioc = res.scalar_one_or_none()
    if not ioc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IOC not found")

    return success_response({
        "id": str(ioc.id),
        "ioc_type": ioc.ioc_type,
        "ioc_value": ioc.ioc_value,
        "source_location": ioc.source_location,
        "risk_level": ioc.risk_level,
        "confidence": ioc.confidence,
        "detection_reason": ioc.detection_reason,
        "is_false_positive": ioc.is_false_positive,
        "tags": ioc.tags or [],
        "first_seen_at": ioc.first_seen_at.isoformat() if ioc.first_seen_at else None,
        "created_at": ioc.created_at.isoformat() if ioc.created_at else None,
    })


@router.put("/{id}", summary="Update IOC (e.g. false positive flag, tags)")
async def update_ioc(
    id: uuid.UUID,
    body: UpdateIOCRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    res = await db.execute(
        select(IOC).where(IOC.id == id, IOC.organization_id == current_user.organization_id)
    )
    ioc = res.scalar_one_or_none()
    if not ioc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IOC not found")

    if body.is_false_positive is not None:
        ioc.is_false_positive = body.is_false_positive
    if body.tags is not None:
        ioc.tags = body.tags

    await db.commit()
    return success_response({"id": str(ioc.id), "is_false_positive": ioc.is_false_positive, "tags": ioc.tags})
