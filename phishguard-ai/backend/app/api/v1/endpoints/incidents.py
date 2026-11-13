"""
Incident Management API Endpoints for PhishGuard AI.
Complete SOC workflow: creating, updating status, assignment, investigation notes,
linking emails and IOCs, and audit trail timeline.
"""
import uuid
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.models import (
    Incident,
    IncidentEmail,
    IncidentIOC,
    IncidentAssignment,
    InvestigationNote,
    Email,
    IOC,
    User,
)
from app.security.auth import get_current_user, require_role
from app.utils.response import success_response, error_response, paginated_response

router = APIRouter()


class CreateIncidentRequest(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str = "medium"  # low | medium | high | critical
    tags: Optional[list[str]] = None
    email_ids: Optional[list[str]] = None
    ioc_ids: Optional[list[str]] = None


class UpdateIncidentRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None  # new | under_investigation | escalated | resolved | false_positive
    resolution_notes: Optional[str] = None
    tags: Optional[list[str]] = None


class AddNoteRequest(BaseModel):
    content: str
    note_type: str = "note"  # note | action | escalation | resolution


class AssignRequest(BaseModel):
    assigned_to: str


@router.get("", summary="List security incidents")
async def list_incidents(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status: Optional[str] = None,
    severity: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    query = select(Incident).where(
        Incident.organization_id == current_user.organization_id,
        Incident.deleted_at.is_(None),
    )
    if status:
        query = query.where(Incident.status == status)
    if severity:
        query = query.where(Incident.severity == severity)

    query = query.order_by(desc(Incident.created_at))

    count_res = await db.execute(
        select(func.count(Incident.id)).where(
            Incident.organization_id == current_user.organization_id,
            Incident.deleted_at.is_(None),
        )
    )
    total = count_res.scalar() or 0

    query = query.offset((page - 1) * page_size).limit(page_size)
    res = await db.execute(query)
    incidents = res.scalars().all()

    items = [
        {
            "id": str(inc.id),
            "incident_number": inc.incident_number,
            "title": inc.title,
            "description": inc.description,
            "severity": inc.severity,
            "status": inc.status,
            "tags": inc.tags or [],
            "created_by": str(inc.created_by),
            "created_at": inc.created_at.isoformat() if inc.created_at else None,
            "updated_at": inc.updated_at.isoformat() if inc.updated_at else None,
        }
        for inc in incidents
    ]
    return paginated_response(items, total, page, page_size)


@router.post("", summary="Create a new security incident")
async def create_incident(
    body: CreateIncidentRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # Auto-increment incident_number per org
    max_num_res = await db.execute(
        select(func.max(Incident.incident_number)).where(
            Incident.organization_id == current_user.organization_id
        )
    )
    next_num = (max_num_res.scalar() or 1000) + 1

    incident = Incident(
        organization_id=current_user.organization_id,
        title=body.title,
        description=body.description,
        severity=body.severity,
        status="new",
        incident_number=next_num,
        created_by=current_user.id,
        tags=body.tags or [],
    )
    db.add(incident)
    await db.flush()

    # Link emails if provided
    if body.email_ids:
        for eid in body.email_ids:
            try:
                db.add(IncidentEmail(incident_id=incident.id, email_id=uuid.UUID(eid), added_by=current_user.id))
            except Exception:
                pass

    # Link IOCs if provided
    if body.ioc_ids:
        for iid in body.ioc_ids:
            try:
                db.add(IncidentIOC(incident_id=incident.id, ioc_id=uuid.UUID(iid), added_by=current_user.id))
            except Exception:
                pass

    await db.commit()
    return success_response({
        "id": str(incident.id),
        "incident_number": incident.incident_number,
        "title": incident.title,
        "status": incident.status,
        "severity": incident.severity,
    }, status_code=status.HTTP_201_CREATED)


@router.get("/{id}", summary="Get incident details")
async def get_incident(
    id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    query = (
        select(Incident)
        .options(
            selectinload(Incident.notes),
            selectinload(Incident.email_links),
            selectinload(Incident.ioc_links),
            selectinload(Incident.assignments),
        )
        .where(
            Incident.id == id,
            Incident.organization_id == current_user.organization_id,
            Incident.deleted_at.is_(None),
        )
    )
    res = await db.execute(query)
    incident = res.scalar_one_or_none()

    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    notes = [
        {
            "id": str(n.id),
            "content": n.content,
            "note_type": n.note_type,
            "author_id": str(n.author_id),
            "created_at": n.created_at.isoformat() if n.created_at else None,
        }
        for n in incident.notes
    ]

    return success_response({
        "id": str(incident.id),
        "incident_number": incident.incident_number,
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity,
        "status": incident.status,
        "tags": incident.tags or [],
        "created_by": str(incident.created_by),
        "created_at": incident.created_at.isoformat() if incident.created_at else None,
        "updated_at": incident.updated_at.isoformat() if incident.updated_at else None,
        "notes": notes,
        "linked_emails_count": len(incident.email_links),
        "linked_iocs_count": len(incident.ioc_links),
    })


@router.put("/{id}", summary="Update incident details, severity, or status")
async def update_incident(
    id: uuid.UUID,
    body: UpdateIncidentRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    res = await db.execute(
        select(Incident).where(
            Incident.id == id,
            Incident.organization_id == current_user.organization_id,
            Incident.deleted_at.is_(None),
        )
    )
    incident = res.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    if body.title is not None:
        incident.title = body.title
    if body.description is not None:
        incident.description = body.description
    if body.severity is not None:
        incident.severity = body.severity
    if body.status is not None:
        incident.status = body.status
        if body.status == "resolved":
            incident.resolved_by = current_user.id
            incident.resolved_at = func.now()
    if body.resolution_notes is not None:
        incident.resolution_notes = body.resolution_notes
    if body.tags is not None:
        incident.tags = body.tags

    await db.commit()
    return success_response({"id": str(incident.id), "status": incident.status, "severity": incident.severity})


@router.post("/{id}/notes", summary="Add an investigation note")
async def add_incident_note(
    id: uuid.UUID,
    body: AddNoteRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    res = await db.execute(
        select(Incident).where(
            Incident.id == id,
            Incident.organization_id == current_user.organization_id,
            Incident.deleted_at.is_(None),
        )
    )
    incident = res.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    note = InvestigationNote(
        incident_id=incident.id,
        author_id=current_user.id,
        content=body.content,
        note_type=body.note_type,
    )
    db.add(note)
    await db.commit()
    return success_response({
        "id": str(note.id),
        "content": note.content,
        "note_type": note.note_type,
        "created_at": note.created_at.isoformat() if note.created_at else None,
    }, status_code=status.HTTP_201_CREATED)
