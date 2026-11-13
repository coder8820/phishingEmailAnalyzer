"""
Enterprise Mail-Flow Webhook Endpoints for PhishGuard AI.

Provides ingestion webhooks for Microsoft 365, Google Workspace, and inbound MTAs,
as well as automated quarantine remediation endpoints.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models import User
from app.security.auth import get_current_user, require_role
from app.services.mail_flow_service import mail_flow_service
from app.utils.response import success_response

router = APIRouter()


class RemediationRequest(BaseModel):
    action: str = "quarantine"  # quarantine | soft_delete | tag_subject


class InboundMtaRequest(BaseModel):
    raw_content: str
    organization_id: Optional[uuid.UUID] = None


@router.get("/m365", summary="Microsoft Graph Webhook Subscription Validation Handshake")
async def m365_validation_handshake(
    validationToken: Optional[str] = Query(None),
) -> Response:
    """
    Microsoft Graph subscription validation requires echoing back the validationToken
    with a 200 OK plain text response.
    """
    if validationToken:
        return Response(content=validationToken, media_type="text/plain", status_code=200)
    return Response(content="PhishGuard M365 Webhook Endpoint Active", media_type="text/plain", status_code=200)


@router.post("/m365", summary="Microsoft Graph Mail Notification Ingestion Webhook")
async def m365_notification_webhook(
    payload: Dict[str, Any],
    db: AsyncSession = Depends(get_db),
    x_organization_id: Optional[str] = Header(None),
) -> Dict[str, Any]:
    """
    Receives notification of new emails from Microsoft Graph API change notifications.
    """
    from app.models import Organization
    from sqlalchemy import select

    org_id = uuid.UUID(x_organization_id) if x_organization_id else None
    if not org_id:
        res_org = await db.execute(select(Organization.id).limit(1))
        org_id = res_org.scalar_one_or_none()
    if not org_id:
        raise HTTPException(status_code=400, detail="Organization context could not be resolved")

    result = await mail_flow_service.handle_m365_notification(
        payload=payload,
        organization_id=org_id,
        db=db,
    )
    return success_response(result)


@router.post("/google-workspace", summary="Google Workspace Gmail Pub/Sub Notification Webhook")
async def google_workspace_webhook(
    payload: Dict[str, Any],
    db: AsyncSession = Depends(get_db),
    x_organization_id: Optional[str] = Header(None),
) -> Dict[str, Any]:
    """
    Receives push notifications from Google Cloud Pub/Sub for Gmail mailbox changes.
    """
    from app.models import Organization
    from sqlalchemy import select

    org_id = uuid.UUID(x_organization_id) if x_organization_id else None
    if not org_id:
        res_org = await db.execute(select(Organization.id).limit(1))
        org_id = res_org.scalar_one_or_none()
    if not org_id:
        raise HTTPException(status_code=400, detail="Organization context could not be resolved")

    result = await mail_flow_service.handle_google_workspace_notification(
        payload=payload,
        organization_id=org_id,
        db=db,
    )
    return success_response(result)


@router.post("/mta", summary="Direct Inbound MTA Webhook Ingestion")
async def mta_webhook(
    body: InboundMtaRequest,
    db: AsyncSession = Depends(get_db),
    x_organization_id: Optional[str] = Header(None),
) -> Dict[str, Any]:
    """
    Direct webhook for Postfix milters, SendGrid inbound parse, or Amazon SES SNS payloads.
    """
    from app.models import Organization
    from sqlalchemy import select

    org_id = body.organization_id
    if not org_id and x_organization_id:
        org_id = uuid.UUID(x_organization_id)
    if not org_id:
        res_org = await db.execute(select(Organization.id).limit(1))
        org_id = res_org.scalar_one_or_none()
    if not org_id:
        raise HTTPException(status_code=400, detail="Organization context could not be resolved")

    email_record = await mail_flow_service.ingest_raw_message(
        raw_content=body.raw_content,
        organization_id=org_id,
        source_type="mta_webhook",
        db=db,
    )
    return success_response({
        "email_id": str(email_record.id),
        "status": "queued",
        "subject": email_record.subject,
        "sender": email_record.sender_email or email_record.sender_raw,
    })


@router.post("/remediate/{email_id}", summary="Execute Quarantine / Remediation Action")
async def execute_remediation(
    email_id: uuid.UUID,
    body: RemediationRequest,
    current_user: User = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """
    SOC Analyst / Admin action to quarantine, soft-delete, or tag a flagged email.
    """
    result = await mail_flow_service.execute_remediation(
        email_id=email_id,
        organization_id=current_user.organization_id,
        action=body.action,
        db=db,
    )
    if result.get("status") == "error":
        raise HTTPException(status_code=404, detail=result.get("message", "Email not found"))
    return success_response(result)
