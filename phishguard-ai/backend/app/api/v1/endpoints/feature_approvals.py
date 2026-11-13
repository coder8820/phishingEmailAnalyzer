"""
PhishGuard AI — Feature Access Approval & Super Admin Contact Desk
Enables normal users (analysts/viewers) to request advanced feature permissions,
contact the Super Admin via direct message/email dispatch, and allows Super Admins
to review, approve, reject feature requests, and reply to user inquiries.
"""
import uuid
from datetime import datetime, timezone
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models import User, FeatureRequest, AdminMessage
from app.security.auth import get_current_user, require_role
from app.utils.response import success_response, error_response, paginated_response

router = APIRouter()

# ─────────────────────────────────────────────────────────────────────────────
# CATALOG OF ENTERPRISE FEATURES SUBJECT TO SUPER ADMIN APPROVAL
# ─────────────────────────────────────────────────────────────────────────────
CATALOG_FEATURES = [
    {
        "key": "advanced_ai_analysis",
        "name": "Advanced AI Contextual Forensics & Deep Heuristics",
        "description": "Unlock prompt-isolated deep LLM investigation, semantic urgency breakdown, and adversarial prompt detection.",
        "category": "AI Forensics",
        "requires_approval": True,
    },
    {
        "key": "custom_detection_rules",
        "name": "Custom SOC Detection Rule Authoring & YARA/Regex",
        "description": "Create, edit, test, and deploy organization-wide detection rules and custom header inspection policies.",
        "category": "Detection Engineering",
        "requires_approval": True,
    },
    {
        "key": "raw_attachment_export",
        "name": "Raw Payload Quarantine & Attachment Dissection",
        "description": "Download quarantined attachment payloads and view hex/magic-byte analysis outside the sandbox.",
        "category": "Malware Analysis",
        "requires_approval": True,
    },
    {
        "key": "siem_integrations",
        "name": "SIEM & SOAR Webhook Pipeline Integration",
        "description": "Configure outbound Splunk, Sentinel, and Elastic telemetry streaming and automated alert dispatch.",
        "category": "Integrations",
        "requires_approval": True,
    },
    {
        "key": "bulk_threat_intel",
        "name": "Multi-Feed Threat Intelligence & VirusTotal Pro",
        "description": "Perform bulk external threat feed lookups across thousands of domains and IP addresses without rate limits.",
        "category": "Threat Intelligence",
        "requires_approval": True,
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# PYDANTIC SCHEMAS
# ─────────────────────────────────────────────────────────────────────────────
class RequestFeaturePayload(BaseModel):
    feature_key: str = Field(..., description="Key of the requested feature")
    justification: str = Field(..., min_length=10, max_length=1000, description="Reason for requesting access")


class ReviewFeaturePayload(BaseModel):
    admin_notes: Optional[str] = Field(None, max_length=500, description="Feedback or conditions from admin")


class ContactAdminPayload(BaseModel):
    subject: str = Field(..., min_length=4, max_length=150, description="Inquiry or issue subject")
    message: str = Field(..., min_length=10, max_length=2000, description="Message body for Super Admin")


class ReplyAdminPayload(BaseModel):
    reply: str = Field(..., min_length=5, max_length=2000, description="Super Admin response to the user")


# ─────────────────────────────────────────────────────────────────────────────
# 1. FEATURES CATALOG & PERMISSIONS STATUS
# ─────────────────────────────────────────────────────────────────────────────
@router.get("/catalog", summary="Get all platform features and current user's approval status")
async def get_feature_catalog(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Returns the feature catalog along with approval status for the current user.
    Super Admins and Security Admins automatically have all features unlocked.
    """
    is_admin = current_user.role in ["super_admin", "security_admin"]

    # Fetch user's approved feature requests
    approved_q = await db.execute(
        select(FeatureRequest.feature_key).where(
            FeatureRequest.user_id == current_user.id,
            FeatureRequest.status == "approved",
        )
    )
    approved_keys = set(approved_q.scalars().all())

    # Fetch user's pending feature requests
    pending_q = await db.execute(
        select(FeatureRequest.feature_key).where(
            FeatureRequest.user_id == current_user.id,
            FeatureRequest.status == "pending",
        )
    )
    pending_keys = set(pending_q.scalars().all())

    features_with_status = []
    for f in CATALOG_FEATURES:
        key = f["key"]
        if is_admin:
            status_val = "unlocked"
            can_access = True
        elif key in approved_keys:
            status_val = "approved"
            can_access = True
        elif key in pending_keys:
            status_val = "pending"
            can_access = False
        else:
            status_val = "locked"
            can_access = False

        features_with_status.append({
            **f,
            "status": status_val,
            "can_access": can_access,
        })

    return success_response({
        "is_admin": is_admin,
        "features": features_with_status,
    })


# ─────────────────────────────────────────────────────────────────────────────
# 2. FEATURE REQUESTS: USER ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/requests", summary="Normal user submits a feature access request")
async def request_feature_access(
    payload: RequestFeaturePayload,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    feature = next((f for f in CATALOG_FEATURES if f["key"] == payload.feature_key), None)
    if not feature:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Feature key not found in catalog")

    # If already an admin, feature is already unlocked
    if current_user.role in ["super_admin", "security_admin"]:
        return success_response(
            message="Feature is already accessible under your administrative privileges.",
            data={"status": "unlocked"},
        )

    # Check if there is already an active or pending request
    existing_res = await db.execute(
        select(FeatureRequest).where(
            FeatureRequest.user_id == current_user.id,
            FeatureRequest.feature_key == payload.feature_key,
            FeatureRequest.status.in_(["pending", "approved"]),
        )
    )
    existing = existing_res.scalar_one_or_none()
    if existing:
        if existing.status == "approved":
            return success_response(
                message="You already have an approved grant for this feature.",
                data={"status": "approved", "request_id": str(existing.id)},
            )
        return error_response(
            code="REQUEST_EXISTS",
            message="You already have a pending request for this feature awaiting Super Admin review.",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    req = FeatureRequest(
        organization_id=current_user.organization_id,
        user_id=current_user.id,
        user_email=current_user.email,
        user_name=current_user.display_name or current_user.username,
        feature_key=payload.feature_key,
        feature_name=feature["name"],
        justification=payload.justification,
        status="pending",
    )
    db.add(req)
    await db.commit()
    await db.refresh(req)

    return success_response(
        message=f"Request for '{feature['name']}' submitted successfully. Super Admin has been notified for approval.",
        data={
            "id": str(req.id),
            "feature_key": req.feature_key,
            "feature_name": req.feature_name,
            "status": req.status,
            "created_at": req.created_at.isoformat() if req.created_at else None,
        },
    )


@router.get("/requests/my", summary="List the current user's submitted feature requests")
async def get_my_feature_requests(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    res = await db.execute(
        select(FeatureRequest)
        .where(FeatureRequest.user_id == current_user.id)
        .order_by(desc(FeatureRequest.created_at))
    )
    requests = res.scalars().all()

    items = [
        {
            "id": str(r.id),
            "feature_key": r.feature_key,
            "feature_name": r.feature_name,
            "justification": r.justification,
            "status": r.status,
            "admin_notes": r.admin_notes,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "reviewed_at": r.reviewed_at.isoformat() if r.reviewed_at else None,
        }
        for r in requests
    ]
    return success_response(items)


# ─────────────────────────────────────────────────────────────────────────────
# 3. FEATURE REQUESTS: SUPER ADMIN REVIEW & APPROVAL ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────
@router.get("/admin/requests", summary="Super Admin: List all feature requests in organization")
async def list_all_feature_requests(
    status_filter: Optional[str] = Query(None, description="pending | approved | rejected"),
    current_user: User = Depends(require_role("security_admin")),
    db: AsyncSession = Depends(get_db),
):
    query = select(FeatureRequest).where(
        FeatureRequest.organization_id == current_user.organization_id
    )
    if status_filter:
        query = query.where(FeatureRequest.status == status_filter)

    query = query.order_by(desc(FeatureRequest.created_at))
    res = await db.execute(query)
    requests = res.scalars().all()

    items = [
        {
            "id": str(r.id),
            "user_id": str(r.user_id),
            "user_email": r.user_email,
            "user_name": r.user_name,
            "feature_key": r.feature_key,
            "feature_name": r.feature_name,
            "justification": r.justification,
            "status": r.status,
            "admin_notes": r.admin_notes,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "reviewed_at": r.reviewed_at.isoformat() if r.reviewed_at else None,
        }
        for r in requests
    ]
    return success_response(items)


@router.post("/admin/requests/{request_id}/approve", summary="Super Admin: Approve a feature request")
async def approve_feature_request(
    request_id: uuid.UUID,
    payload: ReviewFeaturePayload,
    current_user: User = Depends(require_role("security_admin")),
    db: AsyncSession = Depends(get_db),
):
    res = await db.execute(
        select(FeatureRequest).where(
            FeatureRequest.id == request_id,
            FeatureRequest.organization_id == current_user.organization_id,
        )
    )
    req = res.scalar_one_or_none()
    if not req:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Feature request not found")

    req.status = "approved"
    req.admin_notes = payload.admin_notes or "Approved by Super Admin."
    req.reviewed_by = current_user.id
    req.reviewed_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(req)

    return success_response(
        message=f"Feature '{req.feature_name}' successfully approved for {req.user_email}.",
        data={
            "id": str(req.id),
            "status": req.status,
            "reviewed_at": req.reviewed_at.isoformat() if req.reviewed_at else None,
        },
    )


@router.post("/admin/requests/{request_id}/reject", summary="Super Admin: Reject a feature request")
async def reject_feature_request(
    request_id: uuid.UUID,
    payload: ReviewFeaturePayload,
    current_user: User = Depends(require_role("security_admin")),
    db: AsyncSession = Depends(get_db),
):
    res = await db.execute(
        select(FeatureRequest).where(
            FeatureRequest.id == request_id,
            FeatureRequest.organization_id == current_user.organization_id,
        )
    )
    req = res.scalar_one_or_none()
    if not req:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Feature request not found")

    req.status = "rejected"
    req.admin_notes = payload.admin_notes or "Rejected by Super Admin."
    req.reviewed_by = current_user.id
    req.reviewed_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(req)

    return success_response(
        message=f"Feature request for {req.user_email} rejected.",
        data={
            "id": str(req.id),
            "status": req.status,
            "reviewed_at": req.reviewed_at.isoformat() if req.reviewed_at else None,
        },
    )


# ─────────────────────────────────────────────────────────────────────────────
# 4. CONTACT SUPER ADMIN & EMAIL MESSAGES
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/contact", summary="Normal user sends a message / email to Super Admin")
async def contact_super_admin(
    payload: ContactAdminPayload,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    msg = AdminMessage(
        organization_id=current_user.organization_id,
        user_id=current_user.id,
        user_email=current_user.email,
        user_name=current_user.display_name or current_user.username,
        subject=payload.subject,
        message=payload.message,
        status="unread",
    )
    db.add(msg)
    await db.commit()
    await db.refresh(msg)

    return success_response(
        message="Your message has been dispatched to the Super Admin desk. You will receive replies in your console.",
        data={
            "id": str(msg.id),
            "subject": msg.subject,
            "created_at": msg.created_at.isoformat() if msg.created_at else None,
        },
    )


@router.get("/contact/my", summary="Normal user gets their messages sent to Super Admin and replies")
async def get_my_admin_messages(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    res = await db.execute(
        select(AdminMessage)
        .where(AdminMessage.user_id == current_user.id)
        .order_by(desc(AdminMessage.created_at))
    )
    messages = res.scalars().all()

    items = [
        {
            "id": str(m.id),
            "subject": m.subject,
            "message": m.message,
            "status": m.status,
            "admin_reply": m.admin_reply,
            "created_at": m.created_at.isoformat() if m.created_at else None,
            "replied_at": m.replied_at.isoformat() if m.replied_at else None,
        }
        for m in messages
    ]
    return success_response(items)


@router.get("/admin/messages", summary="Super Admin: List incoming user messages and inquiries")
async def list_admin_messages(
    current_user: User = Depends(require_role("security_admin")),
    db: AsyncSession = Depends(get_db),
):
    res = await db.execute(
        select(AdminMessage)
        .where(AdminMessage.organization_id == current_user.organization_id)
        .order_by(desc(AdminMessage.created_at))
    )
    messages = res.scalars().all()

    items = [
        {
            "id": str(m.id),
            "user_id": str(m.user_id),
            "user_email": m.user_email,
            "user_name": m.user_name,
            "subject": m.subject,
            "message": m.message,
            "status": m.status,
            "admin_reply": m.admin_reply,
            "created_at": m.created_at.isoformat() if m.created_at else None,
            "replied_at": m.replied_at.isoformat() if m.replied_at else None,
        }
        for m in messages
    ]
    return success_response(items)


@router.post("/admin/messages/{message_id}/reply", summary="Super Admin: Reply to user message")
async def reply_to_admin_message(
    message_id: uuid.UUID,
    payload: ReplyAdminPayload,
    current_user: User = Depends(require_role("security_admin")),
    db: AsyncSession = Depends(get_db),
):
    res = await db.execute(
        select(AdminMessage).where(
            AdminMessage.id == message_id,
            AdminMessage.organization_id == current_user.organization_id,
        )
    )
    msg = res.scalar_one_or_none()
    if not msg:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Message not found")

    msg.status = "replied"
    msg.admin_reply = payload.reply
    msg.replied_by = current_user.id
    msg.replied_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(msg)

    return success_response(
        message=f"Reply sent to {msg.user_email}.",
        data={
            "id": str(msg.id),
            "status": msg.status,
            "replied_at": msg.replied_at.isoformat() if msg.replied_at else None,
        },
    )
