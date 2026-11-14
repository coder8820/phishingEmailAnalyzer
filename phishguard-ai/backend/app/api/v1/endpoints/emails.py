"""
Email ingestion endpoints for PhishGuard AI.

Handles multipart file upload, raw email submission, listing,
detail, analysis results, IOCs, and soft-delete.
All queries are tenant-scoped by organization_id from the JWT.
"""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from datetime import date, datetime, timezone
from typing import Optional

from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    Query,
    UploadFile,
    status,
)
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.models import Attachment, Email, EmailAnalysis, ExtractedURL, IOC, User
from app.security.auth import get_current_user, require_role
from app.workers.tasks import analyze_email_task, execute_email_analysis
from app.utils.response import success_response, error_response, paginated_response

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Emails"])

# Allowed content types for uploaded email files
_ALLOWED_CONTENT_TYPES = {
    "message/rfc822",
    "application/octet-stream",
    "text/plain",
}
_ALLOWED_EXTENSIONS = {".eml", ".msg"}
_MAX_FILENAME_DISPLAY_LEN = 255


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------


class RawEmailRequest(BaseModel):
    content: Optional[str] = None
    raw_content: Optional[str] = None
    filename: Optional[str] = None

    @property
    def resolved_content(self) -> str:
        return self.raw_content or self.content or ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sanitize_filename(original: str) -> str:
    """
    Return a UUID-based safe filename preserving the .eml extension.
    Rejects path traversal sequences.
    """
    # Always derive a uuid-based name — ignore whatever the client sent
    return f"{uuid.uuid4()}.eml"


def _validate_no_path_traversal(filename: str) -> None:
    """Raise 400 if the filename contains path-traversal characters."""
    dangerous = ["..", "/", "\\", "\x00"]
    for d in dangerous:
        if d in filename:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Filename contains invalid characters.",
            )


async def _save_to_temp(content: bytes, safe_filename: str) -> str:
    """Write content to the configured temp upload directory."""
    os.makedirs(settings.UPLOAD_TEMP_DIR, exist_ok=True)
    dest_path = os.path.join(settings.UPLOAD_TEMP_DIR, safe_filename)
    with open(dest_path, "wb") as fh:
        fh.write(content)
    return dest_path


def _assert_tenant(email: Email, current_user: User) -> None:
    """Raise 404 if the email doesn't belong to the current user's org."""
    if str(email.organization_id) != str(current_user.organization_id):
        # Return 404 to avoid leaking existence of records across tenants
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Email not found.",
        )


# ---------------------------------------------------------------------------
# POST /emails/upload
# ---------------------------------------------------------------------------


@router.post("/upload", status_code=status.HTTP_202_ACCEPTED)
async def upload_email(
    file: UploadFile = File(...),
    current_user: User = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
):
    """
    Upload a .eml file for analysis.

    Validates content-type and file size, sanitizes filename, persists
    metadata, and enqueues the Celery analysis task.
    """
    # --- Content-type check ---
    original_filename = file.filename or "upload.eml"
    _validate_no_path_traversal(original_filename)

    # --- Read and size-check ---
    content = await file.read()
    if len(content) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty.",
        )
    if len(content) > settings.MAX_UPLOAD_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum size of {settings.MAX_UPLOAD_SIZE_BYTES} bytes.",
        )

    ext = os.path.splitext(original_filename)[-1].lower()
    ct = (file.content_type or "").split(";")[0].strip().lower()

    if ext not in _ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only .eml and .msg files are accepted.",
        )

    # --- Sanitize filename & store ---
    safe_name = _sanitize_filename(original_filename)
    file_path = await _save_to_temp(content, safe_name)

    # --- Create DB record ---
    email_record = Email(
        id=uuid.uuid4(),
        organization_id=current_user.organization_id,
        submitted_by=current_user.id,
        original_filename=original_filename[:_MAX_FILENAME_DISPLAY_LEN],
        source_type="eml_upload",
        file_size_bytes=len(content),
        raw_content=content.decode("latin-1", errors="replace"),
        analysis_status="queued",
    )
    db.add(email_record)
    await db.commit()
    await db.refresh(email_record)

    # --- Enqueue analysis task ---
    try:
        analyze_email_task.delay(str(email_record.id), str(current_user.organization_id))
    except Exception as exc:
        logger.warning("Celery broker unavailable (%s); executing analysis via asyncio task", exc)
        asyncio.create_task(execute_email_analysis(str(email_record.id), str(current_user.organization_id)))
    logger.info("Email %s queued for analysis by user %s", email_record.id, current_user.id)

    return success_response(
        {"email_id": str(email_record.id), "status": "queued"},
        status_code=202,
    )


# ---------------------------------------------------------------------------
# POST /emails/raw
# ---------------------------------------------------------------------------


@router.post("/raw", status_code=status.HTTP_202_ACCEPTED)
async def submit_raw_email(
    payload: RawEmailRequest,
    current_user: User = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
):
    """Submit raw RFC-822 email text for analysis."""
    raw_text = payload.resolved_content
    content_bytes = raw_text.encode("utf-8", errors="replace")

    if len(content_bytes) > settings.MAX_UPLOAD_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Raw content exceeds maximum size of {settings.MAX_UPLOAD_SIZE_BYTES} bytes.",
        )

    safe_name = _sanitize_filename(payload.filename or "raw.eml")
    file_path = await _save_to_temp(content_bytes, safe_name)

    email_record = Email(
        id=uuid.uuid4(),
        organization_id=current_user.organization_id,
        submitted_by=current_user.id,
        original_filename=(payload.filename or "raw_submission.eml")[:_MAX_FILENAME_DISPLAY_LEN],
        source_type="raw_input",
        file_size_bytes=len(content_bytes),
        raw_content=raw_text,
        analysis_status="queued",
    )
    db.add(email_record)
    await db.commit()
    await db.refresh(email_record)

    try:
        analyze_email_task.delay(str(email_record.id), str(current_user.organization_id))
    except Exception as exc:
        logger.warning("Celery broker unavailable (%s); executing analysis via asyncio task", exc)
        asyncio.create_task(execute_email_analysis(str(email_record.id), str(current_user.organization_id)))
    logger.info("Raw email %s queued for analysis", email_record.id)

    return success_response(
        {"email_id": str(email_record.id), "status": "queued"},
        status_code=202,
    )


# ---------------------------------------------------------------------------
# GET /emails/
# ---------------------------------------------------------------------------


@router.get("", status_code=status.HTTP_200_OK)
@router.get("/", status_code=status.HTTP_200_OK)
async def list_emails(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status_filter: Optional[str] = Query(None, alias="status"),
    date_from: Optional[date] = Query(None),
    date_to: Optional[date] = Query(None),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List emails belonging to the current user's organization (paginated)."""
    query = select(Email).where(Email.organization_id == current_user.organization_id)

    if status_filter:
        query = query.where(Email.analysis_status == status_filter)
    if date_from:
        query = query.where(Email.created_at >= datetime.combine(date_from, datetime.min.time()))
    if date_to:
        query = query.where(Email.created_at <= datetime.combine(date_to, datetime.max.time()))

    query = query.where(Email.deleted_at.is_(None))

    count_query = select(func.count()).select_from(query.subquery())
    total_result = await db.execute(count_query)
    total = total_result.scalar_one()

    query = query.order_by(Email.created_at.desc())
    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    emails = result.scalars().all()

    email_dicts = [
        {
            "id": str(e.id),
            "original_filename": e.original_filename,
            "subject": e.subject,
            "sender": e.sender_email or e.sender_raw,
            "status": e.analysis_status,
            "analysis_status": e.analysis_status,
            "submitted_at": e.created_at.isoformat() if e.created_at else None,
            "created_at": e.created_at.isoformat() if e.created_at else None,
        }
        for e in emails
    ]
    return paginated_response(email_dicts, total=total, page=page, page_size=page_size)


# ---------------------------------------------------------------------------
# GET /emails/{id}
# ---------------------------------------------------------------------------


@router.get("/{email_id}", status_code=status.HTTP_200_OK)
async def get_email(
    email_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get email detail. Enforces tenant isolation."""
    result = await db.execute(
        select(Email).where(Email.id == email_id, Email.deleted_at.is_(None))
    )
    email_record: Optional[Email] = result.scalar_one_or_none()
    if email_record is None:
        raise HTTPException(status_code=404, detail="Email not found.")

    _assert_tenant(email_record, current_user)

    return success_response(
        {
            "id": str(email_record.id),
            "original_filename": email_record.original_filename,
            "subject": email_record.subject,
            "sender_raw": email_record.sender_raw,
            "sender_email": email_record.sender_email,
            "sender_display_name": email_record.sender_display_name,
            "reply_to": email_record.reply_to,
            "return_path": email_record.return_path,
            "recipient_to": email_record.recipient_to,
            "recipient_cc": email_record.recipient_cc,
            "message_id": email_record.message_id,
            "analysis_status": email_record.analysis_status,
            "file_hash_sha256": email_record.file_hash_sha256,
            "file_size_bytes": email_record.file_size_bytes,
            "submitted_at": email_record.created_at.isoformat() if email_record.created_at else None,
            "created_at": email_record.created_at.isoformat() if email_record.created_at else None,
            "submitted_by": str(email_record.submitted_by),
        }
    )


# ---------------------------------------------------------------------------
# GET /emails/{id}/analysis
# ---------------------------------------------------------------------------


@router.get("/{email_id}/analysis", status_code=status.HTTP_200_OK)
async def get_email_analysis(
    email_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return the full analysis result for an email (tenant-scoped)."""
    result = await db.execute(
        select(Email).where(Email.id == email_id, Email.deleted_at.is_(None))
    )
    email_record: Optional[Email] = result.scalar_one_or_none()
    if email_record is None:
        raise HTTPException(status_code=404, detail="Email not found.")

    _assert_tenant(email_record, current_user)

    analysis_result = await db.execute(
        select(EmailAnalysis).where(EmailAnalysis.email_id == email_id)
    )
    analysis: Optional[EmailAnalysis] = analysis_result.scalar_one_or_none()
    if analysis is None:
        raise HTTPException(
            status_code=404,
            detail="Analysis not yet available.",
        )

    return success_response(
        {
            "analysis_id": str(analysis.id),
            "email_id": str(analysis.email_id),
            "risk_score": analysis.risk_score,
            "risk_classification": analysis.risk_classification,
            "spf_result": analysis.spf_result,
            "dkim_result": analysis.dkim_result,
            "dmarc_result": analysis.dmarc_result,
            "ai_findings": analysis.ai_findings,
            "score_breakdown": analysis.score_breakdown,
            "errors": analysis.errors,
            "analyzed_at": analysis.created_at.isoformat() if analysis.created_at else None,
        }
    )


# ---------------------------------------------------------------------------
# GET /emails/{id}/iocs
# ---------------------------------------------------------------------------


@router.get("/{email_id}/iocs", status_code=status.HTTP_200_OK)
async def get_email_iocs(
    email_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return all IOCs extracted from an email (tenant-scoped)."""
    result = await db.execute(
        select(Email).where(Email.id == email_id, Email.deleted_at.is_(None))
    )
    email_record: Optional[Email] = result.scalar_one_or_none()
    if email_record is None:
        raise HTTPException(status_code=404, detail="Email not found.")

    _assert_tenant(email_record, current_user)

    ioc_result = await db.execute(
        select(IOC).where(IOC.email_id == email_id, IOC.organization_id == current_user.organization_id)
    )
    iocs = ioc_result.scalars().all()

    return success_response(
        [
            {
                "id": str(ioc.id),
                "ioc_type": ioc.ioc_type,
                "ioc_value": ioc.ioc_value,
                "risk_level": ioc.risk_level,
                "confidence": ioc.confidence,
                "source_location": ioc.source_location,
                "is_false_positive": ioc.is_false_positive,
            }
            for ioc in iocs
        ]
    )


# ---------------------------------------------------------------------------
# GET /emails/{id}/urls
# ---------------------------------------------------------------------------


@router.get("/{email_id}/urls", status_code=status.HTTP_200_OK)
async def get_email_urls(
    email_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return all URLs extracted from an email (tenant-scoped)."""
    result = await db.execute(
        select(Email).where(Email.id == email_id, Email.deleted_at.is_(None))
    )
    email_record: Optional[Email] = result.scalar_one_or_none()
    if email_record is None:
        raise HTTPException(status_code=404, detail="Email not found.")

    _assert_tenant(email_record, current_user)

    url_result = await db.execute(
        select(ExtractedURL).where(
            ExtractedURL.email_id == email_id,
            ExtractedURL.organization_id == current_user.organization_id,
        )
    )
    urls = url_result.scalars().all()
    return success_response(
        [
            {
                "id": str(u.id),
                "url_raw": u.url_raw,
                "url_normalized": u.url_normalized or u.url_raw,
                "domain": u.domain,
                "scheme": u.scheme,
                "is_shortener": u.is_shortener or False,
                "is_ip_based": u.is_ip_based or False,
                "is_punycode": u.is_punycode or False,
                "has_suspicious_params": u.has_suspicious_params or False,
                "redirect_chain": u.redirect_chain or [],
                "is_malicious": u.is_malicious,
                "malicious_confidence": u.malicious_confidence,
                "detection_reasons": u.detection_reasons or [],
                "source_location": u.source_location,
            }
            for u in urls
        ]
    )


# ---------------------------------------------------------------------------
# GET /emails/{id}/attachments
# ---------------------------------------------------------------------------


@router.get("/{email_id}/attachments", status_code=status.HTTP_200_OK)
async def get_email_attachments(
    email_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return all attachments belonging to an email (tenant-scoped)."""
    result = await db.execute(
        select(Email).where(Email.id == email_id, Email.deleted_at.is_(None))
    )
    email_record: Optional[Email] = result.scalar_one_or_none()
    if email_record is None:
        raise HTTPException(status_code=404, detail="Email not found.")

    _assert_tenant(email_record, current_user)

    att_result = await db.execute(
        select(Attachment).where(
            Attachment.email_id == email_id,
            Attachment.organization_id == current_user.organization_id,
        )
    )
    attachments = att_result.scalars().all()
    return success_response(
        [
            {
                "id": str(a.id),
                "filename_original": a.filename_original,
                "filename_sanitized": a.filename_sanitized,
                "mime_type_declared": a.mime_type_declared,
                "mime_type_detected": a.mime_type_detected,
                "extension": a.extension,
                "file_size_bytes": a.file_size_bytes,
                "sha256_hash": a.sha256_hash,
                "is_executable": a.is_executable or False,
                "is_archive": a.is_archive or False,
                "has_macro_indicator": a.has_macro_indicator or False,
                "has_double_extension": a.has_double_extension or False,
                "mime_type_mismatch": a.mime_type_mismatch or False,
                "risk_level": a.risk_level or "unknown",
            }
            for a in attachments
        ]
    )


# ---------------------------------------------------------------------------
# DELETE /emails/{id}
# ---------------------------------------------------------------------------


@router.delete("/{email_id}", status_code=status.HTTP_200_OK)
async def delete_email(
    email_id: uuid.UUID,
    current_user: User = Depends(require_role("security_admin")),
    db: AsyncSession = Depends(get_db),
):
    """Soft-delete an email. Admin role required."""
    result = await db.execute(
        select(Email).where(Email.id == email_id, Email.deleted_at.is_(None))
    )
    email_record: Optional[Email] = result.scalar_one_or_none()
    if email_record is None:
        raise HTTPException(status_code=404, detail="Email not found.")

    _assert_tenant(email_record, current_user)

    email_record.deleted_at = datetime.now(timezone.utc)
    db.add(email_record)
    await db.commit()

    logger.info("Email %s soft-deleted by admin %s", email_id, current_user.id)
    return success_response({"message": "Email deleted."})
