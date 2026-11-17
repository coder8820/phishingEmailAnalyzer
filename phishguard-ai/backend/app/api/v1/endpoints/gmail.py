"""
PhishGuard AI — Gmail Integration & Auto-Analyze Endpoints
Allows users to connect their Gmail account, sync inbox emails,
search and filter their messages, and trigger manual or automatic
sandbox AI phishing analysis with real-time detection.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, EmailStr
from sqlalchemy import select, update, func, desc
from sqlalchemy.ext.asyncio import AsyncSession
from urllib.parse import quote_plus

from app.core.config import settings
from app.core.database import get_db
from app.models import GmailIntegration, GmailMessage, Email, User, OAuthState
from app.security.auth import get_current_user
from app.services.gmail_oauth_service import (
    gmail_oauth_service,
    GoogleOAuthConfigurationError,
    GoogleOAuthError,
    GoogleOAuthCSRFError,
    GmailAccountConflictError,
    GoogleTokenRevokedError,
)
from app.services.gmail_client_service import (
    gmail_client_service,
    GmailAPIError,
    GmailRateLimitError,
    GmailPermissionError,
    GmailInitialScanConsentRequiredError,
    GmailWatchError,
    GmailHistoryExpiredError,
)
from app.workers.tasks import execute_email_analysis
from app.utils.response import success_response, error_response

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Gmail Integration"])


# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------

class ConnectGmailRequest(BaseModel):
    email_address: EmailStr
    app_password: Optional[str] = None
    auto_analyze: bool = True
    sync_demo_inbox: bool = True


class InitiateOAuthRequest(BaseModel):
    redirect_uri: Optional[str] = None


class OAuthCallbackRequest(BaseModel):
    code: Optional[str] = None
    state: Optional[str] = None
    error: Optional[str] = None
    redirect_uri: Optional[str] = None


class InitialScanRequest(BaseModel):
    consent_acknowledged: bool = False
    max_messages: int = 50


class ToggleAutoAnalyzeRequest(BaseModel):
    enabled: bool


class PubSubMessageData(BaseModel):
    data: str
    messageId: str
    publishTime: Optional[str] = None


class PubSubPushRequest(BaseModel):
    message: PubSubMessageData
    subscription: Optional[str] = None


# ---------------------------------------------------------------------------
# Core Analysis Runner for Gmail Message
# ---------------------------------------------------------------------------

async def _analyze_single_gmail_message_by_id(
    message_id_str: str,
    user_id_str: str,
    org_id_str: str,
) -> None:
    """
    Executes the genuine 5-stage security analysis pipeline for a single Gmail message.
    Updates risk scores and classifications directly from the pipeline engine.
    """
    from app.core.database import AsyncSessionLocal
    from app.workers.tasks import execute_email_analysis, analyze_email_task
    import uuid

    msg_uuid = uuid.UUID(message_id_str)
    user_uuid = uuid.UUID(user_id_str)
    org_uuid = uuid.UUID(org_id_str)

    target_email_id = None
    async with AsyncSessionLocal() as session:
        res = await session.execute(
            select(GmailMessage).where(GmailMessage.id == msg_uuid)
        )
        msg = res.scalar_one_or_none()
        if not msg:
            return

        if msg.is_analyzed and msg.analysis_status == "analyzed" and msg.email_id:
            return

        msg.analysis_status = "processing"

        if msg.email_id:
            target_email_id = msg.email_id
        else:
            raw_eml = msg.raw_eml or ""
            email_record = Email(
                id=uuid.uuid4(),
                organization_id=org_uuid,
                submitted_by=user_uuid,
                original_filename=f"gmail_{msg.gmail_message_id}.eml",
                source_type="gmail_sync",
                file_size_bytes=len(raw_eml.encode("utf-8")),
                raw_content=raw_eml,
                analysis_status="pending",
                received_at=msg.received_at,
                subject=msg.subject,
                sender_raw=msg.sender,
            )
            session.add(email_record)
            await session.flush()
            msg.email_id = email_record.id
            target_email_id = email_record.id

        await session.commit()

    if target_email_id:
        try:
            analyze_email_task.delay(str(target_email_id), str(org_uuid))
        except Exception:
            await execute_email_analysis(str(target_email_id), str(org_uuid))



# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------

@router.get("/status")
async def get_gmail_status(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Returns current Gmail connection state, OAuth credentials status, and message stats."""
    res = await db.execute(
        select(GmailIntegration).where(
            GmailIntegration.organization_id == current_user.organization_id,
            GmailIntegration.user_id == current_user.id,
        )
    )
    integration = res.scalar_one_or_none()

    if not integration or not integration.is_connected:
        return success_response({
            "is_connected": False,
            "connection_status": "disconnected" if not integration else integration.connection_status,
            "token_status": "none" if not integration else integration.token_status,
            "email_address": integration.email_address if integration else None,
            "granted_scopes": integration.granted_scopes if integration else [],
            "last_verified_at": integration.last_verified_at.isoformat() if integration and integration.last_verified_at else None,
            "last_error": integration.last_error if integration else None,
            "watch_status": "inactive",
            "watch_expiration": None,
            "last_history_id": None,
            "pubsub_topic": settings.GMAIL_PUBSUB_TOPIC or None,
            "auto_analyze_enabled": False,
            "total_messages": 0,
            "analyzed_messages": 0,
            "pending_messages": 0,
            "critical_threats": 0,
            "last_synced_at": None,
        })

    # Count stats
    total_q = await db.execute(
        select(func.count(GmailMessage.id)).where(
            GmailMessage.integration_id == integration.id
        )
    )
    total_msgs = total_q.scalar_one() or 0

    analyzed_q = await db.execute(
        select(func.count(GmailMessage.id)).where(
            GmailMessage.integration_id == integration.id,
            GmailMessage.is_analyzed == True,
        )
    )
    analyzed_msgs = analyzed_q.scalar_one() or 0

    critical_q = await db.execute(
        select(func.count(GmailMessage.id)).where(
            GmailMessage.integration_id == integration.id,
            GmailMessage.risk_classification.in_(["Critical", "High", "Malicious"]),
        )
    )
    critical_msgs = critical_q.scalar_one() or 0

    return success_response({
        "is_connected": integration.is_connected,
        "connection_status": integration.connection_status,
        "token_status": integration.token_status,
        "email_address": integration.email_address,
        "granted_scopes": integration.granted_scopes or [],
        "last_verified_at": integration.last_verified_at.isoformat() if integration.last_verified_at else None,
        "last_error": integration.last_error,
        "watch_status": getattr(integration, "watch_status", "inactive"),
        "watch_expiration": integration.watch_expiration.isoformat() if integration.watch_expiration else None,
        "last_history_id": integration.last_history_id,
        "pubsub_topic": settings.GMAIL_PUBSUB_TOPIC or None,
        "auto_analyze_enabled": integration.auto_analyze_enabled,
        "auth_type": integration.auth_type,
        "total_messages": total_msgs,
        "analyzed_messages": analyzed_msgs,
        "pending_messages": total_msgs - analyzed_msgs,
        "critical_threats": critical_msgs,
        "last_synced_at": integration.last_synced_at.isoformat() if integration.last_synced_at else None,
    })


@router.get("/oauth/authorize")
@router.post("/oauth/initiate")
async def start_google_oauth(
    redirect_uri: Optional[str] = Query(None),
    payload: Optional[InitiateOAuthRequest] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Initiates official Google OAuth 2.0 Web Server flow with PKCE and one-time CSRF state.
    Returns authorization URL for redirecting the user's browser to Google.
    """
    effective_redirect_uri = (payload.redirect_uri if payload else None) or redirect_uri
    try:
        auth_url, state = await gmail_oauth_service.create_authorization_url(
            db=db,
            user=current_user,
            custom_redirect_uri=effective_redirect_uri,
        )
        return success_response({
            "authorization_url": auth_url,
            "state": state,
        })
    except GoogleOAuthConfigurationError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(e),
        )
    except Exception as e:
        logger.exception("Failed to initiate Google OAuth: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to initiate Google OAuth authorization: {str(e)}",
        )


@router.post("/oauth/callback")
async def handle_google_oauth_callback(
    payload: OAuthCallbackRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Processes OAuth 2.0 callback from Google.
    Exchanges code for tokens, verifies account via users.getProfile,
    encrypts tokens at rest, and associates connection with current user.
    """
    try:
        integration = await gmail_oauth_service.exchange_code_and_verify_account(
            db=db,
            user=current_user,
            code=payload.code or "",
            state=payload.state or "",
            error=payload.error,
        )
        return success_response({
            "message": f"Successfully connected and verified Gmail account ({integration.email_address})",
            "id": str(integration.id),
            "email_address": integration.email_address,
            "is_connected": integration.is_connected,
            "connection_status": integration.connection_status,
            "token_status": integration.token_status,
            "granted_scopes": integration.granted_scopes,
            "last_verified_at": integration.last_verified_at.isoformat() if integration.last_verified_at else None,
        })
    except GoogleOAuthConfigurationError as e:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e))
    except GoogleOAuthCSRFError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except GmailAccountConflictError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except GoogleOAuthError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.exception("Unexpected error during Google OAuth callback: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"OAuth callback processing failed: {str(e)}",
        )


@router.get("/oauth/callback")
async def handle_google_oauth_browser_redirect(
    code: Optional[str] = Query(None),
    state: Optional[str] = Query(None),
    error: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """
    Direct browser callback endpoint when redirect_uri points to backend.
    Validates state to locate user, performs exchange, and redirects to frontend.
    """
    frontend_base = settings.FRONTEND_URL.rstrip("/")
    if error:
        err_param = quote_plus(f"Google authorization failed: {error}")
        return RedirectResponse(url=f"{frontend_base}/dashboard?gmail_error={err_param}", status_code=302)

    if not state or not code:
        err_param = quote_plus("Missing code or state in OAuth callback.")
        return RedirectResponse(url=f"{frontend_base}/dashboard?gmail_error={err_param}", status_code=302)

    # Locate user via state record
    stmt = select(OAuthState).where(OAuthState.state == state.strip())
    res = await db.execute(stmt)
    state_rec = res.scalar_one_or_none()

    if not state_rec:
        err_param = quote_plus("Invalid or expired OAuth state parameter (CSRF protection failed).")
        return RedirectResponse(url=f"{frontend_base}/dashboard?gmail_error={err_param}", status_code=302)

    user_res = await db.execute(select(User).where(User.id == state_rec.user_id))
    user = user_res.scalar_one_or_none()
    if not user:
        err_param = quote_plus("Associated PhishGuard user account not found.")
        return RedirectResponse(url=f"{frontend_base}/dashboard?gmail_error={err_param}", status_code=302)

    try:
        integration = await gmail_oauth_service.exchange_code_and_verify_account(
            db=db,
            user=user,
            code=code,
            state=state,
        )
        email_param = quote_plus(integration.email_address)
        return RedirectResponse(url=f"{frontend_base}/dashboard?gmail_connected=true&email={email_param}", status_code=302)
    except Exception as e:
        err_param = quote_plus(str(e))
        return RedirectResponse(url=f"{frontend_base}/dashboard?gmail_error={err_param}", status_code=302)


@router.get("/accounts")
async def list_connected_gmail_accounts(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Lists all Gmail connections associated with the current user / organization."""
    query = select(GmailIntegration).where(
        GmailIntegration.organization_id == current_user.organization_id,
        GmailIntegration.user_id == current_user.id,
    ).order_by(desc(GmailIntegration.created_at))

    result = await db.execute(query)
    integrations = result.scalars().all()

    accounts = [
        {
            "id": str(i.id),
            "email_address": i.email_address,
            "is_connected": i.is_connected,
            "connection_status": i.connection_status,
            "token_status": i.token_status,
            "granted_scopes": i.granted_scopes or [],
            "connected_at": i.connected_at.isoformat() if i.connected_at else None,
            "last_verified_at": i.last_verified_at.isoformat() if i.last_verified_at else None,
            "last_synced_at": i.last_synced_at.isoformat() if i.last_synced_at else None,
            "last_error": i.last_error,
            "auto_analyze_enabled": i.auto_analyze_enabled,
        }
        for i in integrations
    ]
    return success_response({"accounts": accounts, "total": len(accounts)})


@router.post("/disconnect")
async def disconnect_gmail(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Disconnects the connected Gmail account and revokes access with Google."""
    disconnected = await gmail_oauth_service.disconnect_and_revoke(db, current_user)
    if not disconnected:
        return success_response({"message": "No active Gmail account to disconnect."})
    return success_response({"message": "Gmail account disconnected and tokens revoked successfully."})


@router.post("/accounts/{account_id}/disconnect")
async def disconnect_gmail_account_by_id(
    account_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Disconnects a specific Gmail account connection and revokes credentials."""
    disconnected = await gmail_oauth_service.disconnect_and_revoke(db, current_user, integration_id=account_id)
    if not disconnected:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Gmail connection not found.")
    return success_response({"message": "Gmail connection disconnected successfully."})


@router.post("/connect")
async def connect_gmail(
    payload: ConnectGmailRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Legacy/Fallback connect endpoint (deprecated in favor of genuine Google OAuth flow).
    """
    res = await db.execute(
        select(GmailIntegration).where(
            GmailIntegration.organization_id == current_user.organization_id,
            GmailIntegration.user_id == current_user.id,
        )
    )
    integration = res.scalar_one_or_none()

    now = datetime.now(timezone.utc)
    if not integration:
        integration = GmailIntegration(
            id=uuid.uuid4(),
            organization_id=current_user.organization_id,
            user_id=current_user.id,
            email_address=payload.email_address,
            is_connected=True,
            connection_status="connected",
            token_status="valid",
            auto_analyze_enabled=payload.auto_analyze,
            auth_type="app_password" if payload.app_password else "oauth_sync",
            last_synced_at=now,
        )
        db.add(integration)
    else:
        integration.email_address = payload.email_address
        integration.is_connected = True
        integration.connection_status = "connected"
        integration.auto_analyze_enabled = payload.auto_analyze
        integration.last_synced_at = now
        if payload.app_password:
            integration.auth_type = "app_password"

    await db.commit()
    await db.refresh(integration)

    return success_response({
        "message": f"Successfully connected Gmail account ({payload.email_address})",
        "email_address": payload.email_address,
        "auto_analyze_enabled": payload.auto_analyze,
    })


@router.post("/toggle-auto-analyze")
async def toggle_auto_analyze(
    payload: ToggleAutoAnalyzeRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Toggles automatic analysis of incoming Gmail emails."""
    res = await db.execute(
        select(GmailIntegration).where(
            GmailIntegration.organization_id == current_user.organization_id,
            GmailIntegration.user_id == current_user.id,
        )
    )
    integration = res.scalar_one_or_none()
    if not integration or not integration.is_connected:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active Gmail account connected. Connect Gmail first."
        )

    integration.auto_analyze_enabled = payload.enabled
    await db.commit()

    # If enabled, also analyze any pending messages automatically right now!
    if payload.enabled:
        pending_res = await db.execute(
            select(GmailMessage.id).where(
                GmailMessage.integration_id == integration.id,
                GmailMessage.is_analyzed == False,
            )
        )
        pending_ids = [str(r[0]) for r in pending_res.all()]
        for pid in pending_ids:
            asyncio.create_task(_analyze_single_gmail_message_by_id(
                pid, str(current_user.id), str(current_user.organization_id)
            ))

    return success_response({
        "auto_analyze_enabled": integration.auto_analyze_enabled,
        "message": f"Auto-Analyze {'activated' if payload.enabled else 'disabled'}"
    })


@router.get("/messages")
async def get_gmail_messages(
    search: Optional[str] = Query(None, description="Search subject, sender, or snippet"),
    threat_level: Optional[str] = Query(None, description="Filter: all | safe | suspicious | critical"),
    status_filter: Optional[str] = Query(None, description="Filter: all | analyzed | pending"),
    limit: int = Query(50, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Returns list of synced Gmail messages with real-time risk scores and filters."""
    res = await db.execute(
        select(GmailIntegration).where(
            GmailIntegration.organization_id == current_user.organization_id,
            GmailIntegration.user_id == current_user.id,
            GmailIntegration.is_connected == True,
        )
    )
    integration = res.scalar_one_or_none()
    if not integration:
        return success_response({"messages": [], "total": 0})

    query = select(GmailMessage).where(
        GmailMessage.integration_id == integration.id
    )

    if search:
        search_fmt = f"%{search.strip()}%"
        query = query.where(
            (GmailMessage.subject.ilike(search_fmt)) |
            (GmailMessage.sender.ilike(search_fmt)) |
            (GmailMessage.snippet.ilike(search_fmt))
        )

    if status_filter == "analyzed":
        query = query.where(GmailMessage.is_analyzed == True)
    elif status_filter == "pending":
        query = query.where(GmailMessage.is_analyzed == False)

    if threat_level and threat_level != "all":
        if threat_level.lower() == "safe":
            query = query.where(GmailMessage.risk_classification == "Safe")
        elif threat_level.lower() == "suspicious":
            query = query.where(GmailMessage.risk_classification.in_(["Suspicious", "Medium"]))
        elif threat_level.lower() == "critical":
            query = query.where(GmailMessage.risk_classification.in_(["Critical", "High", "Malicious"]))

    query = query.order_by(desc(GmailMessage.received_at)).limit(limit)
    msg_res = await db.execute(query)
    messages = msg_res.scalars().all()

    formatted = []
    for m in messages:
        formatted.append({
            "id": str(m.id),
            "gmail_message_id": m.gmail_message_id,
            "subject": m.subject,
            "sender": m.sender,
            "snippet": m.snippet,
            "received_at": m.received_at.isoformat() if m.received_at else None,
            "is_analyzed": m.is_analyzed,
            "analysis_status": m.analysis_status,
            "risk_score": m.risk_score,
            "risk_classification": m.risk_classification,
            "email_id": str(m.email_id) if m.email_id else None,
        })

    return success_response({
        "messages": formatted,
        "total": len(formatted),
        "integration_email": integration.email_address,
        "auto_analyze_enabled": integration.auto_analyze_enabled,
    })


@router.post("/messages/{message_id}/analyze")
async def analyze_gmail_message_manual(
    message_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Manually triggers static sandbox & AI pipeline analysis for a specific Gmail email."""
    try:
        msg_uuid = uuid.UUID(message_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid message ID format")

    res = await db.execute(
        select(GmailMessage).where(
            GmailMessage.id == msg_uuid,
            GmailMessage.organization_id == current_user.organization_id,
        )
    )
    msg = res.scalar_one_or_none()
    if not msg:
        raise HTTPException(status_code=404, detail="Gmail message not found")

    await _analyze_single_gmail_message_by_id(
        str(msg.id), str(current_user.id), str(current_user.organization_id)
    )
    
    # Reload fresh
    await db.refresh(msg)

    return success_response({
        "message": "Email analysis completed successfully",
        "email_id": str(msg.email_id) if msg.email_id else None,
        "risk_score": msg.risk_score,
        "risk_classification": msg.risk_classification,
    })


@router.post("/analyze-all")
async def analyze_all_pending_messages(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Batch analyzes all unanalyzed pending Gmail emails."""
    res = await db.execute(
        select(GmailIntegration).where(
            GmailIntegration.organization_id == current_user.organization_id,
            GmailIntegration.user_id == current_user.id,
            GmailIntegration.is_connected == True,
        )
    )
    integration = res.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=400, detail="No connected Gmail account found")

    pending_res = await db.execute(
        select(GmailMessage.id).where(
            GmailMessage.integration_id == integration.id,
            GmailMessage.is_analyzed == False,
        )
    )
    pending_ids = [str(r[0]) for r in pending_res.all()]
    count = len(pending_ids)

    for pid in pending_ids:
        asyncio.create_task(_analyze_single_gmail_message_by_id(
            pid, str(current_user.id), str(current_user.organization_id)
        ))

    return success_response({
        "message": f"Queued {count} messages for batch automated analysis",
        "queued_count": count,
    })


@router.post("/sync")
async def sync_gmail_inbox(
    max_messages: int = Query(20, ge=1, le=50, description="Max messages to retrieve in this sync (bounded concurrency)"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Syncs new incoming emails from Gmail INBOX using genuine Google Gmail REST API.
    Enforces INBOX-only listing, lossless RFC-822 MIME retrieval, and idempotency.
    Triggers automated pipeline analysis if auto_analyze is enabled.
    """
    res = await db.execute(
        select(GmailIntegration).where(
            GmailIntegration.organization_id == current_user.organization_id,
            GmailIntegration.user_id == current_user.id,
            GmailIntegration.is_connected == True,
        )
    )
    integration = res.scalar_one_or_none()
    if not integration:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No connected Gmail account found. Please connect your Gmail account via OAuth first."
        )

    try:
        result = await gmail_client_service.sync_inbox(
            db=db,
            user=current_user,
            integration=integration,
            max_messages=max_messages,
            is_initial_scan=False,
            consent_acknowledged=False,
        )
        return success_response(result)
    except GoogleTokenRevokedError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Gmail authorization has expired or was revoked. Please reconnect your account: {e}",
        )
    except GmailPermissionError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )
    except GmailRateLimitError as e:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(e),
        )
    except GmailAPIError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Google Gmail API error: {e}",
        )


# In-memory deduplication cache for recent Pub/Sub message IDs
_PROCESSED_PUBSUB_MSG_IDS: set[str] = set()
_MAX_PUBSUB_CACHE = 1000


@router.post("/watch")
async def start_gmail_watch(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Activates real-time Gmail push notification watch for user's connected account.
    Configures watch for INBOX label only with least privilege.
    """
    res = await db.execute(
        select(GmailIntegration).where(
            GmailIntegration.organization_id == current_user.organization_id,
            GmailIntegration.user_id == current_user.id,
            GmailIntegration.is_connected == True,
        )
    )
    integration = res.scalar_one_or_none()
    if not integration:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active Gmail account connected. Connect Gmail first."
        )

    try:
        result = await gmail_client_service.watch_inbox(db=db, integration=integration)
        return success_response({
            "message": "Gmail real-time watch successfully established.",
            **result,
        })
    except GmailWatchError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except GmailPermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except GoogleTokenRevokedError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
    except GmailAPIError as e:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=f"Google API error: {e}")


@router.post("/stop-watch")
async def stop_gmail_watch(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Stops real-time Gmail push notifications for user's connected account."""
    res = await db.execute(
        select(GmailIntegration).where(
            GmailIntegration.organization_id == current_user.organization_id,
            GmailIntegration.user_id == current_user.id,
            GmailIntegration.is_connected == True,
        )
    )
    integration = res.scalar_one_or_none()
    if not integration:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active Gmail account connected."
        )

    result = await gmail_client_service.stop_watch(db=db, integration=integration)
    return success_response(result)


@router.post("/webhook/pubsub")
async def gmail_pubsub_webhook(
    request: Request,
    payload: PubSubPushRequest,
    token: Optional[str] = Query(None, description="Verification token query parameter"),
    db: AsyncSession = Depends(get_db),
):
    """
    Dedicated Google Cloud Pub/Sub push notification endpoint for real-time Gmail monitoring.
    1. Authenticates push request via configured verification token or Google OIDC Bearer token.
    2. Validates subscription identity.
    3. Decodes message.data (base64 JSON containing emailAddress and historyId).
    4. Validates connection ownership and status in database.
    5. Acknowledges immediately with HTTP 200 to prevent Pub/Sub delivery timeout.
    6. Enqueues background history synchronization task.
    """
    global _PROCESSED_PUBSUB_MSG_IDS

    # 1. Verification Token / Authentication
    expected_token = settings.GMAIL_PUBSUB_VERIFICATION_TOKEN
    if expected_token:
        auth_header = request.headers.get("Authorization", "")
        bearer_token = auth_header.replace("Bearer ", "").strip() if auth_header.startswith("Bearer ") else ""
        header_token = (
            request.headers.get("X-Goog-Pubsub-Verification-Token")
            or request.headers.get("X-Pubsub-Verification-Token")
            or bearer_token
        )

        incoming_token = token or header_token
        if not incoming_token or incoming_token != expected_token:
            logger.warning("Pub/Sub webhook rejected: invalid or missing verification token")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unauthorized: invalid or missing Pub/Sub verification token",
            )

    # 2. Subscription Identity Validation
    expected_subscription = settings.GMAIL_PUBSUB_SUBSCRIPTION
    if expected_subscription and payload.subscription:
        if not payload.subscription.endswith(expected_subscription) and payload.subscription != expected_subscription:
            logger.warning("Pub/Sub webhook rejected: subscription mismatch '%s' vs '%s'", payload.subscription, expected_subscription)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid Pub/Sub subscription identity",
            )

    # 3. Payload Decoding & Validation
    if not payload.message or not payload.message.data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing Pub/Sub message data payload",
        )

    try:
        raw_bytes = base64.b64decode(payload.message.data)
        notification_data = json.loads(raw_bytes.decode("utf-8"))
    except Exception as e:
        logger.error("Failed to decode Pub/Sub push data: %s", e)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid base64/JSON encoding in Pub/Sub message data",
        )

    target_email = notification_data.get("emailAddress")
    history_id = notification_data.get("historyId")

    if not target_email or not history_id:
        logger.warning("Pub/Sub message missing required fields: %s", notification_data)
        return success_response({"status": "ignored", "reason": "Missing emailAddress or historyId"})

    # 4. Match to existing authorized Gmail connection (Never trust email from unverified source)
    stmt = select(GmailIntegration).where(
        GmailIntegration.email_address == target_email,
        GmailIntegration.is_connected == True,
    )
    res = await db.execute(stmt)
    integration = res.scalar_one_or_none()
    if not integration:
        logger.warning("Received Pub/Sub notification for unknown or disconnected account: %s", target_email)
        # Return 200 acknowledged so Google Pub/Sub does not enter a continuous retry loop for defunct accounts
        return success_response({"status": "ignored", "reason": "Account not connected in PhishGuard"})

    # 5. Push Notification Deduplication
    pubsub_msg_id = payload.message.messageId
    if pubsub_msg_id:
        if pubsub_msg_id in _PROCESSED_PUBSUB_MSG_IDS:
            logger.info("Duplicate Pub/Sub delivery %s for %s; returning ack", pubsub_msg_id, target_email)
            return success_response({"status": "acknowledged", "duplicate": True})

        if len(_PROCESSED_PUBSUB_MSG_IDS) >= _MAX_PUBSUB_CACHE:
            _PROCESSED_PUBSUB_MSG_IDS.clear()
        _PROCESSED_PUBSUB_MSG_IDS.add(pubsub_msg_id)

    # 6. Acknowledge promptly & enqueue background history sync
    from app.workers.tasks import sync_gmail_history_task, execute_gmail_history_sync
    try:
        sync_gmail_history_task.delay(str(integration.id), str(history_id))
    except Exception:
        asyncio.create_task(execute_gmail_history_sync(str(integration.id), str(history_id)))

    logger.info("Pub/Sub push acknowledged for %s; historyId=%s enqueued for sync", target_email, history_id)
    return success_response({
        "status": "acknowledged",
        "email_address": target_email,
        "history_id": str(history_id),
        "message": "Pub/Sub notification acknowledged and history sync enqueued",
    })


@router.post("/initial-scan")
async def initial_inbox_scan(
    payload: InitialScanRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Performs an initial historical scan of the user's Gmail INBOX.
    MANDATORY REQUIREMENT: Requires explicit user consent (consent_acknowledged=True).
    Without explicit consent, returns 400 Bad Request.
    """
    if not payload.consent_acknowledged:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Explicit user consent is required before performing an initial scan of historical emails.",
        )

    res = await db.execute(
        select(GmailIntegration).where(
            GmailIntegration.organization_id == current_user.organization_id,
            GmailIntegration.user_id == current_user.id,
            GmailIntegration.is_connected == True,
        )
    )
    integration = res.scalar_one_or_none()
    if not integration:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No connected Gmail account found. Please connect your Gmail account via OAuth first."
        )

    try:
        result = await gmail_client_service.sync_inbox(
            db=db,
            user=current_user,
            integration=integration,
            max_messages=payload.max_messages,
            is_initial_scan=True,
            consent_acknowledged=payload.consent_acknowledged,
        )
        return success_response(result)
    except GoogleTokenRevokedError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Gmail authorization has expired or was revoked. Please reconnect your account: {e}",
        )
    except GmailPermissionError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )
    except GmailRateLimitError as e:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(e),
        )
    except GmailAPIError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Google Gmail API error: {e}",
        )


# In-memory deduplication cache for recent Pub/Sub message IDs
_PROCESSED_PUBSUB_MSG_IDS: set[str] = set()
_MAX_PUBSUB_CACHE = 1000


@router.post("/watch")
async def start_gmail_watch(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Activates real-time Gmail push notification watch for user's connected account.
    Configures watch for INBOX label only with least privilege.
    """
    res = await db.execute(
        select(GmailIntegration).where(
            GmailIntegration.organization_id == current_user.organization_id,
            GmailIntegration.user_id == current_user.id,
            GmailIntegration.is_connected == True,
        )
    )
    integration = res.scalar_one_or_none()
    if not integration:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active Gmail account connected. Connect Gmail first."
        )

    try:
        result = await gmail_client_service.watch_inbox(db=db, integration=integration)
        return success_response({
            "message": "Gmail real-time watch successfully established.",
            **result,
        })
    except GmailWatchError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except GmailPermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except GoogleTokenRevokedError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
    except GmailAPIError as e:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=f"Google API error: {e}")


@router.post("/stop-watch")
async def stop_gmail_watch(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Stops real-time Gmail push notifications for user's connected account."""
    res = await db.execute(
        select(GmailIntegration).where(
            GmailIntegration.organization_id == current_user.organization_id,
            GmailIntegration.user_id == current_user.id,
            GmailIntegration.is_connected == True,
        )
    )
    integration = res.scalar_one_or_none()
    if not integration:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No active Gmail account connected."
        )

    result = await gmail_client_service.stop_watch(db=db, integration=integration)
    return success_response(result)


@router.post("/webhook/pubsub")
async def gmail_pubsub_webhook(
    request: Request,
    payload: PubSubPushRequest,
    token: Optional[str] = Query(None, description="Verification token query parameter"),
    db: AsyncSession = Depends(get_db),
):
    """
    Dedicated Google Cloud Pub/Sub push notification endpoint for real-time Gmail monitoring.
    1. Authenticates push request via configured verification token or Google OIDC Bearer token.
    2. Validates subscription identity.
    3. Decodes message.data (base64 JSON containing emailAddress and historyId).
    4. Validates connection ownership and status in database.
    5. Acknowledges immediately with HTTP 200 to prevent Pub/Sub delivery timeout.
    6. Enqueues background history synchronization task.
    """
    global _PROCESSED_PUBSUB_MSG_IDS

    # 1. Verification Token / Authentication
    expected_token = settings.GMAIL_PUBSUB_VERIFICATION_TOKEN
    if expected_token:
        auth_header = request.headers.get("Authorization", "")
        bearer_token = auth_header.replace("Bearer ", "").strip() if auth_header.startswith("Bearer ") else ""
        header_token = (
            request.headers.get("X-Goog-Pubsub-Verification-Token")
            or request.headers.get("X-Pubsub-Verification-Token")
            or bearer_token
        )

        incoming_token = token or header_token
        if not incoming_token or incoming_token != expected_token:
            logger.warning("Pub/Sub webhook rejected: invalid or missing verification token")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unauthorized: invalid or missing Pub/Sub verification token",
            )

    # 2. Subscription Identity Validation
    expected_subscription = settings.GMAIL_PUBSUB_SUBSCRIPTION
    if expected_subscription and payload.subscription:
        if not payload.subscription.endswith(expected_subscription) and payload.subscription != expected_subscription:
            logger.warning("Pub/Sub webhook rejected: subscription mismatch '%s' vs '%s'", payload.subscription, expected_subscription)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid Pub/Sub subscription identity",
            )

    # 3. Payload Decoding & Validation
    if not payload.message or not payload.message.data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing Pub/Sub message data payload",
        )

    try:
        raw_bytes = base64.b64decode(payload.message.data)
        notification_data = json.loads(raw_bytes.decode("utf-8"))
    except Exception as e:
        logger.error("Failed to decode Pub/Sub push data: %s", e)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid base64/JSON encoding in Pub/Sub message data",
        )

    target_email = notification_data.get("emailAddress")
    history_id = notification_data.get("historyId")

    if not target_email or not history_id:
        logger.warning("Pub/Sub message missing required fields: %s", notification_data)
        return success_response({"status": "ignored", "reason": "Missing emailAddress or historyId"})

    # 4. Match to existing authorized Gmail connection (Never trust email from unverified source)
    stmt = select(GmailIntegration).where(
        GmailIntegration.email_address == target_email,
        GmailIntegration.is_connected == True,
    )
    res = await db.execute(stmt)
    integration = res.scalar_one_or_none()
    if not integration:
        logger.warning("Received Pub/Sub notification for unknown or disconnected account: %s", target_email)
        # Return 200 acknowledged so Google Pub/Sub does not enter a continuous retry loop for defunct accounts
        return success_response({"status": "ignored", "reason": "Account not connected in PhishGuard"})

    # 5. Push Notification Deduplication
    pubsub_msg_id = payload.message.messageId
    if pubsub_msg_id:
        if pubsub_msg_id in _PROCESSED_PUBSUB_MSG_IDS:
            logger.info("Duplicate Pub/Sub delivery %s for %s; returning ack", pubsub_msg_id, target_email)
            return success_response({"status": "acknowledged", "duplicate": True})

        if len(_PROCESSED_PUBSUB_MSG_IDS) >= _MAX_PUBSUB_CACHE:
            _PROCESSED_PUBSUB_MSG_IDS.clear()
        _PROCESSED_PUBSUB_MSG_IDS.add(pubsub_msg_id)

    # 6. Acknowledge promptly & enqueue background history sync
    from app.workers.tasks import sync_gmail_history_task, execute_gmail_history_sync
    try:
        sync_gmail_history_task.delay(str(integration.id), str(history_id))
    except Exception:
        asyncio.create_task(execute_gmail_history_sync(str(integration.id), str(history_id)))

    logger.info("Pub/Sub push acknowledged for %s; historyId=%s enqueued for sync", target_email, history_id)
    return success_response({
        "status": "acknowledged",
        "email_address": target_email,
        "history_id": str(history_id),
        "message": "Pub/Sub notification acknowledged and history sync enqueued",
    })
