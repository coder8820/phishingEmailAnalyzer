"""
PhishGuard AI — Genuine Gmail API Client & Inbox Retrieval Service
Implements:
- Direct Google Gmail REST API v1 integration
- INBOX-only message listing (excluding Sent, Drafts, Spam, Trash, and Archived)
- Lossless raw RFC-822 MIME retrieval and attachment retrieval
- Safe integration with hardened EmailParser
- Strong idempotency (one analysis per Gmail message ID, no duplicate analyses on repeat syncs)
- Automatic token refresh & rate-limit exponential backoff
- Multi-tenant security & untrusted content sanitization
"""

from __future__ import annotations

import asyncio
import base64
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import httpx
from sqlalchemy import select, update, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.analyzers.email_parser import EmailParser, ParsedEmail
from app.core.config import settings
from app.models import GmailIntegration, GmailMessage, Email, User, AuditLog
from app.services.gmail_oauth_service import (
    gmail_oauth_service,
    GoogleOAuthError,
    GoogleTokenRevokedError,
)

logger = logging.getLogger(__name__)

# Google Gmail API v1 Endpoints
GMAIL_MESSAGES_ENDPOINT = "https://gmail.googleapis.com/gmail/v1/users/me/messages"
GMAIL_LABELS_ENDPOINT = "https://gmail.googleapis.com/gmail/v1/users/me/labels"
GMAIL_PROFILE_ENDPOINT = "https://gmail.googleapis.com/gmail/v1/users/me/profile"
GMAIL_WATCH_ENDPOINT = "https://gmail.googleapis.com/gmail/v1/users/me/watch"
GMAIL_STOP_WATCH_ENDPOINT = "https://gmail.googleapis.com/gmail/v1/users/me/stop"
GMAIL_HISTORY_ENDPOINT = "https://gmail.googleapis.com/gmail/v1/users/me/history"

# Query to guarantee INBOX ONLY and exclude drafts, sent, spam, and trash
INBOX_SEARCH_QUERY = "label:INBOX -in:spam -in:trash -in:drafts -in:sent"

# Excluded system labels
EXCLUDED_LABELS = {"SPAM", "TRASH", "DRAFT", "SENT"}


class GmailAPIError(Exception):
    """Base exception for Gmail API client errors."""
    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class GmailRateLimitError(GmailAPIError):
    """Raised when Google API rate limits or quota exceeded (HTTP 429 / 503)."""
    pass


class GmailPermissionError(GmailAPIError):
    """Raised when OAuth token has insufficient permissions or scope."""
    pass


class GmailInitialScanConsentRequiredError(GmailAPIError):
    """Raised when initial historical inbox scan is requested without explicit consent."""
    pass


class GmailWatchError(GmailAPIError):
    """Raised when setting up or renewing Gmail watch fails."""
    pass


class GmailHistoryExpiredError(GmailAPIError):
    """Raised when startHistoryId is too old or invalid and Google returns HTTP 404."""
    pass


class GmailQuarantineError(GmailAPIError):
    """Raised when message quarantine or label operations fail."""
    pass


def decode_base64url_bytes(b64_str: str) -> bytes:
    """
    Safely decodes an RFC 4648 base64url-encoded string into lossless raw bytes,
    handling missing '=' padding gracefully.
    """
    if not b64_str:
        return b""
    # Replace URL-safe chars and add necessary padding
    padded = b64_str + "=" * (-len(b64_str) % 4)
    return base64.urlsafe_b64decode(padded)


class GmailClientService:
    """Production client for interacting with Google's Gmail API."""

    def __init__(self, http_client: Optional[httpx.AsyncClient] = None):
        self._http_client = http_client

    async def _make_api_request(
        self,
        db: AsyncSession,
        integration: GmailIntegration,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        retries: int = 3,
        backoff_factor: float = 1.0,
    ) -> httpx.Response:
        """
        Executes authenticated Google API request with automatic token refresh,
        rate-limit handling, and exponential backoff.
        """
        access_token = await gmail_oauth_service.get_valid_access_token(db, integration)

        for attempt in range(retries):
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
            }
            try:
                async with httpx.AsyncClient(timeout=20.0) as client:
                    resp = await client.request(
                        method=method,
                        url=url,
                        params=params,
                        json=json_data,
                        headers=headers,
                    )

                # Handle 401 Unauthorized -> Refresh token once and retry
                if resp.status_code == 401 and attempt == 0:
                    logger.warning("Gmail API returned 401; refreshing access token for %s", integration.email_address)
                    access_token = await gmail_oauth_service.refresh_access_token(db, integration)
                    continue

                # Handle 403 / 429 Rate Limits -> Exponential backoff
                if resp.status_code in (429, 503):
                    delay = backoff_factor * (2 ** attempt)
                    logger.warning("Gmail API rate limited (HTTP %s). Retrying in %.1fs...", resp.status_code, delay)
                    await asyncio.sleep(delay)
                    continue

                # Handle 403 Insufficient Permissions
                if resp.status_code == 403:
                    err_body = resp.text
                    logger.error("Gmail API 403 Forbidden for %s: %s", integration.email_address, err_body)
                    raise GmailPermissionError(f"Insufficient Gmail permissions for {integration.email_address}: {err_body}")

                # Handle 404 on History API (History ID expired or invalid)
                if resp.status_code == 404 and GMAIL_HISTORY_ENDPOINT in url:
                    logger.warning("Gmail history expired (HTTP 404) for %s: %s", integration.email_address, resp.text)
                    raise GmailHistoryExpiredError(f"Gmail history ID expired or invalid: {resp.text}", status_code=404)

                if resp.status_code >= 400:
                    logger.error("Gmail API HTTP %s: %s", resp.status_code, resp.text)
                    raise GmailAPIError(f"Gmail API error (HTTP {resp.status_code}): {resp.text}", status_code=resp.status_code)

                return resp

            except httpx.RequestError as e:
                if attempt == retries - 1:
                    logger.error("Network error calling Gmail API: %s", e)
                    raise GmailAPIError(f"Network error connecting to Gmail API: {e}") from e
                await asyncio.sleep(backoff_factor * (2 ** attempt))

        raise GmailRateLimitError("Gmail API rate limit exceeded. Please try again later.")

    async def list_inbox_messages(
        self,
        db: AsyncSession,
        integration: GmailIntegration,
        max_results: int = 20,
        page_token: Optional[str] = None,
        query: Optional[str] = None,
    ) -> Tuple[List[Dict[str, str]], Optional[str], int]:
        """
        Lists messages belonging STRICTLY to user's INBOX.
        Explicitly excludes Sent, Drafts, Spam, and Trash.
        Returns: (messages_list, next_page_token, result_size_estimate)
        """
        q = f"{INBOX_SEARCH_QUERY} {query}".strip() if query else INBOX_SEARCH_QUERY

        params: Dict[str, Any] = {
            "labelIds": ["INBOX"],
            "includeSpamTrash": "false",
            "q": q,
            "maxResults": min(max(max_results, 1), 50),  # Bounded concurrency (1-50)
        }
        if page_token:
            params["pageToken"] = page_token

        resp = await self._make_api_request(
            db=db,
            integration=integration,
            method="GET",
            url=GMAIL_MESSAGES_ENDPOINT,
            params=params,
        )

        data = resp.json()
        messages = data.get("messages", [])
        next_page = data.get("nextPageToken")
        result_size = data.get("resultSizeEstimate", len(messages))
        return messages, next_page, result_size

    async def get_message_raw(
        self,
        db: AsyncSession,
        integration: GmailIntegration,
        gmail_message_id: str,
    ) -> Dict[str, Any]:
        """
        Retrieves complete raw RFC-822 MIME content for a message.
        Validates that the message belongs to INBOX and is not Spam/Trash.
        Returns: {
            "id": gmail_message_id,
            "threadId": thread_id,
            "labelIds": label_ids,
            "snippet": snippet,
            "internalDate": internal_date_dt,
            "raw_bytes": raw_rfc822_bytes,
        }
        """
        url = f"{GMAIL_MESSAGES_ENDPOINT}/{gmail_message_id}"
        resp = await self._make_api_request(
            db=db,
            integration=integration,
            method="GET",
            url=url,
            params={"format": "raw"},
        )

        data = resp.json()
        label_ids = data.get("labelIds", [])

        # Security check: Ensure message is in INBOX and not in excluded folders
        labels_set = set(label_ids)
        if "INBOX" not in labels_set or bool(labels_set.intersection(EXCLUDED_LABELS)):
            logger.info("Message %s is not in active INBOX (labels: %s); skipping", gmail_message_id, label_ids)
            raise GmailAPIError(f"Message {gmail_message_id} is not an eligible INBOX message.")

        raw_b64 = data.get("raw", "")
        raw_bytes = decode_base64url_bytes(raw_b64)

        # Parse internalDate timestamp (milliseconds since epoch)
        internal_date_ms = data.get("internalDate")
        internal_date_dt = None
        if internal_date_ms:
            try:
                internal_date_dt = datetime.fromtimestamp(int(internal_date_ms) / 1000.0, tz=timezone.utc)
            except Exception:
                pass

        return {
            "id": data.get("id"),
            "threadId": data.get("threadId"),
            "labelIds": label_ids,
            "snippet": data.get("snippet", ""),
            "internalDate": internal_date_dt,
            "historyId": data.get("historyId"),
            "raw_bytes": raw_bytes,
        }

    async def get_attachment_bytes(
        self,
        db: AsyncSession,
        integration: GmailIntegration,
        gmail_message_id: str,
        attachment_id: str,
    ) -> bytes:
        """
        Retrieves raw binary bytes of a specific attachment via the Gmail API.
        """
        url = f"{GMAIL_MESSAGES_ENDPOINT}/{gmail_message_id}/attachments/{attachment_id}"
        resp = await self._make_api_request(
            db=db,
            integration=integration,
            method="GET",
            url=url,
        )
        data = resp.json()
        data_b64 = data.get("data", "")
        return decode_base64url_bytes(data_b64)

    async def sync_inbox(
        self,
        db: AsyncSession,
        user: User,
        integration: GmailIntegration,
        max_messages: int = 20,
        is_initial_scan: bool = False,
        consent_acknowledged: bool = False,
    ) -> Dict[str, Any]:
        """
        Performs genuine Gmail inbox retrieval:
        1. Lists eligible INBOX messages from Google Gmail REST API.
        2. Idempotently skips already-processed messages (preserving unique message identity).
        3. Losslessly fetches raw RFC-822 MIME bytes for new messages.
        4. Parses through hardened EmailParser and creates root Email & GmailMessage records.
        5. Schedules security analysis via existing pipeline if auto_analyze is enabled.
        """
        if is_initial_scan and not consent_acknowledged:
            raise GmailInitialScanConsentRequiredError(
                "Explicit user consent is required before performing an initial inbox scan of historical emails. "
                "Set consent_acknowledged=True to proceed."
            )

        # 1. List INBOX messages from Google
        bounded_limit = min(max(max_messages, 1), 50)
        messages_meta, _, total_estimate = await self.list_inbox_messages(
            db=db,
            integration=integration,
            max_results=bounded_limit,
        )

        if not messages_meta:
            integration.last_synced_at = datetime.now(timezone.utc)
            await db.commit()
            return {
                "synced_count": 0,
                "skipped_count": 0,
                "total_inbox_estimate": total_estimate,
                "message": "No new messages in INBOX.",
            }

        # 2. Check existing messages in database for idempotency
        incoming_ids = [m["id"] for m in messages_meta if "id" in m]
        existing_stmt = select(GmailMessage.gmail_message_id).where(
            GmailMessage.integration_id == integration.id,
            GmailMessage.gmail_message_id.in_(incoming_ids),
        )
        existing_res = await db.execute(existing_stmt)
        existing_ids = set(existing_res.scalars().all())

        new_message_metas = [m for m in messages_meta if m.get("id") not in existing_ids]
        skipped_count = len(messages_meta) - len(new_message_metas)

        # 3. Retrieve new messages losslessly with bounded concurrency (max 5 simultaneous fetches)
        semaphore = asyncio.Semaphore(5)
        parser = EmailParser()

        synced_records: List[GmailMessage] = []
        new_email_ids: List[uuid.UUID] = []

        async def fetch_and_persist(msg_item: Dict[str, str]) -> Optional[GmailMessage]:
            mid = msg_item.get("id")
            if not mid:
                return None
            async with semaphore:
                try:
                    raw_data = await self.get_message_raw(db, integration, mid)
                except Exception as e:
                    logger.warning("Failed to fetch message %s from Gmail: %s", mid, e)
                    return None

                raw_bytes = raw_data["raw_bytes"]
                if not raw_bytes:
                    return None

                # Pass lossless raw bytes directly to hardened EmailParser
                try:
                    parsed_email: ParsedEmail = parser.parse(raw_bytes)
                except Exception as e:
                    logger.error("EmailParser failed on message %s: %s", mid, e)
                    return None

                # Sanitized / safe representation for storage
                raw_eml_text = raw_bytes.decode("utf-8", errors="replace")

                # Create root Email record in existing pipeline
                email_record = Email(
                    id=uuid.uuid4(),
                    organization_id=user.organization_id,
                    submitted_by=user.id,
                    message_id=parsed_email.message_id or f"gmail-{mid}",
                    subject=parsed_email.subject or "(No Subject)",
                    sender_raw=parsed_email.from_raw or "(Unknown Sender)",
                    sender_email=parsed_email.from_email or "",
                    sender_display_name=parsed_email.from_display_name,
                    reply_to=parsed_email.reply_to,
                    return_path=parsed_email.return_path,
                    recipient_to=parsed_email.to_addresses or [],
                    recipient_cc=parsed_email.cc_addresses or [],
                    received_at=raw_data["internalDate"] or parsed_email.date or datetime.now(timezone.utc),
                    source_type="gmail_sync",
                    raw_content=raw_eml_text,
                    file_size_bytes=len(raw_bytes),
                    original_filename=f"gmail_{mid}.eml",
                    analysis_status="pending",
                )
                db.add(email_record)
                await db.flush()

                # Create GmailMessage record linked to Email
                gmsg = GmailMessage(
                    id=uuid.uuid4(),
                    organization_id=user.organization_id,
                    user_id=user.id,
                    integration_id=integration.id,
                    gmail_message_id=mid,
                    thread_id=raw_data["threadId"],
                    label_ids=raw_data["labelIds"],
                    internal_date=raw_data["internalDate"],
                    subject=parsed_email.subject or "(No Subject)",
                    sender=parsed_email.from_raw or "(Unknown Sender)",
                    snippet=raw_data["snippet"],
                    body_text=parsed_email.body_text[:2000] if parsed_email.body_text else "",
                    raw_eml=raw_eml_text,
                    received_at=raw_data["internalDate"] or parsed_email.date or datetime.now(timezone.utc),
                    is_analyzed=False,
                    analysis_status="pending",
                    email_id=email_record.id,
                )
                db.add(gmsg)
                return gmsg

        # Process new messages
        for item in new_message_metas:
            rec = await fetch_and_persist(item)
            if rec:
                synced_records.append(rec)
                if rec.email_id:
                    new_email_ids.append(rec.email_id)

        # Update last sync timestamp and historyId if present
        integration.last_synced_at = datetime.now(timezone.utc)
        await db.commit()

        # 4. Trigger analysis for new messages if auto_analyze is enabled
        if integration.auto_analyze_enabled and new_email_ids:
            from app.workers.tasks import analyze_email_task, execute_email_analysis
            for eid in new_email_ids:
                try:
                    # Dispatch to Celery background queue
                    analyze_email_task.delay(str(eid), str(user.organization_id))
                except Exception:
                    # Fallback to in-process async task when Celery broker is unavailable
                    asyncio.create_task(execute_email_analysis(str(eid), str(user.organization_id)))

        logger.info(
            "Gmail inbox sync complete for %s: %d new, %d skipped, %d total estimate",
            integration.email_address,
            len(synced_records),
            skipped_count,
            total_estimate,
        )

        return {
            "synced_count": len(synced_records),
            "skipped_count": skipped_count,
            "total_inbox_estimate": total_estimate,
            "message": f"Successfully retrieved {len(synced_records)} new messages from Gmail INBOX ({skipped_count} existing skipped).",
        }

    async def get_profile(
        self,
        db: AsyncSession,
        integration: GmailIntegration,
    ) -> Dict[str, Any]:
        """Fetches profile for connected Gmail account to retrieve email and latest historyId."""
        resp = await self._make_api_request(
            db=db,
            integration=integration,
            method="GET",
            url=GMAIL_PROFILE_ENDPOINT,
        )
        return resp.json()

    async def watch_inbox(
        self,
        db: AsyncSession,
        integration: GmailIntegration,
        topic_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Activates real-time Gmail push notifications via Google Cloud Pub/Sub.
        Configures watch for INBOX label only with least privilege.
        Saves returned historyId and expiration.
        """
        topic = topic_name or settings.GMAIL_PUBSUB_TOPIC
        if not topic:
            raise GmailWatchError(
                "Google Cloud Pub/Sub topic is not configured. Please set GMAIL_PUBSUB_TOPIC in settings."
            )

        payload: Dict[str, Any] = {
            "topicName": topic,
            "labelIds": ["INBOX"],
            "labelFilterAction": "include",
        }

        try:
            resp = await self._make_api_request(
                db=db,
                integration=integration,
                method="POST",
                url=GMAIL_WATCH_ENDPOINT,
                json_data=payload,
            )
            data = resp.json()
            history_id = data.get("historyId")
            expiration_ms = data.get("expiration")
            expiration_dt = None
            if expiration_ms:
                try:
                    expiration_dt = datetime.fromtimestamp(int(expiration_ms) / 1000.0, tz=timezone.utc)
                except Exception:
                    pass

            if history_id:
                integration.last_history_id = str(history_id)
            if expiration_dt:
                integration.watch_expiration = expiration_dt
            integration.watch_status = "active"
            integration.last_error = None
            await db.commit()

            logger.info(
                "Gmail watch successfully established for %s: historyId=%s, expiration=%s",
                integration.email_address, history_id, expiration_dt
            )
            return {
                "status": "active",
                "history_id": str(history_id) if history_id else None,
                "expiration": expiration_dt.isoformat() if expiration_dt else None,
                "topic": topic,
            }
        except Exception as e:
            logger.error("Failed to establish Gmail watch for %s: %s", integration.email_address, e)
            integration.watch_status = "error"
            integration.last_error = str(e)
            await db.commit()
            raise

    async def stop_watch(
        self,
        db: AsyncSession,
        integration: GmailIntegration,
    ) -> Dict[str, Any]:
        """Stops active Gmail push notifications for the connected account."""
        try:
            await self._make_api_request(
                db=db,
                integration=integration,
                method="POST",
                url=GMAIL_STOP_WATCH_ENDPOINT,
            )
        except Exception as e:
            logger.warning("Stop watch API returned warning for %s: %s", integration.email_address, e)

        integration.watch_status = "inactive"
        integration.watch_expiration = None
        await db.commit()
        logger.info("Gmail watch stopped for %s", integration.email_address)
        return {"status": "inactive", "message": "Gmail push notifications stopped successfully."}

    async def sync_history(
        self,
        db: AsyncSession,
        user: User,
        integration: GmailIntegration,
        start_history_id: Optional[str] = None,
        max_pages: int = 5,
    ) -> Dict[str, Any]:
        """
        Synchronizes new incoming emails using the Gmail History API.
        1. Queries changes since startHistoryId (or integration.last_history_id).
        2. Filters strictly for messagesAdded with label 'INBOX', excluding Spam/Trash/Drafts/Sent.
        3. Falls back to controlled Inbox reconciliation on HTTP 404 (expired history).
        4. Idempotently skips already-processed messages.
        5. Losslessly fetches raw RFC-822 MIME bytes and drives EmailParser.
        6. Updates integration.last_history_id and last_synced_at.
        """
        start_hid = start_history_id or integration.last_history_id
        if not start_hid:
            logger.info("No startHistoryId for %s; performing controlled inbox reconciliation", integration.email_address)
            res = await self.sync_inbox(db=db, user=user, integration=integration, max_messages=25)
            try:
                prof = await self.get_profile(db=db, integration=integration)
                if prof.get("historyId"):
                    integration.last_history_id = str(prof["historyId"])
                    await db.commit()
            except Exception:
                pass
            return res

        page_token: Optional[str] = None
        collected_message_ids: List[str] = []
        latest_history_id = start_hid

        try:
            for _ in range(max_pages):
                params: Dict[str, Any] = {
                    "startHistoryId": start_hid,
                    "labelId": "INBOX",
                    "historyTypes": "messageAdded",
                    "maxResults": 50,
                }
                if page_token:
                    params["pageToken"] = page_token

                resp = await self._make_api_request(
                    db=db,
                    integration=integration,
                    method="GET",
                    url=GMAIL_HISTORY_ENDPOINT,
                    params=params,
                )
                data = resp.json()
                latest_history_id = str(data.get("historyId", latest_history_id))
                history_records = data.get("history", [])

                for item in history_records:
                    for added in item.get("messagesAdded", []):
                        msg_meta = added.get("message", {})
                        mid = msg_meta.get("id")
                        if not mid:
                            continue
                        labels = set(msg_meta.get("labelIds", []))
                        # Strictly verify INBOX label and absence of excluded folders
                        if "INBOX" in labels and not bool(labels.intersection(EXCLUDED_LABELS)):
                            collected_message_ids.append(mid)

                page_token = data.get("nextPageToken")
                if not page_token:
                    break

        except GmailHistoryExpiredError:
            logger.warning(
                "Gmail History ID %s expired (HTTP 404) for %s; performing controlled INBOX reconciliation",
                start_hid, integration.email_address
            )
            res = await self.sync_inbox(db=db, user=user, integration=integration, max_messages=25)
            try:
                prof = await self.get_profile(db=db, integration=integration)
                if prof.get("historyId"):
                    integration.last_history_id = str(prof["historyId"])
                    await db.commit()
            except Exception:
                pass
            res["reconciled_after_expiration"] = True
            return res

        # Deduplicate collected message IDs preserving order
        seen = set()
        unique_ids = []
        for mid in collected_message_ids:
            if mid not in seen:
                seen.add(mid)
                unique_ids.append(mid)

        if not unique_ids:
            integration.last_history_id = latest_history_id
            integration.last_synced_at = datetime.now(timezone.utc)
            await db.commit()
            return {
                "synced_count": 0,
                "skipped_count": 0,
                "history_id": latest_history_id,
                "message": "History synchronization complete. No new INBOX messages added.",
            }

        # Check database for existing messages to enforce strong idempotency
        existing_stmt = select(GmailMessage.gmail_message_id).where(
            GmailMessage.integration_id == integration.id,
            GmailMessage.gmail_message_id.in_(unique_ids),
        )
        existing_res = await db.execute(existing_stmt)
        existing_ids = set(existing_res.scalars().all())

        new_ids = [mid for mid in unique_ids if mid not in existing_ids]
        skipped_count = len(unique_ids) - len(new_ids)

        # Retrieve and persist with bounded concurrency
        semaphore = asyncio.Semaphore(5)
        parser = EmailParser()
        synced_records: List[GmailMessage] = []
        new_email_ids: List[uuid.UUID] = []

        async def fetch_and_persist(mid: str) -> Optional[GmailMessage]:
            async with semaphore:
                try:
                    raw_data = await self.get_message_raw(db, integration, mid)
                except Exception as e:
                    logger.warning("Failed to fetch message %s from Gmail: %s", mid, e)
                    return None

                raw_bytes = raw_data["raw_bytes"]
                if not raw_bytes:
                    return None

                try:
                    parsed_email: ParsedEmail = parser.parse(raw_bytes)
                except Exception as e:
                    logger.error("EmailParser failed on message %s: %s", mid, e)
                    return None

                raw_eml_text = raw_bytes.decode("utf-8", errors="replace")

                email_record = Email(
                    id=uuid.uuid4(),
                    organization_id=user.organization_id,
                    submitted_by=user.id,
                    message_id=parsed_email.message_id or f"gmail-{mid}",
                    subject=parsed_email.subject or "(No Subject)",
                    sender_raw=parsed_email.from_raw or "(Unknown Sender)",
                    sender_email=parsed_email.from_email or "",
                    sender_display_name=parsed_email.from_display_name,
                    reply_to=parsed_email.reply_to,
                    return_path=parsed_email.return_path,
                    recipient_to=parsed_email.to_addresses or [],
                    recipient_cc=parsed_email.cc_addresses or [],
                    received_at=raw_data["internalDate"] or parsed_email.date or datetime.now(timezone.utc),
                    source_type="gmail_sync",
                    raw_content=raw_eml_text,
                    file_size_bytes=len(raw_bytes),
                    original_filename=f"gmail_{mid}.eml",
                    analysis_status="pending",
                )
                db.add(email_record)
                await db.flush()

                gmsg = GmailMessage(
                    id=uuid.uuid4(),
                    organization_id=user.organization_id,
                    user_id=user.id,
                    integration_id=integration.id,
                    gmail_message_id=mid,
                    thread_id=raw_data["threadId"],
                    label_ids=raw_data["labelIds"],
                    internal_date=raw_data["internalDate"],
                    subject=parsed_email.subject or "(No Subject)",
                    sender=parsed_email.from_raw or "(Unknown Sender)",
                    snippet=raw_data["snippet"],
                    body_text=parsed_email.body_text[:2000] if parsed_email.body_text else "",
                    raw_eml=raw_eml_text,
                    received_at=raw_data["internalDate"] or parsed_email.date or datetime.now(timezone.utc),
                    is_analyzed=False,
                    analysis_status="pending",
                    email_id=email_record.id,
                )
                db.add(gmsg)
                return gmsg

        for mid in new_ids:
            rec = await fetch_and_persist(mid)
            if rec:
                synced_records.append(rec)
                if rec.email_id:
                    new_email_ids.append(rec.email_id)

        integration.last_history_id = latest_history_id
        integration.last_synced_at = datetime.now(timezone.utc)
        await db.commit()

        # Trigger analysis for new messages if auto_analyze is enabled
        if integration.auto_analyze_enabled and new_email_ids:
            from app.workers.tasks import analyze_email_task, execute_email_analysis
            for eid in new_email_ids:
                try:
                    analyze_email_task.delay(str(eid), str(user.organization_id))
                except Exception:
                    asyncio.create_task(execute_email_analysis(str(eid), str(user.organization_id)))

        logger.info(
            "Gmail history sync complete for %s: %d new, %d skipped, new historyId=%s",
            integration.email_address, len(synced_records), skipped_count, latest_history_id
        )

        return {
            "synced_count": len(synced_records),
            "skipped_count": skipped_count,
            "history_id": latest_history_id,
            "message": f"Successfully retrieved {len(synced_records)} new messages via History API ({skipped_count} skipped).",
        }

    async def get_or_create_quarantine_label(
        self,
        db: AsyncSession,
        integration: GmailIntegration,
        label_name: str = "PhishGuard-Quarantine",
    ) -> str:
        """
        Retrieves the ID of the PhishGuard quarantine label from Google Gmail API.
        Creates the label if it does not yet exist.
        Caches the label ID on the GmailIntegration record.
        """
        # 1. Check if cached label ID is already valid
        if integration.quarantine_label_id:
            try:
                resp = await self._make_api_request(
                    db=db,
                    integration=integration,
                    method="GET",
                    url=f"{GMAIL_LABELS_ENDPOINT}/{integration.quarantine_label_id}",
                )
                if resp.status_code == 200:
                    return integration.quarantine_label_id
            except GmailAPIError:
                logger.warning(
                    "Cached quarantine label ID %s invalid for %s; re-querying labels.",
                    integration.quarantine_label_id, integration.email_address
                )
                integration.quarantine_label_id = None

        # 2. Query all existing labels
        resp = await self._make_api_request(
            db=db,
            integration=integration,
            method="GET",
            url=GMAIL_LABELS_ENDPOINT,
        )
        labels_list = resp.json().get("labels", [])
        for lbl in labels_list:
            if lbl.get("name", "").lower() == label_name.lower():
                integration.quarantine_label_id = lbl["id"]
                integration.quarantine_label_name = lbl["name"]
                await db.commit()
                return lbl["id"]

        # 3. Create the label if not found
        try:
            create_resp = await self._make_api_request(
                db=db,
                integration=integration,
                method="POST",
                url=GMAIL_LABELS_ENDPOINT,
                json_data={
                    "name": label_name,
                    "labelListVisibility": "labelShow",
                    "messageListVisibility": "show",
                },
            )
            created_data = create_resp.json()
            created_id = created_data["id"]
            integration.quarantine_label_id = created_id
            integration.quarantine_label_name = label_name
            await db.commit()
            logger.info("Created Gmail quarantine label '%s' (ID: %s) for %s", label_name, created_id, integration.email_address)
            return created_id
        except GmailAPIError as e:
            # If race condition caused conflict (409), re-fetch
            if getattr(e, "status_code", None) == 409 or "already exists" in str(e).lower():
                list_resp = await self._make_api_request(
                    db=db,
                    integration=integration,
                    method="GET",
                    url=GMAIL_LABELS_ENDPOINT,
                )
                for lbl in list_resp.json().get("labels", []):
                    if lbl.get("name", "").lower() == label_name.lower():
                        integration.quarantine_label_id = lbl["id"]
                        integration.quarantine_label_name = lbl["name"]
                        await db.commit()
                        return lbl["id"]
            raise

    async def quarantine_message(
        self,
        db: AsyncSession,
        user: User,
        integration: GmailIntegration,
        gmail_msg: GmailMessage,
        reason: str,
        is_automatic: bool = False,
    ) -> Dict[str, Any]:
        """
        Safely quarantines a phishing email in Gmail:
        - Adds 'PhishGuard-Quarantine' label
        - Removes 'INBOX' label
        - Stores original labels prior to modification
        - Fully idempotent: duplicate executions are safe
        - Never permanently deletes the message
        - Records operation in immutable AuditLog
        """
        # Validate tenant isolation
        if gmail_msg.organization_id != user.organization_id or gmail_msg.integration_id != integration.id:
            raise GmailPermissionError("Access denied: message does not belong to user's organization or Gmail integration.")

        # Check required scope
        granted = integration.granted_scopes or []
        if not any("gmail.modify" in s for s in granted):
            raise GmailPermissionError(
                "Missing required scope 'https://www.googleapis.com/auth/gmail.modify'. "
                "Please reconnect Gmail with modify permissions to enable quarantine."
            )

        # Preserve original labels before any modification
        current_labels = list(gmail_msg.label_ids or [])
        if not gmail_msg.original_labels:
            gmail_msg.original_labels = current_labels

        quarantine_label_name = integration.quarantine_label_name or "PhishGuard-Quarantine"

        # Fast idempotency check: already quarantined?
        if (
            gmail_msg.is_quarantined
            and "INBOX" not in current_labels
            and (not integration.quarantine_label_id or integration.quarantine_label_id in current_labels)
        ):
            return {
                "status": "already_quarantined",
                "gmail_message_id": gmail_msg.gmail_message_id,
                "label_ids": gmail_msg.label_ids,
                "quarantined_at": gmail_msg.quarantined_at.isoformat() if gmail_msg.quarantined_at else None,
                "message": f"Email is already quarantined with label '{quarantine_label_name}'.",
            }

        quarantine_label_id = await self.get_or_create_quarantine_label(db, integration, quarantine_label_name)

        url = f"{GMAIL_MESSAGES_ENDPOINT}/{gmail_msg.gmail_message_id}/modify"
        body = {
            "addLabelIds": [quarantine_label_id],
            "removeLabelIds": ["INBOX"],
        }

        try:
            resp = await self._make_api_request(
                db=db,
                integration=integration,
                method="POST",
                url=url,
                json_data=body,
            )
            res_data = resp.json()
            updated_labels = res_data.get("labelIds", [])

            # Verify the resulting Gmail labels through a subsequent API read (G5 Requirement 3.8)
            verify_url = f"{GMAIL_MESSAGES_ENDPOINT}/{gmail_msg.gmail_message_id}?format=minimal"
            verify_resp = await self._make_api_request(
                db=db,
                integration=integration,
                method="GET",
                url=verify_url,
            )
            verified_data = verify_resp.json() if hasattr(verify_resp, "json") else {}
            verified_labels = verified_data.get("labelIds", updated_labels)

            if quarantine_label_id not in verified_labels or "INBOX" in verified_labels:
                raise GmailAPIError(
                    f"Quarantine verification failed: subsequent Gmail read shows labels {verified_labels} "
                    f"instead of expected quarantine state (label '{quarantine_label_name}' present, INBOX removed).",
                    status_code=502
                )

            now_dt = datetime.now(timezone.utc)
            gmail_msg.label_ids = verified_labels
            gmail_msg.is_quarantined = True
            gmail_msg.quarantined_at = now_dt
            gmail_msg.quarantine_reason = reason
            gmail_msg.quarantine_action_status = "quarantined"
            gmail_msg.quarantine_error = None

            # Record comprehensive AuditLog entry (G5 Requirement 7)
            audit = AuditLog(
                organization_id=user.organization_id,
                user_id=user.id,
                action="gmail.message.quarantine",
                resource_type="gmail_message",
                resource_id=gmail_msg.id,
                details={
                    "user_id": str(user.id),
                    "integration_id": str(integration.id),
                    "gmail_message_id": gmail_msg.gmail_message_id,
                    "previous_labels": current_labels,
                    "new_labels": verified_labels,
                    "analysis_result": gmail_msg.risk_classification,
                    "risk_score": gmail_msg.risk_score,
                    "quarantine_reason": reason,
                    "action_timestamp": now_dt.isoformat(),
                    "restore_timestamp": None,
                    "api_result": {
                        "modify_status": resp.status_code if hasattr(resp, "status_code") else 200,
                        "verified_read_status": verify_resp.status_code if hasattr(verify_resp, "status_code") else 200,
                        "verification_confirmed": True,
                    },
                    "is_automatic": is_automatic,
                    "quarantine_label_id": quarantine_label_id,
                    "quarantine_label_name": quarantine_label_name,
                },
                severity="warning" if is_automatic else "info",
            )
            db.add(audit)
            await db.commit()

            logger.info(
                "Successfully quarantined Gmail message %s for user %s (%s)",
                gmail_msg.gmail_message_id, user.id, reason
            )

            return {
                "status": "quarantined",
                "gmail_message_id": gmail_msg.gmail_message_id,
                "label_ids": verified_labels,
                "quarantined_at": now_dt.isoformat(),
                "quarantine_reason": reason,
                "is_automatic": is_automatic,
                "message": f"Email successfully moved from INBOX to {quarantine_label_name} and verified.",
            }

        except Exception as e:
            gmail_msg.quarantine_action_status = "failed"
            gmail_msg.quarantine_error = str(e)
            try:
                audit_err = AuditLog(
                    organization_id=user.organization_id,
                    user_id=user.id,
                    action="gmail.message.quarantine_failed",
                    resource_type="gmail_message",
                    resource_id=gmail_msg.id,
                    details={
                        "gmail_message_id": gmail_msg.gmail_message_id,
                        "error": str(e),
                        "is_automatic": is_automatic,
                    },
                    severity="error",
                )
                db.add(audit_err)
                await db.commit()
            except Exception:
                await db.rollback()

            logger.error("Failed to quarantine Gmail message %s: %s", gmail_msg.gmail_message_id, e)
            raise

    async def restore_message(
        self,
        db: AsyncSession,
        user: User,
        integration: GmailIntegration,
        gmail_msg: GmailMessage,
    ) -> Dict[str, Any]:
        """
        Safely restores a previously quarantined email:
        - Removes 'PhishGuard-Quarantine' label
        - Restores 'INBOX' label
        - Preserves the original message completely
        - Fully idempotent: duplicate restore requests are handled safely
        - Records operation in immutable AuditLog
        """
        # Validate tenant isolation
        if gmail_msg.organization_id != user.organization_id or gmail_msg.integration_id != integration.id:
            raise GmailPermissionError("Access denied: message does not belong to user's organization or Gmail integration.")

        # Check required scope
        granted = integration.granted_scopes or []
        if not any("gmail.modify" in s for s in granted):
            raise GmailPermissionError(
                "Missing required scope 'https://www.googleapis.com/auth/gmail.modify'. "
                "Please reconnect Gmail with modify permissions to restore messages."
            )

        quarantine_label_name = integration.quarantine_label_name or "PhishGuard-Quarantine"
        current_labels = list(gmail_msg.label_ids or [])

        # Fast idempotency check: already restored / in inbox?
        if (
            not gmail_msg.is_quarantined
            and "INBOX" in current_labels
            and (not integration.quarantine_label_id or integration.quarantine_label_id not in current_labels)
        ):
            return {
                "status": "already_restored",
                "gmail_message_id": gmail_msg.gmail_message_id,
                "label_ids": gmail_msg.label_ids,
                "restored_at": gmail_msg.restored_at.isoformat() if gmail_msg.restored_at else None,
                "message": "Email is already restored and present in INBOX.",
            }

        quarantine_label_id = await self.get_or_create_quarantine_label(db, integration, quarantine_label_name)

        url = f"{GMAIL_MESSAGES_ENDPOINT}/{gmail_msg.gmail_message_id}/modify"
        body = {
            "addLabelIds": ["INBOX"],
            "removeLabelIds": [quarantine_label_id],
        }

        try:
            resp = await self._make_api_request(
                db=db,
                integration=integration,
                method="POST",
                url=url,
                json_data=body,
            )
            res_data = resp.json()
            updated_labels = res_data.get("labelIds", [])

            # Verify the resulting Gmail labels through a subsequent API read (G5 Requirement 4.6)
            verify_url = f"{GMAIL_MESSAGES_ENDPOINT}/{gmail_msg.gmail_message_id}?format=minimal"
            verify_resp = await self._make_api_request(
                db=db,
                integration=integration,
                method="GET",
                url=verify_url,
            )
            verified_data = verify_resp.json() if hasattr(verify_resp, "json") else {}
            verified_labels = verified_data.get("labelIds", updated_labels)

            if quarantine_label_id in verified_labels:
                raise GmailAPIError(
                    f"Restore verification failed: subsequent Gmail read shows quarantine label '{quarantine_label_name}' "
                    f"was not removed in Google mailbox. Current labels: {verified_labels}",
                    status_code=502
                )
            if "INBOX" in body["addLabelIds"] and "INBOX" not in verified_labels:
                raise GmailAPIError(
                    f"Restore verification failed: subsequent Gmail read shows INBOX label was not restored in Google mailbox. "
                    f"Current labels: {verified_labels}",
                    status_code=502
                )

            now_dt = datetime.now(timezone.utc)
            gmail_msg.label_ids = verified_labels
            gmail_msg.is_quarantined = False
            gmail_msg.restored_at = now_dt
            gmail_msg.restored_by = user.id
            gmail_msg.quarantine_action_status = "restored"
            gmail_msg.quarantine_error = None

            # Record comprehensive AuditLog entry (G5 Requirement 7)
            audit = AuditLog(
                organization_id=user.organization_id,
                user_id=user.id,
                action="gmail.message.restore",
                resource_type="gmail_message",
                resource_id=gmail_msg.id,
                details={
                    "user_id": str(user.id),
                    "integration_id": str(integration.id),
                    "gmail_message_id": gmail_msg.gmail_message_id,
                    "previous_labels": current_labels,
                    "new_labels": verified_labels,
                    "analysis_result": gmail_msg.risk_classification,
                    "risk_score": gmail_msg.risk_score,
                    "quarantine_reason": gmail_msg.quarantine_reason,
                    "action_timestamp": gmail_msg.quarantined_at.isoformat() if gmail_msg.quarantined_at else None,
                    "restore_timestamp": now_dt.isoformat(),
                    "api_result": {
                        "modify_status": resp.status_code if hasattr(resp, "status_code") else 200,
                        "verified_read_status": verify_resp.status_code if hasattr(verify_resp, "status_code") else 200,
                        "verification_confirmed": True,
                    },
                    "quarantine_label_id": quarantine_label_id,
                    "quarantine_label_name": quarantine_label_name,
                    "restored_by": str(user.id),
                },
                severity="info",
            )
            db.add(audit)
            await db.commit()

            logger.info("Successfully restored Gmail message %s for user %s", gmail_msg.gmail_message_id, user.id)

            return {
                "status": "restored",
                "gmail_message_id": gmail_msg.gmail_message_id,
                "label_ids": verified_labels,
                "restored_at": now_dt.isoformat(),
                "message": f"Email successfully restored from {quarantine_label_name} to INBOX and verified.",
            }

        except Exception as e:
            gmail_msg.quarantine_error = str(e)
            try:
                audit_err = AuditLog(
                    organization_id=user.organization_id,
                    user_id=user.id,
                    action="gmail.message.restore_failed",
                    resource_type="gmail_message",
                    resource_id=gmail_msg.id,
                    details={
                        "gmail_message_id": gmail_msg.gmail_message_id,
                        "error": str(e),
                    },
                    severity="error",
                )
                db.add(audit_err)
                await db.commit()
            except Exception:
                await db.rollback()

            logger.error("Failed to restore Gmail message %s: %s", gmail_msg.gmail_message_id, e)
            raise

    async def report_false_positive(
        self,
        db: AsyncSession,
        user: User,
        integration: GmailIntegration,
        gmail_msg: GmailMessage,
        feedback: str = "Reported as legitimate by user",
    ) -> Dict[str, Any]:
        """
        Reports a false positive detection on a Gmail message (G5 Requirement 6.6):
        - Safely restores the message to INBOX if quarantined
        - Marks message status as false_positive
        - Updates associated IOC records to prevent recurring false positives
        - Records an immutable audit log entry
        """
        if gmail_msg.organization_id != user.organization_id or gmail_msg.integration_id != integration.id:
            raise GmailPermissionError("Access denied: message does not belong to user's organization or Gmail integration.")

        restore_result = None
        if gmail_msg.is_quarantined:
            restore_result = await self.restore_message(db, user, integration, gmail_msg)

        now_dt = datetime.now(timezone.utc)
        gmail_msg.quarantine_action_status = "false_positive"

        # Update IOCs linked to this email to prevent recurring false positives
        if gmail_msg.email_id:
            from app.models import IOC
            await db.execute(
                update(IOC)
                .where(IOC.email_id == gmail_msg.email_id)
                .values(is_false_positive=True)
            )

        audit = AuditLog(
            organization_id=user.organization_id,
            user_id=user.id,
            action="gmail.message.false_positive_reported",
            resource_type="gmail_message",
            resource_id=gmail_msg.id,
            details={
                "user_id": str(user.id),
                "integration_id": str(integration.id),
                "gmail_message_id": gmail_msg.gmail_message_id,
                "subject": gmail_msg.subject,
                "sender": gmail_msg.sender,
                "risk_score": gmail_msg.risk_score,
                "risk_classification": gmail_msg.risk_classification,
                "feedback": feedback,
                "restored": bool(restore_result),
                "timestamp": now_dt.isoformat(),
            },
            severity="info",
        )
        db.add(audit)
        await db.commit()

        logger.info(
            "False positive reported for Gmail message %s by user %s (Feedback: %s)",
            gmail_msg.gmail_message_id, user.id, feedback
        )

        return {
            "status": "false_positive_recorded",
            "gmail_message_id": gmail_msg.gmail_message_id,
            "restored": bool(restore_result),
            "feedback": feedback,
            "message": "Message marked as legitimate. Email restored to INBOX and detection indicators updated.",
        }

    def evaluate_quarantine_policy(
        self,
        gmail_msg: GmailMessage,
        analysis: Optional[Any] = None,
        threshold_score: int = 70,
    ) -> Tuple[bool, str, str]:
        """
        Evaluates detection policy and thresholds for automatic/manual quarantine.
        Returns: (is_eligible_for_auto_quarantine, decision_category, reason)
        - decision_category: "quarantine" | "alert_only" | "no_action"
        """
        if not gmail_msg.is_analyzed or gmail_msg.analysis_status != "analyzed":
            return False, "alert_only", "Email analysis is pending or not completed."

        score = gmail_msg.risk_score or 0.0

        # 1. Clean (< 40)
        if score < 40:
            return False, "no_action", f"Threat score {int(score)}/100 is low risk. No quarantine action required."

        # 2. Suspicious or uncertain (40 <= score < threshold_score)
        if score < threshold_score:
            return False, "alert_only", (
                f"Threat score {int(score)}/100 is classified as Suspicious. "
                "Alert generated for manual security analyst review."
            )

        # 3. High / Critical (score >= threshold_score)
        # Check fail-safe: Ensure analysis has no critical errors and is not purely caused by missing third-party APIs
        if analysis:
            analysis_errors = getattr(analysis, "errors", []) or []
            if analysis_errors and len(analysis_errors) > 2:
                return False, "alert_only", (
                    f"Threat score {int(score)}/100 detected, but analysis had errors ({len(analysis_errors)}). "
                    "Fail-safe engaged: hold for manual analyst review."
                )

        return True, "quarantine", (
            f"Confirmed high-confidence phishing (Score: {int(score)}/100, "
            f"Classification: {gmail_msg.risk_classification or 'Critical'}). Eligible for quarantine."
        )


gmail_client_service = GmailClientService()
