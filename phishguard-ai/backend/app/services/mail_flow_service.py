"""
Enterprise Mail-Flow Ingestion & Automated Quarantine Service for PhishGuard AI.

Provides automated mailbox ingestion and remediation connectors for:
- Microsoft 365 (Exchange Online via Microsoft Graph API)
- Google Workspace (Gmail API via Pub/Sub push notifications)
- Direct Inbound MTA Webhooks (Postfix, SendGrid, Amazon SES)
"""

from __future__ import annotations

import base64
import logging
import uuid
from typing import Any, Dict, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.analyzers.email_parser import EmailParser
from app.core.database import AsyncSessionLocal
from app.models import Email, EmailHeader
from app.workers.tasks import analyze_email_task

logger = logging.getLogger(__name__)


class MailFlowService:
    """
    Orchestrates automated mail ingestion from cloud mail providers and MTAs,
    queues them for background security analysis, and executes remediation actions.
    """

    async def ingest_raw_message(
        self,
        raw_content: str,
        organization_id: uuid.UUID,
        source_type: str = "mta_webhook",
        external_id: Optional[str] = None,
        submitted_by: Optional[uuid.UUID] = None,
        db: Optional[AsyncSession] = None,
    ) -> Email:
        """
        Ingest a raw RFC-822 message, create the Email record, parse headers,
        and dispatch the asynchronous security analysis task.
        """
        parser = EmailParser()
        parsed = parser.parse(raw_content)

        should_close = False
        if db is None:
            db = AsyncSessionLocal()
            should_close = True

        try:
            # Resolve submitting user if not provided
            submitter_id = submitted_by
            if submitter_id is None:
                from app.models import User
                res_u = await db.execute(
                    select(User.id).where(User.organization_id == organization_id).limit(1)
                )
                submitter_id = res_u.scalar_one_or_none()
                if submitter_id is None:
                    res_any = await db.execute(select(User.id).limit(1))
                    submitter_id = res_any.scalar_one_or_none()
                    if submitter_id is None:
                        raise ValueError(f"No user found to associate with email in organization {organization_id}")

            email_record = Email(
                organization_id=organization_id,
                submitted_by=submitter_id,
                subject=parsed.subject or "(No Subject)",
                sender_raw=parsed.from_raw,
                sender_email=parsed.from_email,
                sender_display_name=parsed.from_display_name,
                reply_to=parsed.reply_to,
                return_path=parsed.return_path,
                message_id=parsed.message_id,
                received_at=parsed.date,
                source_type=source_type[:20],
                raw_content=raw_content,
                file_size_bytes=len(raw_content.encode("utf-8", errors="replace")),
                analysis_status="queued",
            )
            db.add(email_record)
            await db.flush()

            # Record parsed headers
            for h in parsed.headers:
                db.add(
                    EmailHeader(
                        email_id=email_record.id,
                        name=h.name,
                        value=h.value,
                        position=h.position,
                    )
                )

            await db.commit()
            await db.refresh(email_record)

            # Dispatch background analysis
            try:
                analyze_email_task.delay(str(email_record.id), str(organization_id))
            except Exception as task_exc:
                logger.warning("Could not dispatch Celery task: %s", task_exc)

            logger.info(
                "Ingested mail %s from source %s for org %s",
                email_record.id,
                source_type,
                organization_id,
            )
            return email_record
        finally:
            if should_close:
                await db.close()

    async def handle_m365_notification(
        self,
        payload: Dict[str, Any],
        organization_id: uuid.UUID,
        db: Optional[AsyncSession] = None,
    ) -> Dict[str, Any]:
        """
        Process Microsoft Graph change notification for new mail items.
        Extracts resource URI and triggers message ingestion.
        """
        values = payload.get("value", [])
        ingested_count = 0

        for item in values:
            resource = item.get("resource", "")
            change_type = item.get("changeType", "")
            client_state = item.get("clientState", "")

            logger.info("M365 notification: resource=%s changeType=%s", resource, change_type)

            # In production, Graph API client fetches GET $value for the message.
            # Here we accept inline raw content or simulate inbound sync.
            raw_email = item.get("rawContent")
            if raw_email:
                await self.ingest_raw_message(
                    raw_content=raw_email,
                    organization_id=organization_id,
                    source_type="m365_graph",
                    external_id=resource,
                    db=db,
                )
                ingested_count += 1

        return {
            "status": "processed",
            "provider": "microsoft_365",
            "notifications_received": len(values),
            "messages_ingested": ingested_count,
        }

    async def handle_google_workspace_notification(
        self,
        payload: Dict[str, Any],
        organization_id: uuid.UUID,
        db: Optional[AsyncSession] = None,
    ) -> Dict[str, Any]:
        """
        Process Google Workspace Gmail API Pub/Sub push notification.
        """
        message = payload.get("message", {})
        data_b64 = message.get("data", "")
        raw_email = None

        if data_b64:
            try:
                decoded = base64.b64decode(data_b64).decode("utf-8", errors="replace")
                raw_email = decoded
            except Exception as exc:
                logger.debug("PubSub base64 decode error: %s", exc)

        if not raw_email and "rawContent" in payload:
            raw_email = payload["rawContent"]

        ingested = False
        if raw_email:
            await self.ingest_raw_message(
                raw_content=raw_email,
                organization_id=organization_id,
                source_type="google_workspace",
                db=db,
            )
            ingested = True

        return {
            "status": "processed",
            "provider": "google_workspace",
            "ingested": ingested,
        }

    async def execute_remediation(
        self,
        email_id: uuid.UUID,
        organization_id: uuid.UUID,
        action: str = "quarantine",
        db: Optional[AsyncSession] = None,
    ) -> Dict[str, Any]:
        """
        Execute automated remediation action on a high-risk or malicious email:
        - "quarantine": moves to isolated quarantine state
        - "soft_delete": removes from inbox to Deleted Items
        - "tag_subject": prepends warning flag in metadata
        """
        should_close = False
        if db is None:
            db = AsyncSessionLocal()
            should_close = True

        try:
            res = await db.execute(
                select(Email).where(
                    Email.id == email_id,
                    Email.organization_id == organization_id,
                )
            )
            email_record = res.scalar_one_or_none()
            if not email_record:
                return {"status": "error", "message": "Email not found or access denied"}

            if action == "quarantine":
                email_record.analysis_status = "quarantined"
            elif action == "soft_delete":
                email_record.analysis_status = "deleted"
            elif action == "tag_subject":
                if not email_record.subject.startswith("[SUSPICIOUS]"):
                    email_record.subject = f"[SUSPICIOUS] {email_record.subject}"

            await db.commit()
            return {
                "status": "success",
                "email_id": str(email_id),
                "action": action,
                "resulting_status": email_record.analysis_status,
            }
        finally:
            if should_close:
                await db.close()


mail_flow_service = MailFlowService()
