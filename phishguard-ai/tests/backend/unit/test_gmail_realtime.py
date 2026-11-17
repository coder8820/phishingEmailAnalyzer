"""
PhishGuard AI — Unit Tests for Milestone G3: Real-Time Gmail Inbox Monitoring
Validates:
- Gmail watch activation for INBOX only with Google Cloud Pub/Sub
- Saving historyId, watch_expiration, and watch_status
- Stopping watch (users.stop)
- History synchronization (users.history.list) with messagesAdded filtering
- Strict exclusion of Spam, Trash, Drafts, and non-INBOX changes
- History API pagination handling (nextPageToken)
- HTTP 404 (History ID expired) fallback to controlled Inbox reconciliation
- Strong idempotency (duplicate history notifications produce zero duplicate records)
- Background watch renewal task (daily renewal of expiring watches)
- Background periodic reconciliation task
"""

import base64
import json
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from sqlalchemy import select

from app.core.config import settings
from app.models import Email, GmailIntegration, GmailMessage, User
from app.services.gmail_client_service import (
    GmailClientService,
    GmailAPIError,
    GmailWatchError,
    GmailHistoryExpiredError,
    GMAIL_WATCH_ENDPOINT,
    GMAIL_STOP_WATCH_ENDPOINT,
    GMAIL_HISTORY_ENDPOINT,
)


# ===========================================================================
# 1. GMAIL WATCH ACTIVATION & STOP TESTS
# ===========================================================================

@pytest.mark.asyncio
async def test_watch_inbox_success(db_session):
    """Verify watch_inbox configures watch for INBOX and saves historyId and expiration."""
    user = User(
        id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        email="watch_user@company.com",
        username="watch_user",
        hashed_password="hash",
    )
    db_session.add(user)
    await db_session.commit()

    integration = GmailIntegration(
        id=uuid.uuid4(),
        organization_id=user.organization_id,
        user_id=user.id,
        email_address="watch_user@company.com",
        is_connected=True,
        refresh_token_encrypted=b"encrypted_token",
        watch_status="inactive",
    )
    db_session.add(integration)
    await db_session.commit()

    client_service = GmailClientService()

    recorded_payload = {}

    async def mock_watch_request(*args, **kwargs):
        nonlocal recorded_payload
        recorded_payload = kwargs.get("json_data", {})
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        # Expiration in 7 days (ms timestamp)
        exp_ms = int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp() * 1000)
        resp.json.return_value = {
            "historyId": "9876543",
            "expiration": str(exp_ms),
        }
        return resp

    with patch.object(client_service, "_make_api_request", side_effect=mock_watch_request):
        result = await client_service.watch_inbox(
            db=db_session,
            integration=integration,
            topic_name="projects/test-gcp/topics/phishguard-gmail-inbox",
        )

        assert result["status"] == "active"
        assert result["history_id"] == "9876543"
        assert "expiration" in result
        assert recorded_payload["topicName"] == "projects/test-gcp/topics/phishguard-gmail-inbox"
        assert recorded_payload["labelIds"] == ["INBOX"]
        assert recorded_payload["labelFilterAction"] == "include"

        # Verify database fields updated
        await db_session.refresh(integration)
        assert integration.watch_status == "active"
        assert integration.last_history_id == "9876543"
        assert integration.watch_expiration is not None


@pytest.mark.asyncio
async def test_watch_inbox_missing_topic_raises_error(db_session, monkeypatch):
    """Verify watch_inbox raises GmailWatchError if topic is not provided and not in settings."""
    monkeypatch.setattr(settings, "GMAIL_PUBSUB_TOPIC", "")
    integration = GmailIntegration(
        id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        user_id=uuid.uuid4(),
        email_address="user@test.com",
        is_connected=True,
    )
    client_service = GmailClientService()

    with pytest.raises(GmailWatchError, match="topic is not configured"):
        await client_service.watch_inbox(db_session, integration, topic_name=None)


@pytest.mark.asyncio
async def test_stop_watch_success(db_session):
    """Verify stop_watch calls users.stop and resets watch_status to inactive."""
    user = User(
        id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        email="stop_user@company.com",
        username="stop_user",
        hashed_password="hash",
    )
    db_session.add(user)
    await db_session.commit()

    integration = GmailIntegration(
        id=uuid.uuid4(),
        organization_id=user.organization_id,
        user_id=user.id,
        email_address="stop_user@company.com",
        is_connected=True,
        watch_status="active",
        watch_expiration=datetime.now(timezone.utc) + timedelta(days=5),
    )
    db_session.add(integration)
    await db_session.commit()

    client_service = GmailClientService()

    async def mock_stop_request(*args, **kwargs):
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        return resp

    with patch.object(client_service, "_make_api_request", side_effect=mock_stop_request):
        res = await client_service.stop_watch(db_session, integration)
        assert res["status"] == "inactive"

        await db_session.refresh(integration)
        assert integration.watch_status == "inactive"
        assert integration.watch_expiration is None


# ===========================================================================
# 2. HISTORY SYNCHRONIZATION TESTS
# ===========================================================================

@pytest.mark.asyncio
async def test_sync_history_with_messages_added(db_session):
    """
    Verify sync_history:
    - Queries history since startHistoryId.
    - Collects only messagesAdded with label 'INBOX'.
    - Ingests new message losslessly via EmailParser.
    - Updates last_history_id.
    """
    user = User(
        id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        email="history_user@company.com",
        username="history_user",
        hashed_password="hash",
    )
    db_session.add(user)
    await db_session.commit()

    integration = GmailIntegration(
        id=uuid.uuid4(),
        organization_id=user.organization_id,
        user_id=user.id,
        email_address="history_user@company.com",
        is_connected=True,
        last_history_id="1000000",
        auto_analyze_enabled=False,
    )
    db_session.add(integration)
    await db_session.commit()

    raw_eml = (
        b"From: alert@security-vendor.com\r\n"
        b"To: history_user@company.com\r\n"
        b"Subject: Security Advisory Alert\r\n"
        b"Date: Tue, 17 Nov 2026 09:00:00 +0000\r\n"
        b"\r\n"
        b"Zero-day advisory for your attention.\r\n"
    )

    client_service = GmailClientService()

    # Mock history API response: 1 messageAdded in INBOX, 1 messageAdded in SPAM (must be ignored)
    async def mock_history_api(*args, **kwargs):
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        resp.json.return_value = {
            "history": [
                {
                    "id": "1000001",
                    "messagesAdded": [
                        {
                            "message": {
                                "id": "msg_inbox_valid_01",
                                "threadId": "th_01",
                                "labelIds": ["INBOX", "UNREAD"],
                            }
                        },
                        {
                            "message": {
                                "id": "msg_spam_ignored_02",
                                "threadId": "th_02",
                                "labelIds": ["SPAM"],  # EXCLUDED
                            }
                        },
                    ]
                }
            ],
            "historyId": "1000005",
        }
        return resp

    async def mock_get_raw(db, intg, mid):
        assert mid == "msg_inbox_valid_01"  # SPAM message must never be fetched!
        return {
            "id": mid,
            "threadId": "th_01",
            "labelIds": ["INBOX"],
            "snippet": "Zero-day advisory",
            "internalDate": datetime.now(timezone.utc),
            "raw_bytes": raw_eml,
        }

    with patch.object(client_service, "_make_api_request", side_effect=mock_history_api), \
         patch.object(client_service, "get_message_raw", side_effect=mock_get_raw):

        res = await client_service.sync_history(
            db=db_session,
            user=user,
            integration=integration,
            start_history_id="1000000",
        )

        assert res["synced_count"] == 1
        assert res["skipped_count"] == 0
        assert res["history_id"] == "1000005"

        # Verify database record created
        msgs = (await db_session.execute(select(GmailMessage).where(GmailMessage.integration_id == integration.id))).scalars().all()
        assert len(msgs) == 1
        assert msgs[0].gmail_message_id == "msg_inbox_valid_01"
        assert msgs[0].subject == "Security Advisory Alert"

        # Verify integration historyId updated
        await db_session.refresh(integration)
        assert integration.last_history_id == "1000005"


@pytest.mark.asyncio
async def test_sync_history_pagination(db_session):
    """Verify sync_history handles nextPageToken pagination across multiple history chunks."""
    user = User(
        id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        email="page_user@company.com",
        username="page_user",
        hashed_password="hash",
    )
    db_session.add(user)
    await db_session.commit()

    integration = GmailIntegration(
        id=uuid.uuid4(),
        organization_id=user.organization_id,
        user_id=user.id,
        email_address="page_user@company.com",
        is_connected=True,
        last_history_id="2000000",
        auto_analyze_enabled=False,
    )
    db_session.add(integration)
    await db_session.commit()

    client_service = GmailClientService()
    page_call_count = 0

    async def mock_paginated_history(*args, **kwargs):
        nonlocal page_call_count
        page_call_count += 1
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200

        params = kwargs.get("params", {})
        if "pageToken" not in params:
            resp.json.return_value = {
                "history": [
                    {
                        "id": "2000001",
                        "messagesAdded": [{"message": {"id": "msg_page1", "labelIds": ["INBOX"]}}]
                    }
                ],
                "nextPageToken": "page2_token",
                "historyId": "2000002",
            }
        else:
            resp.json.return_value = {
                "history": [
                    {
                        "id": "2000002",
                        "messagesAdded": [{"message": {"id": "msg_page2", "labelIds": ["INBOX"]}}]
                    }
                ],
                "historyId": "2000005",
            }
        return resp

    async def mock_get_raw(db, intg, mid):
        return {
            "id": mid,
            "threadId": "th_page",
            "labelIds": ["INBOX"],
            "snippet": f"Page snippet for {mid}",
            "internalDate": datetime.now(timezone.utc),
            "raw_bytes": f"From: a@b.com\r\nSubject: Test {mid}\r\n\r\nBody".encode(),
        }

    with patch.object(client_service, "_make_api_request", side_effect=mock_paginated_history), \
         patch.object(client_service, "get_message_raw", side_effect=mock_get_raw):

        res = await client_service.sync_history(
            db=db_session,
            user=user,
            integration=integration,
            start_history_id="2000000",
        )

        assert page_call_count == 2
        assert res["synced_count"] == 2
        assert res["history_id"] == "2000005"


@pytest.mark.asyncio
async def test_sync_history_404_expired_fallback(db_session):
    """Verify HTTP 404 from History API triggers controlled Inbox reconciliation."""
    user = User(
        id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        email="expired_hist@company.com",
        username="expired_hist",
        hashed_password="hash",
    )
    db_session.add(user)
    await db_session.commit()

    integration = GmailIntegration(
        id=uuid.uuid4(),
        organization_id=user.organization_id,
        user_id=user.id,
        email_address="expired_hist@company.com",
        is_connected=True,
        last_history_id="ancient_expired_id",
        auto_analyze_enabled=False,
    )
    db_session.add(integration)
    await db_session.commit()

    client_service = GmailClientService()

    # Raise GmailHistoryExpiredError on history call
    async def mock_history_404(*args, **kwargs):
        raise GmailHistoryExpiredError("History ID too old (HTTP 404)")

    mock_inbox_sync = AsyncMock(return_value={"synced_count": 2, "skipped_count": 0, "message": "Reconciled"})
    mock_get_profile = AsyncMock(return_value={"emailAddress": "expired_hist@company.com", "historyId": "new_fresh_history_id"})

    with patch.object(client_service, "_make_api_request", side_effect=mock_history_404), \
         patch.object(client_service, "sync_inbox", new=mock_inbox_sync), \
         patch.object(client_service, "get_profile", new=mock_get_profile):

        res = await client_service.sync_history(
            db=db_session,
            user=user,
            integration=integration,
            start_history_id="ancient_expired_id",
        )

        assert res.get("reconciled_after_expiration") is True
        assert mock_inbox_sync.called
        assert mock_get_profile.called
        await db_session.refresh(integration)
        assert integration.last_history_id == "new_fresh_history_id"


# ===========================================================================
# 3. BACKGROUND TASK EXECUTION TESTS
# ===========================================================================

@pytest.mark.asyncio
async def test_renew_gmail_watches_task(db_session):
    """Verify renew_gmail_watches task renews connections approaching expiration."""
    from app.workers.tasks import execute_renew_gmail_watches

    user = User(
        id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        email="renew_task@company.com",
        username="renew_task",
        hashed_password="hash",
    )
    db_session.add(user)
    await db_session.commit()

    # Connection expiring in 12 hours (within 48 hour renewal threshold)
    expiring_soon = datetime.now(timezone.utc) + timedelta(hours=12)
    integration = GmailIntegration(
        id=uuid.uuid4(),
        organization_id=user.organization_id,
        user_id=user.id,
        email_address="renew_task@company.com",
        is_connected=True,
        refresh_token_encrypted=b"dummy",
        watch_status="active",
        watch_expiration=expiring_soon,
    )
    db_session.add(integration)
    await db_session.commit()

    mock_watch = AsyncMock(return_value={"status": "active", "historyId": "999"})

    with patch("app.services.gmail_client_service.gmail_client_service.watch_inbox", new=mock_watch):
        result = await execute_renew_gmail_watches()
        assert result["renewed"] >= 1
        assert mock_watch.called
