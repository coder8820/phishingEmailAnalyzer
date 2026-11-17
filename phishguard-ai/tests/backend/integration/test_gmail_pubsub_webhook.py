"""
PhishGuard AI — Integration Tests for Gmail Pub/Sub Push Webhook & Real-Time Monitoring
Tests:
- POST /api/v1/gmail/webhook/pubsub authentication (verification token validation)
- Pub/Sub subscription identity validation
- Pub/Sub base64 payload decoding (emailAddress & historyId extraction)
- Match to existing authorized Gmail connection in database
- Acknowledging unknown/disconnected accounts safely (prevent retry storms)
- Deduplication of push notifications via messageId
- POST /api/v1/gmail/watch (enable push watch)
- POST /api/v1/gmail/stop-watch (disable push watch)
"""

import base64
import json
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app.core.config import settings
from app.models import GmailIntegration, User
from app.services.gmail_client_service import gmail_client_service


@pytest.mark.asyncio
async def test_pubsub_webhook_unauthorized_missing_token(client: AsyncClient, monkeypatch):
    """Verify push requests without valid verification token return 401."""
    monkeypatch.setattr(settings, "GMAIL_PUBSUB_VERIFICATION_TOKEN", "super-secret-token")

    payload = {
        "message": {
            "data": base64.b64encode(json.dumps({"emailAddress": "test@gmail.com", "historyId": "123"}).encode()).decode(),
            "messageId": "msg_001",
        },
        "subscription": "projects/test-project/subscriptions/gmail-inbox-push",
    }

    res = await client.post("/api/v1/gmail/webhook/pubsub", json=payload)
    assert res.status_code == 401
    assert "unauthorized" in res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_pubsub_webhook_subscription_mismatch(client: AsyncClient, monkeypatch):
    """Verify push requests with wrong subscription return 400."""
    monkeypatch.setattr(settings, "GMAIL_PUBSUB_VERIFICATION_TOKEN", "valid-secret")
    monkeypatch.setattr(settings, "GMAIL_PUBSUB_SUBSCRIPTION", "projects/test/subscriptions/expected-sub")

    payload = {
        "message": {
            "data": base64.b64encode(json.dumps({"emailAddress": "test@gmail.com", "historyId": "123"}).encode()).decode(),
            "messageId": "msg_002",
        },
        "subscription": "projects/test/subscriptions/MALICIOUS_SUB",
    }

    res = await client.post("/api/v1/gmail/webhook/pubsub?token=valid-secret", json=payload)
    assert res.status_code == 400
    assert "subscription" in res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_pubsub_webhook_invalid_base64_payload(client: AsyncClient, monkeypatch):
    """Verify push requests with corrupted base64 data return 400."""
    monkeypatch.setattr(settings, "GMAIL_PUBSUB_VERIFICATION_TOKEN", "")  # Token disabled for test

    payload = {
        "message": {
            "data": "NOT_BASE_64_&&&!!!",
            "messageId": "msg_003",
        }
    }

    res = await client.post("/api/v1/gmail/webhook/pubsub", json=payload)
    assert res.status_code == 400


@pytest.mark.asyncio
async def test_pubsub_webhook_unknown_email_acknowledged_safely(client: AsyncClient, monkeypatch, db_session):
    """
    Verify push notification for an email not connected to PhishGuard returns 200 acknowledged
    (with status='ignored') to prevent Pub/Sub retry storms.
    """
    monkeypatch.setattr(settings, "GMAIL_PUBSUB_VERIFICATION_TOKEN", "")

    notif_data = {"emailAddress": "unknown_stranger@gmail.com", "historyId": "55555"}
    payload = {
        "message": {
            "data": base64.b64encode(json.dumps(notif_data).encode()).decode(),
            "messageId": "msg_unknown_001",
        }
    }

    res = await client.post("/api/v1/gmail/webhook/pubsub", json=payload)
    assert res.status_code == 200
    assert res.json()["data"]["status"] == "ignored"


@pytest.mark.asyncio
async def test_pubsub_webhook_valid_notification_enqueues_sync(client: AsyncClient, monkeypatch, db_session):
    """
    Verify valid push notification:
    1. Authenticates token.
    2. Decodes base64 payload.
    3. Matches to active database connection.
    4. Acknowledges with 200 immediately.
    5. Enqueues background sync.
    """
    secret = "verified-push-token-xyz"
    monkeypatch.setattr(settings, "GMAIL_PUBSUB_VERIFICATION_TOKEN", secret)

    user_id = uuid.UUID("00000000-0000-0000-0000-000000000001")
    org_id = uuid.UUID("00000000-0000-0000-0000-000000000002")

    integration = GmailIntegration(
        id=uuid.uuid4(),
        organization_id=org_id,
        user_id=user_id,
        email_address="employee@phishguard-corp.com",
        is_connected=True,
        watch_status="active",
        last_history_id="1000",
    )
    db_session.add(integration)
    await db_session.commit()

    notif_data = {"emailAddress": "employee@phishguard-corp.com", "historyId": "1050"}
    payload = {
        "message": {
            "data": base64.b64encode(json.dumps(notif_data).encode()).decode(),
            "messageId": "pubsub_unique_12345",
        }
    }

    with patch("app.workers.tasks.sync_gmail_history_task.delay") as mock_delay:
        res = await client.post(
            f"/api/v1/gmail/webhook/pubsub?token={secret}",
            json=payload,
        )

        assert res.status_code == 200
        data = res.json()["data"]
        assert data["status"] == "acknowledged"
        assert data["email_address"] == "employee@phishguard-corp.com"
        assert data["history_id"] == "1050"
        assert mock_delay.called

        # Test Deduplication: sending identical messageId returns acknowledged without duplicate enqueue
        mock_delay.reset_mock()
        res_dup = await client.post(
            f"/api/v1/gmail/webhook/pubsub?token={secret}",
            json=payload,
        )
        assert res_dup.status_code == 200
        assert res_dup.json()["data"]["duplicate"] is True
        assert not mock_delay.called


@pytest.mark.asyncio
async def test_watch_and_stop_watch_endpoints(authenticated_client: AsyncClient, db_session):
    """Verify /watch and /stop-watch endpoints for authenticated user."""
    user_id = uuid.UUID("00000000-0000-0000-0000-000000000001")
    org_id = uuid.UUID("00000000-0000-0000-0000-000000000002")

    integration = GmailIntegration(
        id=uuid.uuid4(),
        organization_id=org_id,
        user_id=user_id,
        email_address="watch_endpoint_user@gmail.com",
        is_connected=True,
        watch_status="inactive",
    )
    db_session.add(integration)
    await db_session.commit()

    # 1. Test POST /watch
    mock_watch_res = {
        "status": "active",
        "history_id": "777888",
        "expiration": (datetime.now(timezone.utc) + timedelta(days=7)).isoformat(),
        "topic": "projects/p/topics/t",
    }
    with patch.object(gmail_client_service, "watch_inbox", return_value=mock_watch_res) as mock_w:
        res = await authenticated_client.post("/api/v1/gmail/watch")
        assert res.status_code == 200
        assert res.json()["data"]["status"] == "active"
        assert res.json()["data"]["history_id"] == "777888"
        assert mock_w.called

    # 2. Test POST /stop-watch
    mock_stop_res = {"status": "inactive", "message": "Watch stopped"}
    with patch.object(gmail_client_service, "stop_watch", return_value=mock_stop_res) as mock_s:
        res = await authenticated_client.post("/api/v1/gmail/stop-watch")
        assert res.status_code == 200
        assert res.json()["data"]["status"] == "inactive"
        assert mock_s.called
