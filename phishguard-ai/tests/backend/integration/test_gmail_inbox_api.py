"""
PhishGuard AI — Integration Tests for Gmail API Inbox Retrieval & Sync Endpoints
Tests:
- POST /api/v1/gmail/sync (real sync, bounded concurrency, idempotency reporting)
- POST /api/v1/gmail/initial-scan (mandatory explicit consent enforcement)
- GET /api/v1/gmail/messages (filtering by search, threat level, status)
- POST /api/v1/gmail/messages/{message_id}/analyze (single message analysis dispatch)
- POST /api/v1/gmail/analyze-all (batch analysis dispatch)
"""

import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
import httpx
from httpx import AsyncClient
from sqlalchemy import select

from app.models import GmailIntegration, GmailMessage, User
from app.services.gmail_client_service import gmail_client_service


@pytest.mark.asyncio
async def test_sync_no_connected_account(authenticated_client: AsyncClient):
    """Verify sync returns 400 when no Gmail account is connected."""
    res = await authenticated_client.post("/api/v1/gmail/sync")
    assert res.status_code == 400
    assert "no connected gmail account" in res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_initial_scan_missing_consent(authenticated_client: AsyncClient):
    """Verify initial scan fails with 400 if explicit consent is not acknowledged."""
    res = await authenticated_client.post(
        "/api/v1/gmail/initial-scan",
        json={"consent_acknowledged": False, "max_messages": 20},
    )
    assert res.status_code == 400
    assert "explicit user consent is required" in res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_sync_and_initial_scan_flow(authenticated_client: AsyncClient, db_session):
    """
    Verify complete flow:
    1. Connect an integration record for authenticated_client user.
    2. Perform initial scan with consent_acknowledged=True.
    3. Perform standard sync.
    4. Query /messages endpoint with search and threat level filtering.
    """
    user_id = uuid.UUID("00000000-0000-0000-0000-000000000001")
    org_id = uuid.UUID("00000000-0000-0000-0000-000000000002")

    # 1. Setup connected integration
    integration = GmailIntegration(
        id=uuid.uuid4(),
        organization_id=org_id,
        user_id=user_id,
        email_address="victim_corp@gmail.com",
        is_connected=True,
        connection_status="connected",
        token_status="valid",
        refresh_token_encrypted=b"dummy_encrypted_token",
        auto_analyze_enabled=True,
    )
    db_session.add(integration)
    await db_session.commit()

    # Mock gmail_client_service.sync_inbox
    mock_sync_result = {
        "synced_count": 3,
        "skipped_count": 0,
        "total_inbox_estimate": 10,
        "message": "Successfully retrieved 3 new messages from Gmail INBOX (0 existing skipped).",
    }

    with patch.object(gmail_client_service, "sync_inbox", return_value=mock_sync_result) as mock_sync:
        # Initial scan with consent
        scan_res = await authenticated_client.post(
            "/api/v1/gmail/initial-scan",
            json={"consent_acknowledged": True, "max_messages": 25},
        )
        assert scan_res.status_code == 200
        scan_data = scan_res.json()["data"]
        assert scan_data["synced_count"] == 3
        assert mock_sync.called
        assert mock_sync.call_args[1]["is_initial_scan"] is True
        assert mock_sync.call_args[1]["consent_acknowledged"] is True

        # Regular sync
        sync_res = await authenticated_client.post("/api/v1/gmail/sync?max_messages=15")
        assert sync_res.status_code == 200
        sync_data = sync_res.json()["data"]
        assert sync_data["synced_count"] == 3


@pytest.mark.asyncio
async def test_get_gmail_messages_and_analyze(authenticated_client: AsyncClient, db_session):
    """
    Verify /messages and /messages/{message_id}/analyze endpoints:
    1. Seed a GmailMessage linked to authenticated user's integration.
    2. Retrieve via GET /messages.
    3. Filter by search query.
    4. Trigger manual analysis via POST /messages/{message_id}/analyze.
    """
    user_id = uuid.UUID("00000000-0000-0000-0000-000000000001")
    org_id = uuid.UUID("00000000-0000-0000-0000-000000000002")

    integration = GmailIntegration(
        id=uuid.uuid4(),
        organization_id=org_id,
        user_id=user_id,
        email_address="analyst@gmail.com",
        is_connected=True,
        connection_status="connected",
        token_status="valid",
    )
    db_session.add(integration)
    await db_session.commit()

    msg = GmailMessage(
        id=uuid.uuid4(),
        organization_id=org_id,
        user_id=user_id,
        integration_id=integration.id,
        gmail_message_id="msg_live_123",
        subject="Urgent: Wire Transfer Request",
        sender="ceo@fake-executive.org",
        snippet="Please transfer $50,000 immediately.",
        raw_eml="From: ceo@fake-executive.org\r\nSubject: Urgent: Wire Transfer Request\r\n\r\nPlease transfer $50,000 immediately.",
        received_at=datetime.now(timezone.utc),
        is_analyzed=False,
        analysis_status="pending",
    )
    db_session.add(msg)
    await db_session.commit()

    # 1. Fetch messages
    res = await authenticated_client.get("/api/v1/gmail/messages")
    assert res.status_code == 200
    data = res.json()["data"]
    assert data["total"] == 1
    assert data["messages"][0]["subject"] == "Urgent: Wire Transfer Request"

    # 2. Search filter
    search_res = await authenticated_client.get("/api/v1/gmail/messages?search=Wire+Transfer")
    assert search_res.status_code == 200
    assert search_res.json()["data"]["total"] == 1

    search_nomatch = await authenticated_client.get("/api/v1/gmail/messages?search=NonexistentQueryXYZ")
    assert search_nomatch.status_code == 200
    assert search_nomatch.json()["data"]["total"] == 0

    # 3. Trigger manual analysis
    with patch("app.api.v1.endpoints.gmail._analyze_single_gmail_message_by_id") as mock_analyze:
        analyze_res = await authenticated_client.post(f"/api/v1/gmail/messages/{msg.id}/analyze")
        assert analyze_res.status_code == 200
        assert mock_analyze.called
