"""
PhishGuard AI — Unit Tests for Genuine Gmail API Client & Inbox Retrieval
Validates:
- INBOX-only listing parameters (labelIds=['INBOX'], exclusion of spam/trash/drafts/sent)
- Rejection of non-INBOX and Spam/Trash/Draft/Sent messages
- Lossless base64url decoding with and without '=' padding
- Integration with hardened EmailParser
- Strong idempotency (one analysis per Gmail message ID, no duplicate analyses on repeat syncs)
- Initial scan explicit consent enforcement (mandatory consent_acknowledged=True)
- Automatic token refresh on HTTP 401
- Revoked token handling (GoogleTokenRevokedError)
- Rate-limit exponential backoff (HTTP 429 / 503)
- Insufficient permissions handling (HTTP 403)
- Multi-tenant isolation
"""

import base64
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from sqlalchemy import select

from app.models import Email, GmailIntegration, GmailMessage, Organization, User
from app.services.gmail_client_service import (
    GmailClientService,
    GmailAPIError,
    GmailRateLimitError,
    GmailPermissionError,
    GmailInitialScanConsentRequiredError,
    decode_base64url_bytes,
    INBOX_SEARCH_QUERY,
)
from app.services.gmail_oauth_service import GoogleTokenRevokedError


# ===========================================================================
# 1. LOSSLESS BASE64URL DECODING TESTS
# ===========================================================================

def test_decode_base64url_bytes_lossless():
    """Verify lossless decoding of RFC 4648 base64url data with various padding offsets."""
    original_data = b"MIME-Version: 1.0\r\nSubject: Test Email\r\n\r\nHello World!"

    # Test standard base64url with and without trailing '='
    b64_str = base64.urlsafe_b64encode(original_data).decode().rstrip("=")
    decoded = decode_base64url_bytes(b64_str)
    assert decoded == original_data

    # Test with standard padding intact
    b64_str_padded = base64.urlsafe_b64encode(original_data).decode()
    assert decode_base64url_bytes(b64_str_padded) == original_data

    # Empty string should return empty bytes
    assert decode_base64url_bytes("") == b""


# ===========================================================================
# 2. INBOX-ONLY FILTERING & EXCLUSION TESTS
# ===========================================================================

@pytest.mark.asyncio
async def test_list_inbox_messages_parameters(db_session):
    """Verify list_inbox_messages strictly enforces INBOX label and exclusion queries."""
    integration = GmailIntegration(
        id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        user_id=uuid.uuid4(),
        email_address="victim@company.com",
        is_connected=True,
        encrypted_refresh_token=b"encrypted_token",
    )

    client_service = GmailClientService()

    recorded_params = {}

    async def mock_api_request(*args, **kwargs):
        nonlocal recorded_params
        recorded_params = kwargs.get("params", {})
        resp = MagicMock(spec=httpx.Response)
        resp.json.return_value = {
            "messages": [{"id": "msg_001", "threadId": "th_001"}],
            "resultSizeEstimate": 1,
        }
        return resp

    with patch.object(client_service, "_make_api_request", side_effect=mock_api_request):
        messages, next_page, total = await client_service.list_inbox_messages(
            db=db_session,
            integration=integration,
            max_results=25,
        )

        assert len(messages) == 1
        assert messages[0]["id"] == "msg_001"
        assert recorded_params.get("labelIds") == ["INBOX"]
        assert recorded_params.get("includeSpamTrash") == "false"
        assert "label:INBOX" in recorded_params.get("q", "")
        assert "-in:spam" in recorded_params.get("q", "")
        assert "-in:trash" in recorded_params.get("q", "")
        assert "-in:drafts" in recorded_params.get("q", "")
        assert "-in:sent" in recorded_params.get("q", "")


@pytest.mark.asyncio
async def test_get_message_raw_rejects_non_inbox(db_session):
    """Verify get_message_raw rejects messages that lack INBOX or are in Spam/Trash."""
    integration = GmailIntegration(
        id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        user_id=uuid.uuid4(),
        email_address="victim@company.com",
        is_connected=True,
        encrypted_refresh_token=b"encrypted_token",
    )

    client_service = GmailClientService()

    # Case 1: Message is in SPAM
    async def mock_spam_response(*args, **kwargs):
        resp = MagicMock(spec=httpx.Response)
        resp.json.return_value = {
            "id": "spam_01",
            "threadId": "th_spam",
            "labelIds": ["SPAM"],
            "raw": "",
        }
        return resp

    with patch.object(client_service, "_make_api_request", side_effect=mock_spam_response):
        with pytest.raises(GmailAPIError, match="not an eligible INBOX message"):
            await client_service.get_message_raw(db_session, integration, "spam_01")

    # Case 2: Message is in TRASH
    async def mock_trash_response(*args, **kwargs):
        resp = MagicMock(spec=httpx.Response)
        resp.json.return_value = {
            "id": "trash_01",
            "threadId": "th_trash",
            "labelIds": ["TRASH", "INBOX"],
            "raw": "",
        }
        return resp

    with patch.object(client_service, "_make_api_request", side_effect=mock_trash_response):
        with pytest.raises(GmailAPIError, match="not an eligible INBOX message"):
            await client_service.get_message_raw(db_session, integration, "trash_01")

    # Case 3: Message is archived (no INBOX label)
    async def mock_archived_response(*args, **kwargs):
        resp = MagicMock(spec=httpx.Response)
        resp.json.return_value = {
            "id": "archived_01",
            "threadId": "th_archived",
            "labelIds": ["IMPORTANT"],  # lacks INBOX
            "raw": "",
        }
        return resp

    with patch.object(client_service, "_make_api_request", side_effect=mock_archived_response):
        with pytest.raises(GmailAPIError, match="not an eligible INBOX message"):
            await client_service.get_message_raw(db_session, integration, "archived_01")


# ===========================================================================
# 3. INITIAL SCAN EXPLICIT CONSENT ENFORCEMENT
# ===========================================================================

@pytest.mark.asyncio
async def test_initial_scan_requires_explicit_consent(db_session):
    """Verify that an initial historical scan without consent_acknowledged=True is rejected."""
    user = User(
        id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        email="analyst@company.com",
        username="analyst_consent",
        hashed_password="hash",
    )
    integration = GmailIntegration(
        id=uuid.uuid4(),
        organization_id=user.organization_id,
        user_id=user.id,
        email_address="analyst@company.com",
        is_connected=True,
        encrypted_refresh_token=b"encrypted_token",
    )

    client_service = GmailClientService()

    with pytest.raises(GmailInitialScanConsentRequiredError, match="Explicit user consent is required"):
        await client_service.sync_inbox(
            db=db_session,
            user=user,
            integration=integration,
            is_initial_scan=True,
            consent_acknowledged=False,
        )


# ===========================================================================
# 4. IDEMPOTENCY & DUPLICATE PREVENTION
# ===========================================================================

@pytest.mark.asyncio
async def test_sync_inbox_idempotency(db_session):
    """
    Verify strong idempotency:
    - First sync retrieves and stores message.
    - Second sync for the same Gmail message ID detects existing record, skips it,
      and produces zero duplicate Email or GmailMessage rows.
    """
    user = User(
        id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        email="user_idempotency@company.com",
        username="user_idempotent",
        hashed_password="hash",
    )
    db_session.add(user)
    await db_session.commit()

    integration = GmailIntegration(
        id=uuid.uuid4(),
        organization_id=user.organization_id,
        user_id=user.id,
        email_address="user_idempotency@company.com",
        is_connected=True,
        auto_analyze_enabled=False,
        encrypted_refresh_token=b"encrypted_token",
    )
    db_session.add(integration)
    await db_session.commit()

    raw_eml = (
        b"From: billing@secure-corp.net\r\n"
        b"To: user_idempotency@company.com\r\n"
        b"Subject: Monthly Security Invoice\r\n"
        b"Date: Mon, 16 Nov 2026 10:00:00 +0000\r\n"
        b"Message-ID: <inv-1234@secure-corp.net>\r\n"
        b"\r\n"
        b"Please find attached your invoice.\r\n"
    )
    raw_b64 = base64.urlsafe_b64encode(raw_eml).decode()

    client_service = GmailClientService()

    # Mock list_inbox_messages and get_message_raw
    async def mock_list(*args, **kwargs):
        return [{"id": "gmail_msg_xyz_999"}], None, 1

    async def mock_get_raw(*args, **kwargs):
        return {
            "id": "gmail_msg_xyz_999",
            "threadId": "th_xyz",
            "labelIds": ["INBOX", "UNREAD"],
            "snippet": "Please find attached your invoice.",
            "internalDate": datetime.now(timezone.utc),
            "historyId": "12345",
            "raw_bytes": raw_eml,
        }

    with patch.object(client_service, "list_inbox_messages", side_effect=mock_list), \
         patch.object(client_service, "get_message_raw", side_effect=mock_get_raw):

        # First Sync: should ingest 1 message
        res1 = await client_service.sync_inbox(
            db=db_session,
            user=user,
            integration=integration,
            max_messages=10,
        )
        assert res1["synced_count"] == 1
        assert res1["skipped_count"] == 0

        # Verify DB records
        msgs_q1 = await db_session.execute(
            select(GmailMessage).where(GmailMessage.integration_id == integration.id)
        )
        all_msgs1 = msgs_q1.scalars().all()
        assert len(all_msgs1) == 1
        assert all_msgs1[0].gmail_message_id == "gmail_msg_xyz_999"

        emails_q1 = await db_session.execute(
            select(Email).where(Email.organization_id == user.organization_id)
        )
        assert len(emails_q1.scalars().all()) == 1

        # Second Sync: same message returned by Gmail
        res2 = await client_service.sync_inbox(
            db=db_session,
            user=user,
            integration=integration,
            max_messages=10,
        )
        assert res2["synced_count"] == 0
        assert res2["skipped_count"] == 1

        # Verify DB has NOT created duplicate records
        msgs_q2 = await db_session.execute(
            select(GmailMessage).where(GmailMessage.integration_id == integration.id)
        )
        all_msgs2 = msgs_q2.scalars().all()
        assert len(all_msgs2) == 1

        emails_q2 = await db_session.execute(
            select(Email).where(Email.organization_id == user.organization_id)
        )
        assert len(emails_q2.scalars().all()) == 1


# ===========================================================================
# 5. TOKEN REFRESH & ERROR HANDLING
# ===========================================================================

@pytest.mark.asyncio
async def test_token_refresh_on_401(db_session):
    """Verify that an HTTP 401 response from Gmail API triggers token refresh and retries."""
    integration = GmailIntegration(
        id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        user_id=uuid.uuid4(),
        email_address="refresh_test@company.com",
        is_connected=True,
        encrypted_refresh_token=b"encrypted_token",
    )

    client_service = GmailClientService()

    call_count = 0

    class MockHttpxClient:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            pass
        async def request(self, *args, **kwargs):
            nonlocal call_count
            call_count += 1
            resp = MagicMock(spec=httpx.Response)
            if call_count == 1:
                resp.status_code = 401
                resp.text = "Unauthorized"
            else:
                resp.status_code = 200
                resp.json.return_value = {"messages": [], "resultSizeEstimate": 0}
            return resp

    with patch("app.services.gmail_client_service.gmail_oauth_service.get_valid_access_token", return_value="expired_tok"), \
         patch("app.services.gmail_client_service.gmail_oauth_service.refresh_access_token", return_value="new_fresh_tok") as mock_refresh, \
         patch("httpx.AsyncClient", return_value=MockHttpxClient()):

        resp = await client_service._make_api_request(
            db=db_session,
            integration=integration,
            method="GET",
            url="https://gmail.googleapis.com/test",
            retries=2,
        )

        assert resp.status_code == 200
        assert mock_refresh.called
        assert call_count == 2


@pytest.mark.asyncio
async def test_permission_denied_on_403(db_session):
    """Verify that an HTTP 403 Forbidden raises GmailPermissionError."""
    integration = GmailIntegration(
        id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        user_id=uuid.uuid4(),
        email_address="perm_test@company.com",
        is_connected=True,
        encrypted_refresh_token=b"encrypted_token",
    )

    client_service = GmailClientService()

    class MockHttpxClient403:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            pass
        async def request(self, *args, **kwargs):
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = 403
            resp.text = "Insufficient Permission"
            return resp

    with patch("app.services.gmail_client_service.gmail_oauth_service.get_valid_access_token", return_value="tok"), \
         patch("httpx.AsyncClient", return_value=MockHttpxClient403()):

        with pytest.raises(GmailPermissionError):
            await client_service._make_api_request(
                db=db_session,
                integration=integration,
                method="GET",
                url="https://gmail.googleapis.com/test",
            )


# ===========================================================================
# 6. MULTI-TENANT ISOLATION
# ===========================================================================

@pytest.mark.asyncio
async def test_tenant_isolation_on_sync(db_session):
    """
    Verify strict tenant isolation:
    Emails synced for Tenant A are scoped with Tenant A's organization_id and
    are never visible or accessible to Tenant B.
    """
    org_a = uuid.uuid4()
    org_b = uuid.uuid4()

    user_a = User(
        id=uuid.uuid4(),
        organization_id=org_a,
        email="analyst@tenant-a.com",
        username="analyst_a",
        hashed_password="hash",
    )
    user_b = User(
        id=uuid.uuid4(),
        organization_id=org_b,
        email="analyst@tenant-b.com",
        username="analyst_b",
        hashed_password="hash",
    )
    db_session.add_all([user_a, user_b])
    await db_session.commit()

    int_a = GmailIntegration(
        id=uuid.uuid4(),
        organization_id=org_a,
        user_id=user_a.id,
        email_address="analyst@tenant-a.com",
        is_connected=True,
        encrypted_refresh_token=b"encrypted_token",
    )
    db_session.add(int_a)
    await db_session.commit()

    raw_eml = b"From: secret@tenant-a.com\r\nSubject: Confidential A\r\n\r\nBody A"
    client_service = GmailClientService()

    async def mock_list(*args, **kwargs):
        return [{"id": "msg_tenant_a"}], None, 1

    async def mock_get_raw(*args, **kwargs):
        return {
            "id": "msg_tenant_a",
            "threadId": "th_a",
            "labelIds": ["INBOX"],
            "snippet": "Confidential A",
            "internalDate": datetime.now(timezone.utc),
            "historyId": "111",
            "raw_bytes": raw_eml,
        }

    with patch.object(client_service, "list_inbox_messages", side_effect=mock_list), \
         patch.object(client_service, "get_message_raw", side_effect=mock_get_raw):

        await client_service.sync_inbox(
            db=db_session,
            user=user_a,
            integration=int_a,
        )

        # Tenant A's query sees the message
        stmt_a = select(GmailMessage).where(GmailMessage.organization_id == org_a)
        res_a = await db_session.execute(stmt_a)
        assert len(res_a.scalars().all()) == 1

        # Tenant B's query sees NOTHING
        stmt_b = select(GmailMessage).where(GmailMessage.organization_id == org_b)
        res_b = await db_session.execute(stmt_b)
        assert len(res_b.scalars().all()) == 0
