"""
PhishGuard AI — Unit Tests for Milestone G4: Safe Gmail Phishing Quarantine
Validates:
- Detection policy evaluation (clean, suspicious, high-confidence phishing, fail-safe on incomplete analysis)
- Custom Gmail label creation & lookup (PhishGuard-Quarantine)
- Non-destructive message quarantine (add quarantine label, remove INBOX, preserve original labels)
- Restore action (remove quarantine label, restore INBOX)
- Full idempotency for both quarantine and restore
- AuditLog recording for all quarantine and restore operations
- Scope validation (gmail.modify required)
- Strict tenant and account isolation
- Fail-safe error handling when Gmail API fails
"""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from sqlalchemy import select

from app.models import AuditLog, EmailAnalysis, GmailIntegration, GmailMessage, User, IOC
from app.services.gmail_client_service import (
    GmailClientService,
    GmailAPIError,
    GmailPermissionError,
    GMAIL_LABELS_ENDPOINT,
    GMAIL_MESSAGES_ENDPOINT,
)


@pytest.fixture
def mock_user():
    return User(
        id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        email="analyst@securecorp.com",
        username="analyst_test",
        hashed_password="hashed_pw",
        role="analyst",
    )


@pytest.fixture
def mock_integration(mock_user):
    return GmailIntegration(
        id=uuid.uuid4(),
        organization_id=mock_user.organization_id,
        user_id=mock_user.id,
        email_address="analyst@securecorp.com",
        is_connected=True,
        connection_status="connected",
        token_status="valid",
        refresh_token_encrypted=b"encrypted_refresh_token",
        granted_scopes=["https://www.googleapis.com/auth/gmail.modify"],
        auto_quarantine_enabled=False,
        quarantine_threshold_score=70,
        quarantine_label_name="PhishGuard-Quarantine",
    )


@pytest.fixture
def mock_message(mock_user, mock_integration):
    return GmailMessage(
        id=uuid.uuid4(),
        organization_id=mock_user.organization_id,
        user_id=mock_user.id,
        integration_id=mock_integration.id,
        gmail_message_id="msg_phish_12345",
        thread_id="th_12345",
        label_ids=["INBOX", "UNREAD"],
        subject="URGENT: Payroll Verification Required",
        sender="payroll-update@attacker-domain.com",
        snippet="Please verify your direct deposit credentials immediately.",
        is_analyzed=True,
        analysis_status="analyzed",
        risk_score=85.0,
        risk_classification="High",
        is_quarantined=False,
        quarantine_action_status="none",
    )


# ===========================================================================
# 1. DETECTION POLICY & THRESHOLD EVALUATION
# ===========================================================================

def test_evaluate_quarantine_policy_clean(mock_message):
    """Verify that clean/low-risk emails (< 40) require no action."""
    client = GmailClientService()
    mock_message.risk_score = 15.0
    mock_message.risk_classification = "Safe"

    eligible, decision, reason = client.evaluate_quarantine_policy(mock_message, threshold_score=70)
    assert eligible is False
    assert decision == "no_action"
    assert "low risk" in reason


def test_evaluate_quarantine_policy_suspicious(mock_message):
    """Verify that suspicious emails (40 <= score < 70) generate alert for review, not auto-quarantine."""
    client = GmailClientService()
    mock_message.risk_score = 55.0
    mock_message.risk_classification = "Suspicious"

    eligible, decision, reason = client.evaluate_quarantine_policy(mock_message, threshold_score=70)
    assert eligible is False
    assert decision == "alert_only"
    assert "Suspicious" in reason
    assert "manual security analyst review" in reason


def test_evaluate_quarantine_policy_high_phishing(mock_message):
    """Verify that confirmed high-confidence phishing (>= 70) is eligible for quarantine."""
    client = GmailClientService()
    mock_message.risk_score = 85.0
    mock_message.risk_classification = "Critical"

    eligible, decision, reason = client.evaluate_quarantine_policy(mock_message, threshold_score=70)
    assert eligible is True
    assert decision == "quarantine"
    assert "Confirmed high-confidence phishing" in reason


def test_evaluate_quarantine_policy_incomplete_analysis(mock_message):
    """Verify fail-safe: emails with pending/incomplete analysis are held for review, not quarantined."""
    client = GmailClientService()
    mock_message.is_analyzed = False
    mock_message.analysis_status = "pending"

    eligible, decision, reason = client.evaluate_quarantine_policy(mock_message, threshold_score=70)
    assert eligible is False
    assert decision == "alert_only"
    assert "pending or not completed" in reason


def test_evaluate_quarantine_policy_analysis_errors_failsafe(mock_message):
    """Verify fail-safe: if analysis had multiple errors, hold for manual review."""
    client = GmailClientService()
    mock_message.risk_score = 90.0
    mock_message.risk_classification = "Critical"

    mock_analysis = MagicMock()
    mock_analysis.errors = ["VirusTotal timeout", "AI service 503", "WHOIS lookup failure"]

    eligible, decision, reason = client.evaluate_quarantine_policy(mock_message, analysis=mock_analysis, threshold_score=70)
    assert eligible is False
    assert decision == "alert_only"
    assert "Fail-safe engaged" in reason


# ===========================================================================
# 2. GMAIL LABEL CREATION & LOOKUP
# ===========================================================================

@pytest.mark.asyncio
async def test_get_or_create_quarantine_label_cached(db_session, mock_user, mock_integration):
    """Verify that a valid cached quarantine label ID is returned directly without re-creating."""
    db_session.add(mock_user)
    mock_integration.quarantine_label_id = "Label_cached_999"
    db_session.add(mock_integration)
    await db_session.commit()

    client = GmailClientService()

    async def mock_api(*args, **kwargs):
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        resp.json.return_value = {"id": "Label_cached_999", "name": "PhishGuard-Quarantine"}
        return resp

    with patch.object(client, "_make_api_request", side_effect=mock_api):
        label_id = await client.get_or_create_quarantine_label(db_session, mock_integration)
        assert label_id == "Label_cached_999"


@pytest.mark.asyncio
async def test_get_or_create_quarantine_label_found_in_list(db_session, mock_user, mock_integration):
    """Verify that if label is not cached, it is looked up via users.labels.list."""
    db_session.add(mock_user)
    mock_integration.quarantine_label_id = None
    db_session.add(mock_integration)
    await db_session.commit()

    client = GmailClientService()

    async def mock_api(*args, **kwargs):
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        resp.json.return_value = {
            "labels": [
                {"id": "INBOX", "name": "INBOX"},
                {"id": "Label_existing_456", "name": "PhishGuard-Quarantine"},
            ]
        }
        return resp

    with patch.object(client, "_make_api_request", side_effect=mock_api):
        label_id = await client.get_or_create_quarantine_label(db_session, mock_integration)
        assert label_id == "Label_existing_456"
        assert mock_integration.quarantine_label_id == "Label_existing_456"


@pytest.mark.asyncio
async def test_get_or_create_quarantine_label_creates_new(db_session, mock_user, mock_integration):
    """Verify that if label is not found, users.labels.create is called."""
    db_session.add(mock_user)
    mock_integration.quarantine_label_id = None
    db_session.add(mock_integration)
    await db_session.commit()

    client = GmailClientService()
    calls = []

    async def mock_api(*args, **kwargs):
        method = kwargs.get("method")
        calls.append((method, kwargs.get("url"), kwargs.get("json_data")))
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        if method == "GET":
            # Label list does not contain quarantine label
            resp.json.return_value = {"labels": [{"id": "INBOX", "name": "INBOX"}]}
        elif method == "POST":
            # Creation response
            resp.json.return_value = {"id": "Label_new_789", "name": "PhishGuard-Quarantine"}
        return resp

    with patch.object(client, "_make_api_request", side_effect=mock_api):
        label_id = await client.get_or_create_quarantine_label(db_session, mock_integration)
        assert label_id == "Label_new_789"
        assert mock_integration.quarantine_label_id == "Label_new_789"
        # Verify POST request was sent to create label
        post_calls = [c for c in calls if c[0] == "POST"]
        assert len(post_calls) == 1
        assert post_calls[0][2]["name"] == "PhishGuard-Quarantine"


# ===========================================================================
# 3. MESSAGE QUARANTINE TESTS
# ===========================================================================

@pytest.mark.asyncio
async def test_quarantine_message_success(db_session, mock_user, mock_integration, mock_message):
    """Verify quarantine adds quarantine label, removes INBOX, saves original labels, and logs audit."""
    db_session.add(mock_user)
    mock_integration.quarantine_label_id = "Label_Q123"
    db_session.add(mock_integration)
    db_session.add(mock_message)
    await db_session.commit()

    client = GmailClientService()
    recorded_modify_body = {}

    async def mock_api(*args, **kwargs):
        nonlocal recorded_modify_body
        method = kwargs.get("method")
        url = kwargs.get("url")
        if "labels" in url:
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = 200
            resp.json.return_value = {"id": "Label_Q123", "name": "PhishGuard-Quarantine"}
            return resp
        if "modify" in url:
            recorded_modify_body = kwargs.get("json_data", {})
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = 200
            resp.json.return_value = {
                "id": mock_message.gmail_message_id,
                "labelIds": ["Label_Q123", "UNREAD"],
            }
            return resp
        if "?format=minimal" in url:
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = 200
            resp.json.return_value = {
                "id": mock_message.gmail_message_id,
                "labelIds": ["Label_Q123", "UNREAD"],
            }
            return resp
        raise ValueError(f"Unexpected URL: {url}")

    with patch.object(client, "_make_api_request", side_effect=mock_api):
        res = await client.quarantine_message(
            db=db_session,
            user=mock_user,
            integration=mock_integration,
            gmail_msg=mock_message,
            reason="Confirmed high-confidence phishing (Score: 85/100)",
            is_automatic=False,
        )

        assert res["status"] == "quarantined"
        assert recorded_modify_body == {
            "addLabelIds": ["Label_Q123"],
            "removeLabelIds": ["INBOX"],
        }
        assert mock_message.is_quarantined is True
        assert mock_message.quarantine_action_status == "quarantined"
        assert "INBOX" in mock_message.original_labels
        assert mock_message.label_ids == ["Label_Q123", "UNREAD"]

        # Check AuditLog entry
        audit_res = await db_session.execute(
            select(AuditLog).where(AuditLog.resource_id == mock_message.id)
        )
        audit = audit_res.scalar_one_or_none()
        assert audit is not None
        assert audit.action == "gmail.message.quarantine"
        assert audit.details["quarantine_label_id"] == "Label_Q123"


@pytest.mark.asyncio
async def test_quarantine_message_idempotency(db_session, mock_user, mock_integration, mock_message):
    """Verify that calling quarantine on an already quarantined message is a safe idempotent no-op."""
    db_session.add(mock_user)
    mock_integration.quarantine_label_id = "Label_Q123"
    db_session.add(mock_integration)

    mock_message.is_quarantined = True
    mock_message.quarantined_at = datetime.now(timezone.utc)
    mock_message.label_ids = ["Label_Q123"]
    db_session.add(mock_message)
    await db_session.commit()

    client = GmailClientService()
    api_called = False

    async def mock_api(*args, **kwargs):
        nonlocal api_called
        api_called = True
        return MagicMock(status_code=200)

    with patch.object(client, "_make_api_request", side_effect=mock_api):
        res = await client.quarantine_message(
            db=db_session,
            user=mock_user,
            integration=mock_integration,
            gmail_msg=mock_message,
            reason="Repeat quarantine",
        )

        assert res["status"] == "already_quarantined"
        assert api_called is False  # Did not call modify endpoint unnecessarily


@pytest.mark.asyncio
async def test_quarantine_missing_modify_scope(db_session, mock_user, mock_integration, mock_message):
    """Verify that attempting to quarantine without gmail.modify raises GmailPermissionError."""
    db_session.add(mock_user)
    mock_integration.granted_scopes = ["https://www.googleapis.com/auth/gmail.readonly"]
    db_session.add(mock_integration)
    db_session.add(mock_message)
    await db_session.commit()

    client = GmailClientService()

    with pytest.raises(GmailPermissionError, match="Missing required scope.*gmail.modify"):
        await client.quarantine_message(
            db=db_session,
            user=mock_user,
            integration=mock_integration,
            gmail_msg=mock_message,
            reason="Test",
        )


@pytest.mark.asyncio
async def test_quarantine_tenant_isolation(db_session, mock_user, mock_integration, mock_message):
    """Verify that attempting to quarantine a message from another organization is rejected."""
    other_user = User(
        id=uuid.uuid4(),
        organization_id=uuid.uuid4(),  # Different organization
        email="other@corp.com",
        username="other_analyst",
        hashed_password="pw",
    )
    db_session.add(mock_user)
    db_session.add(other_user)
    db_session.add(mock_integration)
    db_session.add(mock_message)
    await db_session.commit()

    client = GmailClientService()

    with pytest.raises(GmailPermissionError, match="Access denied"):
        await client.quarantine_message(
            db=db_session,
            user=other_user,  # Other user/tenant
            integration=mock_integration,
            gmail_msg=mock_message,
            reason="Test",
        )


@pytest.mark.asyncio
async def test_quarantine_api_failure_handling(db_session, mock_user, mock_integration, mock_message):
    """Verify that Gmail API failure records failure state and does not falsely claim success."""
    db_session.add(mock_user)
    mock_integration.quarantine_label_id = "Label_Q123"
    db_session.add(mock_integration)
    db_session.add(mock_message)
    await db_session.commit()

    client = GmailClientService()

    async def mock_failing_api(*args, **kwargs):
        url = kwargs.get("url")
        if "labels" in url:
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = 200
            resp.json.return_value = {"id": "Label_Q123"}
            return resp
        raise GmailAPIError("Google API 500 Internal Error", status_code=500)

    with patch.object(client, "_make_api_request", side_effect=mock_failing_api):
        with pytest.raises(GmailAPIError):
            await client.quarantine_message(
                db=db_session,
                user=mock_user,
                integration=mock_integration,
                gmail_msg=mock_message,
                reason="Test",
            )

        assert mock_message.is_quarantined is False
        assert mock_message.quarantine_action_status == "failed"
        assert "500" in mock_message.quarantine_error

        # Verify failed audit entry
        audit_res = await db_session.execute(
            select(AuditLog).where(AuditLog.resource_id == mock_message.id)
        )
        audit = audit_res.scalar_one_or_none()
        assert audit is not None
        assert audit.action == "gmail.message.quarantine_failed"
        assert audit.severity == "error"


# ===========================================================================
# 4. MESSAGE RESTORE TESTS
# ===========================================================================

@pytest.mark.asyncio
async def test_restore_message_success(db_session, mock_user, mock_integration, mock_message):
    """Verify restore removes quarantine label, restores INBOX label, updates status, and logs audit."""
    db_session.add(mock_user)
    mock_integration.quarantine_label_id = "Label_Q123"
    db_session.add(mock_integration)

    mock_message.is_quarantined = True
    mock_message.quarantine_action_status = "quarantined"
    mock_message.label_ids = ["Label_Q123"]
    mock_message.original_labels = ["INBOX", "UNREAD"]
    db_session.add(mock_message)
    await db_session.commit()

    client = GmailClientService()
    recorded_modify_body = {}

    async def mock_api(*args, **kwargs):
        nonlocal recorded_modify_body
        url = kwargs.get("url")
        if "labels" in url:
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = 200
            resp.json.return_value = {"id": "Label_Q123"}
            return resp
        if "modify" in url:
            recorded_modify_body = kwargs.get("json_data", {})
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = 200
            resp.json.return_value = {
                "id": mock_message.gmail_message_id,
                "labelIds": ["INBOX", "UNREAD"],
            }
            return resp
        if "?format=minimal" in url:
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = 200
            resp.json.return_value = {
                "id": mock_message.gmail_message_id,
                "labelIds": ["INBOX", "UNREAD"],
            }
            return resp
        raise ValueError(f"Unexpected URL: {url}")

    with patch.object(client, "_make_api_request", side_effect=mock_api):
        res = await client.restore_message(
            db=db_session,
            user=mock_user,
            integration=mock_integration,
            gmail_msg=mock_message,
        )

        assert res["status"] == "restored"
        assert recorded_modify_body == {
            "addLabelIds": ["INBOX"],
            "removeLabelIds": ["Label_Q123"],
        }
        assert mock_message.is_quarantined is False
        assert mock_message.quarantine_action_status == "restored"
        assert mock_message.restored_by == mock_user.id
        assert mock_message.restored_at is not None
        assert "INBOX" in mock_message.label_ids

        # Check AuditLog entry
        audit_res = await db_session.execute(
            select(AuditLog).where(AuditLog.resource_id == mock_message.id, AuditLog.action == "gmail.message.restore")
        )
        audit = audit_res.scalar_one_or_none()
        assert audit is not None
        assert audit.action == "gmail.message.restore"
        assert audit.details["restored_by"] == str(mock_user.id)


@pytest.mark.asyncio
async def test_restore_message_idempotent(db_session, mock_user, mock_integration, mock_message):
    """Verify that calling restore on an unquarantined message is safe and idempotent."""
    db_session.add(mock_user)
    mock_integration.quarantine_label_id = "Label_Q123"
    db_session.add(mock_integration)

    mock_message.is_quarantined = False
    mock_message.label_ids = ["INBOX"]
    db_session.add(mock_message)
    await db_session.commit()

    client = GmailClientService()
    api_called = False

    async def mock_api(*args, **kwargs):
        nonlocal api_called
        api_called = True
        return MagicMock(status_code=200)

    with patch.object(client, "_make_api_request", side_effect=mock_api):
        res = await client.restore_message(
            db=db_session,
            user=mock_user,
            integration=mock_integration,
            gmail_msg=mock_message,
        )

        assert res["status"] == "already_restored"
        assert api_called is False


@pytest.mark.asyncio
async def test_quarantine_subsequent_read_verification_failure(db_session, mock_user, mock_integration, mock_message):
    """
    Verify G5 Requirement 3.8:
    If modify succeeds but subsequent API read shows labels do not match expected quarantine state,
    a GmailAPIError is raised and the message is NOT marked as quarantined.
    """
    db_session.add(mock_user)
    mock_integration.quarantine_label_id = "Label_Q123"
    db_session.add(mock_integration)
    db_session.add(mock_message)
    await db_session.commit()

    client = GmailClientService()

    async def mock_api(db, integration, method, url, **kwargs):
        if method == "POST" and "modify" in url:
            # Modify claims success
            m = MagicMock()
            m.status_code = 200
            m.json.return_value = {"id": mock_message.gmail_message_id, "labelIds": ["Label_Q123"]}
            return m
        elif method == "GET" and "?format=minimal" in url:
            # Subsequent read returns stale or failed state (INBOX still present)
            m = MagicMock()
            m.status_code = 200
            m.json.return_value = {"id": mock_message.gmail_message_id, "labelIds": ["INBOX", "Label_Q123"]}
            return m
        raise ValueError(f"Unexpected call: {method} {url}")

    with patch.object(client, "_make_api_request", side_effect=mock_api):
        with pytest.raises(GmailAPIError, match="Quarantine verification failed"):
            await client.quarantine_message(
                db=db_session,
                user=mock_user,
                integration=mock_integration,
                gmail_msg=mock_message,
                reason="Testing subsequent verification failure",
            )

        assert mock_message.is_quarantined is False
        assert mock_message.quarantine_action_status == "failed"
        assert "Quarantine verification failed" in (mock_message.quarantine_error or "")


@pytest.mark.asyncio
async def test_restore_subsequent_read_verification_failure(db_session, mock_user, mock_integration, mock_message):
    """
    Verify G5 Requirement 4.6:
    If restore modify succeeds but subsequent API read shows quarantine label still present,
    a GmailAPIError is raised and the message remains quarantined.
    """
    db_session.add(mock_user)
    mock_integration.quarantine_label_id = "Label_Q123"
    db_session.add(mock_integration)

    mock_message.is_quarantined = True
    mock_message.quarantined_at = datetime.now(timezone.utc)
    mock_message.quarantine_action_status = "quarantined"
    mock_message.label_ids = ["Label_Q123"]
    mock_message.original_labels = ["INBOX", "UNREAD"]
    db_session.add(mock_message)
    await db_session.commit()

    client = GmailClientService()

    async def mock_api(db, integration, method, url, **kwargs):
        if method == "POST" and "modify" in url:
            m = MagicMock()
            m.status_code = 200
            m.json.return_value = {"id": mock_message.gmail_message_id, "labelIds": ["INBOX"]}
            return m
        elif method == "GET" and "?format=minimal" in url:
            # Subsequent read shows quarantine label is still present
            m = MagicMock()
            m.status_code = 200
            m.json.return_value = {"id": mock_message.gmail_message_id, "labelIds": ["INBOX", "Label_Q123"]}
            return m
        raise ValueError(f"Unexpected call: {method} {url}")

    with patch.object(client, "_make_api_request", side_effect=mock_api):
        with pytest.raises(GmailAPIError, match="Restore verification failed"):
            await client.restore_message(
                db=db_session,
                user=mock_user,
                integration=mock_integration,
                gmail_msg=mock_message,
            )

        assert mock_message.is_quarantined is True
        assert "Restore verification failed" in (mock_message.quarantine_error or "")


@pytest.mark.asyncio
async def test_report_false_positive_success(db_session, mock_user, mock_integration, mock_message):
    """
    Verify G5 Requirement 6.6:
    Reporting a false positive restores the quarantined email to INBOX,
    marks quarantine_action_status as 'false_positive', updates linked IOCs,
    and logs an audit trail.
    """
    from app.models import Email
    db_session.add(mock_user)
    mock_integration.quarantine_label_id = "Label_Q123"
    db_session.add(mock_integration)

    email_obj = Email(
        id=uuid.uuid4(),
        organization_id=mock_user.organization_id,
        user_id=mock_user.id,
        sender="partner@newsletter.com",
        recipient="analyst@securecorp.com",
        subject="Monthly Industry Insights",
        raw_eml_path="/tmp/test.eml",
        raw_eml_sha256="testsha256",
        file_size_bytes=1024,
    )
    db_session.add(email_obj)

    ioc = IOC(
        id=uuid.uuid4(),
        email_id=email_obj.id,
        organization_id=mock_user.organization_id,
        ioc_type="domain",
        ioc_value="newsletter.com",
        threat_level="high",
        is_false_positive=False,
    )
    db_session.add(ioc)

    mock_message.email_id = email_obj.id
    mock_message.is_quarantined = True
    mock_message.quarantined_at = datetime.now(timezone.utc)
    mock_message.label_ids = ["Label_Q123"]
    mock_message.original_labels = ["INBOX"]
    db_session.add(mock_message)
    await db_session.commit()

    client = GmailClientService()

    async def mock_api(db, integration, method, url, **kwargs):
        if method == "POST" and "modify" in url:
            m = MagicMock()
            m.status_code = 200
            m.json.return_value = {"id": mock_message.gmail_message_id, "labelIds": ["INBOX"]}
            return m
        elif method == "GET" and "?format=minimal" in url:
            m = MagicMock()
            m.status_code = 200
            m.json.return_value = {"id": mock_message.gmail_message_id, "labelIds": ["INBOX"]}
            return m
        raise ValueError(f"Unexpected call: {method} {url}")

    with patch.object(client, "_make_api_request", side_effect=mock_api):
        res = await client.report_false_positive(
            db=db_session,
            user=mock_user,
            integration=mock_integration,
            gmail_msg=mock_message,
            feedback="Verified partner newsletter",
        )

        assert res["status"] == "false_positive_recorded"
        assert res["restored"] is True
        assert mock_message.is_quarantined is False
        assert mock_message.quarantine_action_status == "false_positive"

        # Check IOC updated
        await db_session.refresh(ioc)
        assert ioc.is_false_positive is True

        # Check AuditLog entry
        audit_res = await db_session.execute(
            select(AuditLog).where(
                AuditLog.resource_id == mock_message.id,
                AuditLog.action == "gmail.message.false_positive_reported",
            )
        )
        audit = audit_res.scalar_one_or_none()
        assert audit is not None
        assert audit.details["feedback"] == "Verified partner newsletter"
