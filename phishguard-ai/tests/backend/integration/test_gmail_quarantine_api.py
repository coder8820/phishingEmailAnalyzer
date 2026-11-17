"""
PhishGuard AI — Integration Tests for Gmail Quarantine & Remediation Endpoints
Tests:
- GET /api/v1/gmail/quarantine/settings
- POST /api/v1/gmail/quarantine/consent (explicit consent validation, gmail.modify permission enforcement)
- POST /api/v1/gmail/quarantine/disable (disabling auto-quarantine)
- POST /api/v1/gmail/messages/{message_id}/quarantine (manual quarantine)
- POST /api/v1/gmail/messages/{message_id}/restore (manual restore)
- GET /api/v1/gmail/quarantine/records (quarantine records history)
- Multi-tenant security & tenant isolation checks
"""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import httpx
from httpx import AsyncClient
from sqlalchemy import select

from app.models import AuditLog, GmailIntegration, GmailMessage, User
from app.services.gmail_client_service import gmail_client_service


@pytest.mark.asyncio
async def test_quarantine_settings_endpoint(authenticated_client: AsyncClient, db_session):
    """Verify GET /api/v1/gmail/quarantine/settings returns permission explanation and consent state."""
    user_id = uuid.UUID("00000000-0000-0000-0000-000000000001")
    org_id = uuid.UUID("00000000-0000-0000-0000-000000000002")

    integration = GmailIntegration(
        id=uuid.uuid4(),
        organization_id=org_id,
        user_id=user_id,
        email_address="quarantine_user@company.com",
        is_connected=True,
        connection_status="connected",
        token_status="valid",
        refresh_token_encrypted=b"dummy_token",
        granted_scopes=["https://www.googleapis.com/auth/gmail.modify"],
        auto_quarantine_enabled=False,
        quarantine_threshold_score=70,
        quarantine_label_name="PhishGuard-Quarantine",
    )
    db_session.add(integration)
    await db_session.commit()

    res = await authenticated_client.get("/api/v1/gmail/quarantine/settings")
    assert res.status_code == 200
    data = res.json()["data"]
    assert data["is_connected"] is True
    assert data["auto_quarantine_enabled"] is False
    assert data["has_modify_permission"] is True
    assert data["quarantine_threshold_score"] == 70
    assert "gmail.modify" in data["permission_explanation"]


@pytest.mark.asyncio
async def test_quarantine_consent_missing_acknowledgment(authenticated_client: AsyncClient, db_session):
    """Verify POST /api/v1/gmail/quarantine/consent rejects request if explicit consent is False."""
    res = await authenticated_client.post(
        "/api/v1/gmail/quarantine/consent",
        json={"consent_acknowledged": False, "threshold_score": 75},
    )
    assert res.status_code == 400
    assert "explicit user consent acknowledgment is required" in res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_quarantine_consent_missing_modify_scope(authenticated_client: AsyncClient, db_session):
    """Verify POST /api/v1/gmail/quarantine/consent rejects if account lacks gmail.modify scope."""
    user_id = uuid.UUID("00000000-0000-0000-0000-000000000001")
    org_id = uuid.UUID("00000000-0000-0000-0000-000000000002")

    integration = GmailIntegration(
        id=uuid.uuid4(),
        organization_id=org_id,
        user_id=user_id,
        email_address="readonly_user@company.com",
        is_connected=True,
        refresh_token_encrypted=b"dummy_token",
        granted_scopes=["https://www.googleapis.com/auth/gmail.readonly"],  # Missing gmail.modify
    )
    db_session.add(integration)
    await db_session.commit()

    res = await authenticated_client.post(
        "/api/v1/gmail/quarantine/consent",
        json={"consent_acknowledged": True, "threshold_score": 70},
    )
    assert res.status_code == 400
    assert "does not have the 'https://www.googleapis.com/auth/gmail.modify' scope" in res.json()["detail"]


@pytest.mark.asyncio
async def test_quarantine_consent_success_and_disable(authenticated_client: AsyncClient, db_session):
    """Verify enabling quarantine with consent updates integration and disable turns it off."""
    user_id = uuid.UUID("00000000-0000-0000-0000-000000000001")
    org_id = uuid.UUID("00000000-0000-0000-0000-000000000002")

    integration = GmailIntegration(
        id=uuid.uuid4(),
        organization_id=org_id,
        user_id=user_id,
        email_address="consent_user@company.com",
        is_connected=True,
        refresh_token_encrypted=b"dummy_token",
        granted_scopes=["https://www.googleapis.com/auth/gmail.modify"],
        auto_quarantine_enabled=False,
    )
    db_session.add(integration)
    await db_session.commit()

    # Enable
    res = await authenticated_client.post(
        "/api/v1/gmail/quarantine/consent",
        json={"consent_acknowledged": True, "threshold_score": 75, "quarantine_label_name": "PhishGuard-Quarantine"},
    )
    assert res.status_code == 200
    assert res.json()["data"]["auto_quarantine_enabled"] is True
    assert res.json()["data"]["quarantine_threshold_score"] == 75

    # Check AuditLog for enable action
    audit_enable = await db_session.execute(
        select(AuditLog).where(AuditLog.action == "gmail.quarantine.consent_enabled")
    )
    assert audit_enable.scalar_one_or_none() is not None

    # Disable
    dis_res = await authenticated_client.post("/api/v1/gmail/quarantine/disable")
    assert dis_res.status_code == 200
    assert dis_res.json()["data"]["auto_quarantine_enabled"] is False

    # Check AuditLog for disable action
    audit_disable = await db_session.execute(
        select(AuditLog).where(AuditLog.action == "gmail.quarantine.disabled")
    )
    assert audit_disable.scalar_one_or_none() is not None


@pytest.mark.asyncio
async def test_manual_quarantine_and_restore_endpoints(authenticated_client: AsyncClient, db_session):
    """Verify manual quarantine and restore endpoints modify message and record audit logs."""
    user_id = uuid.UUID("00000000-0000-0000-0000-000000000001")
    org_id = uuid.UUID("00000000-0000-0000-0000-000000000002")

    integration = GmailIntegration(
        id=uuid.uuid4(),
        organization_id=org_id,
        user_id=user_id,
        email_address="manual_user@company.com",
        is_connected=True,
        refresh_token_encrypted=b"dummy_token",
        granted_scopes=["https://www.googleapis.com/auth/gmail.modify"],
        quarantine_label_id="Label_TestQuarantine",
    )
    db_session.add(integration)

    msg = GmailMessage(
        id=uuid.uuid4(),
        organization_id=org_id,
        user_id=user_id,
        integration_id=integration.id,
        gmail_message_id="msg_manual_999",
        subject="Malicious Invoice Link",
        sender="attacker@fake-billing.com",
        snippet="Please pay the invoice immediately.",
        is_analyzed=True,
        analysis_status="analyzed",
        risk_score=92.0,
        risk_classification="Critical",
        label_ids=["INBOX"],
        is_quarantined=False,
    )
    db_session.add(msg)
    await db_session.commit()

    # Mock modify API responses
    last_modify_labels = []

    async def mock_api(*args, **kwargs):
        nonlocal last_modify_labels
        url = kwargs.get("url")
        if "labels" in url:
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = 200
            resp.json.return_value = {"id": "Label_TestQuarantine", "name": "PhishGuard-Quarantine"}
            return resp
        if "modify" in url:
            last_modify_labels = kwargs.get("json_data", {}).get("addLabelIds", [])
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = 200
            resp.json.return_value = {
                "id": "msg_manual_999",
                "labelIds": last_modify_labels,
            }
            return resp
        if "?format=minimal" in url:
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = 200
            resp.json.return_value = {
                "id": "msg_manual_999",
                "labelIds": last_modify_labels,
            }
            return resp
        raise ValueError(f"Unexpected url {url}")

    with patch.object(gmail_client_service, "_make_api_request", side_effect=mock_api):
        # 1. Manual Quarantine
        q_res = await authenticated_client.post(
            f"/api/v1/gmail/messages/{msg.id}/quarantine",
            json={"reason": "Analyst manual quarantine of critical invoice lure"},
        )
        assert q_res.status_code == 200
        assert q_res.json()["data"]["status"] == "quarantined"

        # Verify DB state
        await db_session.refresh(msg)
        assert msg.is_quarantined is True
        assert msg.quarantine_action_status == "quarantined"

        # 2. Check /quarantine/records
        rec_res = await authenticated_client.get("/api/v1/gmail/quarantine/records")
        assert rec_res.status_code == 200
        records = rec_res.json()["data"]["records"]
        assert len(records) >= 1
        assert any(r["gmail_message_id"] == "msg_manual_999" and r["is_quarantined"] is True for r in records)

        # 3. Manual Restore
        r_res = await authenticated_client.post(f"/api/v1/gmail/messages/{msg.id}/restore")
        assert r_res.status_code == 200
        assert r_res.json()["data"]["status"] == "restored"

        await db_session.refresh(msg)
        assert msg.is_quarantined is False
        assert msg.quarantine_action_status == "restored"


@pytest.mark.asyncio
async def test_quarantine_tenant_isolation_api(authenticated_client: AsyncClient, db_session):
    """Verify that a user from Org A cannot quarantine a message belonging to Org B."""
    other_org_id = uuid.UUID("00000000-0000-0000-0000-00000000000a")
    other_user_id = uuid.UUID("00000000-0000-0000-0000-00000000000b")

    other_integration = GmailIntegration(
        id=uuid.uuid4(),
        organization_id=other_org_id,
        user_id=other_user_id,
        email_address="other_org@victim.com",
        is_connected=True,
        refresh_token_encrypted=b"dummy_token",
        granted_scopes=["https://www.googleapis.com/auth/gmail.modify"],
    )
    db_session.add(other_integration)

    other_msg = GmailMessage(
        id=uuid.uuid4(),
        organization_id=other_org_id,
        user_id=other_user_id,
        integration_id=other_integration.id,
        gmail_message_id="msg_other_org_123",
        subject="Confidential Org B Email",
        sender="attacker@domain.com",
        is_analyzed=True,
        label_ids=["INBOX"],
    )
    db_session.add(other_msg)
    await db_session.commit()

    # Attempt quarantine by authenticated_client (Org Main) -> 404 (isolated)
    res = await authenticated_client.post(
        f"/api/v1/gmail/messages/{other_msg.id}/quarantine",
        json={"reason": "Unauthorized access test"},
    )
    assert res.status_code == 404


@pytest.mark.asyncio
async def test_report_false_positive_api(authenticated_client: AsyncClient, db_session):
    """
    Verify G5 Requirement 6.6 & Endpoint integration:
    Reporting a false positive restores the message to INBOX, updates status to false_positive,
    and reflects in both /quarantine/records and /messages?quarantine_status=false_positive.
    """
    user_id = uuid.UUID("00000000-0000-0000-0000-000000000001")
    org_id = uuid.UUID("00000000-0000-0000-0000-000000000002")

    integration = GmailIntegration(
        id=uuid.uuid4(),
        organization_id=org_id,
        user_id=user_id,
        email_address="analyst@securecorp.com",
        is_connected=True,
        refresh_token_encrypted=b"dummy_token",
        granted_scopes=["https://www.googleapis.com/auth/gmail.modify"],
        quarantine_label_id="Label_Q123",
        quarantine_label_name="PhishGuard-Quarantine",
    )
    db_session.add(integration)

    msg = GmailMessage(
        id=uuid.uuid4(),
        organization_id=org_id,
        user_id=user_id,
        integration_id=integration.id,
        gmail_message_id="msg_fp_test_123",
        subject="Important Quarterly Update",
        sender="updates@trustedcorp.com",
        is_analyzed=True,
        analysis_status="analyzed",
        risk_score=75,
        risk_classification="High",
        is_quarantined=True,
        quarantine_action_status="quarantined",
        label_ids=["Label_Q123"],
        original_labels=["INBOX", "UNREAD"],
    )
    db_session.add(msg)
    await db_session.commit()

    async def mock_api(db, integration, method, url, **kwargs):
        m = MagicMock()
        m.status_code = 200
        if "labels" in url:
            m.json.return_value = {"id": "Label_Q123", "name": "PhishGuard-Quarantine"}
        else:
            m.json.return_value = {"id": msg.gmail_message_id, "labelIds": ["INBOX", "UNREAD"]}
        return m

    with patch.object(gmail_client_service, "_make_api_request", side_effect=mock_api):
        res = await authenticated_client.post(
            f"/api/v1/gmail/messages/{msg.id}/report-false-positive",
            json={"feedback": "Legitimate quarterly briefing"},
        )
        assert res.status_code == 200
        body = res.json()
        assert body["data"]["status"] == "false_positive_recorded"
        assert body["data"]["restored"] is True

        # Verify in /quarantine/records
        rec_res = await authenticated_client.get("/api/v1/gmail/quarantine/records")
        assert rec_res.status_code == 200
        records = rec_res.json()["data"]["records"]
        assert any(r["id"] == str(msg.id) and r["quarantine_action_status"] == "false_positive" for r in records)

        # Verify in /messages?quarantine_status=false_positive
        filter_res = await authenticated_client.get("/api/v1/gmail/messages?quarantine_status=false_positive")
        assert filter_res.status_code == 200
        msgs = filter_res.json()["data"]["messages"]
        assert any(m["id"] == str(msg.id) for m in msgs)
