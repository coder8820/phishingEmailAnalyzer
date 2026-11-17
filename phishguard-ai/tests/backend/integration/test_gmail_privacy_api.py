"""
PhishGuard AI — Privacy & Data Management Integration Tests (G6 Requirement 4)
Validates:
- Privacy policy & retention disclosure endpoint
- Formal User Data Deletion Request (Right to Erasure)
- Reversible restore of quarantined emails prior to deletion
- Revocation of OAuth grant with Google Identity Services
- Database message purging and immutable AuditLog generation
"""

import uuid
from unittest.mock import MagicMock, patch

import pytest
from httpx import AsyncClient
from sqlalchemy import select

from app.models import AuditLog, GmailIntegration, GmailMessage, User
from app.services.gmail_client_service import gmail_client_service
from app.services.gmail_oauth_service import gmail_oauth_service


@pytest.mark.asyncio
async def test_get_privacy_policy_endpoint(authenticated_client: AsyncClient):
    """Verify privacy policy endpoint returns retention settings and Google compliance disclosures."""
    res = await authenticated_client.get("/api/v1/gmail/privacy/policy")
    assert res.status_code == 200
    data = res.json()["data"]
    assert "data_retention_days" in data
    assert data["data_retention_days"]["raw_mime_content"] >= 0
    assert "google_api_disclosure" in data
    assert "user_rights" in data
    assert len(data["user_rights"]) >= 3


@pytest.mark.asyncio
async def test_data_deletion_invalid_confirmation(authenticated_client: AsyncClient):
    """Verify that user data deletion is rejected if confirmation string does not match."""
    res = await authenticated_client.post(
        "/api/v1/gmail/data-deletion",
        json={
            "confirmation": "WRONG_TEXT",
            "restore_quarantined": True,
            "purge_synced_messages": True,
            "revoke_google_oauth": True,
        },
    )
    assert res.status_code == 400
    assert "Confirmation string must match" in res.json()["detail"]


@pytest.mark.asyncio
async def test_data_deletion_success(authenticated_client: AsyncClient, db_session):
    """
    Verify complete user data deletion flow:
    - Restores quarantined messages
    - Stops watch
    - Revokes OAuth
    - Purges synced messages
    - Creates AuditLog entry
    """
    user_id = uuid.UUID("00000000-0000-0000-0000-000000000001")
    org_id = uuid.UUID("00000000-0000-0000-0000-000000000002")

    integration = GmailIntegration(
        id=uuid.uuid4(),
        organization_id=org_id,
        user_id=user_id,
        email_address="gdpr_test@securecorp.com",
        is_connected=True,
        watch_status="active",
        refresh_token_encrypted=b"dummy_token",
        granted_scopes=["https://www.googleapis.com/auth/gmail.modify"],
        quarantine_label_id="Label_Q123",
        quarantine_label_name="PhishGuard-Quarantine",
    )
    db_session.add(integration)

    msg_quarantined = GmailMessage(
        id=uuid.uuid4(),
        organization_id=org_id,
        user_id=user_id,
        integration_id=integration.id,
        gmail_message_id="msg_quarantine_del_1",
        subject="Threat to Restore on Deletion",
        sender="threat@evil.com",
        is_analyzed=True,
        is_quarantined=True,
        quarantine_action_status="quarantined",
        label_ids=["Label_Q123"],
        original_labels=["INBOX"],
    )
    msg_normal = GmailMessage(
        id=uuid.uuid4(),
        organization_id=org_id,
        user_id=user_id,
        integration_id=integration.id,
        gmail_message_id="msg_normal_del_2",
        subject="Normal Message",
        sender="friend@good.com",
        is_analyzed=True,
        is_quarantined=False,
        label_ids=["INBOX"],
    )
    db_session.add(msg_quarantined)
    db_session.add(msg_normal)
    await db_session.commit()

    async def mock_api(db, integration, method, url, **kwargs):
        m = MagicMock()
        m.status_code = 200
        if "labels" in url:
            m.json.return_value = {"id": "Label_Q123", "name": "PhishGuard-Quarantine"}
        else:
            m.json.return_value = {"id": msg_quarantined.gmail_message_id, "labelIds": ["INBOX"]}
        return m

    with patch.object(gmail_client_service, "_make_api_request", side_effect=mock_api):
        with patch.object(gmail_oauth_service, "disconnect_and_revoke", return_value=True):
            res = await authenticated_client.post(
                "/api/v1/gmail/data-deletion",
                json={
                    "confirmation": "CONFIRM_DELETE",
                    "restore_quarantined": True,
                    "purge_synced_messages": True,
                    "revoke_google_oauth": True,
                },
            )

            assert res.status_code == 200
            data = res.json()["data"]
            assert data["restored_count"] == 1
            assert data["purged_messages"] == 2
            assert data["oauth_revoked"] is True

            # Verify messages are purged from database
            msg_check = await db_session.execute(
                select(GmailMessage).where(GmailMessage.integration_id == integration.id)
            )
            assert len(msg_check.scalars().all()) == 0

            # Verify audit log entry
            audit_res = await db_session.execute(
                select(AuditLog).where(AuditLog.action == "gmail.data.deletion_completed")
            )
            audit = audit_res.scalar_one_or_none()
            assert audit is not None
            assert audit.details["purged_message_count"] == 2
