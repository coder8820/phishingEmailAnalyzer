"""
Integration tests for Enterprise Mail-Flow Webhook Ingestion & Automated Quarantine.
"""

import uuid
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_m365_handshake_validation(client: AsyncClient):
    """Verify Microsoft Graph webhook subscription validation handshake."""
    response = await client.get("/api/v1/webhooks/m365?validationToken=SecretTokenXYZ123")
    assert response.status_code == 200
    assert response.text == "SecretTokenXYZ123"


@pytest.mark.asyncio
async def test_mta_webhook_ingestion(client: AsyncClient):
    """Verify inbound MTA webhook receives raw email, parses and queues it."""
    raw_email = """From: security@external-partner.com
To: user@phishguard.local
Subject: Partner Security Advisory
Date: Tue, 08 Nov 2026 12:00:00 +0000

Please review the attached advisory.
"""
    response = await client.post(
        "/api/v1/webhooks/mta",
        json={"raw_content": raw_email},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert "email_id" in data["data"]
    assert data["data"]["status"] == "queued"
    assert data["data"]["subject"] == "Partner Security Advisory"


@pytest.mark.asyncio
async def test_analyst_can_quarantine_email(
    authenticated_client: AsyncClient,
):
    """Verify analyst can execute quarantine remediation on an email."""
    # 1. Ingest an email
    raw_email = """From: phisher@bad-site.com
To: victim@phishguard.local
Subject: Urgent Account Warning

Click here to verify.
"""
    ingest_res = await authenticated_client.post(
        "/api/v1/emails/raw",
        json={"content": raw_email},
    )
    assert ingest_res.status_code in (200, 202)
    email_id = ingest_res.json()["data"]["email_id"]

    # 2. Execute quarantine
    remediate_res = await authenticated_client.post(
        f"/api/v1/webhooks/remediate/{email_id}",
        json={"action": "quarantine"},
    )
    assert remediate_res.status_code == 200
    rem_data = remediate_res.json()["data"]
    assert rem_data["status"] == "success"
    assert rem_data["resulting_status"] == "quarantined"

    # 3. Verify email record has updated status
    email_res = await authenticated_client.get(f"/api/v1/emails/{email_id}")
    assert email_res.status_code == 200
    assert email_res.json()["data"]["analysis_status"] == "quarantined"


@pytest.mark.asyncio
async def test_remediation_tenant_isolation(
    org_a_client: AsyncClient,
    org_b_client: AsyncClient,
):
    """Verify Org B analyst cannot quarantine or mutate an email owned by Org A."""
    # Org A submits email
    raw_email = """From: admin@org-a.com
To: staff@org-a.com
Subject: Org A Confidential Briefing

Confidential.
"""
    res_a = await org_a_client.post(
        "/api/v1/emails/raw",
        json={"content": raw_email},
    )
    assert res_a.status_code in (200, 202)
    email_id = res_a.json()["data"]["email_id"]

    # Org B attempts to quarantine Org A's email
    res_b = await org_b_client.post(
        f"/api/v1/webhooks/remediate/{email_id}",
        json={"action": "quarantine"},
    )
    assert res_b.status_code == 404
