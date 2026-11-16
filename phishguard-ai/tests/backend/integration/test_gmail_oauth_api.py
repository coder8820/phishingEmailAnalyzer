"""
PhishGuard AI — Integration Tests for Gmail OAuth 2.0 API Endpoints
Tests:
- GET /api/v1/gmail/oauth/authorize
- POST /api/v1/gmail/oauth/callback
- GET /api/v1/gmail/accounts
- GET /api/v1/gmail/status
- POST /api/v1/gmail/disconnect
"""

import uuid
from unittest.mock import MagicMock, patch
import pytest
import httpx
from httpx import AsyncClient

from app.models import GmailIntegration


@pytest.mark.asyncio
async def test_start_google_oauth_endpoint(authenticated_client: AsyncClient):
    """Verify authenticated user can initiate Google OAuth flow and receive valid auth URL."""
    res = await authenticated_client.get("/api/v1/gmail/oauth/authorize")
    assert res.status_code == 200
    data = res.json()["data"]
    assert "authorization_url" in data
    assert "state" in data
    assert "accounts.google.com" in data["authorization_url"]
    assert "gmail.modify" in data["authorization_url"]


@pytest.mark.asyncio
async def test_start_google_oauth_unauthenticated(client: AsyncClient):
    """Verify unauthenticated requests cannot initiate OAuth."""
    res = await client.get("/api/v1/gmail/oauth/authorize")
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_oauth_callback_endpoint_success(authenticated_client: AsyncClient):
    """Verify OAuth callback exchange returns verified account info without exposing tokens."""
    # 1. Initiate OAuth to generate valid state in DB
    init_res = await authenticated_client.get("/api/v1/gmail/oauth/authorize")
    assert init_res.status_code == 200
    state = init_res.json()["data"]["state"]

    # 2. Mock Google responses for exchange and profile check
    google_tokens = {
        "access_token": "ya29.test_access_token",
        "refresh_token": "1//04_test_refresh_token",
        "expires_in": 3600,
        "scope": "openid email https://www.googleapis.com/auth/gmail.modify",
    }
    google_profile = {
        "emailAddress": "soc.analyst@gmail.com",
        "messagesTotal": 50,
        "historyId": "12345",
    }

    orig_post = httpx.AsyncClient.post
    orig_get = httpx.AsyncClient.get

    async def selective_post(self, *args, **kwargs):
        url = args[0] if args else kwargs.get("url", "")
        if "googleapis.com" in str(url):
            r = MagicMock(spec=httpx.Response)
            r.status_code = 200
            r.json.return_value = google_tokens
            return r
        return await orig_post(self, *args, **kwargs)

    async def selective_get(self, *args, **kwargs):
        url = args[0] if args else kwargs.get("url", "")
        if "googleapis.com" in str(url):
            r = MagicMock(spec=httpx.Response)
            r.status_code = 200
            r.json.return_value = google_profile
            return r
        return await orig_get(self, *args, **kwargs)

    with patch("httpx.AsyncClient.post", new=selective_post), patch("httpx.AsyncClient.get", new=selective_get):
        callback_res = await authenticated_client.post(
            "/api/v1/gmail/oauth/callback",
            json={"code": "sample_authorization_code", "state": state},
        )

    assert callback_res.status_code == 200
    cb_data = callback_res.json()["data"]
    assert cb_data["email_address"] == "soc.analyst@gmail.com"
    assert cb_data["is_connected"] is True
    assert cb_data["token_status"] == "valid"
    # STRICT SECURITY: Tokens must NEVER appear in API responses!
    assert "access_token" not in cb_data
    assert "refresh_token" not in cb_data


@pytest.mark.asyncio
async def test_oauth_callback_invalid_state(authenticated_client: AsyncClient):
    """Verify callback with fake or replayed state is rejected."""
    res = await authenticated_client.post(
        "/api/v1/gmail/oauth/callback",
        json={"code": "some_code", "state": "tampered_fake_state"},
    )
    assert res.status_code == 400
    assert "state" in res.json()["detail"].lower()


@pytest.mark.asyncio
async def test_list_connected_accounts_endpoint(authenticated_client: AsyncClient):
    """Verify accounts endpoint lists connections for authenticated user."""
    res = await authenticated_client.get("/api/v1/gmail/accounts")
    assert res.status_code == 200
    data = res.json()["data"]
    assert "accounts" in data
    assert "total" in data


@pytest.mark.asyncio
async def test_disconnect_endpoint(authenticated_client: AsyncClient):
    """Verify disconnect endpoint revokes and clears connection."""
    res = await authenticated_client.post("/api/v1/gmail/disconnect")
    assert res.status_code == 200
    assert res.json()["success"] is True
