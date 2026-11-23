"""
Integration tests for Google Authentication API endpoints.
Tests:
- GET /api/v1/auth/google/config
- GET /api/v1/auth/google/url
- POST /api/v1/auth/google/callback
- POST /api/v1/auth/google/token
- POST /api/v1/auth/google/demo
"""
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
import httpx
from httpx import AsyncClient

from app.core.config import settings
from app.services.google_auth_service import google_auth_service


@pytest.mark.asyncio
async def test_get_google_config(client: AsyncClient):
    res = await client.get("/api/v1/auth/google/config")
    assert res.status_code == 200
    data = res.json()["data"]
    assert "is_configured" in data
    assert "client_id" in data


@pytest.mark.asyncio
async def test_get_google_auth_url(client: AsyncClient):
    with patch.object(settings, "GOOGLE_CLIENT_ID", "test-client.apps.googleusercontent.com"), \
         patch.object(settings, "GOOGLE_CLIENT_SECRET", "test-secret"):
        res = await client.get("/api/v1/auth/google/url?intent=login")
        assert res.status_code == 200
        data = res.json()["data"]
        assert "authorization_url" in data
        assert "state" in data
        assert "accounts.google.com" in data["authorization_url"]


@pytest.mark.asyncio
async def test_google_auth_callback_flow(client: AsyncClient):
    with patch.object(settings, "GOOGLE_CLIENT_ID", "test-client.apps.googleusercontent.com"), \
         patch.object(settings, "GOOGLE_CLIENT_SECRET", "test-secret"):
        # 1. Generate auth url to obtain valid state
        url_res = await client.get("/api/v1/auth/google/url?intent=login")
        assert url_res.status_code == 200
        state = url_res.json()["data"]["state"]

        # 2. Mock Google token exchange and userinfo
        mock_tokens = {
            "access_token": "ya29.test_token_analyst",
            "token_type": "Bearer",
            "expires_in": 3600,
        }
        mock_profile = {
            "sub": "google-oauth-analyst-123",
            "email": "test.google.analyst@phishguard.local",
            "name": "Test Google Analyst",
            "picture": "https://lh3.googleusercontent.com/test",
            "email_verified": True,
        }

        with patch.object(google_auth_service, "exchange_code", new_callable=AsyncMock) as mock_exchange, \
             patch.object(google_auth_service, "get_user_profile", new_callable=AsyncMock) as mock_profile_fetch:
            mock_exchange.return_value = mock_tokens
            mock_profile_fetch.return_value = mock_profile

            callback_res = await client.post(
                "/api/v1/auth/google/callback",
                json={
                    "code": "test_auth_code_from_google",
                    "state": state,
                },
            )
            assert callback_res.status_code == 200
            data = callback_res.json()["data"]
            assert "access_token" in data
            assert "refresh_token" in data
            assert data["user"]["email"] == "test.google.analyst@phishguard.local"
            assert data["user"]["display_name"] == "Test Google Analyst"


@pytest.mark.asyncio
async def test_google_demo_login(client: AsyncClient):
    res = await client.post(
        "/api/v1/auth/google/demo",
        json={
            "email": "instant.analyst@phishguard.local",
            "display_name": "Instant Google Analyst",
        },
    )
    assert res.status_code == 200
    data = res.json()["data"]
    assert "access_token" in data
    assert data["user"]["email"] == "instant.analyst@phishguard.local"
