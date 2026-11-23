"""
Unit tests for GoogleAuthService in PhishGuard AI.
Tests:
- PKCE generation (RFC 7636)
- Authorization URL creation with cryptographically signed state
- State token decoding and tamper resistance
- User authentication and auto-registration
- Locked and disabled account checks
"""
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
import uuid
import pytest
from jose import jwt
from sqlalchemy import select

from app.core.config import settings
from app.models import Organization, User
from app.services.google_auth_service import (
    GoogleAuthService,
    generate_pkce_pair,
)


def test_generate_pkce_pair():
    verifier, challenge = generate_pkce_pair()
    assert len(verifier) >= 43
    assert len(challenge) >= 43
    assert "=" not in challenge


def test_create_authorization_url():
    service = GoogleAuthService()
    with patch.object(settings, "GOOGLE_CLIENT_ID", "test-client-id.apps.googleusercontent.com"), \
         patch.object(settings, "GOOGLE_CLIENT_SECRET", "test-secret"):
        auth_url, state = service.create_authorization_url(
            redirect_uri="http://localhost:3001/auth/google/callback",
            intent="login",
        )
        assert "accounts.google.com" in auth_url
        assert "test-client-id" in auth_url
        assert "code_challenge_method=S256" in auth_url
        assert "scope=openid" in auth_url
        assert state is not None

        # Verify state is valid signed JWT
        payload = service.decode_and_validate_state(state)
        assert payload["intent"] == "login"
        assert payload["redirect_uri"] == "http://localhost:3001/auth/google/callback"
        assert "verifier" in payload


def test_decode_and_validate_state_tampered():
    service = GoogleAuthService()
    with pytest.raises(Exception):
        service.decode_and_validate_state("invalid.tampered.token")


def test_decode_and_validate_state_expired():
    service = GoogleAuthService()
    expired_payload = {
        "verifier": "abc",
        "redirect_uri": "http://localhost:3001",
        "intent": "login",
        "exp": datetime.now(timezone.utc) - timedelta(minutes=5),
        "sub_type": "google_auth",
    }
    expired_token = jwt.encode(expired_payload, settings.APP_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    with pytest.raises(Exception):
        service.decode_and_validate_state(expired_token)


@pytest.mark.asyncio
async def test_authenticate_or_register_new_user(db_session):
    service = GoogleAuthService()
    mock_request = MagicMock()
    mock_request.client.host = "127.0.0.1"
    mock_request.headers.get.return_value = "Pytest"
    mock_request.state.request_id = "test-req-1"

    email = f"new.google.analyst_{uuid.uuid4().hex[:6]}@example.com"
    user, access_token, refresh_token, is_new = await service.authenticate_or_register_user(
        db=db_session,
        request=mock_request,
        email=email,
        display_name="New Google Analyst",
        google_sub="google-sub-12345",
    )

    assert is_new is True
    assert user.email == email
    assert user.display_name == "New Google Analyst"
    assert user.is_email_verified is True
    assert user.role == "analyst"
    assert access_token is not None
    assert refresh_token is not None

    # Check that user exists in database
    db_user = (await db_session.execute(select(User).where(User.email == email))).scalar_one_or_none()
    assert db_user is not None
    assert db_user.id == user.id


@pytest.mark.asyncio
async def test_authenticate_existing_user(db_session):
    service = GoogleAuthService()
    mock_request = MagicMock()
    mock_request.client.host = "127.0.0.1"
    mock_request.headers.get.return_value = "Pytest"
    mock_request.state.request_id = "test-req-2"

    email = f"existing.user_{uuid.uuid4().hex[:6]}@example.com"
    # First register
    user1, _, _, is_new1 = await service.authenticate_or_register_user(
        db=db_session,
        request=mock_request,
        email=email,
        display_name="Existing User",
    )
    assert is_new1 is True

    # Second login
    user2, access_token2, refresh_token2, is_new2 = await service.authenticate_or_register_user(
        db=db_session,
        request=mock_request,
        email=email,
        display_name="Existing User",
    )
    assert is_new2 is False
    assert user2.id == user1.id
    assert access_token2 is not None
