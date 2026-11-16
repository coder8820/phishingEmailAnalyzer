"""
PhishGuard AI — Unit Tests for Genuine Google OAuth 2.0 & Token Security
Validates:
- Cryptographic token encryption at rest (MultiFernet key rotation)
- PKCE code verifier and challenge generation (RFC 7636)
- One-time CSRF OAuth state generation, expiry, and single-use validation
- Google token exchange and real users.getProfile email extraction
- Multi-user account collision / tenant isolation policy
- Token refresh, rotation, and revocation handling
"""

import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import httpx
from cryptography.fernet import Fernet
from sqlalchemy import select

from app.core.config import settings
from app.models import GmailIntegration, OAuthState, Organization, User
from app.security.encryption import TokenEncryptionService, TokenEncryptionError
from app.services.gmail_oauth_service import (
    GmailOAuthService,
    GoogleOAuthConfigurationError,
    GoogleOAuthCSRFError,
    GoogleOAuthError,
    GmailAccountConflictError,
    GoogleTokenRevokedError,
    generate_pkce_pair,
)


# ===========================================================================
# 1. TOKEN ENCRYPTION & KEY ROTATION TESTS
# ===========================================================================

def test_token_encryption_at_rest():
    """Verify that tokens are encrypted into ciphertext and decrypted accurately."""
    key = Fernet.generate_key().decode()
    service = TokenEncryptionService(key_source=key)

    plain_token = "1//04fake_google_refresh_token_xyz_123456789"
    encrypted = service.encrypt(plain_token)

    assert isinstance(encrypted, bytes)
    assert plain_token.encode() not in encrypted  # Plaintext never present in ciphertext

    decrypted = service.decrypt(encrypted)
    assert decrypted == plain_token


def test_token_encryption_randomized_nonces():
    """Verify two encryptions of the same token yield different ciphertexts (nonce protection)."""
    key = Fernet.generate_key().decode()
    service = TokenEncryptionService(key_source=key)

    token = "secret_refresh_token"
    enc1 = service.encrypt(token)
    enc2 = service.encrypt(token)

    assert enc1 != enc2
    assert service.decrypt(enc1) == token
    assert service.decrypt(enc2) == token


def test_token_key_rotation_support():
    """
    Verify MultiFernet key rotation: tokens encrypted under older keys can still be
    decrypted and seamlessly re-encrypted under the new primary key.
    """
    old_key = Fernet.generate_key().decode()
    new_primary_key = Fernet.generate_key().decode()

    # Step 1: Token was previously encrypted using old_key
    legacy_service = TokenEncryptionService(key_source=old_key)
    ciphertext_old = legacy_service.encrypt("sensitive_token_data")

    # Step 2: Service initialized with new primary key + old key in rotation list
    rotating_service = TokenEncryptionService(key_source=f"{new_primary_key},{old_key}")

    # Can decrypt ciphertext created with old key
    decrypted = rotating_service.decrypt(ciphertext_old)
    assert decrypted == "sensitive_token_data"

    # Rotate ciphertext to new primary key
    rotated_ciphertext = rotating_service.rotate(ciphertext_old)
    assert rotated_ciphertext != ciphertext_old

    # New primary service alone can decrypt the rotated ciphertext
    new_service_only = TokenEncryptionService(key_source=new_primary_key)
    assert new_service_only.decrypt(rotated_ciphertext) == "sensitive_token_data"


def test_token_decryption_invalid_ciphertext():
    """Ensure invalid or tampered ciphertexts raise TokenEncryptionError without leaking keys."""
    key = Fernet.generate_key().decode()
    service = TokenEncryptionService(key_source=key)

    with pytest.raises(TokenEncryptionError):
        service.decrypt(b"corrupted_invalid_ciphertext_12345")


# ===========================================================================
# 2. PKCE & OAUTH AUTHORIZATION URL TESTS
# ===========================================================================

def test_pkce_generation():
    """Verify RFC 7636 PKCE pair structure and S256 challenge length."""
    verifier, challenge = generate_pkce_pair()
    assert len(verifier) >= 43
    assert len(challenge) == 43  # SHA256 base64url unpadded is 43 chars
    assert "=" not in challenge


@pytest.mark.asyncio
async def test_authorization_url_generation(db_session):
    """
    Verify Google OAuth URL contains required parameters:
    - client_id
    - redirect_uri
    - code challenge & method (PKCE)
    - one-time CSRF state
    - least privilege gmail.modify scope
    - offline access and consent prompt
    """
    user_id = uuid.uuid4()
    org_id = uuid.uuid4()
    user = User(
        id=user_id,
        organization_id=org_id,
        email="test_user@phishguard.local",
        username="test_user",
        hashed_password="hash",
    )
    db_session.add(user)
    await db_session.commit()

    service = GmailOAuthService()
    auth_url, state = await service.create_authorization_url(
        db=db_session,
        user=user,
        custom_redirect_uri="http://localhost:3001/integrations/gmail/callback",
    )

    assert "https://accounts.google.com/o/oauth2/v2/auth" in auth_url
    assert f"client_id={settings.GOOGLE_CLIENT_ID}" in auth_url
    assert "response_type=code" in auth_url
    assert "access_type=offline" in auth_url
    assert "prompt=consent" in auth_url
    assert "code_challenge_method=S256" in auth_url
    assert "code_challenge=" in auth_url
    assert "gmail.modify" in auth_url
    assert "mail.google.com" not in auth_url  # Strictly prohibited broad scope
    assert f"state={state}" in auth_url

    # Verify state record saved to database
    stmt = select(OAuthState).where(OAuthState.state == state)
    res = await db_session.execute(stmt)
    state_record = res.scalar_one_or_none()
    assert state_record is not None
    assert state_record.user_id == user.id
    assert state_record.organization_id == user.organization_id
    assert state_record.code_verifier is not None


@pytest.mark.asyncio
async def test_authorization_url_missing_credentials(monkeypatch):
    """Verify that attempting OAuth without client credentials raises descriptive error."""
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_ID", "")
    service = GmailOAuthService()
    dummy_user = User(id=uuid.uuid4(), organization_id=uuid.uuid4())

    with pytest.raises(GoogleOAuthConfigurationError) as exc_info:
        await service.create_authorization_url(db=MagicMock(), user=dummy_user)
    assert "GOOGLE_CLIENT_ID is not configured" in str(exc_info.value)


# ===========================================================================
# 3. OAUTH CALLBACK & ACCOUNT VERIFICATION TESTS
# ===========================================================================

@pytest.mark.asyncio
async def test_callback_state_csrf_validation(db_session):
    """Verify that invalid or expired OAuth state parameters are rejected immediately."""
    user = User(
        id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        email="csrf_victim@phishguard.local",
        username="csrf_victim",
        hashed_password="hash",
    )
    db_session.add(user)
    await db_session.commit()

    service = GmailOAuthService()

    # Case 1: Non-existent state
    with pytest.raises(GoogleOAuthCSRFError):
        await service.exchange_code_and_verify_account(
            db=db_session,
            user=user,
            code="fake_code",
            state="completely_fabricated_state",
        )

    # Case 2: State created for different user
    attacker_user = User(
        id=uuid.uuid4(),
        organization_id=user.organization_id,
        email="attacker@phishguard.local",
        username="attacker",
        hashed_password="hash",
    )
    db_session.add(attacker_user)
    await db_session.commit()

    _, attacker_state = await service.create_authorization_url(db=db_session, user=attacker_user)

    with pytest.raises(GoogleOAuthCSRFError):
        await service.exchange_code_and_verify_account(
            db=db_session,
            user=user,  # Victim attempts to use attacker's state
            code="fake_code",
            state=attacker_state,
        )


@pytest.mark.asyncio
async def test_successful_oauth_exchange_and_profile_verification(db_session, monkeypatch):
    """
    Verify complete OAuth code exchange:
    - Code is exchanged with Google token endpoint
    - users.getProfile is called and real email extracted
    - Refresh token is stored encrypted at rest
    - Integration record is created with active status
    - State is consumed (one-time protection)
    """
    user = User(
        id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        email="analyst@phishguard.local",
        username="analyst_1",
        hashed_password="hash",
    )
    db_session.add(user)
    await db_session.commit()

    service = GmailOAuthService()
    _, valid_state = await service.create_authorization_url(db=db_session, user=user)

    # Mock Google token and users.getProfile endpoints
    google_tokens = {
        "access_token": "ya29.google_access_token_mock_12345",
        "refresh_token": "1//04_google_refresh_token_mock_67890",
        "expires_in": 3600,
        "token_type": "Bearer",
        "scope": "openid https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/gmail.modify",
    }
    google_profile = {
        "emailAddress": "security.ops@gmail.com",
        "messagesTotal": 142,
        "threadsTotal": 89,
        "historyId": "987654",
    }

    orig_post = httpx.AsyncClient.post
    orig_get = httpx.AsyncClient.get

    async def mock_post(self, *args, **kwargs):
        url = args[0] if args else kwargs.get("url", "")
        if "googleapis.com" in str(url):
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = 200
            resp.json.return_value = google_tokens
            return resp
        return await orig_post(self, *args, **kwargs)

    async def mock_get(self, *args, **kwargs):
        url = args[0] if args else kwargs.get("url", "")
        if "googleapis.com" in str(url):
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = 200
            resp.json.return_value = google_profile
            return resp
        return await orig_get(self, *args, **kwargs)

    with patch("httpx.AsyncClient.post", new=mock_post), patch("httpx.AsyncClient.get", new=mock_get):
        integration = await service.exchange_code_and_verify_account(
            db=db_session,
            user=user,
            code="valid_google_auth_code_xyz",
            state=valid_state,
        )

    assert integration is not None
    assert integration.email_address == "security.ops@gmail.com"
    assert integration.is_connected is True
    assert integration.connection_status == "connected"
    assert integration.token_status == "valid"
    assert integration.last_verified_at is not None

    # Verify encrypted tokens at rest
    assert integration.refresh_token_encrypted is not None
    assert b"1//04_google_refresh_token_mock_67890" not in integration.refresh_token_encrypted
    decrypted_refresh = service.encryptor.decrypt(integration.refresh_token_encrypted)
    assert decrypted_refresh == "1//04_google_refresh_token_mock_67890"

    # Verify state was consumed (one-time protection)
    state_check = await db_session.execute(select(OAuthState).where(OAuthState.state == valid_state))
    assert state_check.scalar_one_or_none() is None


@pytest.mark.asyncio
async def test_account_conflict_prevention(db_session, monkeypatch):
    """
    Verify security rule: One Gmail account cannot be linked to multiple unrelated users.
    """
    org_id = uuid.uuid4()
    user1 = User(id=uuid.uuid4(), organization_id=org_id, email="u1@org.local", username="u1", hashed_password="h")
    user2 = User(id=uuid.uuid4(), organization_id=org_id, email="u2@org.local", username="u2", hashed_password="h")
    db_session.add_all([user1, user2])
    await db_session.commit()

    service = GmailOAuthService()

    # Pre-existing active connection on user1
    existing_conn = GmailIntegration(
        id=uuid.uuid4(),
        organization_id=org_id,
        user_id=user1.id,
        email_address="corporate.admin@gmail.com",
        is_connected=True,
        connection_status="connected",
        refresh_token_encrypted=service.encryptor.encrypt("existing_token"),
    )
    db_session.add(existing_conn)
    await db_session.commit()

    # User2 attempts to connect the same Gmail address
    _, state_user2 = await service.create_authorization_url(db=db_session, user=user2)

    async def mock_post(self, *args, **kwargs):
        r = MagicMock(spec=httpx.Response)
        r.status_code = 200
        r.json.return_value = {
            "access_token": "token",
            "refresh_token": "token",
            "expires_in": 3600,
            "scope": "openid email gmail.modify",
        }
        return r

    async def mock_get(self, *args, **kwargs):
        r = MagicMock(spec=httpx.Response)
        r.status_code = 200
        r.json.return_value = {"emailAddress": "corporate.admin@gmail.com"}  # Colliding address
        return r

    with patch("httpx.AsyncClient.post", new=mock_post), patch("httpx.AsyncClient.get", new=mock_get):
        with pytest.raises(GmailAccountConflictError) as exc_info:
            await service.exchange_code_and_verify_account(
                db=db_session,
                user=user2,
                code="auth_code_u2",
                state=state_user2,
            )
        assert "already connected to another PhishGuard user" in str(exc_info.value)


@pytest.mark.asyncio
async def test_preserve_refresh_token_on_reauthorization(db_session, monkeypatch):
    """
    Verify that if Google omits the refresh_token during reauthorization
    (standard Google behavior if prompt=consent is omitted or already granted),
    the existing encrypted refresh token is safely preserved.
    """
    user = User(
        id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        email="reauth_user@phishguard.local",
        username="reauth_user",
        hashed_password="h",
    )
    db_session.add(user)
    await db_session.commit()

    service = GmailOAuthService()
    original_refresh = "1//04_original_refresh_token_that_must_be_preserved"

    existing_conn = GmailIntegration(
        id=uuid.uuid4(),
        organization_id=user.organization_id,
        user_id=user.id,
        email_address="reauth.test@gmail.com",
        is_connected=True,
        connection_status="connected",
        refresh_token_encrypted=service.encryptor.encrypt(original_refresh),
    )
    db_session.add(existing_conn)
    await db_session.commit()

    _, reauth_state = await service.create_authorization_url(db=db_session, user=user)

    # Google response with access token ONLY (no refresh token returned)
    async def mock_post(url, **kwargs):
        r = MagicMock(spec=httpx.Response)
        r.status_code = 200
        r.json.return_value = {
            "access_token": "fresh_access_token_123",
            # refresh_token intentionally omitted by Google
            "expires_in": 3600,
            "scope": "openid email gmail.modify",
        }
        return r

    async def mock_get(url, **kwargs):
        r = MagicMock(spec=httpx.Response)
        r.status_code = 200
        r.json.return_value = {"emailAddress": "reauth.test@gmail.com"}
        return r

    with patch("httpx.AsyncClient.post", new=mock_post), patch("httpx.AsyncClient.get", new=mock_get):
        updated = await service.exchange_code_and_verify_account(
            db=db_session,
            user=user,
            code="reauth_code",
            state=reauth_state,
        )

    assert updated.is_connected is True
    # Verify original refresh token was retained intact
    assert service.encryptor.decrypt(updated.refresh_token_encrypted) == original_refresh


@pytest.mark.asyncio
async def test_token_refresh_and_revocation_handling(db_session, monkeypatch):
    """
    Verify that token refresh handles invalid_grant by marking token_status="revoked".
    """
    user = User(
        id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        email="revoked_test@phishguard.local",
        username="revoked_test",
        hashed_password="h",
    )
    db_session.add(user)
    await db_session.commit()

    service = GmailOAuthService()
    integration = GmailIntegration(
        id=uuid.uuid4(),
        organization_id=user.organization_id,
        user_id=user.id,
        email_address="revoked.user@gmail.com",
        is_connected=True,
        connection_status="connected",
        token_status="valid",
        refresh_token_encrypted=service.encryptor.encrypt("revoked_refresh_token"),
    )
    db_session.add(integration)
    await db_session.commit()

    # Simulate Google returning invalid_grant (user revoked access in myaccount.google.com)
    async def mock_post_revoked(url, **kwargs):
        r = MagicMock(spec=httpx.Response)
        r.status_code = 400
        r.json.return_value = {
            "error": "invalid_grant",
            "error_description": "Token has been expired or revoked.",
        }
        return r

    with patch("httpx.AsyncClient.post", new=mock_post_revoked):
        with pytest.raises(GoogleTokenRevokedError):
            await service.refresh_access_token(db=db_session, integration=integration)

    # Integration record updated to revoked status
    await db_session.refresh(integration)
    assert integration.token_status == "revoked"
    assert integration.connection_status == "error"


@pytest.mark.asyncio
async def test_disconnect_and_revocation(db_session):
    """
    Verify disconnect purges stored encrypted tokens and calls revocation endpoint.
    """
    user = User(
        id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        email="disconnect_user@phishguard.local",
        username="disconnect_user",
        hashed_password="h",
    )
    db_session.add(user)
    await db_session.commit()

    service = GmailOAuthService()
    integration = GmailIntegration(
        id=uuid.uuid4(),
        organization_id=user.organization_id,
        user_id=user.id,
        email_address="disconnect.target@gmail.com",
        is_connected=True,
        connection_status="connected",
        token_status="valid",
        refresh_token_encrypted=service.encryptor.encrypt("token_to_purge"),
    )
    db_session.add(integration)
    await db_session.commit()

    async def mock_revoke(url, **kwargs):
        r = MagicMock(spec=httpx.Response)
        r.status_code = 200
        return r

    with patch("httpx.AsyncClient.post", new=mock_revoke):
        disconnected = await service.disconnect_and_revoke(db=db_session, user=user)

    assert disconnected is True
    await db_session.refresh(integration)
    assert integration.is_connected is False
    assert integration.connection_status == "disconnected"
    assert integration.token_status == "revoked"
    assert integration.refresh_token_encrypted is None
    assert integration.access_token_encrypted is None
