"""
PhishGuard AI — Genuine Google OAuth 2.0 & Gmail API Service
Implements:
- Official Google OAuth 2.0 Web Server authorization code flow
- PKCE (RFC 7636) code verifier & S256 challenge
- One-time cryptographically secure CSRF state management
- Real Google token exchange (access & refresh tokens)
- Real account verification via users.getProfile
- Multi-user / multi-tenant account collision prevention
- Transparent refresh token re-use / preservation on reauthorization
- Automatic token refresh & revocation handling
- Token encryption at rest via TokenEncryptionService (AES-128/Fernet)
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlencode
from uuid import UUID

import httpx
from sqlalchemy import select, delete, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models import GmailIntegration, OAuthState, User
from app.security.encryption import get_token_encryptor, TokenEncryptionError

logger = logging.getLogger(__name__)

# Google OAuth Endpoints
GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GOOGLE_REVOKE_ENDPOINT = "https://oauth2.googleapis.com/revoke"
GMAIL_PROFILE_ENDPOINT = "https://gmail.googleapis.com/gmail/v1/users/me/profile"

# Approved Least-Privilege Scopes (Quarantine & Inspection; NO mail.google.com, NO send)
APPROVED_OAUTH_SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/gmail.modify",
]


class GoogleOAuthConfigurationError(Exception):
    """Raised when required Google Cloud OAuth credentials are missing."""
    pass


class GoogleOAuthError(Exception):
    """Raised when Google OAuth exchange or verification fails."""
    pass


class GoogleOAuthCSRFError(GoogleOAuthError):
    """Raised when OAuth state is missing, expired, or invalid."""
    pass


class GmailAccountConflictError(GoogleOAuthError):
    """Raised when an attempt is made to link an already-linked Gmail account."""
    pass


class GoogleTokenRevokedError(GoogleOAuthError):
    """Raised when a Google refresh token has been revoked or expired."""
    pass


def generate_pkce_pair() -> Tuple[str, str]:
    """Generates an RFC 7636 compliant code_verifier and S256 code_challenge."""
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


class GmailOAuthService:
    """Service orchestrating genuine Google OAuth 2.0 flow and Gmail verification."""

    def __init__(self, http_client: Optional[httpx.AsyncClient] = None):
        self._http_client = http_client
        self.encryptor = get_token_encryptor()

    def _ensure_credentials(self) -> None:
        """Verifies that Google Cloud OAuth credentials are configured."""
        if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_CLIENT_ID.strip():
            raise GoogleOAuthConfigurationError(
                "GOOGLE_CLIENT_ID is not configured. Please configure your Google Cloud OAuth Client ID."
            )
        if not settings.GOOGLE_CLIENT_SECRET or not settings.GOOGLE_CLIENT_SECRET.strip():
            raise GoogleOAuthConfigurationError(
                "GOOGLE_CLIENT_SECRET is not configured. Please configure your Google Cloud OAuth Client Secret."
            )

    async def create_authorization_url(
        self,
        db: AsyncSession,
        user: User,
        custom_redirect_uri: Optional[str] = None,
    ) -> Tuple[str, str]:
        """
        Generates Google OAuth 2.0 consent URL with PKCE and stores one-time state.
        Returns: (authorization_url, state)
        """
        self._ensure_credentials()

        redirect_uri = custom_redirect_uri or settings.GOOGLE_REDIRECT_URI
        if not redirect_uri:
            raise GoogleOAuthConfigurationError("GOOGLE_REDIRECT_URI must be configured.")

        # Cryptographically random state
        state_value = secrets.token_urlsafe(32)
        code_verifier, code_challenge = generate_pkce_pair()

        # State valid for 10 minutes
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)

        oauth_state = OAuthState(
            state=state_value,
            organization_id=user.organization_id,
            user_id=user.id,
            code_verifier=code_verifier,
            redirect_uri=redirect_uri,
            expires_at=expires_at,
        )
        db.add(oauth_state)
        await db.commit()

        params = {
            "client_id": settings.GOOGLE_CLIENT_ID.strip(),
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": " ".join(APPROVED_OAUTH_SCOPES),
            "access_type": "offline",
            "prompt": "consent",  # Guaranteed refresh_token on authorization
            "state": state_value,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }

        auth_url = f"{GOOGLE_AUTH_ENDPOINT}?{urlencode(params)}"
        return auth_url, state_value

    async def exchange_code_and_verify_account(
        self,
        db: AsyncSession,
        user: User,
        code: str,
        state: str,
        error: Optional[str] = None,
    ) -> GmailIntegration:
        """
        Validates state (one-time anti-CSRF), exchanges authorization code for tokens,
        calls users.getProfile to verify account access, and securely stores encrypted tokens.
        """
        if error:
            logger.warning("Google OAuth callback returned error parameter: %s", error)
            raise GoogleOAuthError(f"Google authorization was denied or failed: {error}")

        if not code or not code.strip():
            raise GoogleOAuthError("Authorization code is missing from callback.")
        if not state or not state.strip():
            raise GoogleOAuthCSRFError("OAuth state parameter is missing.")

        self._ensure_credentials()

        # 1. Validate state from database (one-time use)
        now = datetime.now(timezone.utc)
        stmt = select(OAuthState).where(OAuthState.state == state.strip())
        result = await db.execute(stmt)
        saved_state = result.scalar_one_or_none()

        if not saved_state:
            raise GoogleOAuthCSRFError("Invalid or expired OAuth state parameter (CSRF protection).")

        # Verify state ownership and expiry
        if saved_state.user_id != user.id or saved_state.organization_id != user.organization_id:
            await db.delete(saved_state)
            await db.commit()
            raise GoogleOAuthCSRFError("OAuth state does not match the currently authenticated user.")

        if saved_state.expires_at < now:
            await db.delete(saved_state)
            await db.commit()
            raise GoogleOAuthCSRFError("OAuth state has expired. Please restart authorization.")

        # Extract parameters then delete state immediately (one-time consumption)
        code_verifier = saved_state.code_verifier
        redirect_uri = saved_state.redirect_uri or settings.GOOGLE_REDIRECT_URI
        await db.delete(saved_state)
        await db.commit()

        # 2. Exchange authorization code with Google token endpoint
        token_payload = {
            "client_id": settings.GOOGLE_CLIENT_ID.strip(),
            "client_secret": settings.GOOGLE_CLIENT_SECRET.strip(),
            "code": code.strip(),
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri,
        }
        if code_verifier:
            token_payload["code_verifier"] = code_verifier

        async with httpx.AsyncClient(timeout=15.0) as client:
            token_resp = await client.post(GOOGLE_TOKEN_ENDPOINT, data=token_payload)

        if token_resp.status_code != 200:
            error_data = {}
            try:
                error_data = token_resp.json()
            except Exception:
                pass
            err_desc = error_data.get("error_description") or error_data.get("error") or token_resp.text
            logger.error("Google token exchange failed (HTTP %s): %s", token_resp.status_code, err_desc)
            raise GoogleOAuthError(f"Failed to exchange authorization code with Google: {err_desc}")

        tokens = token_resp.json()
        access_token = tokens.get("access_token")
        refresh_token = tokens.get("refresh_token")
        expires_in = tokens.get("expires_in", 3600)
        granted_scope_str = tokens.get("scope", "")
        granted_scopes = [s for s in granted_scope_str.split(" ") if s]

        if not access_token:
            raise GoogleOAuthError("Google did not return an access token.")

        # 3. Call Google's actual Gmail API users.getProfile to verify real mailbox access
        async with httpx.AsyncClient(timeout=15.0) as client:
            profile_resp = await client.get(
                GMAIL_PROFILE_ENDPOINT,
                headers={"Authorization": f"Bearer {access_token}"},
            )

        if profile_resp.status_code != 200:
            logger.error("Gmail users.getProfile verification failed (HTTP %s): %s", profile_resp.status_code, profile_resp.text)
            raise GoogleOAuthError("Failed to verify Gmail account access with Google API.")

        profile_data = profile_resp.json()
        verified_email = profile_data.get("emailAddress")
        if not verified_email or not verified_email.strip():
            raise GoogleOAuthError("Google API did not return a valid email address.")

        verified_email = verified_email.strip().lower()

        # 4. Multi-Tenant / Multi-User Account Conflict Prevention
        # Check if this Gmail address is linked to ANY other user
        conflict_query = select(GmailIntegration).where(
            GmailIntegration.email_address == verified_email,
            GmailIntegration.user_id != user.id,
            GmailIntegration.is_connected == True,
        )
        conflict_res = await db.execute(conflict_query)
        if conflict_res.scalar_one_or_none():
            raise GmailAccountConflictError(
                f"The Gmail account '{verified_email}' is already connected to another PhishGuard user. "
                "Disconnect it from the existing account before linking it here."
            )

        # 5. Look up existing integration for this user
        existing_query = select(GmailIntegration).where(
            GmailIntegration.organization_id == user.organization_id,
            GmailIntegration.user_id == user.id,
        )
        existing_res = await db.execute(existing_query)
        integration = existing_res.scalar_one_or_none()

        # Encrypt tokens
        encrypted_access = self.encryptor.encrypt(access_token)
        token_expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)

        # Handle refresh token preservation
        encrypted_refresh = None
        if refresh_token:
            encrypted_refresh = self.encryptor.encrypt(refresh_token)
        elif integration and integration.refresh_token_encrypted:
            # Preserve existing refresh token if Google omitted it during re-authorization
            encrypted_refresh = integration.refresh_token_encrypted
            logger.info("Preserving existing encrypted refresh token during re-authorization.")
        else:
            raise GoogleOAuthError(
                "Google did not provide a refresh token and no previous token exists. "
                "Please revoke access in your Google Account security settings and re-authorize."
            )

        # Upsert record
        if not integration:
            integration = GmailIntegration(
                organization_id=user.organization_id,
                user_id=user.id,
                email_address=verified_email,
                is_connected=True,
                connection_status="connected",
                token_status="valid",
                refresh_token_encrypted=encrypted_refresh,
                access_token_encrypted=encrypted_access,
                token_expires_at=token_expires_at,
                granted_scopes=granted_scopes,
                auth_type="oauth2",
                last_verified_at=datetime.now(timezone.utc),
                last_error=None,
                auto_analyze_enabled=True,
            )
            db.add(integration)
        else:
            integration.email_address = verified_email
            integration.is_connected = True
            integration.connection_status = "connected"
            integration.token_status = "valid"
            integration.refresh_token_encrypted = encrypted_refresh
            integration.access_token_encrypted = encrypted_access
            integration.token_expires_at = token_expires_at
            integration.granted_scopes = granted_scopes
            integration.auth_type = "oauth2"
            integration.last_verified_at = datetime.now(timezone.utc)
            integration.last_error = None

        await db.commit()
        await db.refresh(integration)
        logger.info("Successfully connected and verified Gmail account %s for user %s", verified_email, user.id)
        return integration

    async def get_valid_access_token(
        self,
        db: AsyncSession,
        integration: GmailIntegration,
    ) -> str:
        """
        Retrieves a valid decrypted access token for the given integration.
        Refreshes token automatically if expired or expiring within 5 minutes.
        """
        now = datetime.now(timezone.utc)

        # Check if existing access token is still valid (with 5 min buffer)
        needs_refresh = True
        if integration.access_token_encrypted and integration.token_expires_at:
            if integration.token_expires_at > now + timedelta(minutes=5):
                needs_refresh = False

        if not needs_refresh:
            try:
                return self.encryptor.decrypt(integration.access_token_encrypted)
            except TokenEncryptionError:
                logger.warning("Failed to decrypt cached access token; refreshing from Google.")

        # Token refresh required
        return await self.refresh_access_token(db, integration)

    async def refresh_access_token(
        self,
        db: AsyncSession,
        integration: GmailIntegration,
    ) -> str:
        """
        Uses the stored encrypted refresh token to obtain a fresh access token from Google.
        Handles revoked and expired grants.
        """
        self._ensure_credentials()

        if not integration.refresh_token_encrypted:
            integration.token_status = "revoked"
            integration.connection_status = "error"
            integration.last_error = "No refresh token available. Reconnection required."
            await db.commit()
            raise GoogleTokenRevokedError("No refresh token stored. Reconnection required.")

        try:
            refresh_token = self.encryptor.decrypt(integration.refresh_token_encrypted)
        except TokenEncryptionError as e:
            integration.token_status = "invalid"
            integration.last_error = "Token decryption failed."
            await db.commit()
            raise GoogleOAuthError("Decryption of refresh token failed.") from e

        refresh_payload = {
            "client_id": settings.GOOGLE_CLIENT_ID.strip(),
            "client_secret": settings.GOOGLE_CLIENT_SECRET.strip(),
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        }

        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(GOOGLE_TOKEN_ENDPOINT, data=refresh_payload)

        if resp.status_code != 200:
            error_data = {}
            try:
                error_data = resp.json()
            except Exception:
                pass
            err_code = error_data.get("error", "unknown_error")
            err_desc = error_data.get("error_description", resp.text)

            if err_code in ("invalid_grant", "unauthorized_client"):
                integration.token_status = "revoked"
                integration.connection_status = "error"
                integration.last_error = f"Google access revoked: {err_desc}"
                await db.commit()
                raise GoogleTokenRevokedError(f"OAuth grant has been revoked or expired: {err_desc}")

            integration.last_error = f"Token refresh failed: {err_desc}"
            await db.commit()
            raise GoogleOAuthError(f"Failed to refresh Google access token: {err_desc}")

        tokens = resp.json()
        new_access_token = tokens.get("access_token")
        expires_in = tokens.get("expires_in", 3600)

        if not new_access_token:
            raise GoogleOAuthError("Google did not return an access token upon refresh.")

        # Encrypt and store updated token
        integration.access_token_encrypted = self.encryptor.encrypt(new_access_token)
        integration.token_expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
        integration.token_status = "valid"
        integration.last_error = None

        # Google may occasionally rotate the refresh token
        if "refresh_token" in tokens and tokens["refresh_token"]:
            integration.refresh_token_encrypted = self.encryptor.encrypt(tokens["refresh_token"])

        await db.commit()
        return new_access_token

    async def disconnect_and_revoke(
        self,
        db: AsyncSession,
        user: User,
        integration_id: Optional[UUID] = None,
    ) -> bool:
        """
        Revokes token with Google Identity Services and purges tokens from local storage.
        """
        query = select(GmailIntegration).where(
            GmailIntegration.organization_id == user.organization_id,
            GmailIntegration.user_id == user.id,
        )
        if integration_id:
            query = query.where(GmailIntegration.id == integration_id)

        res = await db.execute(query)
        integration = res.scalar_one_or_none()
        if not integration:
            return False

        # Attempt to revoke token with Google
        token_to_revoke = None
        if integration.refresh_token_encrypted:
            try:
                token_to_revoke = self.encryptor.decrypt(integration.refresh_token_encrypted)
            except Exception:
                pass
        elif integration.access_token_encrypted:
            try:
                token_to_revoke = self.encryptor.decrypt(integration.access_token_encrypted)
            except Exception:
                pass

        if token_to_revoke:
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    await client.post(GOOGLE_REVOKE_ENDPOINT, params={"token": token_to_revoke})
            except Exception as e:
                logger.warning("Failed to revoke token with Google revocation endpoint: %s", e)

        # Clear encrypted tokens from database and mark disconnected
        integration.access_token_encrypted = None
        integration.refresh_token_encrypted = None
        integration.access_token = None
        integration.refresh_token = None
        integration.is_connected = False
        integration.connection_status = "disconnected"
        integration.token_status = "revoked"
        integration.last_error = None

        await db.commit()
        logger.info("Gmail integration disconnected and tokens purged for user %s", user.id)
        return True


gmail_oauth_service = GmailOAuthService()
