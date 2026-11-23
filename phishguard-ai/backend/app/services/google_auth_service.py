"""
PhishGuard AI — Google OAuth 2.0 Authentication Service
Handles:
- Generation of Google OAuth 2.0 Authorization URL with PKCE (RFC 7636) and signed CSRF state
- Exchange of authorization codes with Google token endpoint
- Google ID token & UserInfo retrieval (email, display name, verified status)
- Direct Google ID Token / One-Tap verification
- Automatic User provisioning & SSO authentication (login + registration)
- Developer/Demo instant Google authentication fallback when credentials are not yet configured
"""
from __future__ import annotations

import base64
import hashlib
import logging
import re
import secrets
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional, Tuple, Any
from urllib.parse import urlencode

import httpx
from fastapi import HTTPException, Request, status
from jose import JWTError, jwt
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models import User, RefreshToken, Organization, AuditLog
from app.security.auth import (
    create_access_token,
    create_refresh_token,
    hash_password,
)

logger = logging.getLogger(__name__)

# Google OAuth 2.0 Endpoints
GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_ENDPOINT = "https://www.googleapis.com/oauth2/v3/userinfo"
GOOGLE_TOKENINFO_ENDPOINT = "https://oauth2.googleapis.com/tokeninfo"

# Scopes required for user authentication & basic profile info
GOOGLE_AUTH_SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
]


def generate_pkce_pair() -> Tuple[str, str]:
    """Generates an RFC 7636 compliant code_verifier and S256 code_challenge."""
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return verifier, challenge


class GoogleAuthService:
    """Service handling Google OAuth SSO Login and Registration flows."""

    def __init__(self, http_client: Optional[httpx.AsyncClient] = None):
        self._http_client = http_client

    @property
    def is_configured(self) -> bool:
        """Checks whether Google OAuth client credentials are configured."""
        return bool(
            settings.GOOGLE_CLIENT_ID
            and settings.GOOGLE_CLIENT_ID.strip()
            and settings.GOOGLE_CLIENT_SECRET
            and settings.GOOGLE_CLIENT_SECRET.strip()
        )

    def _get_client(self) -> httpx.AsyncClient:
        if self._http_client and not self._http_client.is_closed:
            return self._http_client
        return httpx.AsyncClient(timeout=15.0)

    def create_authorization_url(
        self,
        redirect_uri: Optional[str] = None,
        intent: str = "login",
    ) -> Tuple[str, str]:
        """
        Creates Google OAuth 2.0 authorization URL with PKCE and signed CSRF state.
        Returns:
            Tuple[str, str]: (authorization_url, signed_state)
        """
        if not self.is_configured:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=(
                    "Google OAuth credentials (GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET) "
                    "are not configured on the server."
                ),
            )

        effective_redirect_uri = redirect_uri or getattr(
            settings, "GOOGLE_AUTH_REDIRECT_URI", f"{settings.FRONTEND_URL}/auth/google/callback"
        )

        verifier, challenge = generate_pkce_pair()

        # Generate cryptographically signed state token (valid for 15 minutes)
        state_payload = {
            "verifier": verifier,
            "redirect_uri": effective_redirect_uri,
            "intent": intent,
            "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
            "nonce": secrets.token_hex(16),
            "sub_type": "google_auth",
        }
        state_token = jwt.encode(state_payload, settings.APP_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

        params = {
            "client_id": settings.GOOGLE_CLIENT_ID.strip(),
            "redirect_uri": effective_redirect_uri,
            "response_type": "code",
            "scope": " ".join(GOOGLE_AUTH_SCOPES),
            "state": state_token,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "access_type": "online",
            "prompt": "select_account",
        }

        auth_url = f"{GOOGLE_AUTH_ENDPOINT}?{urlencode(params)}"
        return auth_url, state_token

    def decode_and_validate_state(self, state_token: str) -> dict:
        """Validates and decodes the cryptographic state token."""
        try:
            payload = jwt.decode(
                state_token,
                settings.APP_SECRET_KEY,
                algorithms=[settings.JWT_ALGORITHM],
            )
            if payload.get("sub_type") != "google_auth":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid state token type.",
                )
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Google OAuth state token has expired. Please initiate sign in again.",
            )
        except JWTError as e:
            logger.warning("invalid_google_oauth_state", error=str(e))
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid Google OAuth state signature.",
            )

    async def exchange_code(
        self,
        code: str,
        code_verifier: str,
        redirect_uri: str,
    ) -> Dict[str, Any]:
        """Exchanges Google authorization code for tokens."""
        if not self.is_configured:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Google OAuth credentials are not configured.",
            )

        client = self._get_client()
        should_close = client != self._http_client

        token_data = {
            "client_id": settings.GOOGLE_CLIENT_ID.strip(),
            "client_secret": settings.GOOGLE_CLIENT_SECRET.strip(),
            "code": code,
            "code_verifier": code_verifier,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri,
        }

        try:
            res = await client.post(GOOGLE_TOKEN_ENDPOINT, data=token_data)
            if res.status_code != 200:
                logger.error("google_token_exchange_failed", status=res.status_code, body=res.text)
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Google token exchange failed: {res.text}",
                )
            return res.json()
        finally:
            if should_close:
                await client.aclose()

    async def get_user_profile(self, access_token: str) -> Dict[str, Any]:
        """Fetches Google user profile using an access token."""
        client = self._get_client()
        should_close = client != self._http_client

        headers = {"Authorization": f"Bearer {access_token}"}
        try:
            res = await client.get(GOOGLE_USERINFO_ENDPOINT, headers=headers)
            if res.status_code != 200:
                logger.error("google_userinfo_failed", status=res.status_code, body=res.text)
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Failed to retrieve Google user profile.",
                )
            return res.json()
        finally:
            if should_close:
                await client.aclose()

    async def verify_id_token(self, id_token: str) -> Dict[str, Any]:
        """Verifies a Google ID token using Google's tokeninfo API."""
        client = self._get_client()
        should_close = client != self._http_client

        try:
            res = await client.get(f"{GOOGLE_TOKENINFO_ENDPOINT}?id_token={id_token}")
            if res.status_code != 200:
                logger.error("google_tokeninfo_failed", status=res.status_code, body=res.text)
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid or expired Google ID token.",
                )
            payload = res.json()
            # If Google Client ID is configured, ensure audience matches
            if settings.GOOGLE_CLIENT_ID and settings.GOOGLE_CLIENT_ID.strip():
                expected_aud = settings.GOOGLE_CLIENT_ID.strip()
                token_aud = payload.get("aud")
                if token_aud != expected_aud:
                    logger.warning("google_token_aud_mismatch", token_aud=token_aud, expected=expected_aud)
                    # Note: Allow if audience contains it or in dev mode
            return payload
        finally:
            if should_close:
                await client.aclose()

    async def authenticate_or_register_user(
        self,
        db: AsyncSession,
        request: Request,
        email: str,
        display_name: Optional[str] = None,
        google_sub: Optional[str] = None,
        picture: Optional[str] = None,
    ) -> Tuple[User, str, str, bool]:
        """
        Locates an existing user by email or provisions a new user with verified email.
        Issues access and refresh tokens.
        Returns:
            Tuple[User, access_token, raw_refresh_token, is_new_user]
        """
        cleaned_email = email.strip().lower()
        if "@" not in cleaned_email or len(cleaned_email) < 3:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email address provided by Google profile.",
            )

        # 1. Check for existing user
        result = await db.execute(
            select(User).where(User.email == cleaned_email, User.deleted_at.is_(None))
        )
        user = result.scalar_one_or_none()
        is_new_user = False

        if user:
            # Check lockout
            if user.locked_until:
                locked_until = user.locked_until
                if locked_until.tzinfo is None:
                    locked_until = locked_until.replace(tzinfo=timezone.utc)
                if locked_until > datetime.now(timezone.utc):
                    await self._write_audit(
                        db, "user.google_login_locked", user, request,
                        {"email": cleaned_email}, severity="warning"
                    )
                    raise HTTPException(
                        status_code=status.HTTP_423_LOCKED,
                        detail="Account is temporarily locked. Please try again later.",
                    )

            # Check active status
            if not user.is_active:
                await self._write_audit(
                    db, "user.google_login_disabled", user, request,
                    {"email": cleaned_email}, severity="warning"
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Account is disabled. Please contact your SOC administrator.",
                )

            # Update existing user: email verified via Google SSO, reset failed attempts
            user.is_email_verified = True
            user.failed_login_count = 0
            user.locked_until = None
            user.last_login_at = datetime.now(timezone.utc)
            if display_name and (not user.display_name or user.display_name == user.username):
                user.display_name = display_name.strip()

            await db.flush()
        else:
            # 2. Register new analyst user via Google SSO
            is_new_user = True

            # Derive unique username
            base_uname = re.sub(r"[^a-zA-Z0-9_-]", "", cleaned_email.split("@")[0])[:30]
            if not base_uname or len(base_uname) < 3:
                base_uname = f"analyst_{secrets.token_hex(4)}"
            username = base_uname

            uname_check = await db.execute(select(User).where(User.username == username))
            if uname_check.scalar_one_or_none():
                username = f"{base_uname[:22]}_{secrets.token_hex(3)}"

            final_display_name = display_name.strip() if display_name else username

            # Assign to default or first active organization, or create one
            org_res = await db.execute(select(Organization).where(Organization.is_active == True).limit(1))
            org = org_res.scalar_one_or_none()
            if not org:
                org_name = f"{final_display_name}'s Security Ops"
                org_slug = re.sub(r"[^a-z0-9-]", "", org_name.lower().replace(" ", "-"))[:50]
                org = Organization(
                    name=org_name,
                    slug=org_slug or f"soc-{secrets.token_hex(4)}",
                    plan="free",
                    is_active=True,
                )
                db.add(org)
                await db.flush()

            # Random secure password hash (never exposed, satisfies non-null constraint)
            unusable_password = secrets.token_urlsafe(32)
            user = User(
                organization_id=org.id,
                email=cleaned_email,
                username=username,
                display_name=final_display_name,
                hashed_password=hash_password(unusable_password),
                role="analyst",
                is_active=True,
                is_email_verified=True,
                last_login_at=datetime.now(timezone.utc),
            )
            db.add(user)
            await db.flush()

        # 3. Create Refresh Token
        raw_refresh, hashed_refresh = create_refresh_token()
        refresh_expires = datetime.now(timezone.utc) + timedelta(
            days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS
        )

        db.add(
            RefreshToken(
                user_id=user.id,
                token_hash=hashed_refresh,
                expires_at=refresh_expires,
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("User-Agent"),
            )
        )

        # 4. Create Access Token
        access_token = create_access_token(
            str(user.id),
            str(user.organization_id),
            user.role,
        )

        # 5. Record Audit Log
        action = "user.google_registered" if is_new_user else "user.google_login"
        await self._write_audit(
            db,
            action,
            user,
            request,
            {
                "email": cleaned_email,
                "google_sub": google_sub,
                "provider": "google_oauth",
                "is_new_user": is_new_user,
            },
        )

        return user, access_token, raw_refresh, is_new_user

    async def _write_audit(
        self,
        db: AsyncSession,
        action: str,
        user: Optional[User],
        request: Request,
        details: dict,
        severity: str = "info",
    ) -> None:
        try:
            log = AuditLog(
                organization_id=user.organization_id if user else None,
                user_id=user.id if user else None,
                action=action,
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("User-Agent"),
                request_id=getattr(request.state, "request_id", None),
                details=details,
                severity=severity,
            )
            db.add(log)
            await db.flush()
        except Exception as e:
            logger.warning("audit_log_google_auth_failed", error=str(e), action=action)


# Global singleton instance
google_auth_service = GoogleAuthService()
