"""
PhishGuard AI — Custom Middleware
Security headers, request ID, audit logging.
"""
import time
import uuid
from typing import Callable

import structlog
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

logger = structlog.get_logger(__name__)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds secure HTTP response headers on every response."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        # Remove server fingerprint
        if "server" in response.headers:
            del response.headers["server"]
        return response


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Attaches a unique X-Request-ID to every request/response."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


class AuditLogMiddleware(BaseHTTPMiddleware):
    """Logs security-relevant HTTP events for audit trail."""

    AUDIT_PATHS = {
        "/api/v1/auth/login",
        "/api/v1/auth/logout",
        "/api/v1/auth/refresh",
        "/api/v1/emails/upload",
        "/api/v1/emails/raw",
    }

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start = time.monotonic()
        response = await call_next(request)
        duration_ms = int((time.monotonic() - start) * 1000)

        path = request.url.path
        if any(path.startswith(p) for p in self.AUDIT_PATHS):
            user_id = None
            org_id = None
            if hasattr(request.state, "current_user") and request.state.current_user:
                try:
                    user_id = str(getattr(request.state.current_user, "id", None))
                    org_id = str(getattr(request.state.current_user, "organization_id", None))
                except Exception:
                    pass

            logger.info(
                "api_request",
                path=path,
                method=request.method,
                status_code=response.status_code,
                duration_ms=duration_ms,
                request_id=getattr(request.state, "request_id", None),
                user_id=user_id,
                org_id=org_id,
                # Note: ip_address logged but not client details
                ip=request.client.host if request.client else None,
            )

        return response
