"""
PhishGuard AI Backend Package
Provides graceful shims for optional logging and rate-limiting modules
if they are not yet installed in the current environment.
"""
import sys
import types
import logging

# Fallback for structlog
if "structlog" not in sys.modules:
    try:
        import structlog  # noqa: F401
    except ImportError:
        class _FallbackLogger:
            def __init__(self, name="root"):
                self._logger = logging.getLogger(name)

            def info(self, msg, *args, **kwargs):
                extra = " ".join(f"{k}={v}" for k, v in kwargs.items())
                self._logger.info(f"{msg} {extra}".strip())

            def warning(self, msg, *args, **kwargs):
                extra = " ".join(f"{k}={v}" for k, v in kwargs.items())
                self._logger.warning(f"{msg} {extra}".strip())

            def error(self, msg, *args, **kwargs):
                extra = " ".join(f"{k}={v}" for k, v in kwargs.items())
                self._logger.error(f"{msg} {extra}".strip())

            def debug(self, msg, *args, **kwargs):
                extra = " ".join(f"{k}={v}" for k, v in kwargs.items())
                self._logger.debug(f"{msg} {extra}".strip())

            def exception(self, msg, *args, **kwargs):
                extra = " ".join(f"{k}={v}" for k, v in kwargs.items())
                self._logger.exception(f"{msg} {extra}".strip())

        class _MockStructlog(types.ModuleType):
            def get_logger(self, name=None):
                return _FallbackLogger(name or "phishguard")

            def configure(self, *args, **kwargs):
                pass

        _mod = _MockStructlog("structlog")
        _mod.contextvars = types.SimpleNamespace(merge_contextvars=lambda *a: None)
        _mod.stdlib = types.SimpleNamespace(add_log_level=lambda *a: None, add_logger_name=lambda *a: None)
        _mod.processors = types.SimpleNamespace(
            TimeStamper=lambda *a, **k: None,
            StackInfoRenderer=lambda *a, **k: None,
            JSONRenderer=lambda *a, **k: None,
        )
        _mod.dev = types.SimpleNamespace(ConsoleRenderer=lambda *a, **k: None)
        _mod.BoundLogger = object
        _mod.PrintLoggerFactory = lambda *a, **k: None
        sys.modules["structlog"] = _mod

# Fallback for slowapi
if "slowapi" not in sys.modules:
    try:
        import slowapi  # noqa: F401
    except ImportError:
        from starlette.responses import JSONResponse

        class _MockLimiter:
            def __init__(self, *args, **kwargs):
                pass

            def limit(self, *args, **kwargs):
                return lambda f: f

        class RateLimitExceeded(Exception):
            pass

        class _MockSlowAPIMiddleware:
            def __init__(self, app):
                self.app = app

            async def __call__(self, scope, receive, send):
                await self.app(scope, receive, send)

        def _get_remote_address(request):
            return "127.0.0.1"

        def _rate_limit_exceeded_handler(request, exc):
            return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})

        _slowapi_mod = types.ModuleType("slowapi")
        _slowapi_mod.Limiter = _MockLimiter
        _slowapi_mod._rate_limit_exceeded_handler = _rate_limit_exceeded_handler
        _slowapi_mod.middleware = types.SimpleNamespace(SlowAPIMiddleware=_MockSlowAPIMiddleware)
        _slowapi_mod.util = types.SimpleNamespace(get_remote_address=_get_remote_address)
        _slowapi_mod.errors = types.SimpleNamespace(RateLimitExceeded=RateLimitExceeded)
        _slowapi_mod.SlowAPIMiddleware = _MockSlowAPIMiddleware

        sys.modules["slowapi"] = _slowapi_mod
        sys.modules["slowapi.middleware"] = _slowapi_mod.middleware
        sys.modules["slowapi.util"] = _slowapi_mod.util
        sys.modules["slowapi.errors"] = _slowapi_mod.errors
