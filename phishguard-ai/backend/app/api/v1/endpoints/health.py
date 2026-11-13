"""
PhishGuard AI — Health Check Endpoints
"""
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.config import settings

router = APIRouter()


@router.get("", summary="Basic liveness check")
async def health():
    return {"status": "ok", "version": settings.APP_VERSION}


@router.get("/detailed", summary="Detailed component health")
async def health_detailed(db: AsyncSession = Depends(get_db)):
    """Check health of all components. Requires authentication in production."""
    components = {}

    # Database check
    try:
        await db.execute(text("SELECT 1"))
        components["database"] = {"status": "ok"}
    except Exception as e:
        components["database"] = {"status": "error", "detail": str(e)}

    overall = "ok" if all(c["status"] == "ok" for c in components.values()) else "degraded"
    return {
        "status": overall,
        "version": settings.APP_VERSION,
        "environment": settings.APP_ENV,
        "components": components,
    }
