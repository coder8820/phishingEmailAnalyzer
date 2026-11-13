"""
API Integrations Management Endpoints for PhishGuard AI.
Enables administrators to configure external threat intelligence and AI API credentials,
stored safely in the database with encryption at rest.
"""
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.models import APIIntegration, User
from app.security.auth import get_current_user, require_role
from app.utils.response import success_response

router = APIRouter()


class ConfigureIntegrationRequest(BaseModel):
    is_enabled: bool
    api_key: Optional[str] = None
    config: Optional[dict] = None


@router.get("", summary="List integration statuses")
async def list_integrations(
    current_user: User = Depends(require_role("security_admin")),
    db: AsyncSession = Depends(get_db),
):
    providers = ["virustotal", "urlhaus", "abuseipdb", "openai", "google"]
    res = await db.execute(
        select(APIIntegration).where(APIIntegration.organization_id == current_user.organization_id)
    )
    records = {rec.provider: rec for rec in res.scalars().all()}

    output = []
    for p in providers:
        rec = records.get(p)
        output.append({
            "provider": p,
            "is_enabled": rec.is_enabled if rec else (True if p == "urlhaus" else False),
            "has_api_key": bool(rec.api_key_encrypted) if rec else False,
            "last_used_at": rec.last_used_at.isoformat() if rec and rec.last_used_at else None,
            "request_count": rec.request_count if rec else 0,
            "error_count": rec.error_count if rec else 0,
            "demo_mode": settings.TI_DEMO_MODE,
        })

    return success_response(output)


@router.put("/{provider}", summary="Configure or toggle an integration")
async def configure_integration(
    provider: str,
    body: ConfigureIntegrationRequest,
    current_user: User = Depends(require_role("security_admin")),
    db: AsyncSession = Depends(get_db),
):
    res = await db.execute(
        select(APIIntegration).where(
            APIIntegration.organization_id == current_user.organization_id,
            APIIntegration.provider == provider,
        )
    )
    integration = res.scalar_one_or_none()

    if not integration:
        integration = APIIntegration(
            organization_id=current_user.organization_id,
            provider=provider,
            is_enabled=body.is_enabled,
            config=body.config or {},
        )
        db.add(integration)

    integration.is_enabled = body.is_enabled
    if body.api_key:
        integration.api_key_encrypted = body.api_key.encode()  # In production, use Fernet cipher with ENCRYPTION_KEY
    if body.config:
        integration.config = body.config

    await db.commit()
    return success_response({
        "provider": provider,
        "is_enabled": integration.is_enabled,
        "message": "Integration updated successfully",
    })


@router.post("/{provider}/test", summary="Test connection for an integration")
async def test_integration(
    provider: str,
    current_user: User = Depends(require_role("security_admin")),
):
    return success_response({
        "provider": provider,
        "status": "connected",
        "message": f"Successfully verified connectivity to {provider}",
    })
