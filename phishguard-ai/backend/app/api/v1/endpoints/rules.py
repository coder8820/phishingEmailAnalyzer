"""
Detection Rules API Endpoints for PhishGuard AI.
Allows security administrators to configure custom regex, keyword, and heuristic detection rules.
"""
import uuid
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models import DetectionRule, User
from app.security.auth import get_current_user, require_role
from app.utils.response import success_response, paginated_response

router = APIRouter()


class CreateRuleRequest(BaseModel):
    name: str
    description: Optional[str] = None
    category: str  # auth_failure | url_threat | attachment_threat | spoofing | phishing_language
    rule_type: str = "keyword"  # keyword | regex | heuristic
    rule_definition: dict
    severity: str = "medium"  # low | medium | high | critical
    score_impact: int = 15
    is_enabled: bool = True


class UpdateRuleRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    score_impact: Optional[int] = None
    is_enabled: Optional[bool] = None
    rule_definition: Optional[dict] = None


@router.get("", summary="List detection rules (global + org-specific)")
async def list_rules(
    current_user: User = Depends(require_role("analyst")),
    db: AsyncSession = Depends(get_db),
):
    query = (
        select(DetectionRule)
        .where(
            (DetectionRule.organization_id == current_user.organization_id)
            | (DetectionRule.is_global == True)
        )
        .order_by(desc(DetectionRule.created_at))
    )
    res = await db.execute(query)
    rules = res.scalars().all()

    items = [
        {
            "id": str(r.id),
            "name": r.name,
            "description": r.description,
            "category": r.category,
            "rule_type": r.rule_type,
            "severity": r.severity,
            "score_impact": r.score_impact,
            "is_enabled": r.is_enabled,
            "is_global": r.is_global,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rules
    ]
    return success_response(items)


@router.post("", summary="Create a new custom detection rule")
async def create_rule(
    body: CreateRuleRequest,
    current_user: User = Depends(require_role("security_admin")),
    db: AsyncSession = Depends(get_db),
):
    rule = DetectionRule(
        organization_id=current_user.organization_id,
        name=body.name,
        description=body.description,
        category=body.category,
        rule_type=body.rule_type,
        rule_definition=body.rule_definition,
        severity=body.severity,
        score_impact=body.score_impact,
        is_enabled=body.is_enabled,
        is_global=False,
        created_by=current_user.id,
    )
    db.add(rule)
    await db.commit()
    return success_response({
        "id": str(rule.id),
        "name": rule.name,
        "is_enabled": rule.is_enabled,
    }, status_code=status.HTTP_201_CREATED)


@router.put("/{id}", summary="Update custom detection rule")
async def update_rule(
    id: uuid.UUID,
    body: UpdateRuleRequest,
    current_user: User = Depends(require_role("security_admin")),
    db: AsyncSession = Depends(get_db),
):
    res = await db.execute(
        select(DetectionRule).where(
            DetectionRule.id == id,
            DetectionRule.organization_id == current_user.organization_id,
        )
    )
    rule = res.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found or not editable")

    if body.name is not None:
        rule.name = body.name
    if body.description is not None:
        rule.description = body.description
    if body.severity is not None:
        rule.severity = body.severity
    if body.score_impact is not None:
        rule.score_impact = body.score_impact
    if body.is_enabled is not None:
        rule.is_enabled = body.is_enabled
    if body.rule_definition is not None:
        rule.rule_definition = body.rule_definition

    await db.commit()
    return success_response({"id": str(rule.id), "name": rule.name, "is_enabled": rule.is_enabled})


@router.delete("/{id}", summary="Delete custom detection rule")
async def delete_rule(
    id: uuid.UUID,
    current_user: User = Depends(require_role("security_admin")),
    db: AsyncSession = Depends(get_db),
):
    res = await db.execute(
        select(DetectionRule).where(
            DetectionRule.id == id,
            DetectionRule.organization_id == current_user.organization_id,
        )
    )
    rule = res.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")

    await db.delete(rule)
    await db.commit()
    return success_response({"message": "Rule deleted"})
