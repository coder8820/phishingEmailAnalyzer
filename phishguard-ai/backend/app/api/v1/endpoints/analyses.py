"""
Analyses API Endpoints for PhishGuard AI.
Tenant-scoped queries for full analysis outcomes, score breakdowns, and findings.
"""
import uuid
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.models import EmailAnalysis, DetectionFinding, Email, User
from app.security.auth import get_current_user
from app.utils.response import success_response, error_response, paginated_response

router = APIRouter()


@router.get("", summary="List email analyses for organization")
async def list_analyses(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    classification: Optional[str] = None,
    min_score: Optional[int] = None,
    max_score: Optional[int] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    query = select(EmailAnalysis).where(
        EmailAnalysis.organization_id == current_user.organization_id
    )

    if classification:
        query = query.where(EmailAnalysis.risk_classification == classification)
    if min_score is not None:
        query = query.where(EmailAnalysis.risk_score >= min_score)
    if max_score is not None:
        query = query.where(EmailAnalysis.risk_score <= max_score)

    query = query.order_by(desc(EmailAnalysis.created_at))

    # Total count
    count_res = await db.execute(select(EmailAnalysis).where(EmailAnalysis.organization_id == current_user.organization_id))
    total = len(count_res.scalars().all())

    # Paginate
    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    analyses = result.scalars().all()

    items = [
        {
            "id": str(a.id),
            "email_id": str(a.email_id),
            "risk_score": a.risk_score,
            "risk_classification": a.risk_classification,
            "spf_result": a.spf_result,
            "dkim_result": a.dkim_result,
            "dmarc_result": a.dmarc_result,
            "url_count": a.url_count,
            "malicious_url_count": a.malicious_url_count,
            "attachment_count": a.attachment_count,
            "malicious_attachment_count": a.malicious_attachment_count,
            "ioc_count": a.ioc_count,
            "ai_phishing_assessment": a.ai_phishing_assessment,
            "ai_confidence": a.ai_confidence,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        }
        for a in analyses
    ]
    return paginated_response(items, total, page, page_size)


@router.get("/{id}", summary="Get full email analysis detail")
async def get_analysis(
    id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    query = (
        select(EmailAnalysis)
        .options(selectinload(EmailAnalysis.findings))
        .where(
            EmailAnalysis.id == id,
            EmailAnalysis.organization_id == current_user.organization_id,
        )
    )
    result = await db.execute(query)
    a = result.scalar_one_or_none()

    if not a:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis not found")

    findings = [
        {
            "id": str(f.id),
            "category": f.category,
            "name": f.name,
            "description": f.description,
            "severity": f.severity,
            "confidence": f.confidence,
            "evidence": f.evidence,
            "score_impact": f.score_impact,
        }
        for f in a.findings
    ]

    return success_response({
        "id": str(a.id),
        "email_id": str(a.email_id),
        "risk_score": a.risk_score,
        "risk_classification": a.risk_classification,
        "spf_result": a.spf_result,
        "dkim_result": a.dkim_result,
        "dmarc_result": a.dmarc_result,
        "auth_alignment": a.auth_alignment,
        "display_name_spoofing": a.display_name_spoofing,
        "sender_domain_mismatch": a.sender_domain_mismatch,
        "reply_to_mismatch": a.reply_to_mismatch,
        "url_count": a.url_count,
        "malicious_url_count": a.malicious_url_count,
        "suspicious_url_count": a.suspicious_url_count,
        "attachment_count": a.attachment_count,
        "malicious_attachment_count": a.malicious_attachment_count,
        "ioc_count": a.ioc_count,
        "ai_provider": a.ai_provider,
        "ai_model": a.ai_model,
        "ai_analysis_available": a.ai_analysis_available,
        "ai_phishing_assessment": a.ai_phishing_assessment,
        "ai_confidence": a.ai_confidence,
        "ai_summary": a.ai_summary,
        "ai_findings": a.ai_findings or [],
        "ai_recommended_actions": a.ai_recommended_actions or [],
        "score_breakdown": a.score_breakdown or {},
        "missing_evidence": a.missing_evidence or [],
        "analysis_duration_ms": a.analysis_duration_ms,
        "findings": findings,
        "created_at": a.created_at.isoformat() if a.created_at else None,
    })


@router.get("/{id}/findings", summary="Get detection findings for analysis")
async def get_analysis_findings(
    id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    query = (
        select(DetectionFinding)
        .join(EmailAnalysis, DetectionFinding.analysis_id == EmailAnalysis.id)
        .where(
            DetectionFinding.analysis_id == id,
            EmailAnalysis.organization_id == current_user.organization_id,
        )
    )
    res = await db.execute(query)
    findings = res.scalars().all()
    return success_response([
        {
            "id": str(f.id),
            "category": f.category,
            "name": f.name,
            "description": f.description,
            "severity": f.severity,
            "confidence": f.confidence,
            "evidence": f.evidence,
            "score_impact": f.score_impact,
        }
        for f in findings
    ])
