"""
SOC Dashboard API Endpoints for PhishGuard AI.
Aggregates metrics, trends, top suspicious domains, and category distributions.
All statistics derive from actual tenant database records.
"""
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models import Email, EmailAnalysis, DetectionFinding, User
from app.security.auth import get_current_user
from app.utils.response import success_response

router = APIRouter()


@router.get("/stats", summary="Get overall SOC dashboard statistics")
async def get_dashboard_stats(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    org_id = current_user.organization_id

    # Total emails
    total_emails_res = await db.execute(
        select(func.count(Email.id)).where(Email.organization_id == org_id, Email.deleted_at.is_(None))
    )
    total_emails = total_emails_res.scalar() or 0

    # Counts by risk classification
    analyses_res = await db.execute(
        select(EmailAnalysis.risk_classification, func.count(EmailAnalysis.id))
        .where(EmailAnalysis.organization_id == org_id)
        .group_by(EmailAnalysis.risk_classification)
    )
    class_counts = dict(analyses_res.all())

    phishing_count = (class_counts.get("critical", 0) + class_counts.get("high", 0))
    suspicious_count = (class_counts.get("medium", 0) + class_counts.get("suspicious", 0))
    clean_count = class_counts.get("low", 0)
    critical_count = class_counts.get("critical", 0)

    # Average score
    avg_score_res = await db.execute(
        select(func.avg(EmailAnalysis.risk_score)).where(EmailAnalysis.organization_id == org_id)
    )
    avg_risk_score = round(float(avg_score_res.scalar() or 0), 1)

    # Time windows
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = now - timedelta(days=7)

    today_res = await db.execute(
        select(func.count(Email.id)).where(
            Email.organization_id == org_id,
            Email.created_at >= today_start,
        )
    )
    emails_today = today_res.scalar() or 0

    week_res = await db.execute(
        select(func.count(Email.id)).where(
            Email.organization_id == org_id,
            Email.created_at >= week_start,
        )
    )
    emails_this_week = week_res.scalar() or 0

    return success_response({
        "total_emails": total_emails,
        "phishing_count": phishing_count,
        "suspicious_count": suspicious_count,
        "clean_count": clean_count,
        "critical_count": critical_count,
        "avg_risk_score": avg_risk_score,
        "emails_today": emails_today,
        "emails_this_week": emails_this_week,
    })


@router.get("/trends", summary="Get 30-day threat trend timeline")
async def get_dashboard_trends(
    days: int = 30,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    org_id = current_user.organization_id
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    try:
        bind = db.get_bind()
        dialect_name = bind.dialect.name
    except Exception:
        dialect_name = "sqlite"

    if dialect_name == "postgresql":
        day_expr = func.date_trunc('day', EmailAnalysis.created_at).label('day')
    else:
        day_expr = func.strftime('%Y-%m-%d', EmailAnalysis.created_at).label('day')

    res = await db.execute(
        select(
            day_expr,
            EmailAnalysis.risk_classification,
            func.count(EmailAnalysis.id),
        )
        .where(EmailAnalysis.organization_id == org_id, EmailAnalysis.created_at >= cutoff)
        .group_by('day', EmailAnalysis.risk_classification)
        .order_by('day')
    )
    rows = res.all()

    timeline_map: dict[str, dict] = {}
    for d, cls_name, count in rows:
        if isinstance(d, datetime):
            d_str = d.strftime("%Y-%m-%d")
        else:
            d_str = str(d)[:10] if d else ""
        if not d_str:
            continue
        if d_str not in timeline_map:
            timeline_map[d_str] = {"date": d_str, "phishing": 0, "suspicious": 0, "clean": 0, "total": 0}
        if cls_name in ("critical", "high"):
            timeline_map[d_str]["phishing"] += count
        elif cls_name in ("medium", "suspicious"):
            timeline_map[d_str]["suspicious"] += count
        else:
            timeline_map[d_str]["clean"] += count
        timeline_map[d_str]["total"] += count

    # If timeline is empty, provide current day placeholder with 0s so frontend charts render smoothly
    if not timeline_map:
        today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        timeline_map[today_str] = {"date": today_str, "phishing": 0, "suspicious": 0, "clean": 0, "total": 0}

    return success_response(list(timeline_map.values()))


@router.get("/top-domains", summary="Get top suspicious/impersonated sender domains")
async def get_top_domains(
    limit: int = 10,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    org_id = current_user.organization_id
    res = await db.execute(
        select(Email.sender_email, func.count(Email.id))
        .join(EmailAnalysis, Email.id == EmailAnalysis.email_id)
        .where(
            Email.organization_id == org_id,
            EmailAnalysis.risk_score >= 40,
            Email.sender_email.isnot(None),
        )
        .group_by(Email.sender_email)
        .order_by(desc(func.count(Email.id)))
        .limit(limit)
    )
    rows = res.all()
    results = []
    for sender, cnt in rows:
        domain = sender.split("@")[-1] if sender and "@" in sender else (sender or "unknown")
        results.append({
            "domain": domain,
            "count": cnt,
            "risk": "high",
        })
    return success_response(results)


@router.get("/recent-analyses", summary="Get recent email analyses")
async def get_recent_analyses(
    limit: int = 10,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    org_id = current_user.organization_id
    res = await db.execute(
        select(EmailAnalysis, Email)
        .join(Email, EmailAnalysis.email_id == Email.id)
        .where(EmailAnalysis.organization_id == org_id)
        .order_by(desc(EmailAnalysis.created_at))
        .limit(limit)
    )
    rows = res.all()
    data = []
    for analysis, email in rows:
        data.append({
            "id": str(analysis.id),
            "email_id": str(email.id),
            "subject": email.subject or "(No Subject)",
            "sender": email.sender_email or "Unknown",
            "risk_score": analysis.risk_score,
            "risk_classification": analysis.risk_classification,
            "spf_result": analysis.spf_result,
            "url_count": analysis.url_count,
            "created_at": analysis.created_at.isoformat() if analysis.created_at else None,
        })
    return success_response(data)


@router.get("/indicator-distribution", summary="Count findings by detection category")
async def get_indicator_distribution(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    org_id = current_user.organization_id
    res = await db.execute(
        select(DetectionFinding.category, func.count(DetectionFinding.id))
        .where(DetectionFinding.organization_id == org_id)
        .group_by(DetectionFinding.category)
    )
    rows = res.all()
    return success_response([{"category": cat, "count": count} for cat, count in rows])
