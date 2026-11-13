"""
Reports Generation and Export API Endpoints for PhishGuard AI.
Exports complete investigation reports in JSON, CSV, or formatted text.
"""
import csv
import io
import json
import uuid
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import get_db
from app.models import Email, EmailAnalysis, User
from app.security.auth import get_current_user
from app.utils.response import success_response

router = APIRouter()


@router.get("/email/{email_id}", summary="Generate and export comprehensive investigation report")
@router.post("/email/{email_id}", summary="Generate and export comprehensive investigation report")
async def generate_email_report(
    email_id: uuid.UUID,
    format: str = Query("json", pattern="^(json|csv|txt)$"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    query = (
        select(Email)
        .options(
            selectinload(Email.analysis).selectinload(EmailAnalysis.findings),
            selectinload(Email.headers),
            selectinload(Email.urls),
            selectinload(Email.attachments),
            selectinload(Email.iocs),
        )
        .where(
            Email.id == email_id,
            Email.organization_id == current_user.organization_id,
        )
    )
    res = await db.execute(query)
    email = res.scalar_one_or_none()

    if not email:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Email not found")

    analysis = email.analysis
    if not analysis:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email analysis has not completed yet")

    report_data = {
        "report_id": str(uuid.uuid4()),
        "generated_by": current_user.username,
        "email_metadata": {
            "id": str(email.id),
            "subject": email.subject,
            "sender": email.sender_email,
            "sender_display_name": email.sender_display_name,
            "received_at": email.received_at.isoformat() if email.received_at else None,
            "message_id": email.message_id,
        },
        "threat_assessment": {
            "risk_score": analysis.risk_score,
            "classification": analysis.risk_classification,
            "spf_result": analysis.spf_result,
            "dkim_result": analysis.dkim_result,
            "dmarc_result": analysis.dmarc_result,
            "display_name_spoofing": analysis.display_name_spoofing,
            "sender_domain_mismatch": analysis.sender_domain_mismatch,
        },
        "ai_findings": {
            "summary": analysis.ai_summary,
            "assessment": analysis.ai_phishing_assessment,
            "confidence": analysis.ai_confidence,
            "findings": analysis.ai_findings or [],
            "recommended_actions": analysis.ai_recommended_actions or [],
        },
        "extracted_urls": [
            {
                "url": u.url_raw,
                "domain": u.domain,
                "is_malicious": u.is_malicious,
                "reasons": u.detection_reasons,
            }
            for u in email.urls
        ],
        "attachments": [
            {
                "filename": a.filename_original,
                "sha256": a.sha256_hash,
                "size_bytes": a.file_size_bytes,
                "risk_level": a.risk_level,
                "is_executable": a.is_executable,
            }
            for a in email.attachments
        ],
        "iocs": [
            {
                "type": i.ioc_type,
                "value": i.ioc_value,
                "risk": i.risk_level,
                "confidence": i.confidence,
                "reason": i.detection_reason,
            }
            for i in email.iocs
        ],
        "technical_findings": [
            {
                "category": f.category,
                "name": f.name,
                "severity": f.severity,
                "confidence": f.confidence,
                "description": f.description,
            }
            for f in analysis.findings
        ],
    }

    if format == "json":
        return Response(
            content=json.dumps(report_data, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=report_{email.id}.json"},
        )
    elif format == "csv":
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow(["Section", "Key", "Value"])
        writer.writerow(["Email", "Subject", email.subject or ""])
        writer.writerow(["Email", "Sender", email.sender_email or ""])
        writer.writerow(["Risk", "Score", str(analysis.risk_score)])
        writer.writerow(["Risk", "Classification", analysis.risk_classification])
        writer.writerow(["Authentication", "SPF", analysis.spf_result or "none"])
        writer.writerow(["Authentication", "DKIM", analysis.dkim_result or "none"])
        writer.writerow(["Authentication", "DMARC", analysis.dmarc_result or "none"])
        for ioc in email.iocs:
            writer.writerow(["IOC", ioc.ioc_type, ioc.ioc_value])
        return Response(
            content=out.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=report_{email.id}.csv"},
        )
    else:  # txt
        txt = f"""====================================================
PHISHGUARD AI — SECURITY INVESTIGATION REPORT
====================================================
Report ID: {report_data['report_id']}
Subject:   {email.subject}
Sender:    {email.sender_email}
Risk:      {analysis.risk_score}/100 ({analysis.risk_classification.upper()})

EMAIL AUTHENTICATION:
  SPF:   {analysis.spf_result}
  DKIM:  {analysis.dkim_result}
  DMARC: {analysis.dmarc_result}

AI SUMMARY:
  {analysis.ai_summary or 'N/A'}

EXTRACTED IOCs ({len(email.iocs)} total):
"""
        for i in email.iocs:
            txt += f"  - [{i.ioc_type.upper()}] {i.ioc_value} ({i.risk_level})\n"

        return Response(
            content=txt,
            media_type="text/plain",
            headers={"Content-Disposition": f"attachment; filename=report_{email.id}.txt"},
        )
