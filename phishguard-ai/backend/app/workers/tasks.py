"""
Celery Background Tasks and Pipeline Execution for PhishGuard AI.
Integrates parser, header analyzer, URL analyzer, attachment analyzer,
IOC extractor, threat intelligence, AI provider, and risk scorer.
"""
from __future__ import annotations
import asyncio
import logging
import time
import uuid
from typing import Optional

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.workers.celery_app import celery_app
from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.models import (
    Email,
    EmailHeader,
    Attachment,
    ExtractedURL,
    EmailAnalysis,
    DetectionFinding,
    IOC,
    ThreatIntelligenceResult,
)
from app.analyzers.email_parser import EmailParser
from app.analyzers.header_analyzer import HeaderAnalyzer
from app.analyzers.url_analyzer import URLAnalyzer
from app.analyzers.attachment_analyzer import AttachmentAnalyzer
from app.analyzers.ioc_extractor import IOCExtractor
from app.analyzers.risk_scorer import RiskScorer
from app.intelligence.mock_provider import MockThreatIntelProvider
from app.intelligence.urlhaus_provider import URLhausProvider
from app.intelligence.virustotal_provider import VirusTotalProvider
from app.ai.mock_provider import MockAIProvider
from app.ai.openai_provider import OpenAIProvider
from app.ai.gemini_provider import GeminiProvider

logger = logging.getLogger(__name__)


def get_ai_provider():
    if settings.AI_PROVIDER == "openai" and settings.OPENAI_API_KEY:
        return OpenAIProvider()
    elif settings.AI_PROVIDER == "google" and settings.GOOGLE_API_KEY:
        return GeminiProvider()
    return MockAIProvider()


def get_threat_intel_providers():
    providers = []
    if settings.TI_DEMO_MODE:
        providers.append(MockThreatIntelProvider())
    else:
        if settings.URLHAUS_ENABLED:
            providers.append(URLhausProvider())
        if settings.VIRUSTOTAL_ENABLED and settings.VIRUSTOTAL_API_KEY:
            providers.append(VirusTotalProvider())
    if not providers:
        providers.append(MockThreatIntelProvider())
    return providers


async def execute_email_analysis(email_id: str, organization_id: str) -> None:
    """
    Executes the entire multi-stage analysis pipeline for a single email.
    Saves all intermediate findings, IOCs, score, and updates email status.
    """
    start_time = time.monotonic()
    errors: list[str] = []

    async with AsyncSessionLocal() as session:
        try:
            # 1. Fetch Email
            res = await session.execute(
                select(Email).where(
                    Email.id == uuid.UUID(email_id),
                    Email.organization_id == uuid.UUID(organization_id),
                )
            )
            email_record = res.scalar_one_or_none()
            if not email_record:
                logger.error("email_not_found_for_analysis: %s", email_id)
                return

            email_record.analysis_status = "processing"
            await session.commit()

            raw_content = email_record.raw_content or ""

            # 2. Parse Email
            parser = EmailParser()
            parsed_email = parser.parse(raw_content)

            # Update email fields with parsed metadata
            email_record.subject = parsed_email.subject
            email_record.sender_raw = parsed_email.from_raw
            email_record.sender_email = parsed_email.from_email
            email_record.sender_display_name = parsed_email.from_display_name
            email_record.reply_to = parsed_email.reply_to
            email_record.return_path = parsed_email.return_path
            email_record.recipient_to = parsed_email.to_addresses
            email_record.recipient_cc = parsed_email.cc_addresses
            email_record.message_id = parsed_email.message_id
            if parsed_email.date:
                email_record.received_at = parsed_email.date

            # Store headers
            for h in parsed_email.headers:
                header_obj = EmailHeader(
                    email_id=email_record.id,
                    name=h.name,
                    value=h.value,
                    position=h.position,
                )
                session.add(header_obj)

            # 3. Header Analysis
            header_analyzer = HeaderAnalyzer()
            header_result = header_analyzer.analyze(parsed_email)

            # 4. URL Analysis
            url_analyzer = URLAnalyzer()
            url_result = url_analyzer.analyze(
                parsed_email.body_text or "",
                parsed_email.body_html,
            )

            # 5. Attachment Analysis
            attachment_analyzer = AttachmentAnalyzer()
            attachment_result = attachment_analyzer.analyze(parsed_email.attachments)

            # Save attachments to DB
            for att_f in attachment_result.findings:
                att_record = Attachment(
                    email_id=email_record.id,
                    organization_id=email_record.organization_id,
                    filename_original=att_f.filename_original,
                    filename_sanitized=att_f.filename_sanitized,
                    mime_type_declared=att_f.mime_type_declared,
                    mime_type_detected=att_f.mime_type_detected,
                    extension=att_f.extension,
                    file_size_bytes=att_f.file_size_bytes,
                    sha256_hash=att_f.sha256_hash,
                    is_executable=att_f.is_executable,
                    is_archive=att_f.is_archive,
                    has_macro_indicator=att_f.has_macro_indicator,
                    has_double_extension=att_f.has_double_extension,
                    mime_type_mismatch=att_f.mime_type_mismatch,
                    risk_level=att_f.risk_level,
                )
                session.add(att_record)

            # 6. Threat Intelligence Lookups for URLs
            ti_providers = get_threat_intel_providers()
            ti_findings_for_urls = {}
            for u in url_result.findings:
                # Query first available provider
                for provider in ti_providers:
                    try:
                        ti_res = await provider.lookup_url(u.url_raw)
                        if ti_res and ti_res.is_malicious is not None:
                            ti_findings_for_urls[u.url_raw] = ti_res
                            break
                    except Exception as ex:
                        errors.append(f"TI lookup failed for {u.url_raw}: {str(ex)}")

            # Store extracted URLs to DB
            for u in url_result.findings:
                ti_info = ti_findings_for_urls.get(u.url_raw)
                is_mal = ti_info.is_malicious if ti_info else (u.risk_level in ("high", "critical"))
                mal_conf = ti_info.confidence if ti_info else ("high" if u.risk_level in ("high", "critical") else "suspicious")

                url_record = ExtractedURL(
                    email_id=email_record.id,
                    organization_id=email_record.organization_id,
                    url_raw=u.url_raw,
                    url_normalized=u.url_normalized,
                    domain=u.domain,
                    scheme=u.scheme,
                    is_shortener=u.is_shortener,
                    is_ip_based=u.is_ip_based,
                    is_punycode=u.is_punycode,
                    is_homograph_suspect=u.is_homograph_suspect,
                    has_suspicious_params=u.has_suspicious_params,
                    redirect_chain=u.redirect_chain or [],
                    reputation_score=ti_info.detections if ti_info else None,
                    reputation_source=ti_info.provider if ti_info else None,
                    is_malicious=is_mal,
                    malicious_confidence=mal_conf,
                    detection_reasons=u.detection_reasons,
                    source_location=u.source_location,
                )
                session.add(url_record)

            # 7. AI Phishing Analysis
            ai_provider = get_ai_provider()
            ai_result = None
            try:
                ai_result = await ai_provider.analyze_email(
                    subject=parsed_email.subject or "",
                    sender=parsed_email.from_email or "",
                    body_text=parsed_email.body_text or "",
                    header_findings=[{"name": f.name, "severity": f.severity} for f in header_result.findings],
                    url_findings=[{"url_raw": uf.url_raw, "domain": uf.domain} for uf in url_result.findings],
                )
            except Exception as e:
                errors.append(f"AI analysis failed: {str(e)}")

            # 8. IOC Extraction
            ioc_extractor = IOCExtractor()
            ioc_items = ioc_extractor.extract(
                email_text=f"{parsed_email.subject or ''}\n{parsed_email.body_text or ''}",
                header_data={
                    "from": parsed_email.from_email,
                    "reply_to": parsed_email.reply_to,
                    "return_path": parsed_email.return_path,
                },
                url_findings=url_result.findings,
                attachment_findings=attachment_result.findings,
            )

            # 9. Compute Explainable Risk Score
            risk_scorer = RiskScorer()
            score_result = risk_scorer.compute(
                header_result=header_result,
                url_result=url_result,
                attachment_result=attachment_result,
                ai_result=ai_result,
                domain_intel=None,
            )

            duration_ms = int((time.monotonic() - start_time) * 1000)

            # 10. Persist Analysis Record
            ai_findings_json = [
                {
                    "category": f.category,
                    "description": f.description,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "evidence_quotes": f.evidence_quotes,
                }
                for f in (ai_result.findings if ai_result else [])
            ]

            score_breakdown_json = {
                "signals": [
                    {
                        "name": s.name,
                        "weight": s.weight,
                        "applied_score": s.applied_score,
                        "confidence": s.confidence,
                        "reason": s.reason,
                    }
                    for s in score_result.breakdown
                ],
                "explanation": score_result.explanation,
            }

            analysis_record = EmailAnalysis(
                email_id=email_record.id,
                organization_id=email_record.organization_id,
                risk_score=score_result.score,
                risk_classification=score_result.classification,
                spf_result=header_result.spf_result,
                dkim_result=header_result.dkim_result,
                dmarc_result=header_result.dmarc_result,
                auth_alignment=header_result.auth_alignment,
                display_name_spoofing=header_result.display_name_spoofing,
                sender_domain_mismatch=header_result.sender_domain_mismatch,
                reply_to_mismatch=header_result.reply_to_mismatch,
                url_count=len(url_result.findings),
                malicious_url_count=url_result.malicious_count,
                suspicious_url_count=url_result.suspicious_count,
                attachment_count=len(attachment_result.findings),
                malicious_attachment_count=attachment_result.high_risk_count,
                ioc_count=len(ioc_items),
                ai_provider=ai_result.provider if ai_result else None,
                ai_model=ai_result.model if ai_result else None,
                ai_analysis_available=ai_result.is_available if ai_result else False,
                ai_phishing_assessment=ai_result.phishing_assessment if ai_result else None,
                ai_confidence=ai_result.confidence if ai_result else None,
                ai_summary=ai_result.summary if ai_result else None,
                ai_findings=ai_findings_json,
                ai_recommended_actions=ai_result.recommended_actions if ai_result else [],
                score_breakdown=score_breakdown_json,
                analysis_duration_ms=duration_ms,
                missing_evidence=score_result.missing_evidence,
                errors=errors,
            )
            session.add(analysis_record)
            await session.flush()

            # Save Detection Findings
            all_findings = []
            for hf in header_result.findings:
                all_findings.append(DetectionFinding(
                    analysis_id=analysis_record.id,
                    organization_id=email_record.organization_id,
                    category="header_auth",
                    name=hf.name,
                    description=hf.description,
                    severity=hf.severity,
                    confidence=hf.confidence,
                    evidence=hf.evidence,
                    score_impact=10,
                ))
            for uf in url_result.findings:
                if uf.detection_reasons:
                    all_findings.append(DetectionFinding(
                        analysis_id=analysis_record.id,
                        organization_id=email_record.organization_id,
                        category="url_threat",
                        name=f"Suspicious URL: {uf.domain}",
                        description=", ".join(uf.detection_reasons),
                        severity="high" if uf.risk_level in ("high", "critical") else "medium",
                        confidence="suspicious",
                        evidence={"url": uf.url_raw, "reasons": uf.detection_reasons},
                        score_impact=15,
                    ))
            for af in attachment_result.findings:
                if af.risk_level in ("high", "critical", "suspicious"):
                    all_findings.append(DetectionFinding(
                        analysis_id=analysis_record.id,
                        organization_id=email_record.organization_id,
                        category="attachment_threat",
                        name=f"Risky Attachment: {af.filename_original}",
                        description=", ".join(af.detection_reasons),
                        severity=af.risk_level,
                        confidence="confirmed" if af.is_executable else "heuristic",
                        evidence={"filename": af.filename_original, "sha256": af.sha256_hash},
                        score_impact=20,
                    ))

            for finding in all_findings:
                session.add(finding)

            # Save IOCs
            for ioc in ioc_items:
                ioc_record = IOC(
                    organization_id=email_record.organization_id,
                    email_id=email_record.id,
                    analysis_id=analysis_record.id,
                    ioc_type=ioc.ioc_type,
                    ioc_value=ioc.ioc_value,
                    source_location=ioc.source_location,
                    risk_level=ioc.risk_level,
                    confidence=ioc.confidence,
                    detection_reason=ioc.detection_reason,
                )
                session.add(ioc_record)

            email_record.analysis_status = "complete"

            # If linked to a GmailMessage, update the GmailMessage with verified pipeline risk metrics
            from app.models import GmailMessage
            gmail_msg_res = await session.execute(
                select(GmailMessage).where(GmailMessage.email_id == email_record.id)
            )
            gmsg = gmail_msg_res.scalar_one_or_none()
            if gmsg:
                gmsg.is_analyzed = True
                gmsg.analysis_status = "analyzed"
                gmsg.risk_score = score_result.score
                gmsg.risk_classification = score_result.risk_classification

            await session.commit()
            logger.info("analysis_completed_successfully for %s, risk_score=%s", email_id, score_result.score)

        except Exception as e:
            logger.error("analysis_pipeline_failed for %s: %s", email_id, str(e), exc_info=True)
            await session.rollback()
            try:
                from app.models import GmailMessage
                await session.execute(
                    update(Email)
                    .where(Email.id == uuid.UUID(email_id))
                    .values(analysis_status="failed")
                )
                await session.execute(
                    update(GmailMessage)
                    .where(GmailMessage.email_id == uuid.UUID(email_id))
                    .values(analysis_status="failed")
                )
                await session.commit()
            except Exception:
                pass


@celery_app.task(name="app.workers.tasks.analyze_email_task", bind=True, max_retries=2)
def analyze_email_task(self, email_id: str, organization_id: str):
    """Celery task entry point."""
    try:
        asyncio.run(execute_email_analysis(email_id, organization_id))
    except Exception as exc:
        logger.error("celery_task_error for %s: %s", email_id, str(exc))
        raise self.retry(exc=exc, countdown=10)


async def execute_gmail_sync(
    integration_id: str,
    user_id: str,
    organization_id: str,
    max_messages: int = 20,
    is_initial_scan: bool = False,
    consent_acknowledged: bool = False,
) -> dict:
    """Executes asynchronous Gmail inbox sync."""
    from app.services.gmail_client_service import gmail_client_service
    from app.models import GmailIntegration, User

    async with AsyncSessionLocal() as session:
        int_res = await session.execute(
            select(GmailIntegration).where(
                GmailIntegration.id == uuid.UUID(integration_id),
                GmailIntegration.organization_id == uuid.UUID(organization_id),
            )
        )
        integration = int_res.scalar_one_or_none()
        if not integration or not integration.is_connected:
            return {"status": "skipped", "reason": "Integration not active"}

        user_res = await session.execute(
            select(User).where(User.id == uuid.UUID(user_id))
        )
        user = user_res.scalar_one_or_none()
        if not user:
            return {"status": "error", "reason": "User not found"}

        return await gmail_client_service.sync_inbox(
            db=session,
            user=user,
            integration=integration,
            max_messages=max_messages,
            is_initial_scan=is_initial_scan,
            consent_acknowledged=consent_acknowledged,
        )


@celery_app.task(name="app.workers.tasks.sync_gmail_account_task", bind=True, max_retries=3, default_retry_delay=15)
def sync_gmail_account_task(
    self,
    integration_id: str,
    user_id: str,
    organization_id: str,
    max_messages: int = 20,
    is_initial_scan: bool = False,
    consent_acknowledged: bool = False,
):
    """Celery background worker task for syncing Gmail inbox messages."""
    try:
        return asyncio.run(
            execute_gmail_sync(
                integration_id=integration_id,
                user_id=user_id,
                organization_id=organization_id,
                max_messages=max_messages,
                is_initial_scan=is_initial_scan,
                consent_acknowledged=consent_acknowledged,
            )
        )
    except Exception as exc:
        logger.error("sync_gmail_account_task error: %s", exc)
        raise self.retry(exc=exc, countdown=15 * (2 ** self.request.retries))
