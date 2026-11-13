"""
PhishGuard AI — Demo Data Seeder Utility
Populates the database with synthetic emails, completed analyses, IOCs, and SOC incidents
for instant local demonstration without requiring manual uploads.
"""
import asyncio
import os
import sys
import uuid

# Ensure backend package is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app.core.database import AsyncSessionLocal, engine, Base
from app.models import (
    Organization,
    User,
    Email,
    EmailAnalysis,
    ExtractedURL,
    Attachment,
    IOC,
    Incident,
    IncidentEmail,
    IncidentIOC,
    InvestigationNote,
    DetectionFinding,
)
from app.security.auth import hash_password


async def seed_demo():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as session:
        # Organization
        org = Organization(
            name="Cyber Defense SOC Alpha",
            slug="cyber-defense-alpha",
            plan="enterprise",
        )
        session.add(org)
        await session.flush()

        # Admin user
        analyst = User(
            organization_id=org.id,
            email="analyst@phishguard.local",
            username="analyst_lead",
            display_name="Senior SOC Lead",
            hashed_password=hash_password("Analyst123!"),
            role="security_admin",
            is_active=True,
            is_email_verified=True,
        )
        session.add(analyst)
        await session.flush()

        # 1. Phishing Email
        phish_email = Email(
            organization_id=org.id,
            submitted_by=analyst.id,
            message_id="<phish-alert-991@paypa1-update.com>",
            subject="URGENT: PayPal Account Limited - Immediate Verification Required",
            sender_raw='"PayPal Security" <security@paypa1-update.com>',
            sender_email="security@paypa1-update.com",
            sender_display_name="PayPal Security",
            reply_to="stealer@harvest-creds.ru",
            return_path="bounce@unverified-relay.net",
            source_type="eml_upload",
            file_hash_sha256="d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
            file_size_bytes=14200,
            original_filename="urgent_paypal_notice.eml",
            analysis_status="complete",
        )
        session.add(phish_email)
        await session.flush()

        # Phishing Analysis
        phish_analysis = EmailAnalysis(
            email_id=phish_email.id,
            organization_id=org.id,
            analyzed_by=analyst.id,
            risk_score=94,
            risk_classification="critical",
            spf_result="fail",
            dkim_result="fail",
            dmarc_result="fail",
            auth_alignment="misaligned",
            display_name_spoofing=True,
            sender_domain_mismatch=True,
            reply_to_mismatch=True,
            url_count=2,
            malicious_url_count=2,
            attachment_count=1,
            malicious_attachment_count=1,
            ioc_count=4,
            ai_provider="mock_ai",
            ai_model="simulated-gpt4-guard",
            ai_analysis_available=True,
            ai_phishing_assessment="phishing",
            ai_confidence="high",
            ai_summary="High-confidence phishing campaign impersonating PayPal with credential harvesting landing pages and fraudulent urgency pressure.",
            ai_findings=[
                {
                    "category": "impersonation",
                    "description": "Domain 'paypa1-update.com' typosquats legitimate trademark 'PayPal'.",
                    "severity": "critical",
                    "confidence": "high",
                    "evidence_quotes": ["Sender: security@paypa1-update.com"],
                },
                {
                    "category": "urgency",
                    "description": "Artificial 24-hour deadline designed to cause reckless user compliance.",
                    "severity": "high",
                    "confidence": "high",
                    "evidence_quotes": ["within 24 hours to prevent permanent account suspension"],
                },
            ],
            ai_recommended_actions=[
                "Block domain 'paypa1-update.com' at edge DNS and email perimeter.",
                "Revoke sessions and reset credentials for any employee who clicked the links.",
                "Quarantine all inbound emails matching the message-id domain pattern.",
            ],
            score_breakdown={
                "signals": [
                    {"name": "spf_fail", "weight": 15, "applied_score": 15, "confidence": "confirmed", "reason": "SPF authentication failed"},
                    {"name": "dkim_fail", "weight": 10, "applied_score": 10, "confidence": "confirmed", "reason": "DKIM signature invalid or missing"},
                    {"name": "display_name_spoofing", "weight": 20, "applied_score": 20, "confidence": "confirmed", "reason": "Display name 'PayPal' mismatches sender domain"},
                    {"name": "malicious_url_confirmed", "weight": 25, "applied_score": 25, "confidence": "confirmed", "reason": "Identified known phishing URL destination"},
                    {"name": "dangerous_attachment_confirmed", "weight": 25, "applied_score": 24, "confidence": "confirmed", "reason": "Executable attachment masked with double extension"},
                ],
                "explanation": "Critical risk determined by failed email authentication, brand typosquatting, executable payload disguised as invoice, and known phishing link destination.",
            },
        )
        session.add(phish_analysis)
        await session.flush()

        # URLs
        u1 = ExtractedURL(
            email_id=phish_email.id,
            organization_id=org.id,
            url_raw="http://bit.ly/fake-paypal-verify",
            domain="bit.ly",
            is_shortener=True,
            is_malicious=True,
            malicious_confidence="confirmed",
            detection_reasons=["URL shortener obfuscating destination", "Phishing domain reputation"],
        )
        u2 = ExtractedURL(
            email_id=phish_email.id,
            organization_id=org.id,
            url_raw="http://198.51.100.12/login/verify",
            domain="198.51.100.12",
            is_ip_based=True,
            is_malicious=True,
            malicious_confidence="confirmed",
            detection_reasons=["IP-based URL without hostname", "Credential keywords in URI path"],
        )
        session.add(u1)
        session.add(u2)

        # Attachment
        att = Attachment(
            email_id=phish_email.id,
            organization_id=org.id,
            filename_original="invoice_receipt.pdf.exe",
            filename_sanitized="safe_uuid_attachment.exe",
            mime_type_declared="application/pdf",
            mime_type_detected="application/x-dosexec",
            extension="exe",
            file_size_bytes=1048576,
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            is_executable=True,
            has_double_extension=True,
            mime_type_mismatch=True,
            risk_level="critical",
        )
        session.add(att)

        # IOCs
        ioc1 = IOC(
            organization_id=org.id,
            email_id=phish_email.id,
            analysis_id=phish_analysis.id,
            ioc_type="domain",
            ioc_value="paypa1-update.com",
            source_location="From Header",
            risk_level="critical",
            confidence="confirmed",
            detection_reason="Typosquatting brand impersonation",
        )
        ioc2 = IOC(
            organization_id=org.id,
            email_id=phish_email.id,
            analysis_id=phish_analysis.id,
            ioc_type="url",
            ioc_value="http://198.51.100.12/login/verify",
            source_location="HTML Body Link",
            risk_level="critical",
            confidence="confirmed",
            detection_reason="Direct IP credential harvesting portal",
        )
        ioc3 = IOC(
            organization_id=org.id,
            email_id=phish_email.id,
            analysis_id=phish_analysis.id,
            ioc_type="ip",
            ioc_value="198.51.100.12",
            source_location="Body URL Host",
            risk_level="high",
            confidence="confirmed",
            detection_reason="Rogue phishing server IP",
        )
        session.add(ioc1)
        session.add(ioc2)
        session.add(ioc3)

        # Incident
        inc = Incident(
            organization_id=org.id,
            title="CRITICAL: Targeted PayPal Typosquat Phishing Campaign",
            description="Active brand impersonation email delivered to corporate finance with double-extension executable and credential harvesting portal.",
            severity="critical",
            status="under_investigation",
            incident_number=1001,
            created_by=analyst.id,
            tags=["phishing", "typosquatting", "credential_harvesting"],
        )
        session.add(inc)
        await session.flush()

        session.add(IncidentEmail(incident_id=inc.id, email_id=phish_email.id, added_by=analyst.id))
        session.add(IncidentIOC(incident_id=inc.id, ioc_id=ioc1.id, added_by=analyst.id))
        session.add(IncidentIOC(incident_id=inc.id, ioc_id=ioc2.id, added_by=analyst.id))
        session.add(InvestigationNote(
            incident_id=inc.id,
            author_id=analyst.id,
            content="Threat confirmed on VirusTotal and URLhaus. Perimeter DNS block enacted for paypa1-update.com.",
            note_type="action",
        ))

        # 2. Clean Email
        clean_email = Email(
            organization_id=org.id,
            submitted_by=analyst.id,
            message_id="<monthly-meeting-102@legitimate-corp.com>",
            subject="Monthly IT Infrastructure Security Sync Meeting",
            sender_raw='"Marcus Vance" <marcus.vance@legitimate-corp.com>',
            sender_email="marcus.vance@legitimate-corp.com",
            sender_display_name="Marcus Vance",
            reply_to="marcus.vance@legitimate-corp.com",
            return_path="marcus.vance@legitimate-corp.com",
            source_type="eml_upload",
            file_hash_sha256="4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
            file_size_bytes=4200,
            original_filename="security_sync.eml",
            analysis_status="complete",
        )
        session.add(clean_email)
        await session.flush()

        clean_analysis = EmailAnalysis(
            email_id=clean_email.id,
            organization_id=org.id,
            analyzed_by=analyst.id,
            risk_score=8,
            risk_classification="low",
            spf_result="pass",
            dkim_result="pass",
            dmarc_result="pass",
            auth_alignment="aligned",
            display_name_spoofing=False,
            sender_domain_mismatch=False,
            reply_to_mismatch=False,
            url_count=0,
            attachment_count=0,
            ioc_count=0,
            ai_provider="mock_ai",
            ai_model="simulated-gpt4-guard",
            ai_analysis_available=True,
            ai_phishing_assessment="legitimate",
            ai_confidence="high",
            ai_summary="Internal routine organizational meeting discussion with aligned cryptographic SPF, DKIM, and DMARC verification.",
            score_breakdown={
                "signals": [],
                "explanation": "Low risk. Complete email authentication pass, zero anomalous linguistic or routing indicators.",
            },
        )
        session.add(clean_analysis)

        await session.commit()
        print("[+] Demo data seeded successfully!")
        print(f"    Organization: {org.name}")
        print(f"    Analyst User: {analyst.email} / Analyst123!")
        print("    Ingested: 1 Critical Phishing email, 1 Clean business email, 3 IOCs, 1 Incident #1001")


if __name__ == "__main__":
    asyncio.run(seed_demo())
