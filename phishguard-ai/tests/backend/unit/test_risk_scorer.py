"""
Unit tests for RiskScorer in PhishGuard AI.
"""
from app.analyzers.risk_scorer import RiskScorer
from app.analyzers.header_analyzer import HeaderAnalysisResult, Finding
from app.analyzers.url_analyzer import URLAnalysisResult, URLFinding
from app.analyzers.attachment_analyzer import AttachmentAnalysisResult, AttachmentFinding
from app.ai.base_provider import AIAnalysisResult, AIFinding


def test_clean_signals_produce_low_risk_score():
    scorer = RiskScorer()

    header_res = HeaderAnalysisResult(
        spf_result="pass",
        dkim_result="pass",
        dmarc_result="pass",
        auth_alignment="aligned",
        display_name_spoofing=False,
        sender_domain_mismatch=False,
        reply_to_mismatch=False,
        suspicious_routing=False,
        routing_hops=2,
        findings=[],
    )

    url_res = URLAnalysisResult(findings=[], total_count=0, suspicious_count=0, malicious_count=0)
    att_res = AttachmentAnalysisResult(findings=[], total_count=0, high_risk_count=0)
    ai_res = AIAnalysisResult(
        provider="mock",
        model="test",
        is_available=True,
        phishing_assessment="legitimate",
        confidence="high",
        summary="Benign content",
        findings=[],
    )

    result = scorer.compute(header_res, url_res, att_res, ai_res)

    assert result.score < 20
    assert result.classification == "low"


def test_phishing_signals_produce_high_risk_score():
    scorer = RiskScorer()

    header_res = HeaderAnalysisResult(
        spf_result="fail",
        dkim_result="fail",
        dmarc_result="fail",
        auth_alignment="misaligned",
        display_name_spoofing=True,
        sender_domain_mismatch=True,
        reply_to_mismatch=True,
        suspicious_routing=True,
        routing_hops=12,
        findings=[],
    )

    url_res = URLAnalysisResult(
        findings=[
            URLFinding(
                url_raw="http://198.51.100.12/phish",
                url_normalized="http://198.51.100.12/phish",
                domain="198.51.100.12",
                scheme="http",
                is_shortener=False,
                is_ip_based=True,
                is_punycode=False,
                is_homograph_suspect=False,
                has_suspicious_params=True,
                detection_reasons=["IP-based URL", "Credential keywords in parameters"],
                risk_level="critical",
                source_location="body_text",
            )
        ],
        total_count=1,
        suspicious_count=1,
        malicious_count=1,
    )

    att_res = AttachmentAnalysisResult(
        findings=[
            AttachmentFinding(
                filename_safe="safe_uuid.exe",
                filename_original="invoice.pdf.exe",
                extension="exe",
                mime_type_declared="application/pdf",
                mime_type_detected="application/x-dosexec",
                file_size_bytes=1048576,
                sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                is_executable=True,
                is_archive=False,
                has_macro_indicator=False,
                has_double_extension=True,
                mime_type_mismatch=True,
                risk_level="critical",
                detection_reasons=["Executable extension", "Double extension", "MIME mismatch"],
            )
        ],
        total_count=1,
        high_risk_count=1,
    )

    ai_res = AIAnalysisResult(
        provider="mock",
        model="test",
        is_available=True,
        phishing_assessment="phishing",
        confidence="high",
        summary="High-severity phishing attack detected",
        findings=[
            AIFinding(
                category="credential_harvesting",
                description="Urgent credential harvesting request",
                severity="critical",
                confidence="high",
            )
        ],
    )

    result = scorer.compute(header_res, url_res, att_res, ai_res)

    assert result.score >= 70
    assert result.classification in ("high", "critical")
    assert result.score <= 100
