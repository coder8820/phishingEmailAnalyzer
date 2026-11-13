"""
Integration tests for the complete PhishGuard AI analysis pipeline.
Exercises the end-to-end analyzer chain:
  EmailParser -> HeaderAnalyzer -> URLAnalyzer -> AttachmentAnalyzer -> IOCExtractor -> RiskScorer
Using real sample EML fixtures.
"""
from pathlib import Path

from app.analyzers.email_parser import EmailParser
from app.analyzers.header_analyzer import HeaderAnalyzer
from app.analyzers.url_analyzer import URLAnalyzer
from app.analyzers.attachment_analyzer import AttachmentAnalyzer
from app.analyzers.ioc_extractor import IOCExtractor
from app.analyzers.risk_scorer import RiskScorer
from app.ai.base_provider import AIAnalysisResult

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "fixtures" / "emails"


def test_clean_email_full_pipeline():
    """Verify clean email produces low risk score across full pipeline."""
    eml_path = FIXTURES_DIR / "clean_email.eml"
    with open(eml_path, "rb") as f:
        raw_bytes = f.read()

    # 1. Parse Email
    parser = EmailParser()
    parsed = parser.parse(raw_bytes)
    assert parsed.subject == "Project Status Review: Sprint 42 Deliverables"
    assert parsed.from_email == "alice.montgomery@legitimate-corp.com"

    # 2. Analyze Headers
    header_analyzer = HeaderAnalyzer()
    header_res = header_analyzer.analyze(parsed)
    assert header_res.spf_result == "pass"
    assert header_res.dkim_result == "pass"
    assert header_res.dmarc_result == "pass"
    assert not header_res.display_name_spoofing
    assert not header_res.sender_domain_mismatch

    # 3. Analyze URLs
    url_analyzer = URLAnalyzer()
    url_res = url_analyzer.analyze(text=parsed.body_text or "", html=parsed.body_html)
    assert url_res.total_count == 0
    assert url_res.malicious_count == 0

    # 4. Analyze Attachments
    att_analyzer = AttachmentAnalyzer()
    att_res = att_analyzer.analyze(parsed.attachments)
    assert att_res.total_count == 0

    # 5. Extract IOCs
    ioc_extractor = IOCExtractor()
    header_dict = {
        "from_email": parsed.from_email,
        "reply_to": parsed.reply_to,
        "return_path": parsed.return_path,
    }
    iocs = ioc_extractor.extract(
        email_text=parsed.body_text or "",
        header_data=header_dict,
        url_findings=url_res.findings,
        attachment_findings=att_res.findings,
    )
    assert any(ioc.ioc_type == "email" for ioc in iocs)

    # 6. Score Risk
    scorer = RiskScorer()
    ai_stub = AIAnalysisResult(
        provider="mock",
        model="mock",
        is_available=True,
        phishing_assessment="legitimate",
        confidence="high",
        summary="Benign corporate communication.",
        findings=[],
    )
    score_res = scorer.compute(header_res, url_res, att_res, ai_stub)
    assert score_res.score < 25
    assert score_res.classification == "low"


def test_phishing_email_full_pipeline():
    """Verify phishing email produces high/critical risk score and extracts indicators."""
    eml_path = FIXTURES_DIR / "phishing_simple.eml"
    with open(eml_path, "rb") as f:
        raw_bytes = f.read()

    # 1. Parse Email
    parser = EmailParser()
    parsed = parser.parse(raw_bytes)
    assert "PayPal" in parsed.subject
    assert parsed.from_email == "service-security@paypa1-support.com"

    # 2. Analyze Headers
    header_analyzer = HeaderAnalyzer()
    header_res = header_analyzer.analyze(parsed)
    assert header_res.spf_result == "fail"
    assert header_res.dkim_result == "fail"
    assert header_res.dmarc_result == "fail"

    # 3. Analyze URLs
    url_analyzer = URLAnalyzer()
    url_res = url_analyzer.analyze(text=parsed.body_text or "", html=parsed.body_html)
    assert url_res.total_count >= 1
    # Check IP-based or shortener detection
    assert any(u.is_ip_based or u.is_shortener for u in url_res.findings)

    # 4. Attachments
    att_analyzer = AttachmentAnalyzer()
    att_res = att_analyzer.analyze(parsed.attachments)

    # 5. Extract IOCs
    ioc_extractor = IOCExtractor()
    header_dict = {
        "from_email": parsed.from_email,
        "reply_to": parsed.reply_to,
        "return_path": parsed.return_path,
    }
    iocs = ioc_extractor.extract(
        email_text=parsed.body_html or parsed.body_text or "",
        header_data=header_dict,
        url_findings=url_res.findings,
        attachment_findings=att_res.findings,
    )
    assert len(iocs) >= 3
    ioc_values = [i.ioc_value for i in iocs]
    assert any("evil-redirect.ru" in v or "paypa1" in v or "198.51.100" in v for v in ioc_values)

    # 6. Score Risk
    scorer = RiskScorer()
    ai_stub = AIAnalysisResult(
        provider="mock",
        model="mock",
        is_available=True,
        phishing_assessment="phishing",
        confidence="high",
        summary="High-risk phishing attack impersonating PayPal.",
        findings=[],
    )
    score_res = scorer.compute(header_res, url_res, att_res, ai_stub)
    assert score_res.score >= 60
    assert score_res.classification in ("high", "critical")


def test_prompt_injection_does_not_suppress_detection():
    """Verify prompt injection payload in email body does not prevent phishing detection."""
    eml_path = FIXTURES_DIR / "prompt_injection.eml"
    with open(eml_path, "rb") as f:
        raw_bytes = f.read()

    parser = EmailParser()
    parsed = parser.parse(raw_bytes)

    header_analyzer = HeaderAnalyzer()
    header_res = header_analyzer.analyze(parsed)
    assert header_res.spf_result == "fail"
    assert header_res.dmarc_result == "fail"

    url_analyzer = URLAnalyzer()
    url_res = url_analyzer.analyze(text=parsed.body_text or "", html=parsed.body_html)

    att_analyzer = AttachmentAnalyzer()
    att_res = att_analyzer.analyze(parsed.attachments)

    # Even if an attacker tried to inject a zero score via AI prompt injection:
    scorer = RiskScorer()
    # The rule-based signals (SPF fail, DMARC fail, suspicious link) cannot be bypassed
    score_res = scorer.compute(header_res, url_res, att_res, None)
    assert score_res.score > 30, "Rule-based security must detect threat regardless of prompt injection"
