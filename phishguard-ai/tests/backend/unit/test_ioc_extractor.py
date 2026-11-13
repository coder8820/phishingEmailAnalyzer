"""
Unit tests for IOCExtractor in PhishGuard AI.
"""
from app.analyzers.ioc_extractor import IOCExtractor
from app.analyzers.url_analyzer import URLFinding
from app.analyzers.attachment_analyzer import AttachmentFinding


def test_ioc_extractor_finds_ips_domains_and_hashes():
    text = """
    Suspicious connection detected from 198.51.100.42 to bad-actor-server.com.
    Contact administrator at security-alert@external-warning.org.
    """

    urls = [
        URLFinding(
            url_raw="https://phishing-portal.com/login",
            url_normalized="https://phishing-portal.com/login",
            domain="phishing-portal.com",
            scheme="https",
            risk_level="high",
        )
    ]

    attachments = [
        AttachmentFinding(
            filename_safe="safe_uuid.exe",
            filename_original="trojan.exe",
            extension="exe",
            mime_type_declared="application/octet-stream",
            mime_type_detected="application/x-dosexec",
            file_size_bytes=2048,
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            is_executable=True,
            risk_level="critical",
        )
    ]

    extractor = IOCExtractor()
    iocs = extractor.extract(
        email_text=text,
        header_data={"from": "spoofed@phishing-portal.com"},
        url_findings=urls,
        attachment_findings=attachments,
    )

    ioc_types = {ioc.ioc_type for ioc in iocs}
    assert "ipv4" in ioc_types
    assert "domain" in ioc_types
    assert "url" in ioc_types
    assert "sha256" in ioc_types
    assert "filename" in ioc_types
    assert "email" in ioc_types

    values = {ioc.ioc_value for ioc in iocs}
    assert "198.51.100.42" in values
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in values
    assert "https://phishing-portal.com/login" in values
