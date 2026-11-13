"""
Unit tests for HeaderAnalyzer in PhishGuard AI.
"""
from app.analyzers.email_parser import EmailParser
from app.analyzers.header_analyzer import HeaderAnalyzer


def test_header_analyzer_spf_and_dkim_pass():
    raw_email = """From: Alice <alice@trusted-corp.com>
To: Bob <bob@trusted-corp.com>
Subject: Legitimate Report
Authentication-Results: mx.trusted-corp.com;
  spf=pass smtp.mailfrom=trusted-corp.com;
  dkim=pass header.d=trusted-corp.com;
  dmarc=pass
Date: Tue, 08 Nov 2026 12:00:00 +0000

Clean message body.
"""
    parser = EmailParser()
    parsed = parser.parse(raw_email)

    analyzer = HeaderAnalyzer()
    result = analyzer.analyze(parsed)

    assert result.spf_result == "pass"
    assert result.dkim_result == "pass"
    assert result.dmarc_result == "pass"
    assert not result.display_name_spoofing


def test_header_analyzer_spoofing_detection():
    raw_email = """From: "PayPal Support" <attacker@evil-domain.com>
To: victim@example.com
Subject: Account Alert
Authentication-Results: mx.example.com;
  spf=fail smtp.mailfrom=evil-domain.com;
  dkim=fail;
  dmarc=fail
Reply-To: phisher@harvest-creds.net
Date: Tue, 08 Nov 2026 12:00:00 +0000

Please verify your credentials.
"""
    parser = EmailParser()
    parsed = parser.parse(raw_email)

    analyzer = HeaderAnalyzer()
    result = analyzer.analyze(parsed)

    assert result.spf_result == "fail"
    assert result.display_name_spoofing is True
    assert result.reply_to_mismatch is True
    assert any(f.severity in ("critical", "high") for f in result.findings)


def test_header_analyzer_injected_auth_results_defense():
    """
    Test defense against Authentication-Results header injection:
    Top header from border MTA reports failure; injected second header claims pass.
    The analyzer MUST use the top header and flag the spoofing attempt as critical.
    """
    raw_email = """Authentication-Results: border-mta.victim-corp.com;
  spf=fail smtp.mailfrom=evil.com;
  dkim=fail;
  dmarc=fail
From: attacker@evil.com
To: victim@victim-corp.com
Subject: Important Invoice
Authentication-Results: fake-hop.evil.com;
  spf=pass;
  dkim=pass;
  dmarc=pass
Date: Tue, 08 Nov 2026 12:00:00 +0000

Check this out.
"""
    parser = EmailParser()
    parsed = parser.parse(raw_email)

    analyzer = HeaderAnalyzer()
    result = analyzer.analyze(parsed)

    # Must NOT be fooled by the injected 'pass' header
    assert result.spf_result == "fail"
    assert result.dkim_result == "fail"
    assert result.dmarc_result == "fail"

    # Must generate critical finding for auth results spoofing attempt
    spoof_finding = next(
        (f for f in result.findings if f.name == "auth_results_spoofing_attempt"),
        None,
    )
    assert spoof_finding is not None
    assert spoof_finding.severity == "critical"

