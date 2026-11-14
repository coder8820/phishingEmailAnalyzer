"""
Unit tests for URLAnalyzer in PhishGuard AI (Phase 4 Advanced URL Forensics).
"""
import pytest
from app.analyzers.url_analyzer import URLAnalyzer, URLFinding
from app.analyzers.redirect_forensics import RedirectForensicsEngine, SSRFProtectionError


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


# ---------------------------------------------------------------------------
# Phase 4 Advanced Forensics Tests
# ---------------------------------------------------------------------------

def test_url_normalization_preserves_original_and_canonicalizes():
    """Verify safe normalization, port removal, trailing dot removal, case canonicalization."""
    raw = "HTTP://Example.COM.:80/login/../verify?user=test#section"
    analyzer = URLAnalyzer()
    normalized, flags = analyzer.normalize_url(raw)

    assert normalized == "http://example.com/verify?user=test"
    assert "trailing_dot_removed" in flags

    finding = analyzer.analyze(text=f"Visit {raw}")
    assert len(finding.findings) == 1
    f = finding.findings[0]
    assert f.url_raw == raw
    assert f.url_normalized == "http://example.com/verify?user=test"
    assert f.domain == "example.com"


def test_url_obfuscation_and_double_encoding():
    """Detect double percent encoding and userinfo (@) trickery."""
    raw = "https://user:pass@evil-phishing.com/test%252Fadmin"
    analyzer = URLAnalyzer()
    res = analyzer.analyze(text=raw)
    assert res.total_count == 1
    f = res.findings[0]
    assert f.is_obfuscated_encoding is True
    assert any("double percent-encoded" in r.lower() for r in f.detection_reasons)
    assert any("user credentials embedded before '@'" in r.lower() for r in f.detection_reasons)


def test_punycode_and_homoglyphs():
    """Detect IDN punycode and mixed Cyrillic/Latin homograph attacks."""
    # Cyrillic 'а' (U+0430) instead of Latin 'a'
    homoglyph_url = "https://pаypal.com/signin"
    punycode_url = "https://xn--e1afmkfd.xn--p1ai/auth"

    analyzer = URLAnalyzer()
    res = analyzer.analyze(text=f"{homoglyph_url} and {punycode_url}")
    assert res.total_count == 2

    homoglyph_finding = next(f for f in res.findings if "pаypal" in f.domain)
    assert homoglyph_finding.is_homograph_suspect is True
    assert any("homograph" in r.lower() for r in homoglyph_finding.detection_reasons)

    puny_finding = next(f for f in res.findings if "xn--" in f.domain)
    assert puny_finding.is_punycode is True


def test_suspicious_ports_and_paths():
    """Detect unusual ports and credential harvesting path patterns."""
    url = "https://legit-lookalike.org:8888/password-reset/verify"
    analyzer = URLAnalyzer()
    res = analyzer.analyze(text=url)
    assert res.total_count == 1
    f = res.findings[0]
    assert f.has_unusual_port is True
    assert f.port == 8888
    assert f.has_suspicious_path is True
    assert any("port" in r.lower() for r in f.detection_reasons)
    assert any("suspicious path" in r.lower() for r in f.detection_reasons)


def test_excessive_subdomains():
    """Detect excessive subdomain nesting (e.g. >= 5 labels)."""
    url = "https://login.security.account.update.paypal.attacker-domain.com/index.html"
    analyzer = URLAnalyzer()
    res = analyzer.analyze(text=url)
    assert res.total_count == 1
    f = res.findings[0]
    assert f.has_excessive_subdomains is True
    assert f.subdomain_count >= 5
    assert any("excessive subdomain nesting" in r.lower() for r in f.detection_reasons)


def test_brand_impersonation_and_typosquatting():
    """Detect typosquatting of known brands while avoiding false positives on legitimate domains."""
    malicious_url = "https://paypa1-security-verification.com/login"
    legit_url = "https://www.paypal.com/signin"

    analyzer = URLAnalyzer()
    res = analyzer.analyze(text=f"Check {malicious_url} and {legit_url}")
    assert res.total_count == 2

    mal_finding = next(f for f in res.findings if "paypa1" in f.domain)
    assert mal_finding.brand_impersonation_target == "paypal"
    assert mal_finding.risk_level in ("high", "critical")

    legit_finding = next(f for f in res.findings if "www.paypal.com" in f.domain)
    assert legit_finding.brand_impersonation_target is None
    # Legitimate paypal domain should not be flagged as brand impersonation
    assert not any("brand impersonation" in r.lower() for r in legit_finding.detection_reasons)


def test_clean_legitimate_urls_false_positive_controls():
    """Ensure standard legitimate URLs don't trigger false positives."""
    clean_urls = """
    https://github.com/torvalds/linux
    https://docs.python.org/3/library/urllib.parse.html
    https://stackoverflow.com/questions/123456
    https://en.wikipedia.org/wiki/Phishing
    """
    analyzer = URLAnalyzer()
    res = analyzer.analyze(text=clean_urls)
    assert res.total_count == 4
    for f in res.findings:
        assert f.risk_level == "low"
        assert not f.is_malicious


# ---------------------------------------------------------------------------
# Redirect Forensics & SSRF Prevention Unit Tests
# ---------------------------------------------------------------------------

def test_redirect_forensics_blocked_ips():
    """Verify that private, loopback, cloud metadata, and broadcast IPs are blocked."""
    engine = RedirectForensicsEngine()

    # Loopback
    blocked, reason = engine.is_ip_blocked("127.0.0.1")
    assert blocked is True
    assert "loopback" in reason.lower()

    # Private RFC1918
    for ip in ["10.0.0.1", "172.16.0.5", "192.168.1.100"]:
        blocked, reason = engine.is_ip_blocked(ip)
        assert blocked is True
        assert "private" in reason.lower()

    # Cloud metadata
    blocked, reason = engine.is_ip_blocked("169.254.169.254")
    assert blocked is True
    assert "metadata" in reason.lower()

    # Carrier-grade NAT
    blocked, _ = engine.is_ip_blocked("100.64.0.1")
    assert blocked is True


def test_redirect_forensics_validate_destination_blocks_ssrf(monkeypatch):
    """Destination validation must raise SSRFProtectionError when resolving to private IP."""
    engine = RedirectForensicsEngine()

    # Localhost name
    with pytest.raises(SSRFProtectionError) as exc:
        engine.validate_destination("localhost")
    assert "blocked" in str(exc.value).lower()

    # Mock DNS resolving to internal IP (DNS rebinding simulation)
    def mock_getaddrinfo(host, port, proto=0):
        return [(2, 1, 6, "", ("192.168.1.50", port))]

    monkeypatch.setattr("socket.getaddrinfo", mock_getaddrinfo)
    with pytest.raises(SSRFProtectionError) as exc:
        engine.validate_destination("attacker-rebound.com")
    assert "blocked destination" in str(exc.value).lower()


def test_redirect_forensics_trace_redirects_blocks_ssrf(monkeypatch):
    """Tracing redirect to internal IP is immediately intercepted and blocked."""
    def mock_getaddrinfo(host, port, proto=0):
        return [(2, 1, 6, "", ("127.0.0.1", port))]

    monkeypatch.setattr("socket.getaddrinfo", mock_getaddrinfo)

    engine = RedirectForensicsEngine()
    result = engine.trace_redirects("http://malicious-local-pivot.com/test")
    assert result.blocked is True
    assert result.is_safe is False
    assert "blocked" in (result.block_reason or "").lower()
    # Confirm internal IP is not leaked in finding
    for hop in result.hops:
        assert hop.resolved_ip is None


def test_redirect_forensics_redirect_limit_exceeded(monkeypatch):
    """Redirect chains exceeding max_redirects are terminated safely."""
    class DummyResponse:
        status = 302
        def getheaders(self):
            return [("location", "http://example.com/loop")]
        def read(self, n=0):
            return b""

    class DummyConn:
        def __init__(self, *args, **kwargs):
            pass
        def request(self, *args, **kwargs):
            pass
        def getresponse(self):
            return DummyResponse()
        def close(self):
            pass

    monkeypatch.setattr("http.client.HTTPConnection", DummyConn)
    monkeypatch.setattr(
        RedirectForensicsEngine,
        "validate_destination",
        lambda self, host, port=80: ["93.184.216.34"],
    )

    engine = RedirectForensicsEngine(max_redirects=3)
    result = engine.trace_redirects("http://example.com/start")
    # Loop detection or limit exceeded should be triggered
    assert result.loop_detected or result.limit_exceeded
    assert result.is_safe is False
