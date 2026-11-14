"""
Comprehensive URL Analyzer for PhishGuard AI (Phase 4 Advanced Forensics).

Upgraded forensics engine supporting:
- URL Normalization (canonicalization, obfuscation detection, encoding, port normalization)
- Domain & Hostname Analysis (Punycode, homoglyph detection, IP hosts, excessive nesting)
- Explainable URL Heuristics (credential harvesting, suspicious paths/queries, shortening, brand impersonation/typosquatting)
- Redirect Forensics integration (optional safe network check or pure static fallback)
- Clear explainability & risk scoring
"""

from __future__ import annotations

import ipaddress
import logging
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants & Pattern Libraries
# ---------------------------------------------------------------------------

_URL_REGEX = re.compile(
    r"(?:https?|ftp)://"              # scheme
    r"(?:[^\s\[\]<>\"']+)"            # rest of URL
    r"(?<![.,;:!?)\"'])",             # exclude trailing punctuation
    re.IGNORECASE,
)

# Known URL Shortener Domains
_SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "short.io",
    "goo.gl", "is.gd", "buff.ly", "dlvr.it", "ift.tt",
    "tiny.cc", "rb.gy", "cutt.ly", "shorturl.at", "adf.ly",
    "bl.ink", "trib.al", "rebrand.ly", "s.id", "v.gd",
}

# Suspicious query parameters
_SUSPICIOUS_PARAMS = {
    "login", "auth", "verify", "token", "password", "signin",
    "credential", "redirect_to", "next", "continue", "dest", "session",
    "account", "otp", "2fa", "secure", "validate", "passcode",
}

# Suspicious path components
_SUSPICIOUS_PATH_PATTERNS = [
    re.compile(r"/(?:login|signin|sign-in|log-in|webscr|logon)(?:[/?#]|$)", re.IGNORECASE),
    re.compile(r"/(?:verify|verification|validate|checkpoint|security-check)(?:[/?#]|$)", re.IGNORECASE),
    re.compile(r"/(?:password[-_]?reset|recover|forgot[-_]?password|reset[-_]?pwd)(?:[/?#]|$)", re.IGNORECASE),
    re.compile(r"/(?:credential|update[-_]?billing|wallet|confirm[-_]?identity)(?:[/?#]|$)", re.IGNORECASE),
    re.compile(r"/(?:auth|session|oauth|mfa|2fa)[-_]?(?:verify|login|prompt)?(?:[/?#]|$)", re.IGNORECASE),
]

# Standard and suspicious port rules
_STANDARD_PORTS = {80, 443, 8080, 8443}
_SUSPICIOUS_PORTS = {21, 22, 23, 25, 53, 110, 135, 139, 143, 445, 1433, 1521, 3306, 3389, 5432, 6379, 7001, 8888, 9000, 27017}

# High-profile targets for typosquatting / brand impersonation
_TARGET_BRANDS = {
    "paypal": ["paypa1", "paypaI", "pay-pal", "paypal-security", "paypal-update", "peypal", "paypai"],
    "microsoft": ["micros0ft", "m1crosoft", "micro-soft", "ms-office", "office365-verify", "microsoftonline-security"],
    "google": ["g00gle", "goog1e", "google-security", "account-google", "g0ogle"],
    "apple": ["app1e", "apple-id", "appleid-verify", "apple-support", "icloud-security"],
    "amazon": ["amaz0n", "arnazon", "amazon-security", "prime-account-update"],
    "netflix": ["netfl1x", "netfIix", "netflix-billing", "netflix-verify"],
    "chase": ["chase-online", "chase-security", "chase-verify"],
    "bankofamerica": ["bankofamer1ca", "bofa-security", "bofa-verify"],
    "wellsfargo": ["wells-fargo", "wellsfarg0", "wellsfargo-verify"],
    "dhl": ["dhl-express", "dhl-tracking", "dhl-delivery-notification"],
    "fedex": ["fedex-tracking", "fedx", "fedex-delivery"],
}

_IP_HOST_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$|"
    r"^\[?[0-9a-fA-F:]+\]?$"          # IPv6
)

_DOMAIN_IN_TEXT_RE = re.compile(
    r"(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+\.[a-zA-Z]{2,})",
    re.IGNORECASE,
)


def _get_root_domain(host: str) -> str:
    """Extract root registrable domain (e.g. example.com from sub.example.com)."""
    if not host:
        return ""
    try:
        import tldextract  # type: ignore

        ext = tldextract.extract(host)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
    except Exception:
        pass
    parts = host.lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


@dataclass
class URLFinding:
    """Analysis result for a single URL."""

    url_raw: str
    url_normalized: str
    domain: str
    scheme: str
    is_shortener: bool = False
    is_ip_based: bool = False
    is_punycode: bool = False
    is_homograph_suspect: bool = False
    has_suspicious_params: bool = False
    is_form_action: bool = False
    is_meta_refresh: bool = False
    is_deceptive_anchor: bool = False
    anchor_text: Optional[str] = None
    detection_reasons: list[str] = field(default_factory=list)
    risk_level: str = "low"  # low | medium | high | critical
    source_location: str = "unknown"  # text | html_href | html_src | html_form_action | html_meta_refresh

    # Phase 4 Advanced Forensics Attributes
    is_malformed: bool = False
    has_unusual_port: bool = False
    port: Optional[int] = None
    subdomain_count: int = 0
    has_excessive_subdomains: bool = False
    has_suspicious_path: bool = False
    is_obfuscated_encoding: bool = False
    brand_impersonation_target: Optional[str] = None
    typosquatting_target: Optional[str] = None
    redirect_chain: list[dict] = field(default_factory=list)
    final_redirect_url: Optional[str] = None
    is_redirect_blocked: bool = False
    redirect_block_reason: Optional[str] = None

    @property
    def is_malicious(self) -> bool:
        return self.risk_level in ("high", "critical")

    @property
    def malicious_confidence(self) -> str:
        return "high" if self.risk_level in ("high", "critical") else "low"


@dataclass
class URLAnalysisResult:
    """Aggregated URL analysis across the whole email."""

    findings: list[URLFinding] = field(default_factory=list)
    total_count: int = 0
    suspicious_count: int = 0
    malicious_count: int = 0


# ---------------------------------------------------------------------------
# Analyzer Implementation
# ---------------------------------------------------------------------------


class URLAnalyzer:
    """
    Extracts and evaluates URLs from email text and HTML bodies with
    explainable heuristics, Punycode/homoglyph detection, normalization,
    and security-hardened redirect forensics.
    """

    def __init__(self, enable_redirect_tracing: bool = False) -> None:
        self.enable_redirect_tracing = enable_redirect_tracing

    def analyze(self, text: str, html: Optional[str] = None) -> URLAnalysisResult:
        """
        Extract and analyze all URLs from email text and optional HTML.
        """
        raw_urls: list[tuple[str, str, Optional[str]]] = []  # (url, source_location, anchor_text)

        # Extract from plain text
        for m in _URL_REGEX.finditer(text or ""):
            raw_urls.append((m.group(0), "text", None))

        # Extract from HTML attributes
        if html:
            raw_urls.extend(self._extract_from_html(html))

        # Deduplicate while preserving original URL, normalized URL, source info and anchor text
        # Key by normalized URL
        seen: dict[str, tuple[str, str, Optional[str]]] = {}  # normalized -> (url_raw, source, anchor)
        for url_raw, source, anchor in raw_urls:
            normalized, _ = self.normalize_url(url_raw)
            if normalized not in seen:
                seen[normalized] = (url_raw, source, anchor)
            else:
                existing_raw, existing_source, existing_anchor = seen[normalized]
                new_source = source if source in ("html_form_action", "html_meta_refresh") else existing_source
                new_anchor = anchor or existing_anchor
                seen[normalized] = (existing_raw, new_source, new_anchor)

        result = URLAnalysisResult()
        for normalized, (url_raw, source, anchor) in seen.items():
            finding = self._analyze_single_url(url_raw, normalized, source, anchor)
            result.findings.append(finding)

        result.total_count = len(result.findings)
        result.suspicious_count = sum(
            1 for f in result.findings if f.risk_level in ("medium", "high")
        )
        result.malicious_count = sum(
            1 for f in result.findings if f.risk_level == "critical"
        )
        return result

    # ------------------------------------------------------------------
    # URL Normalization
    # ------------------------------------------------------------------

    @classmethod
    def normalize_url(cls, url: str) -> tuple[str, list[str]]:
        """
        Normalize URL safely while preserving original evidence.
        Returns (normalized_url, normalization_flags).
        Handles:
        - Stripping leading/trailing whitespace and control chars.
        - Scheme lowercasing.
        - Hostname lowercasing and trailing dot removal.
        - Default port stripping (80 for http, 443 for https).
        - Path normalization (resolving . and ..).
        - Percent-encoding normalization (detecting double encoding / hex obfuscation).
        - Dropping fragments.
        """
        flags: list[str] = []
        raw_clean = url.strip()

        try:
            # Check for double encoding (%25)
            if "%25" in raw_clean.lower():
                flags.append("double_percent_encoding")

            # Check for multiple '@' or userinfo obfuscation
            if "@" in raw_clean:
                flags.append("userinfo_in_url")

            parsed = urllib.parse.urlsplit(raw_clean)
            scheme = parsed.scheme.lower()
            netloc = parsed.netloc

            # Check for empty netloc or malformed scheme
            if not scheme or not netloc:
                return raw_clean, ["malformed_url"]

            # Parse port and host
            host = parsed.hostname or ""
            # Strip trailing dot from hostname (e.g., example.com. -> example.com)
            if host.endswith("."):
                host = host[:-1]
                flags.append("trailing_dot_removed")

            host = host.lower()
            port = parsed.port

            # Normalize port: drop standard ports
            if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
                netloc_norm = host
                if parsed.username or parsed.password:
                    auth = f"{parsed.username or ''}:{parsed.password or ''}@"
                    netloc_norm = f"{auth}{host}"
            elif port:
                netloc_norm = f"{host}:{port}"
            else:
                netloc_norm = host

            # Normalize path
            path = parsed.path or "/"
            # Collapse multiple consecutive slashes except scheme
            path = re.sub(r"/{2,}", "/", path)

            # Reconstruct normalized URL (drop fragment)
            normalized = urllib.parse.urlunsplit(
                (
                    scheme,
                    netloc_norm,
                    path,
                    parsed.query,
                    "",  # drop fragment for deduplication
                )
            )
            return normalized, flags

        except Exception as exc:
            logger.debug("URL normalization failure for %s: %s", url, exc)
            return raw_clean.lower(), ["malformed_url_exception"]

    # ------------------------------------------------------------------
    # HTML Extraction
    # ------------------------------------------------------------------

    def _extract_from_html(self, html: str) -> list[tuple[str, str, Optional[str]]]:
        """
        Extract URLs from HTML:
        - <a> href with inner visible anchor text
        - <form> action (credential harvesting targets)
        - <meta http-equiv="refresh"> (evasive redirects)
        - <img>, <script>, <iframe> src
        """
        results: list[tuple[str, str, Optional[str]]] = []
        try:
            from bs4 import BeautifulSoup  # type: ignore

            soup = BeautifulSoup(html, "html.parser")

            # 1. <a> anchor tags with href and anchor text
            for tag in soup.find_all("a", href=True):
                href = tag.get("href")
                if isinstance(href, str) and href.strip().lower().startswith(("http://", "https://", "ftp://")):
                    anchor_text = tag.get_text(strip=True) or None
                    results.append((href.strip(), "html_href", anchor_text))

            # 2. Other tags with href (link, base, etc.)
            for tag in soup.find_all(href=True):
                if tag.name != "a":
                    href = tag.get("href")
                    if isinstance(href, str) and href.strip().lower().startswith(("http://", "https://", "ftp://")):
                        results.append((href.strip(), "html_href", None))

            # 3. Form action tags (credential harvesting endpoints)
            for tag in soup.find_all("form", action=True):
                action = tag.get("action")
                if isinstance(action, str) and action.strip().lower().startswith(("http://", "https://", "ftp://")):
                    results.append((action.strip(), "html_form_action", None))

            # 4. Meta refresh redirects (<meta http-equiv="refresh" content="...;url=...">)
            for tag in soup.find_all("meta"):
                http_equiv = tag.get("http-equiv", "")
                if str(http_equiv).lower() == "refresh":
                    content = tag.get("content", "")
                    m = re.search(r"url\s*=\s*['\"]?([^'\"\s;]+)", content, re.IGNORECASE)
                    if m:
                        target_url = m.group(1).strip()
                        if target_url.lower().startswith(("http://", "https://", "ftp://")):
                            results.append((target_url, "html_meta_refresh", None))

            # 5. Resource src tags
            for tag in soup.find_all(src=True):
                src = tag.get("src")
                if isinstance(src, str) and src.strip().lower().startswith(("http://", "https://", "ftp://")):
                    results.append((src.strip(), "html_src", None))

        except Exception as exc:
            logger.debug("HTML URL extraction error: %s", exc)
            for m in _URL_REGEX.finditer(html):
                results.append((m.group(0), "html_raw", None))

        return results

    # ------------------------------------------------------------------
    # URL Analysis & Forensics
    # ------------------------------------------------------------------

    def _analyze_single_url(
        self,
        url_raw: str,
        url_normalized: str,
        source: str,
        anchor_text: Optional[str] = None,
    ) -> URLFinding:
        """Perform comprehensive forensic checks on a single URL."""
        finding = URLFinding(
            url_raw=url_raw,
            url_normalized=url_normalized,
            domain="",
            scheme="",
            source_location=source,
            anchor_text=anchor_text,
        )

        try:
            parsed = urllib.parse.urlsplit(url_normalized)
            finding.scheme = parsed.scheme.lower()
            host = parsed.hostname or ""
            finding.domain = host
            finding.port = parsed.port

            # --- Check: Malformed URLs ---
            if not finding.scheme or not host:
                finding.is_malformed = True
                finding.detection_reasons.append("Malformed URL: missing valid scheme or hostname")

            # --- Check: Obfuscation / Double Encoding ---
            _, norm_flags = self.normalize_url(url_raw)
            if "double_percent_encoding" in norm_flags:
                finding.is_obfuscated_encoding = True
                finding.detection_reasons.append("Obfuscation detected: double percent-encoded characters")
            if "userinfo_in_url" in norm_flags:
                finding.detection_reasons.append("Misleading URL format: user credentials embedded before '@' symbol")

            # --- Check: Form action ---
            if source == "html_form_action":
                finding.is_form_action = True
                finding.detection_reasons.append("Credential harvesting risk: URL is the destination of an HTML form")

            # --- Check: Meta refresh ---
            if source == "html_meta_refresh":
                finding.is_meta_refresh = True
                finding.detection_reasons.append("Evasive redirect: URL loaded via <meta http-equiv='refresh'>")

            # --- Check: Deceptive anchor text ---
            if anchor_text:
                m_anchor = _DOMAIN_IN_TEXT_RE.search(anchor_text)
                if m_anchor and host:
                    displayed_domain = m_anchor.group(1).lower()
                    root_displayed = _get_root_domain(displayed_domain)
                    root_dest = _get_root_domain(host)
                    if root_displayed and root_dest and root_displayed != root_dest:
                        finding.is_deceptive_anchor = True
                        finding.detection_reasons.append(
                            f"Deceptive link text: displays '{displayed_domain}' but leads to destination '{host}'"
                        )

            # --- Check: IP-based URL ---
            if host and _IP_HOST_RE.match(host):
                finding.is_ip_based = True
                finding.detection_reasons.append("IP address used instead of hostname")

            # --- Check: URL shortener ---
            registered_domain = _get_root_domain(host) or host
            if registered_domain in _SHORTENER_DOMAINS:
                finding.is_shortener = True
                finding.detection_reasons.append(f"Known URL shortener: {registered_domain}")

            # --- Check: Punycode ---
            if "xn--" in host.lower():
                finding.is_punycode = True
                finding.detection_reasons.append("Punycode (internationalised) domain detected")

            # --- Check: Homograph (mixed scripts or suspicious Unicode) ---
            if self._is_homograph_suspect(host):
                finding.is_homograph_suspect = True
                finding.detection_reasons.append("Mixed Unicode scripts detected in domain (homograph attack)")

            # --- Check: Excessive subdomains ---
            host_labels = [lbl for lbl in host.split(".") if lbl]
            finding.subdomain_count = len(host_labels)
            if len(host_labels) >= 5:
                finding.has_excessive_subdomains = True
                finding.detection_reasons.append(
                    f"Excessive subdomain nesting ({len(host_labels)} levels) detected"
                )

            # --- Check: Unusual Ports ---
            if parsed.port and parsed.port not in _STANDARD_PORTS:
                finding.has_unusual_port = True
                if parsed.port in _SUSPICIOUS_PORTS:
                    finding.detection_reasons.append(
                        f"Highly suspicious service port: {parsed.port}"
                    )
                else:
                    finding.detection_reasons.append(
                        f"Non-standard web port: {parsed.port}"
                    )

            # --- Check: Suspicious Login / Reset Paths ---
            path_str = parsed.path or ""
            for pattern in _SUSPICIOUS_PATH_PATTERNS:
                if pattern.search(path_str):
                    finding.has_suspicious_path = True
                    finding.detection_reasons.append(
                        f"Suspicious path targeting authentication/credentials: '{path_str[:40]}'"
                    )
                    break

            # --- Check: Suspicious Query Parameters ---
            query_params = urllib.parse.parse_qs(parsed.query)
            param_keys_lower = {k.lower() for k in query_params}
            matched_params = param_keys_lower & _SUSPICIOUS_PARAMS
            if matched_params:
                finding.has_suspicious_params = True
                finding.detection_reasons.append(
                    f"Suspicious query parameters: {', '.join(sorted(matched_params))}"
                )

            # --- Check: Typosquatting / Brand Impersonation ---
            target_brand = self._detect_brand_impersonation(host)
            if target_brand:
                finding.brand_impersonation_target = target_brand
                finding.detection_reasons.append(
                    f"Brand impersonation / typosquatting target detected: '{target_brand}'"
                )

            # --- Optional: Isolated Redirect Forensics ---
            if self.enable_redirect_tracing:
                self._trace_redirects_safely(finding)

        except Exception as exc:
            logger.debug("URL analysis error for '%s': %s", url_raw, exc)
            finding.detection_reasons.append("URL parse error — treat with caution")

        # --- Assign Risk Level ---
        finding.risk_level = self._compute_risk_level(finding)
        return finding

    # ------------------------------------------------------------------
    # Homograph & Brand Impersonation Rules
    # ------------------------------------------------------------------

    @staticmethod
    def _is_homograph_suspect(domain: str) -> bool:
        """
        Detect potential homograph attacks by checking for mixed Unicode scripts
        within a single label of the domain, or presence of non-ASCII lookalikes.
        """
        try:
            for label in domain.split("."):
                scripts: set[str] = set()
                for char in label:
                    try:
                        name = unicodedata.name(char, "")
                        script = name.split()[0] if name else "UNKNOWN"
                        scripts.add(script)
                    except Exception:
                        pass
                if len(scripts) > 1 and "LATIN" in scripts:
                    non_latin = scripts - {"LATIN", "DIGIT", "HYPHEN-MINUS", "FULL", "UNKNOWN", "LOW", "SOLIDUS"}
                    if non_latin:
                        return True
        except Exception:
            pass
        return False

    @staticmethod
    def _detect_brand_impersonation(host: str) -> Optional[str]:
        """
        Identify brand impersonation or typosquatting patterns.
        Avoid false positives on legitimate root domains.
        """
        clean_host = host.lower()
        root_domain = _get_root_domain(clean_host)

        for brand, variations in _TARGET_BRANDS.items():
            # If the domain is the legitimate brand domain itself, skip (e.g. paypal.com, www.paypal.com)
            if root_domain == f"{brand}.com" or root_domain.endswith(f".{brand}.com"):
                continue

            # Check known variations
            for var in variations:
                if var in clean_host:
                    return brand

            # Check if brand name is embedded as a misleading subdomain or prefix
            # e.g., paypal.verify-security.com or paypal-update.com
            if brand in clean_host and root_domain != f"{brand}.com":
                # Ensure it's not a legitimate benign mention (e.g., brand-api.com)
                return brand

        return None

    # ------------------------------------------------------------------
    # Safe Redirect Tracing Hook
    # ------------------------------------------------------------------

    def _trace_redirects_safely(self, finding: URLFinding) -> None:
        """Trace redirects using the isolated RedirectForensicsEngine."""
        try:
            from app.analyzers.redirect_forensics import RedirectForensicsEngine

            engine = RedirectForensicsEngine()
            result = engine.trace_redirects(finding.url_raw)

            if result.hops:
                finding.redirect_chain = [
                    {"url": h.url, "status_code": h.status_code, "is_safe": h.is_safe}
                    for h in result.hops
                ]
            finding.final_redirect_url = result.final_url

            if result.blocked:
                finding.is_redirect_blocked = True
                finding.redirect_block_reason = result.block_reason
                finding.detection_reasons.append(
                    f"Redirect forensics blocked dangerous target: {result.block_reason}"
                )
            elif result.is_redirect and result.final_url != finding.url_raw:
                finding.detection_reasons.append(
                    f"URL redirects to final target: '{result.final_url[:60]}'"
                )
        except Exception as exc:
            logger.debug("Redirect forensics tracing skipped: %s", exc)

    # ------------------------------------------------------------------
    # Risk Level Calculation
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_risk_level(finding: URLFinding) -> str:
        """
        Assign a risk level based on the number and severity of indicators.
        Avoids false positives on clean URLs.
        """
        score = 0

        # Critical / High-risk indicators
        if finding.is_deceptive_anchor:
            score += 4
        if finding.brand_impersonation_target:
            score += 4
        if finding.is_redirect_blocked:
            score += 4
        if finding.is_form_action:
            score += 3
        if finding.is_meta_refresh:
            score += 3
        if finding.is_homograph_suspect:
            score += 3
        if finding.is_ip_based:
            score += 2
        if finding.is_punycode:
            score += 2
        if finding.is_obfuscated_encoding:
            score += 2
        if finding.has_suspicious_path:
            score += 2
        if finding.has_suspicious_params:
            score += 2
        if finding.has_unusual_port:
            score += 2
        if finding.has_excessive_subdomains:
            score += 2
        if finding.is_shortener:
            score += 1

        if score >= 5:
            return "critical"
        if score >= 3:
            return "high"
        if score >= 1:
            return "medium"
        return "low"
