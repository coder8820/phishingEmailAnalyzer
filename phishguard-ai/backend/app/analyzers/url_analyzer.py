"""
URL analyzer for PhishGuard AI.

Extracts and evaluates URLs from email body text and HTML.
Never fetches or follows any URL.
"""

from __future__ import annotations

import logging
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_URL_REGEX = re.compile(
    r"(?:https?|ftp)://"              # scheme
    r"(?:[^\s\[\]<>\"']+)"            # rest of URL
    r"(?<![.,;:!?)\"'])",             # exclude trailing punctuation
    re.IGNORECASE,
)

_SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "short.io",
    "goo.gl", "is.gd", "buff.ly", "dlvr.it", "ift.tt",
    "tiny.cc", "rb.gy", "cutt.ly", "shorturl.at", "adf.ly",
}

_SUSPICIOUS_PARAMS = {"login", "auth", "verify", "token", "password", "signin", "credential"}

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
# Data models
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
# Analyzer
# ---------------------------------------------------------------------------


class URLAnalyzer:
    """
    Extracts and evaluates URLs from email text and HTML bodies.

    Security contract:
    - NEVER fetches any URL.
    - NEVER follows redirects.
    - Analysis is purely static / lexical.
    """

    def analyze(self, text: str, html: Optional[str] = None) -> URLAnalysisResult:
        """
        Extract and analyze all URLs from email text and optional HTML.

        Args:
            text: Plain-text body of the email.
            html: HTML body of the email (stored as string, not rendered).

        Returns:
            URLAnalysisResult containing all URL findings.
        """
        raw_urls: list[tuple[str, str, Optional[str]]] = []  # (url, source_location, anchor_text)

        # Extract from plain text
        for m in _URL_REGEX.finditer(text or ""):
            raw_urls.append((m.group(0), "text", None))

        # Extract from HTML attributes
        if html:
            raw_urls.extend(self._extract_from_html(html))

        # Deduplicate by normalized URL while preserving source info and anchor text
        seen: dict[str, tuple[str, Optional[str]]] = {}
        for url_raw, source, anchor in raw_urls:
            normalized = self._normalize_url(url_raw)
            if normalized not in seen:
                seen[normalized] = (source, anchor)
            else:
                existing_source, existing_anchor = seen[normalized]
                new_source = source if source in ("html_form_action", "html_meta_refresh") else existing_source
                new_anchor = anchor or existing_anchor
                seen[normalized] = (new_source, new_anchor)

        result = URLAnalysisResult()
        for normalized, (source, anchor) in seen.items():
            finding = self._analyze_url(normalized, source, anchor)
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
    # HTML extraction
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
            # Fallback: regex on raw HTML string
            for m in _URL_REGEX.finditer(html):
                results.append((m.group(0), "html_raw", None))

        return results

    # ------------------------------------------------------------------
    # URL analysis
    # ------------------------------------------------------------------

    def _normalize_url(self, url: str) -> str:
        """Return a lowercased, stripped URL for deduplication."""
        try:
            parsed = urllib.parse.urlparse(url.strip())
            normalized = urllib.parse.urlunparse(
                (
                    parsed.scheme.lower(),
                    parsed.netloc.lower(),
                    parsed.path,
                    parsed.params,
                    parsed.query,
                    "",  # drop fragment
                )
            )
            return normalized
        except Exception:
            return url.strip().lower()

    def _analyze_url(self, url: str, source: str, anchor_text: Optional[str] = None) -> URLFinding:
        """Perform all checks on a single normalized URL."""
        finding = URLFinding(
            url_raw=url,
            url_normalized=url,
            domain="",
            scheme="",
            source_location=source,
            anchor_text=anchor_text,
        )

        try:
            parsed = urllib.parse.urlparse(url)
            finding.scheme = parsed.scheme.lower()
            host = parsed.hostname or ""
            finding.domain = host

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

            # --- Check: Homograph (mixed scripts) ---
            if self._is_homograph_suspect(host):
                finding.is_homograph_suspect = True
                finding.detection_reasons.append("Mixed Unicode scripts detected in domain (homograph attack)")

            # --- Check: Suspicious query parameters ---
            query_params = urllib.parse.parse_qs(parsed.query)
            param_keys_lower = {k.lower() for k in query_params}
            matched_params = param_keys_lower & _SUSPICIOUS_PARAMS
            if matched_params:
                finding.has_suspicious_params = True
                finding.detection_reasons.append(
                    f"Suspicious query parameters: {', '.join(sorted(matched_params))}"
                )

        except Exception as exc:
            logger.debug("URL analysis error for '%s': %s", url, exc)
            finding.detection_reasons.append("URL parse error — treat with caution")

        # --- Assign risk level ---
        finding.risk_level = self._compute_risk_level(finding)
        return finding

    @staticmethod
    def _is_homograph_suspect(domain: str) -> bool:
        """
        Detect potential homograph attacks by checking for mixed Unicode scripts
        within a single label of the domain.
        """
        try:
            for label in domain.split("."):
                scripts: set[str] = set()
                for char in label:
                    try:
                        name = unicodedata.name(char, "")
                        # Extract script name from Unicode character name
                        # e.g. "LATIN SMALL LETTER A" → "LATIN"
                        script = name.split()[0] if name else "UNKNOWN"
                        scripts.add(script)
                    except Exception:
                        pass
                # Mixed Latin + Cyrillic / Greek in one label = suspicious
                if len(scripts) > 1 and "LATIN" in scripts:
                    non_latin = scripts - {"LATIN", "DIGIT", "HYPHEN-MINUS", "FULL", "UNKNOWN", "LOW", "SOLIDUS"}
                    if non_latin:
                        return True
        except Exception:
            pass
        return False

    @staticmethod
    def _compute_risk_level(finding: URLFinding) -> str:
        """Assign a risk level based on the number and severity of indicators."""
        score = 0
        if finding.is_deceptive_anchor:
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
        if finding.has_suspicious_params:
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
