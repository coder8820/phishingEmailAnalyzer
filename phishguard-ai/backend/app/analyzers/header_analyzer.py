"""
Email header analyzer for PhishGuard AI.

Inspects authentication results (SPF, DKIM, DMARC), strict and relaxed DMARC alignment,
Received header routing forensics (IP classification and transit latency), sender identity
divergence (From, Reply-To, Return-Path), and display-name spoofing/homoglyph attacks.
"""

from __future__ import annotations

import email.utils
import ipaddress
import logging
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Optional

from app.analyzers.email_parser import ParsedEmail

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """A single security finding from header analysis."""

    name: str
    severity: str  # critical | high | medium | low | info
    confidence: str  # confirmed | suspicious | heuristic
    description: str
    evidence: dict = field(default_factory=dict)


@dataclass
class RoutingHop:
    """Parsed forensic details for an individual Received hop."""

    hop_number: int
    by_host: Optional[str] = None
    from_host: Optional[str] = None
    relay_ip: Optional[str] = None
    ip_type: str = "unknown"  # public | private | loopback | reserved | unknown
    protocol: Optional[str] = None
    timestamp_raw: Optional[str] = None
    timestamp_epoch: Optional[float] = None
    delay_seconds: Optional[float] = None


@dataclass
class HeaderAnalysisResult:
    """Full result of header analysis for one email."""

    spf_result: str = "unknown"       # pass | fail | softfail | neutral | none | temperror | permerror | unknown
    dkim_result: str = "unknown"      # pass | fail | none | temperror | permerror | unknown
    dmarc_result: str = "unknown"     # pass | fail | none | temperror | permerror | unknown
    auth_alignment: str = "unknown"   # aligned | misaligned | unknown

    # DMARC alignment details
    dmarc_spf_alignment: str = "unknown"   # strict | relaxed | fail | unknown
    dmarc_dkim_alignment: str = "unknown"  # strict | relaxed | fail | unknown
    dkim_signing_domain: Optional[str] = None
    dkim_selector: Optional[str] = None
    spf_envelope_domain: Optional[str] = None
    spf_client_ip: Optional[str] = None

    display_name_spoofing: bool = False
    sender_domain_mismatch: bool = False
    reply_to_mismatch: bool = False
    suspicious_routing: bool = False
    routing_hops: int = 0
    hops: list[RoutingHop] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Constants & Reference Sets
# ---------------------------------------------------------------------------

_KNOWN_BRAND_NAMES = {
    "paypal", "apple", "microsoft", "amazon", "google", "facebook",
    "netflix", "bank of america", "chase", "wells fargo", "citibank",
    "dhl", "fedex", "ups", "usps", "irs", "support", "security",
    "noreply", "no-reply", "account", "billing", "helpdesk", "admin",
}

# Targeted high-risk brands for homoglyph / visual lookalike impersonation
_PROTECTED_BRANDS = [
    "paypal", "microsoft", "google", "apple", "amazon", "netflix",
    "chase", "wellsfargo", "citibank", "bankofamerica", "dhl", "fedex",
]

_EMAIL_IN_DISPLAY_PATTERN = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
)

_DOMAIN_RE = re.compile(r"@([\w.\-]+)")

# Multi-part public suffixes to enable accurate relaxed alignment without external dependencies
_MULTI_PART_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "net.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.jp", "ne.jp", "or.jp", "go.jp", "ac.jp",
    "co.za", "org.za", "gov.za",
    "com.br", "org.br", "gov.br",
    "com.mx", "org.mx", "gob.mx",
    "com.sg", "org.sg", "edu.sg",
    "co.in", "net.in", "org.in", "gen.in",
    "com.tr", "org.tr", "gov.tr",
    "com.cn", "net.cn", "org.cn", "gov.cn",
    "com.tw", "org.tw", "gov.tw",
    "com.hk", "org.hk", "gov.hk",
}

# Common homoglyph mappings (Cyrillic, Greek, lookalikes to Latin base)
_HOMOGLYPH_MAP = {
    # Cyrillic
    "\u0430": "a", "\u0441": "c", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0455": "s", "\u0445": "x", "\u0443": "y", "\u0456": "i", "\u0458": "j",
    "\u0410": "a", "\u0412": "b", "\u0421": "c", "\u0415": "e", "\u041d": "h",
    "\u0406": "i", "\u0408": "j", "\u041a": "k", "\u041c": "m", "\u041d": "n",
    "\u041e": "o", "\u0420": "p", "\u0422": "t", "\u0425": "x", "\u0423": "y",
    # Greek
    "\u03bf": "o", "\u03c1": "p", "\u03b1": "a", "\u03bd": "v", "\u03b9": "i",
    "\u03ba": "k", "\u039f": "o", "\u0391": "a", "\u0392": "b", "\u0395": "e",
}

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _extract_domain(email_addr: str) -> str:
    """Return the normalized lowercase domain part of an email address, or empty string."""
    if not email_addr:
        return ""
    m = _DOMAIN_RE.search(email_addr)
    return m.group(1).lower().strip() if m else ""


def _strip_angle_brackets(addr: str) -> str:
    """Remove RFC-822 angle brackets from an address."""
    addr = (addr or "").strip()
    if addr.startswith("<") and addr.endswith(">"):
        return addr[1:-1]
    return addr


def _extract_root_domain(domain: str) -> str:
    """
    Extract the organizational (root) domain from a FQDN.
    e.g. 'mail.corp.example.co.uk' -> 'example.co.uk'
         'auth.accounts.google.com' -> 'google.com'
    """
    if not domain:
        return ""
    domain = domain.lower().strip().rstrip(".")
    parts = domain.split(".")
    if len(parts) <= 2:
        return domain

    # Check for known 2-part ccTLDs (e.g. .co.uk)
    two_part = ".".join(parts[-2:])
    if two_part in _MULTI_PART_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])

    return ".".join(parts[-2:])


def _classify_ip(ip_str: str) -> str:
    """Classify an IP string into public, private, loopback, reserved, or unknown."""
    if not ip_str:
        return "unknown"
    try:
        obj = ipaddress.ip_address(ip_str)
        if obj.is_loopback:
            return "loopback"
        if obj.is_private:
            return "private"
        if obj.is_reserved or obj.is_multicast or obj.is_unspecified:
            return "reserved"
        if obj.is_global:
            return "public"
        return "unknown"
    except ValueError:
        return "unknown"


# ---------------------------------------------------------------------------
# Header Analyzer
# ---------------------------------------------------------------------------


class HeaderAnalyzer:
    """
    Analyzes email headers for authentication failures, alignment, spoofing indicators,
    and transit routing anomalies.
    """

    def analyze(self, parsed_email: ParsedEmail) -> HeaderAnalysisResult:
        """
        Run all header forensics checks and return a HeaderAnalysisResult.
        """
        result = HeaderAnalysisResult()

        self._parse_auth_results(parsed_email, result)
        self._check_sender_and_envelope(parsed_email, result)
        self._check_display_name_and_homoglyphs(parsed_email, result)
        self._check_reply_to_mismatch(parsed_email, result)
        self._analyze_received_headers(parsed_email, result)
        self._compute_dmarc_alignment(parsed_email, result)

        return result

    # ------------------------------------------------------------------
    # 1. Auth-Results Forensics (SPF, DKIM, DMARC)
    # ------------------------------------------------------------------

    def _parse_auth_results(self, parsed: ParsedEmail, result: HeaderAnalysisResult) -> None:
        """
        Parse Authentication-Results header to extract SPF, DKIM, and DMARC results.
        Only the outermost (topmost) Authentication-Results header is trusted.
        """
        auth_entries = [h for h in parsed.headers if h.name.lower() == "authentication-results"]
        # Topmost header from border MTA is at position 0
        auth_entries.sort(key=lambda h: h.position)

        if not auth_entries:
            result.spf_result = "none"
            result.dkim_result = "none"
            result.dmarc_result = "none"
            result.findings.append(
                Finding(
                    name="missing_authentication_results",
                    severity="medium",
                    confidence="confirmed",
                    description="No Authentication-Results header found. Cannot verify SPF/DKIM/DMARC.",
                    evidence={"headers_present": [h.name for h in parsed.headers]},
                )
            )
            return

        topmost = auth_entries[0]
        topmost_val = topmost.value
        border_authserv_id = topmost_val.split(";")[0].strip() if ";" in topmost_val else topmost_val.split()[0]

        # Extract SPF result and details
        spf_match = re.search(r"\bspf\s*=\s*([a-zA-Z0-9_\-]+)", topmost_val, re.IGNORECASE)
        if spf_match:
            result.spf_result = self._normalize_auth_result(spf_match.group(1))

        # Extract smtp.mailfrom or envelope-from
        mailfrom_match = re.search(r"(?:smtp\.mailfrom|envelope-from)\s*=\s*([^\s;]+)", topmost_val, re.IGNORECASE)
        if mailfrom_match:
            raw_mf = mailfrom_match.group(1).strip("<>\"' ,;")
            result.spf_envelope_domain = _extract_domain(raw_mf) or raw_mf.lower()

        # Extract client IP if present in Authentication-Results
        client_ip_match = re.search(r"(?:smtp\.client-ip|client-ip)\s*=\s*([0-9a-fA-F:.]+)", topmost_val, re.IGNORECASE)
        if client_ip_match:
            result.spf_client_ip = client_ip_match.group(1).strip(" ;,")

        # Extract DKIM result and header.d / header.s
        dkim_match = re.search(r"\bdkim\s*=\s*([a-zA-Z0-9_\-]+)", topmost_val, re.IGNORECASE)
        if dkim_match:
            result.dkim_result = self._normalize_auth_result(dkim_match.group(1))

        dkim_d_match = re.search(r"\bheader\.d\s*=\s*([^\s;]+)", topmost_val, re.IGNORECASE)
        if dkim_d_match:
            result.dkim_signing_domain = dkim_d_match.group(1).strip("<>\"' ,;").lower()

        dkim_s_match = re.search(r"\bheader\.s\s*=\s*([^\s;]+)", topmost_val, re.IGNORECASE)
        if dkim_s_match:
            result.dkim_selector = dkim_s_match.group(1).strip("<>\"' ,;")

        # Fallback inspection: if header.d not in Auth-Results, inspect DKIM-Signature headers
        if not result.dkim_signing_domain:
            for h in parsed.headers:
                if h.name.lower() == "dkim-signature":
                    sig_d = re.search(r"\bd\s*=\s*([^\s;]+)", h.value, re.IGNORECASE)
                    if sig_d:
                        result.dkim_signing_domain = sig_d.group(1).strip("<>\"' ,;").lower()
                    sig_s = re.search(r"\bs\s*=\s*([^\s;]+)", h.value, re.IGNORECASE)
                    if sig_s:
                        result.dkim_selector = sig_s.group(1).strip("<>\"' ,;")
                    break

        # Extract DMARC result
        dmarc_match = re.search(r"\bdmarc\s*=\s*([a-zA-Z0-9_\-]+)", topmost_val, re.IGNORECASE)
        if dmarc_match:
            result.dmarc_result = self._normalize_auth_result(dmarc_match.group(1))

        # Detect multiple Authentication-Results headers and spoofing/injection attempts
        if len(auth_entries) > 1:
            downstream_claimed_pass = False
            for entry in auth_entries[1:]:
                for match in re.finditer(r"\b(?:spf|dkim|dmarc)\s*=\s*([a-zA-Z0-9_\-]+)", entry.value, re.IGNORECASE):
                    if match.group(1).lower() == "pass":
                        downstream_claimed_pass = True
                        break

            topmost_failed = any(
                getattr(result, f"{proto}_result") in ("fail", "softfail", "none", "temperror", "permerror", "unknown")
                for proto in ("spf", "dkim", "dmarc")
            )

            if downstream_claimed_pass and topmost_failed:
                result.findings.append(
                    Finding(
                        name="auth_results_spoofing_attempt",
                        severity="critical",
                        confidence="confirmed",
                        description=(
                            "Potential Authentication-Results injection detected: border MTA reported "
                            f"authentication issues (SPF={result.spf_result}, DKIM={result.dkim_result}, "
                            f"DMARC={result.dmarc_result}), while downstream header claimed authentication pass."
                        ),
                        evidence={
                            "border_authserv_id": border_authserv_id,
                            "total_auth_headers": len(auth_entries),
                            "downstream_headers": [h.value[:120] for h in auth_entries[1:]],
                        },
                    )
                )
            else:
                result.findings.append(
                    Finding(
                        name="multiple_authentication_results",
                        severity="medium",
                        confidence="suspicious",
                        description=(
                            f"Multiple ({len(auth_entries)}) Authentication-Results headers detected. "
                            "Only the outermost border MTA header was evaluated to defend against header spoofing."
                        ),
                        evidence={
                            "border_authserv_id": border_authserv_id,
                            "total_auth_headers": len(auth_entries),
                        },
                    )
                )

        # Generate findings for SPF, DKIM, DMARC
        self._auth_failure_finding(result, "spf")
        self._auth_failure_finding(result, "dkim")
        self._auth_failure_finding(result, "dmarc")

    @staticmethod
    def _normalize_auth_result(raw: str) -> str:
        """Map raw auth result strings to our canonical set."""
        mapping = {
            "pass": "pass",
            "fail": "fail",
            "softfail": "softfail",
            "neutral": "neutral",
            "none": "none",
            "temperror": "temperror",
            "permerror": "permerror",
            "hardfail": "fail",
        }
        return mapping.get(raw.lower(), "unknown")

    def _auth_failure_finding(self, result: HeaderAnalysisResult, protocol: str) -> None:
        """Add findings for SPF/DKIM/DMARC status."""
        value = getattr(result, f"{protocol}_result")
        if value == "fail":
            result.findings.append(
                Finding(
                    name=f"{protocol}_fail",
                    severity="high",
                    confidence="confirmed",
                    description=f"{protocol.upper()} authentication check failed — email may be spoofed.",
                    evidence={"result": value},
                )
            )
        elif value == "softfail":
            result.findings.append(
                Finding(
                    name=f"{protocol}_softfail",
                    severity="medium",
                    confidence="suspicious",
                    description=f"{protocol.upper()} softfail — sender host not explicitly authorized by domain policy.",
                    evidence={"result": value},
                )
            )
        elif value in ("temperror", "permerror"):
            result.findings.append(
                Finding(
                    name=f"{protocol}_{value}",
                    severity="low",
                    confidence="confirmed",
                    description=f"{protocol.upper()} returned {value} during DNS evaluation.",
                    evidence={"result": value},
                )
            )

    # ------------------------------------------------------------------
    # 2. Sender, Return-Path & Envelope Mismatch Forensics
    # ------------------------------------------------------------------

    def _check_sender_and_envelope(self, parsed: ParsedEmail, result: HeaderAnalysisResult) -> None:
        """
        Compare the From domain with Return-Path and SPF envelope domain.
        A mismatch indicates sender identity divergence.
        """
        from_domain = _extract_domain(parsed.from_email)
        rp_raw = _strip_angle_brackets(parsed.return_path)
        rp_domain = _extract_domain(rp_raw)
        spf_env_domain = result.spf_envelope_domain

        # Compare From vs Return-Path
        if from_domain and rp_domain and from_domain != rp_domain:
            result.sender_domain_mismatch = True
            result.findings.append(
                Finding(
                    name="sender_domain_mismatch",
                    severity="high",
                    confidence="confirmed",
                    description=(
                        f"From domain '{from_domain}' does not match Return-Path domain '{rp_domain}'."
                    ),
                    evidence={
                        "from_domain": from_domain,
                        "return_path_domain": rp_domain,
                        "from_email": parsed.from_email,
                        "return_path": parsed.return_path,
                    },
                )
            )

        # Compare From vs SPF envelope domain if different from Return-Path check
        if from_domain and spf_env_domain and from_domain != spf_env_domain and spf_env_domain != rp_domain:
            result.sender_domain_mismatch = True
            result.findings.append(
                Finding(
                    name="envelope_sender_mismatch",
                    severity="medium",
                    confidence="suspicious",
                    description=(
                        f"From domain '{from_domain}' does not match SPF envelope domain '{spf_env_domain}'."
                    ),
                    evidence={
                        "from_domain": from_domain,
                        "spf_envelope_domain": spf_env_domain,
                    },
                )
            )

    # ------------------------------------------------------------------
    # 3. Display-Name, Homoglyphs & Brand Impersonation Forensics
    # ------------------------------------------------------------------

    def _check_display_name_and_homoglyphs(self, parsed: ParsedEmail, result: HeaderAnalysisResult) -> None:
        """
        Detect display-name spoofing, embedded emails, brand impersonation,
        Cyrillic/Greek homoglyphs, and Punycode spoofing in domains or display names.
        """
        display_name = (parsed.from_display_name or "").strip()
        from_email = (parsed.from_email or "").strip().lower()
        from_domain = _extract_domain(from_email)

        # 1. Check embedded email address in display name
        embedded_match = _EMAIL_IN_DISPLAY_PATTERN.search(display_name)
        if embedded_match:
            spoofed_addr = embedded_match.group(0)
            spoofed_domain = _extract_domain(spoofed_addr)
            if spoofed_domain and spoofed_domain != from_domain:
                result.display_name_spoofing = True
                result.findings.append(
                    Finding(
                        name="display_name_email_spoof",
                        severity="critical",
                        confidence="confirmed",
                        description=(
                            f"Display name contains '{spoofed_addr}' but actual sender is "
                            f"'{from_email}'. Classic display-name spoofing."
                        ),
                        evidence={
                            "display_name": display_name,
                            "actual_email": from_email,
                            "spoofed_email": spoofed_addr,
                        },
                    )
                )
                return

        # 2. Check for Punycode domains (IDN)
        if "xn--" in from_domain:
            result.findings.append(
                Finding(
                    name="punycode_domain_detected",
                    severity="high",
                    confidence="confirmed",
                    description=f"Sender domain '{from_domain}' uses Punycode (IDN) encoding, frequently used in homograph phishing.",
                    evidence={"domain": from_domain},
                )
            )

        # 3. Check for Unicode / Homoglyphs in sender domain
        has_suspicious_homoglyph = False
        homoglyph_details = []
        for char in from_domain:
            if char in _HOMOGLYPH_MAP:
                has_suspicious_homoglyph = True
                homoglyph_details.append(f"U+{ord(char):04X} ('{char}' -> '{_HOMOGLYPH_MAP[char]}')")
            elif ord(char) > 127:
                cat = unicodedata.category(char)
                # Format characters (zero-width spaces, joiners)
                if cat in ("Cf", "Cc", "Cs"):
                    has_suspicious_homoglyph = True
                    homoglyph_details.append(f"Hidden/Control U+{ord(char):04X}")

        if has_suspicious_homoglyph:
            result.display_name_spoofing = True
            result.findings.append(
                Finding(
                    name="homoglyph_domain_spoof",
                    severity="critical",
                    confidence="confirmed",
                    description=f"Sender domain '{from_domain}' contains homoglyph/spoofed Unicode characters: {', '.join(homoglyph_details)}.",
                    evidence={
                        "domain": from_domain,
                        "homoglyphs": homoglyph_details,
                    },
                )
            )

        # 4. Check for Brand Impersonation in display name
        display_lower = display_name.lower()
        from_domain_clean = from_domain.replace(".", "").replace("-", "")
        for brand in _KNOWN_BRAND_NAMES:
            # Word boundary matching to avoid false positives (e.g., 'Appleby' or 'Supportive')
            pattern = rf"\b{re.escape(brand)}\b"
            if re.search(pattern, display_lower):
                brand_token = brand.replace(" ", "").replace("-", "")
                if brand_token not in from_domain_clean:
                    result.display_name_spoofing = True
                    result.findings.append(
                        Finding(
                            name="display_name_brand_impersonation",
                            severity="high",
                            confidence="suspicious",
                            description=(
                                f"Display name references brand '{brand}' but sender domain "
                                f"'{from_domain}' does not match."
                            ),
                            evidence={
                                "display_name": display_name,
                                "from_domain": from_domain,
                                "brand": brand,
                            },
                        )
                    )
                    break

        # 5. Lookalike visual substitutions in sender domain (e.g., 'paypaI.com', 'micros0ft.com')
        for p_brand in _PROTECTED_BRANDS:
            # Normalize visual substitutions
            normalized_domain = from_domain.lower()
            normalized_domain = normalized_domain.replace("0", "o").replace("1", "l").replace("vv", "w")
            if p_brand in normalized_domain and p_brand not in from_domain:
                result.findings.append(
                    Finding(
                        name="lookalike_domain_detected",
                        severity="high",
                        confidence="suspicious",
                        description=f"Sender domain '{from_domain}' appears to be a visual lookalike impersonating '{p_brand}'.",
                        evidence={
                            "domain": from_domain,
                            "impersonated_brand": p_brand,
                            "normalized_domain": normalized_domain,
                        },
                    )
                )
                break

    # ------------------------------------------------------------------
    # 4. Reply-To & Divergence Forensics
    # ------------------------------------------------------------------

    def _check_reply_to_mismatch(self, parsed: ParsedEmail, result: HeaderAnalysisResult) -> None:
        """
        Detect Reply-To domain differing from From domain, especially
        corporate sender domains redirecting responses to free webmail providers.
        """
        from_domain = _extract_domain(parsed.from_email)
        reply_to_domain = _extract_domain(parsed.reply_to)

        if reply_to_domain and from_domain and reply_to_domain != from_domain:
            result.reply_to_mismatch = True

            free_webmail_domains = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "proton.me", "protonmail.com"}
            is_suspicious_webmail = reply_to_domain in free_webmail_domains and from_domain not in free_webmail_domains

            severity = "high" if is_suspicious_webmail else "medium"
            description = (
                f"Corporate From domain '{from_domain}' diverts replies to free webmail domain '{reply_to_domain}'."
                if is_suspicious_webmail
                else f"Reply-To domain '{reply_to_domain}' differs from From domain '{from_domain}'."
            )

            result.findings.append(
                Finding(
                    name="reply_to_mismatch",
                    severity=severity,
                    confidence="confirmed" if is_suspicious_webmail else "suspicious",
                    description=description,
                    evidence={
                        "from_domain": from_domain,
                        "reply_to_domain": reply_to_domain,
                        "reply_to_raw": parsed.reply_to,
                        "diverts_to_free_webmail": is_suspicious_webmail,
                    },
                )
            )

    # ------------------------------------------------------------------
    # 5. Received Header Forensics & Routing
    # ------------------------------------------------------------------

    def _analyze_received_headers(self, parsed: ParsedEmail, result: HeaderAnalysisResult) -> None:
        """
        Parse and inspect all Received headers:
        - Hop count calculation (>10 suspicious, <=2 minimal, normal 3-8)
        - IP address extraction and classification (public, private, loopback, reserved)
        - Latency calculation between hops and clock skew anomaly detection.
        """
        received_headers = [h for h in parsed.headers if h.name.lower() == "received"]
        # Topmost Received header is the border MTA (latest hop); subsequent are earlier hops
        received_headers.sort(key=lambda h: h.position)
        result.routing_hops = len(received_headers)

        hops: list[RoutingHop] = []
        ip_regex = re.compile(r"\[([0-9a-fA-F:.]+)\]")
        by_regex = re.compile(r"\bby\s+([^\s;]+)", re.IGNORECASE)
        from_regex = re.compile(r"\bfrom\s+([^\s;]+)", re.IGNORECASE)

        for i, h in enumerate(received_headers):
            raw_val = h.value
            hop = RoutingHop(hop_number=i + 1)

            # Extract by and from hosts
            by_m = by_regex.search(raw_val)
            if by_m:
                hop.by_host = by_m.group(1).rstrip(";,")

            from_m = from_regex.search(raw_val)
            if from_m:
                hop.from_host = from_m.group(1).rstrip(";,")

            # Extract IP
            ip_m = ip_regex.search(raw_val)
            if ip_m:
                candidate_ip = ip_m.group(1)
                hop.relay_ip = candidate_ip
                hop.ip_type = _classify_ip(candidate_ip)

            # Extract timestamp after semicolon
            if ";" in raw_val:
                ts_str = raw_val.split(";")[-1].strip()
                hop.timestamp_raw = ts_str
                try:
                    dt = email.utils.parsedate_to_datetime(ts_str)
                    hop.timestamp_epoch = dt.timestamp()
                except Exception:
                    pass

            hops.append(hop)

        result.hops = hops

        # Latency calculations: compare chronologically (bottom to top)
        # Hop i is chronologically AFTER Hop i+1
        transit_delay_anomaly = False
        for i in range(len(hops) - 1):
            curr_hop = hops[i]       # later hop (closer to recipient)
            prev_hop = hops[i + 1]   # earlier hop (closer to sender)
            if curr_hop.timestamp_epoch is not None and prev_hop.timestamp_epoch is not None:
                delay = curr_hop.timestamp_epoch - prev_hop.timestamp_epoch
                curr_hop.delay_seconds = delay

                # If delay is significantly negative (< -300s / 5 minutes), clock skew or forged hop
                if delay < -300:
                    transit_delay_anomaly = True

        if result.routing_hops > 10:
            result.suspicious_routing = True
            result.findings.append(
                Finding(
                    name="suspicious_routing",
                    severity="low",
                    confidence="heuristic",
                    description=(
                        f"Email passed through {result.routing_hops} Received hops "
                        "(normal is fewer than 10). May indicate mail relay abuse or open relays."
                    ),
                    evidence={"hop_count": result.routing_hops},
                )
            )

        if transit_delay_anomaly:
            result.suspicious_routing = True
            result.findings.append(
                Finding(
                    name="transit_clock_skew_anomaly",
                    severity="medium",
                    confidence="suspicious",
                    description="Significant negative transit delay detected between relay hops. Indicates possible forged Received headers or severe clock skew.",
                    evidence={"hops_analyzed": len(hops)},
                )
            )

    # ------------------------------------------------------------------
    # 6. DMARC Strict & Relaxed Alignment Forensics
    # ------------------------------------------------------------------

    def _compute_dmarc_alignment(self, parsed: ParsedEmail, result: HeaderAnalysisResult) -> None:
        """
        Evaluate strict and relaxed DMARC identifier alignment for SPF and DKIM
        against the RFC-5322 From domain.

        Strict alignment: exact domain match (from_domain == auth_domain)
        Relaxed alignment: organizational root domain match (root_from == root_auth)
        """
        from_domain = _extract_domain(parsed.from_email)
        from_root = _extract_root_domain(from_domain)

        # 1. Evaluate SPF Alignment
        spf_domain = result.spf_envelope_domain or _extract_domain(_strip_angle_brackets(parsed.return_path))
        if spf_domain and result.spf_result == "pass":
            spf_root = _extract_root_domain(spf_domain)
            if from_domain == spf_domain:
                result.dmarc_spf_alignment = "strict"
            elif from_root == spf_root:
                result.dmarc_spf_alignment = "relaxed"
            else:
                result.dmarc_spf_alignment = "fail"
        elif result.spf_result == "pass":
            # Pass claimed without verifiable domain
            result.dmarc_spf_alignment = "unknown"
        else:
            result.dmarc_spf_alignment = "fail" if result.spf_result in ("fail", "softfail") else "unknown"

        # 2. Evaluate DKIM Alignment
        dkim_domain = result.dkim_signing_domain
        if dkim_domain and result.dkim_result == "pass":
            dkim_root = _extract_root_domain(dkim_domain)
            if from_domain == dkim_domain:
                result.dmarc_dkim_alignment = "strict"
            elif from_root == dkim_root:
                result.dmarc_dkim_alignment = "relaxed"
            else:
                result.dmarc_dkim_alignment = "fail"
        elif result.dkim_result == "pass":
            result.dmarc_dkim_alignment = "unknown"
        else:
            result.dmarc_dkim_alignment = "fail" if result.dkim_result == "fail" else "unknown"

        # 3. Overall Alignment Assessment
        if result.spf_result == "none" and result.dkim_result == "none" and result.dmarc_result == "none":
            result.auth_alignment = "unknown"
            return

        is_spf_aligned = result.dmarc_spf_alignment in ("strict", "relaxed")
        is_dkim_aligned = result.dmarc_dkim_alignment in ("strict", "relaxed")

        if result.dmarc_result == "pass" or is_spf_aligned or is_dkim_aligned:
            result.auth_alignment = "aligned"
        elif result.dmarc_result in ("fail", "softfail") or (result.dmarc_spf_alignment == "fail" and result.dmarc_dkim_alignment == "fail"):
            result.auth_alignment = "misaligned"
            result.findings.append(
                Finding(
                    name="dmarc_alignment_failure",
                    severity="high",
                    confidence="confirmed",
                    description=(
                        f"DMARC identifier alignment check failed. From domain '{from_domain}' "
                        f"does not align with SPF domain '{spf_domain}' ({result.dmarc_spf_alignment}) "
                        f"or DKIM signing domain '{dkim_domain}' ({result.dmarc_dkim_alignment})."
                    ),
                    evidence={
                        "from_domain": from_domain,
                        "spf_envelope_domain": spf_domain,
                        "spf_alignment": result.dmarc_spf_alignment,
                        "dkim_signing_domain": dkim_domain,
                        "dkim_alignment": result.dmarc_dkim_alignment,
                        "dmarc_result": result.dmarc_result,
                    },
                )
            )
        else:
            result.auth_alignment = "unknown"
