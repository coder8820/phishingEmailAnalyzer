"""
IOC (Indicator of Compromise) extractor for PhishGuard AI.

Extracts IPs, domains, URLs, email addresses, hashes, and filenames
from email content. All IOCs start at "suspicious" confidence — TI
lookups are required to confirm malicious classification.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from ipaddress import ip_address, IPv4Address, IPv6Address, AddressValueError

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

_IPV6_RE = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b|"
    r"\b::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}\b|"
    r"\b(?:[0-9a-fA-F]{1,4}:)*::[0-9a-fA-F]{1,4}\b"
)

_EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
)

_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")

_URL_RE = re.compile(
    r"(?:https?|ftp)://[^\s\[\]<>\"']+(?<![.,;:!?)\"'])",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Private IP ranges (RFC 1918, loopback, link-local, etc.)
# ---------------------------------------------------------------------------

_PRIVATE_NETWORKS_V4 = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",   # link-local
    "100.64.0.0/10",    # shared address space
    "0.0.0.0/8",
    "255.255.255.255/32",
]

_PRIVATE_V4_NETWORKS: list = []


def _load_private_networks() -> None:
    global _PRIVATE_V4_NETWORKS
    if _PRIVATE_V4_NETWORKS:
        return
    import ipaddress
    _PRIVATE_V4_NETWORKS = [ipaddress.ip_network(n, strict=False) for n in _PRIVATE_NETWORKS_V4]


def _is_private_ipv4(addr: str) -> bool:
    """Return True for RFC-1918 / reserved IPv4 addresses."""
    _load_private_networks()
    try:
        ip = ip_address(addr)
        return any(ip in net for net in _PRIVATE_V4_NETWORKS)
    except (AddressValueError, ValueError):
        return False


def _is_loopback_ipv6(addr: str) -> bool:
    try:
        return ip_address(addr) == ip_address("::1")
    except (AddressValueError, ValueError):
        return False


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class IOCItem:
    """A single extracted indicator of compromise."""

    ioc_type: str           # ipv4 | ipv6 | domain | url | email | sha256 | filename
    ioc_value: str
    source_location: str    # headers | body_text | url | attachment
    risk_level: str         # low | medium | high | critical
    confidence: str         # suspicious | heuristic | confirmed
    detection_reason: str


# ---------------------------------------------------------------------------
# Extractor
# ---------------------------------------------------------------------------


class IOCExtractor:
    """
    Extracts indicators of compromise from email content.

    Deduplicates by (ioc_type, ioc_value).
    Initial confidence is "suspicious" unless TI confirms malicious.
    """

    def extract(
        self,
        email_text: str,
        header_data: dict,
        url_findings: list,
        attachment_findings: list,
    ) -> list[IOCItem]:
        """
        Extract all IOCs from the available email data.

        Args:
            email_text: Combined plain-text body + header text.
            header_data: Dict with header metadata (from_email, return_path, etc.).
            url_findings: List of URLFinding objects or dicts.
            attachment_findings: List of AttachmentFinding objects or dicts.

        Returns:
            Deduplicated list of IOCItem.
        """
        seen: dict[tuple[str, str], IOCItem] = {}

        def _add(item: IOCItem) -> None:
            key = (item.ioc_type, item.ioc_value.lower())
            if key not in seen:
                seen[key] = item

        # --- IPs from body text ---
        for ip_str in _IPV4_RE.findall(email_text or ""):
            if not _is_private_ipv4(ip_str):
                _add(
                    IOCItem(
                        ioc_type="ipv4",
                        ioc_value=ip_str,
                        source_location="body_text",
                        risk_level="medium",
                        confidence="suspicious",
                        detection_reason="IPv4 address extracted from email body",
                    )
                )

        for ip_str in _IPV6_RE.findall(email_text or ""):
            if not _is_loopback_ipv6(ip_str):
                _add(
                    IOCItem(
                        ioc_type="ipv6",
                        ioc_value=ip_str,
                        source_location="body_text",
                        risk_level="medium",
                        confidence="suspicious",
                        detection_reason="IPv6 address extracted from email body",
                    )
                )

        # --- IPs from headers ---
        header_text = " ".join(str(v) for v in header_data.values())
        for ip_str in _IPV4_RE.findall(header_text):
            if not _is_private_ipv4(ip_str):
                _add(
                    IOCItem(
                        ioc_type="ipv4",
                        ioc_value=ip_str,
                        source_location="headers",
                        risk_level="medium",
                        confidence="suspicious",
                        detection_reason="IPv4 address found in email headers",
                    )
                )

        # --- Email addresses from body ---
        for email_addr in _EMAIL_RE.findall(email_text or ""):
            _add(
                IOCItem(
                    ioc_type="email",
                    ioc_value=email_addr.lower(),
                    source_location="body_text",
                    risk_level="low",
                    confidence="heuristic",
                    detection_reason="Email address extracted from body",
                )
            )

        # --- Sender email from headers ---
        from_email = header_data.get("from_email", "")
        if from_email:
            _add(
                IOCItem(
                    ioc_type="email",
                    ioc_value=from_email.lower(),
                    source_location="headers",
                    risk_level="low",
                    confidence="heuristic",
                    detection_reason="Sender email address from From: header",
                )
            )
            # Domain from sender
            domain = _domain_from_email(from_email)
            if domain:
                _add(
                    IOCItem(
                        ioc_type="domain",
                        ioc_value=domain.lower(),
                        source_location="headers",
                        risk_level="low",
                        confidence="heuristic",
                        detection_reason="Sender domain from From: header",
                    )
                )

        # --- SHA-256 hashes from body ---
        for hash_val in _SHA256_RE.findall(email_text or ""):
            _add(
                IOCItem(
                    ioc_type="sha256",
                    ioc_value=hash_val.lower(),
                    source_location="body_text",
                    risk_level="low",
                    confidence="heuristic",
                    detection_reason="SHA-256 hash found in email body",
                )
            )

        # --- URLs from url_findings ---
        for uf in url_findings:
            url_val = _get_attr(uf, "url_normalized") or _get_attr(uf, "url_raw", "")
            risk = _get_attr(uf, "risk_level", "low")
            domain = _get_attr(uf, "domain", "")

            if url_val:
                _add(
                    IOCItem(
                        ioc_type="url",
                        ioc_value=url_val,
                        source_location=_get_attr(uf, "source_location", "url"),
                        risk_level=risk,
                        confidence="suspicious",
                        detection_reason="URL extracted from email",
                    )
                )
            if domain:
                _add(
                    IOCItem(
                        ioc_type="domain",
                        ioc_value=domain.lower(),
                        source_location="url",
                        risk_level=risk,
                        confidence="suspicious",
                        detection_reason="Domain from extracted URL",
                    )
                )

        # --- Hashes and filenames from attachments ---
        for af in attachment_findings:
            sha256 = _get_attr(af, "sha256_hash", "")
            filename_original = _get_attr(af, "filename_original", "")
            risk = _get_attr(af, "risk_level", "low")

            if sha256 and len(sha256) == 64:
                _add(
                    IOCItem(
                        ioc_type="sha256",
                        ioc_value=sha256.lower(),
                        source_location="attachment",
                        risk_level=risk,
                        confidence="suspicious",
                        detection_reason=f"SHA-256 hash of attachment '{filename_original}'",
                    )
                )

            if filename_original:
                _add(
                    IOCItem(
                        ioc_type="filename",
                        ioc_value=filename_original,
                        source_location="attachment",
                        risk_level=risk,
                        confidence="heuristic",
                        detection_reason="Attachment filename",
                    )
                )

        return list(seen.values())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _domain_from_email(email_addr: str) -> str:
    """Extract domain portion from an email address."""
    if "@" in email_addr:
        return email_addr.split("@", 1)[-1].strip()
    return ""


def _get_attr(obj, attr: str, default=""):
    """Get an attribute from either a dataclass/object or dict."""
    if isinstance(obj, dict):
        return obj.get(attr, default)
    return getattr(obj, attr, default)
