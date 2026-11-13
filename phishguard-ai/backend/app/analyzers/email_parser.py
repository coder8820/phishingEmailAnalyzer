"""
Safe, hardened RFC-822 / MIME email parser for PhishGuard AI.

Uses Python standard-library `email` with BytesParser(policy=policy.default).
Never executes or renders parsed content.
Accurately preserves binary payloads for uncorrupted SHA-256 and magic detection.
Detects inline and nameless attachments, decodes RFC 2047 headers,
and recursively parses message/rfc822 nested emails.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from email import policy
from email.header import decode_header, make_header
from email.parser import BytesParser
from email.utils import parseaddr, parsedate_to_datetime
from typing import Optional, Union

from app.analyzers.magic_detector import detect_mime_type_from_bytes

logger = logging.getLogger(__name__)

# Hard limit on body size (5 MB)
_MAX_BODY_BYTES = 5 * 1024 * 1024

# MIME to default extension mapping for nameless attachments
_MIME_EXTENSION_MAP: dict[str, str] = {
    "application/pdf": ".pdf",
    "application/x-dosexec": ".exe",
    "application/x-msdownload": ".exe",
    "application/x-executable": ".elf",
    "application/zip": ".zip",
    "application/x-zip-compressed": ".zip",
    "application/x-rar-compressed": ".rar",
    "application/x-7z-compressed": ".7z",
    "application/x-tar": ".tar",
    "application/gzip": ".gz",
    "application/x-bzip2": ".bz2",
    "application/x-iso9660-image": ".iso",
    "application/msword": ".doc",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/vnd.ms-excel": ".xls",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
    "application/vnd.ms-powerpoint": ".ppt",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": ".pptx",
    "application/octet-stream": ".bin",
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/gif": ".gif",
    "image/svg+xml": ".svg",
    "message/rfc822": ".eml",
    "text/html": ".html",
    "text/plain": ".txt",
}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class ParsedAttachment:
    """Metadata for a single email attachment. Payload bytes are discarded after hashing."""

    filename_original: str
    filename_safe: str  # UUID-based, no path components
    content_type: str
    size: int
    sha256: str
    mime_type_detected: str = "unknown"

    @property
    def filename_sanitized(self) -> str:
        """Alias for filename_safe to maintain full pipeline compatibility."""
        return self.filename_safe


@dataclass
class HeaderEntry:
    """A single email header with its ordinal position."""

    name: str
    value: str
    position: int


@dataclass
class ParsedEmail:
    """
    Structured representation of a parsed RFC-822 email.

    - body_html is stored as a plain string — it is NEVER rendered or executed.
    - attachments only carry metadata; raw bytes are not retained.
    - nested_emails contains recursively parsed message/rfc822 attachments.
    """

    headers: list[HeaderEntry] = field(default_factory=list)
    from_raw: str = ""
    from_email: str = ""
    from_display_name: str = ""
    reply_to: str = ""
    return_path: str = ""
    to_addresses: list[str] = field(default_factory=list)
    cc_addresses: list[str] = field(default_factory=list)
    subject: str = ""
    date: Optional[datetime] = None
    message_id: str = ""
    body_text: Optional[str] = None
    body_html: Optional[str] = None
    attachments: list[ParsedAttachment] = field(default_factory=list)
    nested_emails: list[ParsedEmail] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------


def decode_rfc2047(value: Optional[str]) -> str:
    """
    Safely decode RFC 2047 encoded words in email headers.
    Handles multi-charset chunks, malformed words, and raw text seamlessly.
    """
    if not value:
        return ""
    str_val = str(value).strip()
    if "=?" not in str_val:
        return str_val

    try:
        decoded_parts = decode_header(str_val)
        return str(make_header(decoded_parts))
    except Exception as exc:
        logger.debug("decode_rfc2047 error on '%s': %s", str_val, exc)
        return str_val


def _sanitize_original_name(name: str) -> str:
    """Remove path components and null bytes from an attachment filename for safe display."""
    if not name:
        return "unnamed_attachment"
    cleaned = decode_rfc2047(name)
    cleaned = cleaned.replace("\x00", "").replace("\\", "/")
    cleaned = cleaned.split("/")[-1].strip()
    return cleaned[:200] if cleaned else "unnamed_attachment"


def _infer_extension(content_type: str, detected_mime: str) -> str:
    """Infer file extension from declared and detected MIME types."""
    if detected_mime and detected_mime in _MIME_EXTENSION_MAP:
        return _MIME_EXTENSION_MAP[detected_mime]
    if content_type and content_type in _MIME_EXTENSION_MAP:
        return _MIME_EXTENSION_MAP[content_type]
    return ".bin"


def extract_body_text(parsed: ParsedEmail) -> str:
    """
    Return a displayable plain-text representation of the email body.

    Prefers body_text; falls back to HTML with tags stripped via BeautifulSoup or regex.
    """
    if parsed.body_text:
        return parsed.body_text

    if parsed.body_html:
        try:
            from bs4 import BeautifulSoup  # type: ignore

            soup = BeautifulSoup(parsed.body_html, "html.parser")
            return soup.get_text(separator="\n")
        except Exception as exc:
            logger.debug("HTML strip error: %s", exc)
            import re

            return re.sub(r"<[^>]+>", " ", parsed.body_html)

    return ""


# ---------------------------------------------------------------------------
# Safe Email Parser
# ---------------------------------------------------------------------------


class EmailParser:
    """
    Safe parser for RFC-822 email content.

    Features:
    - Uses BytesParser(policy=policy.default) to eliminate string-decode corruption.
    - Accurately preserves raw binary payloads for cryptographic SHA-256 and magic detection.
    - Accurately detects explicit, inline, and nameless attachments.
    - Decodes RFC 2047 encoded words in all headers, display names, and subjects.
    - Recursively parses attached forwarded emails (message/rfc822).
    """

    def __init__(self, max_recursion_depth: int = 3):
        self._max_recursion_depth = max_recursion_depth

    def parse(
        self,
        raw_content: Union[str, bytes],
        current_depth: int = 0,
    ) -> ParsedEmail:
        """
        Parse raw RFC-822 email string or bytes into a structured ParsedEmail.

        Args:
            raw_content: Full email content as bytes or string.
            current_depth: Current recursion depth for nested message/rfc822 parsing.

        Returns:
            ParsedEmail with populated headers, sender metadata, body, and attachments.
        """
        result = ParsedEmail()

        # Normalize input to bytes without destructive string conversions
        if isinstance(raw_content, bytes):
            raw_bytes = raw_content
        elif isinstance(raw_content, str):
            raw_bytes = raw_content.encode("utf-8", errors="surrogateescape")
        else:
            logger.warning("EmailParser received unsupported type: %s", type(raw_content))
            return result

        try:
            # Primary parse using modern BytesParser with default RFC policy
            msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
        except Exception as exc:
            logger.warning("BytesParser(policy.default) failed (%s); falling back to compat32", exc)
            try:
                msg = BytesParser(policy=policy.compat32).parsebytes(raw_bytes)
            except Exception as fatal_exc:
                logger.error("EmailParser fatal parse error: %s", fatal_exc, exc_info=True)
                return result

        try:
            self._extract_headers(msg, result)
            self._extract_addresses(msg, result)
            self._extract_metadata(msg, result)
            self._extract_body_and_attachments(msg, result, current_depth)
        except Exception as exc:
            logger.error("EmailParser: unhandled error during extraction — %s", exc, exc_info=True)

        return result

    # ------------------------------------------------------------------
    # Extraction Helpers
    # ------------------------------------------------------------------

    def _extract_headers(self, msg, result: ParsedEmail) -> None:
        """Extract all headers with RFC 2047 decoding and ordinal positions."""
        try:
            for position, (name, value) in enumerate(msg.items()):
                raw_val = str(value) if value is not None else ""
                decoded_val = decode_rfc2047(raw_val)
                result.headers.append(
                    HeaderEntry(
                        name=str(name),
                        value=decoded_val,
                        position=position,
                    )
                )
        except Exception as exc:
            logger.warning("Header extraction error: %s", exc)

    def _extract_addresses(self, msg, result: ParsedEmail) -> None:
        """Parse and decode From, Reply-To, Return-Path, To, and Cc."""
        # 1. From Header
        try:
            from_raw = str(msg.get("From", "") or "")
            decoded_from = decode_rfc2047(from_raw)
            result.from_raw = decoded_from
            display_name, email_addr = parseaddr(decoded_from)
            result.from_display_name = display_name or ""
            result.from_email = (email_addr or "").strip().lower()
        except Exception as exc:
            logger.warning("From-address parse error: %s", exc)

        # 2. Reply-To
        try:
            reply_to_raw = str(msg.get("Reply-To", "") or "")
            result.reply_to = decode_rfc2047(reply_to_raw)
        except Exception:
            pass

        # 3. Return-Path
        try:
            return_path_raw = str(msg.get("Return-Path", "") or "")
            result.return_path = decode_rfc2047(return_path_raw)
        except Exception:
            pass

        # 4. To Addresses
        try:
            to_headers = msg.get_all("To") or []
            for to_hdr in to_headers:
                decoded_to = decode_rfc2047(str(to_hdr))
                for part in decoded_to.split(","):
                    _, addr = parseaddr(part.strip())
                    if addr and addr not in result.to_addresses:
                        result.to_addresses.append(addr.strip().lower())
        except Exception as exc:
            logger.warning("To-address parse error: %s", exc)

        # 5. Cc Addresses
        try:
            cc_headers = msg.get_all("Cc") or []
            for cc_hdr in cc_headers:
                decoded_cc = decode_rfc2047(str(cc_hdr))
                for part in decoded_cc.split(","):
                    _, addr = parseaddr(part.strip())
                    if addr and addr not in result.cc_addresses:
                        result.cc_addresses.append(addr.strip().lower())
        except Exception as exc:
            logger.warning("Cc-address parse error: %s", exc)

    def _extract_metadata(self, msg, result: ParsedEmail) -> None:
        """Extract decoded Subject, Date, and Message-ID."""
        try:
            subj_raw = str(msg.get("Subject", "") or "")
            result.subject = decode_rfc2047(subj_raw)
        except Exception:
            pass

        try:
            date_raw = str(msg.get("Date", "") or "")
            if date_raw:
                result.date = parsedate_to_datetime(date_raw)
        except Exception as exc:
            logger.debug("Date parse error: %s", exc)

        try:
            result.message_id = str(msg.get("Message-ID", "") or "").strip()
        except Exception:
            pass

    def _extract_body_and_attachments(
        self,
        msg,
        result: ParsedEmail,
        current_depth: int,
    ) -> None:
        """Walk MIME parts with support for binary integrity, inline items, and nested emails."""
        try:
            if msg.is_multipart():
                nested_child_ids: set[int] = set()
                for part in msg.walk():
                    # Skip children that belong to an already handled message/rfc822 nested email
                    if id(part) in nested_child_ids:
                        continue

                    content_type = (part.get_content_type() or "text/plain").lower()

                    # Handle message/rfc822 attached emails directly (even if is_multipart is True)
                    if content_type == "message/rfc822":
                        if part.is_multipart():
                            for subpart in part.walk():
                                if id(subpart) != id(part):
                                    nested_child_ids.add(id(subpart))
                        self._process_single_part(part, result, current_depth)
                        continue

                    # Skip structural container multipart boundaries (multipart/mixed, multipart/alternative, etc.)
                    if part.is_multipart():
                        continue

                    self._process_single_part(part, result, current_depth)
            else:
                self._process_single_part(msg, result, current_depth)
        except Exception as exc:
            logger.warning("Body/Attachment extraction walk error: %s", exc)


    def _process_single_part(
        self,
        part,
        result: ParsedEmail,
        current_depth: int,
    ) -> None:
        """Inspect a single MIME part, accurately distinguishing body content from attachments."""
        try:
            content_type = (part.get_content_type() or "text/plain").lower()
            disposition = (part.get_content_disposition() or "").lower()

            raw_filename = part.get_filename() or part.get_param("name") or ""
            filename = decode_rfc2047(raw_filename).strip() if raw_filename else ""

            # -------------------------------------------------------------
            # Case 1: Nested Forwarded Email (message/rfc822)
            # -------------------------------------------------------------
            if content_type == "message/rfc822":
                self._handle_nested_email(part, filename, result, current_depth)
                return

            # -------------------------------------------------------------
            # Case 2: Attachment Detection (Explicit, Inline, or Nameless)
            # -------------------------------------------------------------
            is_attachment = self._is_attachment_part(part, content_type, disposition, filename)

            if is_attachment:
                self._handle_attachment(part, content_type, filename, result)
                return

            # -------------------------------------------------------------
            # Case 3: Email Body Content (text/plain & text/html)
            # -------------------------------------------------------------
            if content_type == "text/plain" and result.body_text is None:
                text_payload = self._decode_text_payload(part)
                if text_payload:
                    result.body_text = text_payload[:_MAX_BODY_BYTES]

            elif content_type == "text/html" and result.body_html is None:
                html_payload = self._decode_text_payload(part)
                if html_payload:
                    # Stored as plain string — NEVER rendered or executed
                    result.body_html = html_payload[:_MAX_BODY_BYTES]

        except Exception as exc:
            logger.debug("Part processing error: %s", exc)

    def _is_attachment_part(
        self,
        part,
        content_type: str,
        disposition: str,
        filename: str,
    ) -> bool:
        """
        Deterministic identification of attachments.
        Captures explicit attachments, inline files with names, and nameless non-text binaries.
        """
        # Explicit attachment disposition
        if disposition == "attachment":
            return True

        # Has a declared filename and is not a plain container
        if filename:
            # Even if disposition is inline or absent, if it has a filename it is an attachment
            # unless it's the primary text body without disposition
            if disposition == "inline" or content_type not in ("text/plain", "text/html"):
                return True
            if disposition != "" and content_type in ("text/plain", "text/html"):
                return True

        # Non-text payload types (application/*, image/*, audio/*, video/*)
        if content_type.startswith(("application/", "image/", "audio/", "video/", "font/")):
            return True

        # Inline binary payload without filename
        if disposition == "inline" and content_type not in ("text/plain", "text/html"):
            return True

        return False

    def _handle_attachment(
        self,
        part,
        content_type: str,
        filename: str,
        result: ParsedEmail,
    ) -> None:
        """
        Extract attachment metadata, compute uncorrupted SHA-256 and detect MIME magic bytes.
        Raw payload bytes are strictly discarded after hashing.
        """
        try:
            payload_bytes = self._extract_raw_payload_bytes(part)
            size = len(payload_bytes)
            sha256_hash = hashlib.sha256(payload_bytes).hexdigest()

            # Magic byte detection from first 2048 bytes
            detected_mime = detect_mime_type_from_bytes(payload_bytes[:2048])

            # Nameless attachment handling
            if not filename:
                ext = _infer_extension(content_type, detected_mime)
                nameless_idx = len(result.attachments) + 1
                filename = f"unnamed_attachment_{nameless_idx}{ext}"

            safe_filename = f"{uuid.uuid4()}_attachment"

            attachment = ParsedAttachment(
                filename_original=_sanitize_original_name(filename),
                filename_safe=safe_filename,
                content_type=content_type,
                size=size,
                sha256=sha256_hash,
                mime_type_detected=detected_mime,
            )
            result.attachments.append(attachment)
            # Payload bytes explicitly discarded here to free memory
        except Exception as exc:
            logger.warning("Attachment processing error: %s", exc)

    def _handle_nested_email(
        self,
        part,
        filename: str,
        result: ParsedEmail,
        current_depth: int,
    ) -> None:
        """
        Handle attached message/rfc822 forwarded emails:
        1. Catalog the attached .eml file as an attachment with SHA-256.
        2. Recursively parse the inner email up to max_recursion_depth.
        3. Aggregate nested indicators for comprehensive SOC threat evaluation.
        """
        try:
            # 1. Extract raw inner message bytes
            raw_inner_bytes = b""
            inner_payload = part.get_payload()

            if isinstance(inner_payload, list) and inner_payload:
                sub_msg = inner_payload[0]
                if hasattr(sub_msg, "as_bytes"):
                    raw_inner_bytes = sub_msg.as_bytes()
            elif hasattr(part, "get_payload") and callable(part.get_payload):
                decoded = part.get_payload(decode=True)
                if isinstance(decoded, bytes):
                    raw_inner_bytes = decoded

            if not raw_inner_bytes and hasattr(part, "as_bytes"):
                raw_inner_bytes = part.as_bytes()

            # 2. Treat the forwarded .eml as an attachment
            display_name = filename or "forwarded_message.eml"
            sha256_hash = hashlib.sha256(raw_inner_bytes).hexdigest()

            attachment = ParsedAttachment(
                filename_original=_sanitize_original_name(display_name),
                filename_safe=f"{uuid.uuid4()}_forwarded_eml",
                content_type="message/rfc822",
                size=len(raw_inner_bytes),
                sha256=sha256_hash,
                mime_type_detected="message/rfc822",
            )
            result.attachments.append(attachment)

            # 3. Recursive parse
            if current_depth < self._max_recursion_depth and raw_inner_bytes:
                nested_parsed = self.parse(raw_inner_bytes, current_depth=current_depth + 1)
                result.nested_emails.append(nested_parsed)

                # Inherit nested attachments
                for nested_att in nested_parsed.attachments:
                    result.attachments.append(nested_att)

                # If parent body is empty, surface nested body for URL & text analysis
                if not result.body_text and nested_parsed.body_text:
                    result.body_text = (
                        f"[Forwarded Message - Subject: {nested_parsed.subject}]\n"
                        f"{nested_parsed.body_text}"
                    )
                if not result.body_html and nested_parsed.body_html:
                    result.body_html = nested_parsed.body_html

        except Exception as exc:
            logger.warning("Nested email extraction error: %s", exc)

    def _extract_raw_payload_bytes(self, part) -> bytes:
        """Extract uncorrupted raw bytes from a MIME part payload."""
        try:
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                return payload
            if isinstance(payload, str):
                return payload.encode("utf-8", errors="replace")

            raw = part.get_payload()
            if isinstance(raw, bytes):
                return raw
            if isinstance(raw, str):
                charset = part.get_content_charset() or "utf-8"
                return raw.encode(charset, errors="replace")
            return b""
        except Exception as exc:
            logger.debug("Raw payload bytes extraction error: %s", exc)
            return b""

    def _decode_text_payload(self, part) -> Optional[str]:
        """Decode a text MIME part payload safely without crashing."""
        try:
            payload_bytes = part.get_payload(decode=True)
            if payload_bytes is None:
                raw_str = part.get_payload()
                return str(raw_str) if raw_str else None

            if isinstance(payload_bytes, str):
                return payload_bytes

            charset = part.get_content_charset() or "utf-8"
            try:
                return payload_bytes.decode(charset)
            except (UnicodeDecodeError, LookupError):
                try:
                    return payload_bytes.decode("utf-8", errors="replace")
                except Exception:
                    return payload_bytes.decode("latin-1", errors="replace")
        except Exception as exc:
            logger.debug("Text payload decode error: %s", exc)
            return None
