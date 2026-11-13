"""
Attachment metadata analyzer for PhishGuard AI.

Performs static analysis on attachment metadata only.
NEVER executes, opens, or extracts attachment content.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field

from app.analyzers.email_parser import ParsedAttachment

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_EXECUTABLE_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".com",
    ".scr", ".pif", ".msi", ".hta", ".wsf", ".wsh", ".reg",
    ".dll", ".sys", ".cpl", ".lnk", ".inf",
}

_ARCHIVE_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
    ".tgz", ".z", ".cab", ".iso",
}

_MACRO_EXTENSIONS = {
    ".xlsm", ".xlsb", ".docm", ".dotm", ".pptm", ".potm",
    ".xlam", ".dotx", ".xltm", ".ppam", ".sldm",
}

_SAFE_EXTENSIONS = {
    ".pdf", ".txt", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".csv", ".json", ".xml", ".html", ".htm", ".md",
}

_EXECUTABLE_MIMES = {
    "application/x-dosexec",
    "application/x-msdownload",
    "application/x-executable",
    "application/x-sharedlib",
    "application/x-msi",
}

_ARCHIVE_MIMES = {
    "application/zip",
    "application/x-zip-compressed",
    "application/x-7z-compressed",
    "application/x-rar-compressed",
    "application/gzip",
    "application/x-tar",
    "application/x-bzip2",
    "application/x-xz",
}

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class AttachmentFinding:
    """Analysis result for a single email attachment."""

    filename_safe: str         # UUID-based, no path components
    filename_original: str
    extension: str
    mime_type_declared: str
    mime_type_detected: str    # from python-magic, or "unknown"
    file_size_bytes: int
    sha256_hash: str
    is_executable: bool = False
    is_archive: bool = False
    has_macro_indicator: bool = False
    has_double_extension: bool = False
    mime_type_mismatch: bool = False
    risk_level: str = "low"    # critical | high | medium | low
    detection_reasons: list[str] = field(default_factory=list)

    @property
    def filename_sanitized(self) -> str:
        """Alias for filename_safe to maintain pipeline compatibility."""
        return self.filename_safe


@dataclass
class AttachmentAnalysisResult:
    """Aggregated result for all attachments in an email."""

    findings: list[AttachmentFinding] = field(default_factory=list)
    high_risk_count: int = 0
    total_count: int = 0


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------


class AttachmentAnalyzer:
    """
    Analyzes attachment metadata for risk indicators.

    Security contract:
    - NEVER executes, opens, launches, or extracts attachment content.
    - Only reads already-computed metadata (filename, content-type, size, sha256).
    """

    def analyze(self, parsed_attachments: list[ParsedAttachment]) -> AttachmentAnalysisResult:
        """
        Evaluate risk for each parsed attachment.

        Args:
            parsed_attachments: List from EmailParser — only metadata is available.

        Returns:
            AttachmentAnalysisResult with per-file findings and aggregate counts.
        """
        result = AttachmentAnalysisResult()

        for attachment in parsed_attachments:
            try:
                finding = self._analyze_one(attachment)
                result.findings.append(finding)
            except Exception as exc:
                logger.error("AttachmentAnalyzer error on '%s': %s", attachment.filename_original, exc)

        result.total_count = len(result.findings)
        result.high_risk_count = sum(
            1 for f in result.findings if f.risk_level in ("critical", "high")
        )
        return result

    # ------------------------------------------------------------------
    # Single attachment
    # ------------------------------------------------------------------

    def _analyze_one(self, att: ParsedAttachment) -> AttachmentFinding:
        """Perform all checks on a single attachment's metadata."""
        name_lower = att.filename_original.lower()
        ext = self._primary_extension(name_lower)
        declared_mime = (att.content_type or "application/octet-stream").lower()
        detected_mime = getattr(att, "mime_type_detected", "unknown") or "unknown"

        finding = AttachmentFinding(
            filename_safe=att.filename_safe,
            filename_original=att.filename_original,
            extension=ext,
            mime_type_declared=declared_mime,
            mime_type_detected=detected_mime,
            file_size_bytes=att.size,
            sha256_hash=att.sha256,
        )

        # --- Executable checks (Extension & Magic Bytes) ---
        if ext in _EXECUTABLE_EXTENSIONS:
            finding.is_executable = True
            finding.detection_reasons.append(f"Executable extension: {ext}")
        if detected_mime.lower() in _EXECUTABLE_MIMES:
            finding.is_executable = True
            finding.detection_reasons.append(f"Executable binary identified via magic bytes: {detected_mime}")

        # --- Archive checks ---
        if ext in _ARCHIVE_EXTENSIONS:
            finding.is_archive = True
            finding.detection_reasons.append(f"Archive extension: {ext} (may contain malware)")
        elif detected_mime.lower() in _ARCHIVE_MIMES:
            finding.is_archive = True
            finding.detection_reasons.append(f"Archive format identified via magic bytes: {detected_mime}")

        # --- Macro ---
        if ext in _MACRO_EXTENSIONS:
            finding.has_macro_indicator = True
            finding.detection_reasons.append(f"Office macro-enabled format: {ext}")

        # --- Double extension ---
        if self._has_double_extension(name_lower):
            finding.has_double_extension = True
            finding.detection_reasons.append(
                f"Double extension detected in '{att.filename_original}' — classic masking technique"
            )

        # --- Disguised executable / Magic Byte mismatch ---
        if detected_mime.lower() in _EXECUTABLE_MIMES and (
            ext in _SAFE_EXTENSIONS or declared_mime.startswith(("image/", "text/", "application/pdf"))
        ):
            finding.mime_type_mismatch = True
            finding.detection_reasons.append(
                f"CRITICAL DISGUISED MALWARE: File claims extension '{ext}' / declared '{declared_mime}' "
                f"but magic bytes indicate executable binary ({detected_mime})"
            )
        elif (
            detected_mime != "unknown"
            and not detected_mime.startswith("expected:")
            and declared_mime not in ("application/octet-stream", "application/x-binary")
            and not declared_mime.startswith(detected_mime.split(";")[0])
            and not (detected_mime == "application/zip" and "openxmlformats" in declared_mime)
        ):
            finding.mime_type_mismatch = True
            finding.detection_reasons.append(
                f"Magic byte mismatch: declared '{declared_mime}' vs detected '{detected_mime}'"
            )

        # --- Extension vs Declared MIME mismatch ---
        expected_mime = self._extension_to_mime(ext)
        if expected_mime and not declared_mime.startswith(expected_mime):
            if declared_mime not in ("application/octet-stream", "application/x-binary"):
                finding.mime_type_mismatch = True
                if finding.mime_type_detected == "unknown":
                    finding.mime_type_detected = f"expected:{expected_mime}"
                finding.detection_reasons.append(
                    f"MIME type mismatch: declared '{declared_mime}' vs "
                    f"extension-expected '{expected_mime}'"
                )

        # --- Risk level ---
        finding.risk_level = self._compute_risk_level(finding)
        return finding

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _primary_extension(filename_lower: str) -> str:
        """Return the last extension (e.g. '.exe') from a filename."""
        _, ext = os.path.splitext(filename_lower)
        return ext

    @staticmethod
    def _has_double_extension(filename_lower: str) -> bool:
        """
        Detect double-extension masking such as 'invoice.pdf.exe'.
        Returns True when the second-to-last extension is a known safe type
        and the final extension is executable/dangerous.
        """
        parts = filename_lower.rsplit(".", maxsplit=3)
        if len(parts) < 3:
            return False

        # e.g. parts = ['invoice', 'pdf', 'exe']
        inner_ext = f".{parts[-2]}"
        outer_ext = f".{parts[-1]}"

        return inner_ext in _SAFE_EXTENSIONS and outer_ext in _EXECUTABLE_EXTENSIONS

    @staticmethod
    def _extension_to_mime(ext: str) -> str:
        """Return the expected MIME prefix for common extensions."""
        mapping = {
            ".pdf": "application/pdf",
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".gif": "image/gif",
            ".txt": "text/plain",
            ".html": "text/html",
            ".htm": "text/html",
            ".csv": "text/csv",
            ".json": "application/json",
            ".xml": "application/xml",
            ".zip": "application/zip",
            ".exe": "application/x-msdownload",
            ".ps1": "text/plain",
            ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        }
        return mapping.get(ext, "")

    @staticmethod
    def _compute_risk_level(finding: AttachmentFinding) -> str:
        """Determine risk level from individual indicators."""
        if finding.is_executable and finding.has_double_extension:
            return "critical"
        if finding.is_executable:
            return "critical"
        if finding.has_macro_indicator:
            return "high"
        if finding.has_double_extension:
            return "high"
        if finding.mime_type_mismatch:
            return "medium"
        if finding.is_archive:
            return "medium"
        return "low"
