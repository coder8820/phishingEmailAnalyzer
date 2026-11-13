"""
Magic byte detection module for PhishGuard AI.

Inspects raw binary buffers to identify actual file types independently
of declared MIME types or file extensions.

Provides a robust pure-Python signature engine with fallback to python-magic
if installed in the host environment.
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Try importing python-magic (optional host dependency)
try:
    import magic  # type: ignore

    _HAS_PYTHON_MAGIC = True
except Exception:
    _HAS_PYTHON_MAGIC = False


def detect_mime_type_from_bytes(data: bytes) -> str:
    """
    Detect the MIME type of a byte buffer using magic byte inspection.

    Args:
        data: Initial bytes of the file payload (recommended: at least 2048 bytes).

    Returns:
        Canonical MIME type string, or "unknown" if unrecognized.
    """
    if not data:
        return "unknown"

    # 1. Try python-magic if available
    if _HAS_PYTHON_MAGIC:
        try:
            detected = magic.from_buffer(data[:2048], mime=True)
            if detected and detected != "application/octet-stream":
                return detected
        except Exception as exc:
            logger.debug("python-magic detection error: %s", exc)

    # 2. Pure-Python signature evaluation
    buf = data[:2048]

    # Windows / DOS Executables (PE, EXE, DLL, SCR, SYS, OCX, CPL)
    if buf.startswith(b"MZ"):
        return "application/x-dosexec"

    # Linux / UNIX ELF Binaries
    if buf.startswith(b"\x7fELF"):
        return "application/x-executable"

    # Java Class / Mach-O Binaries
    if buf.startswith(b"\xca\xfe\xba\xbe") or buf.startswith(b"\xfe\xed\xfa\xce") or buf.startswith(b"\xfe\xed\xfa\xcf"):
        return "application/java-archive"

    # PDF Documents
    if buf.startswith(b"%PDF"):
        return "application/pdf"

    # Microsoft Compound File Binary Format (Legacy Word, Excel, PowerPoint, MSI)
    if buf.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "application/x-ole-storage"

    # ZIP archives & modern OpenXML Office docs (DOCX, XLSX, PPTX, JAR, APK)
    if buf.startswith(b"PK\x03\x04") or buf.startswith(b"PK\x05\x06") or buf.startswith(b"PK\x07\x08"):
        if b"word/" in buf:
            return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        if b"xl/" in buf:
            return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        if b"ppt/" in buf:
            return "application/vnd.openxmlformats-officedocument.presentationml.presentation"
        return "application/zip"

    # 7-Zip
    if buf.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "application/x-7z-compressed"

    # RAR
    if buf.startswith(b"Rar!\x1a\x07\x00") or buf.startswith(b"Rar!\x1a\x07\x01\x00"):
        return "application/x-rar-compressed"

    # GZIP
    if buf.startswith(b"\x1f\x8b"):
        return "application/gzip"

    # BZIP2
    if buf.startswith(b"BZh"):
        return "application/x-bzip2"

    # XZ
    if buf.startswith(b"\xfd7zXZ\x00"):
        return "application/x-xz"

    # TAR (posix tar has 'ustar' at offset 257)
    if len(buf) > 262 and buf[257:262] == b"ustar":
        return "application/x-tar"

    # Images
    if buf.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if buf.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if buf.startswith(b"GIF87a") or buf.startswith(b"GIF89a"):
        return "image/gif"
    if buf.startswith(b"RIFF") and len(buf) >= 12 and buf[8:12] == b"WEBP":
        return "image/webp"
    if buf.startswith(b"\x00\x00\x01\x00"):
        return "image/x-icon"
    if buf.startswith(b"BM"):
        return "image/bmp"

    # Scripts & Text formats
    if buf.startswith(b"#!"):
        return "text/x-shellscript"

    stripped = buf.lstrip()
    if stripped.lower().startswith(b"<!doctype html") or stripped.lower().startswith(b"<html"):
        return "text/html"
    if stripped.startswith(b"<?xml"):
        return "application/xml"

    return "unknown"
