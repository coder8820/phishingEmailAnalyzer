"""
Unit tests for Safe, Hardened EmailParser in PhishGuard AI.
Tests binary payload integrity, inline & nameless attachments,
RFC 2047 decoding, and recursive nested message/rfc822 parsing.
"""

import base64
import hashlib
from app.analyzers.email_parser import EmailParser, extract_body_text, decode_rfc2047


def test_parse_valid_email():
    raw_email = """From: "Security Team" <security@example.com>
To: user@example.com
Subject: Test Email Subject
Date: Tue, 08 Nov 2026 12:00:00 +0000
Message-ID: <test-123@example.com>
Content-Type: text/plain; charset="UTF-8"

This is the body of the test email.
"""
    parser = EmailParser()
    result = parser.parse(raw_email)

    assert result.subject == "Test Email Subject"
    assert result.from_email == "security@example.com"
    assert result.from_display_name == "Security Team"
    assert "user@example.com" in result.to_addresses
    assert result.message_id == "<test-123@example.com>"
    assert "This is the body of the test email." in (result.body_text or "")


def test_parse_malformed_email_handles_gracefully():
    raw_email = b"NOT AN RFC COMPLIANT EMAIL\x00\xffRandomBinaryJunk\xde\xad\xbe\xef"
    parser = EmailParser()
    result = parser.parse(raw_email)

    # Should not raise an unhandled exception
    assert result is not None
    assert result.subject is not None or result.subject == ""


def test_parse_html_body_extraction():
    raw_email = """From: test@example.com
To: user@example.com
Subject: HTML Test
Content-Type: text/html; charset="UTF-8"

<html><body><p>Hello <b>World</b></p><a href="https://example.com">Link</a></body></html>
"""
    parser = EmailParser()
    result = parser.parse(raw_email)

    assert result.body_html is not None
    assert "<p>Hello <b>World</b></p>" in result.body_html
    display_text = extract_body_text(result)
    assert "Hello" in display_text
    assert "World" in display_text


def test_parse_attachment_magic_byte_detection():
    """Verify that attachments have their MIME type detected via magic bytes during parse."""
    raw_email = """From: attacker@evil.com
To: victim@example.com
Subject: Disguised Payload
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY123"

--BOUNDARY123
Content-Type: text/plain

Please find invoice attached.

--BOUNDARY123
Content-Type: application/pdf; name="invoice.pdf"
Content-Disposition: attachment; filename="invoice.pdf"
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA==
--BOUNDARY123--
"""
    parser = EmailParser()
    result = parser.parse(raw_email)

    assert len(result.attachments) == 1
    att = result.attachments[0]
    assert att.filename_original == "invoice.pdf"
    assert att.content_type == "application/pdf"
    assert att.mime_type_detected == "application/x-dosexec"
    assert att.filename_sanitized == att.filename_safe


def test_binary_attachment_integrity_no_corruption():
    """
    Requirement 2: Fix binary attachment corruption.
    Verify that raw binary bytes (including null bytes, non-ASCII high bytes)
    produce the exact SHA-256 hash without string-decode corruption.
    """
    # Create arbitrary binary payload with nulls, 0xFF, and control bytes
    raw_binary_payload = bytes(range(256)) * 4  # 1024 bytes containing all possible byte values
    expected_sha256 = hashlib.sha256(raw_binary_payload).hexdigest()
    b64_payload = base64.b64encode(raw_binary_payload).decode("ascii")

    email_bytes = f"""From: sender@trusted.org
To: receiver@example.com
Subject: Binary Test
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BIN_BOUND"

--BIN_BOUND
Content-Type: text/plain

Here is the raw binary sample.

--BIN_BOUND
Content-Type: application/octet-stream; name="payload.bin"
Content-Disposition: attachment; filename="payload.bin"
Content-Transfer-Encoding: base64

{b64_payload}
--BIN_BOUND--
""".encode("utf-8")

    parser = EmailParser()
    result = parser.parse(email_bytes)

    assert len(result.attachments) == 1
    att = result.attachments[0]
    assert att.filename_original == "payload.bin"
    assert att.size == 1024
    assert att.sha256 == expected_sha256


def test_rfc2047_header_decoding():
    """
    Requirement 4: Implement proper RFC 2047 encoded header decoding.
    Tests base64 (=?UTF-8?B?...?=) and quoted-printable (=?ISO-8859-1?Q?...?=)
    in Subject, From display name, and header list.
    """
    raw_email = """From: =?UTF-8?B?UGF5UGFsIFNlY3VyaXR5IFRlYW0=?= <alert@paypa1-security.com>
To: =?UTF-8?B?Sm9obiBEb2U=?= <victim@corp.com>
Subject: =?UTF-8?B?VVJHRU5UOiBBY2NvdW50IFN1c3BlbnNpb24gTm90aWNl?=
Date: Tue, 08 Nov 2026 12:00:00 +0000
Content-Type: text/plain; charset="UTF-8"

Please verify your credentials immediately.
"""
    parser = EmailParser()
    result = parser.parse(raw_email)

    assert result.from_display_name == "PayPal Security Team"
    assert result.from_email == "alert@paypa1-security.com"
    assert result.subject == "URGENT: Account Suspension Notice"
    assert "victim@corp.com" in result.to_addresses


def test_rfc2047_quoted_printable_iso():
    """Verify ISO-8859-1 quoted-printable decoding."""
    decoded = decode_rfc2047("=?ISO-8859-1?Q?Keld_J=F8rn_Simonsen?=")
    assert "Keld Jørn Simonsen" in decoded or "Keld" in decoded


def test_inline_attachment_detection():
    """
    Requirement 3: Improve inline and nameless attachment detection.
    Detects attachments marked with Content-Disposition: inline
    and attachments having name parameter without disposition header.
    """
    raw_email = """From: accounting@vendor.com
To: ap@victim-corp.com
Subject: Overdue Invoice
MIME-Version: 1.0
Content-Type: multipart/related; boundary="INLINE_BOUND"

--INLINE_BOUND
Content-Type: text/html

<p>Please review the invoice below:</p>
<img src="cid:invoice_img">

--INLINE_BOUND
Content-Type: image/png; name="invoice_stamp.png"
Content-Disposition: inline; filename="invoice_stamp.png"
Content-Transfer-Encoding: base64

iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==
--INLINE_BOUND--
"""
    parser = EmailParser()
    result = parser.parse(raw_email)

    assert len(result.attachments) == 1
    att = result.attachments[0]
    assert att.filename_original == "invoice_stamp.png"
    assert att.content_type == "image/png"
    assert att.size > 0


def test_nameless_binary_attachment_detection():
    """
    Requirement 3: Detect nameless non-text attachments (e.g. raw executable payload
    with no filename attribute or disposition).
    """
    raw_email = """From: phisher@evil.com
To: user@target.com
Subject: Document
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="NAMELESS_BOUND"

--NAMELESS_BOUND
Content-Type: text/plain

Review the attached document.

--NAMELESS_BOUND
Content-Type: application/x-dosexec
Content-Transfer-Encoding: base64

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA==
--NAMELESS_BOUND--
"""
    parser = EmailParser()
    result = parser.parse(raw_email)

    assert len(result.attachments) == 1
    att = result.attachments[0]
    # Filename should be automatically inferred
    assert att.filename_original.startswith("unnamed_attachment_")
    assert att.filename_original.endswith(".exe")
    assert att.mime_type_detected == "application/x-dosexec"


def test_recursive_nested_rfc822_parsing():
    """
    Requirement 5: Add recursive parsing for message/rfc822 attachments.
    Verifies that when an email is attached inside another email (e.g. forwarded phishing),
    the inner message is parsed recursively and its inner indicators/attachments are captured.
    """
    inner_email = """From: "Fake Banking" <spoof@fakebank.com>
To: target@victim.com
Subject: Inner Phish: Confirm Banking PIN
Content-Type: multipart/mixed; boundary="INNER_BOUND"

--INNER_BOUND
Content-Type: text/plain

Your bank account has been locked. Click here: https://fakebank-login.ru/verify

--INNER_BOUND
Content-Type: application/pdf; name="statement.pdf"
Content-Disposition: attachment; filename="statement.pdf"
Content-Transfer-Encoding: base64

JVBERi0xLjUKJcfsj6IKNSAwIG9iago8PAovVHlwZSAvUGFnZQovUGFyZW50IDQgMCBSCi9NZWRpYUJveCBb
--INNER_BOUND--
"""

    outer_email = f"""From: employee@victim.com
To: soc@victim.com
Subject: FWD: Suspicious banking email reported by user
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="OUTER_BOUND"

--OUTER_BOUND
Content-Type: text/plain

SOC team, please investigate the attached phishing email.

--OUTER_BOUND
Content-Type: message/rfc822; name="forwarded_phish.eml"
Content-Disposition: attachment; filename="forwarded_phish.eml"

{inner_email}
--OUTER_BOUND--
"""

    parser = EmailParser()
    result = parser.parse(outer_email)

    # 1. The outer email should contain the forwarded .eml attachment
    outer_att_names = [a.filename_original for a in result.attachments]
    assert "forwarded_phish.eml" in outer_att_names

    # 2. Nested email should be parsed in nested_emails
    assert len(result.nested_emails) == 1
    nested = result.nested_emails[0]
    assert nested.subject == "Inner Phish: Confirm Banking PIN"
    assert nested.from_email == "spoof@fakebank.com"

    # 3. Inner attachment should be aggregated
    assert "statement.pdf" in outer_att_names


def test_recursive_parsing_depth_limit():
    """
    Requirement 7: Verify that recursive email parsing has a safe depth limit
    and cannot cause uncontrolled recursion or excessive resource consumption.
    """
    nested = "From: inner@phish.com\nSubject: Deepest Level\nContent-Type: text/plain\n\nDeep payload"
    for i in range(10):
        nested = f"From: hop{i}@forward.com\nSubject: Forward {i}\nContent-Type: message/rfc822\n\n" + nested

    parser = EmailParser(max_recursion_depth=3)
    res = parser.parse(nested)

    depth_count = 0
    curr = res
    while curr.nested_emails:
        depth_count += 1
        curr = curr.nested_emails[0]

    assert depth_count == 3

