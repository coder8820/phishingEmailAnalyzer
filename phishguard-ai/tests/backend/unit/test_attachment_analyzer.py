"""
Unit tests for AttachmentAnalyzer in PhishGuard AI.
"""
from app.analyzers.attachment_analyzer import AttachmentAnalyzer
from app.analyzers.email_parser import ParsedAttachment


def test_attachment_analyzer_dangerous_extensions():
    attachments = [
        ParsedAttachment(
            filename_original="invoice.pdf.exe",
            filename_safe="uuid_1.exe",
            content_type="application/octet-stream",
            size=1024,
            sha256="abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
        ),
        ParsedAttachment(
            filename_original="financial_macro.xlsm",
            filename_safe="uuid_2.xlsm",
            content_type="application/vnd.ms-excel.sheet.macroEnabled.12",
            size=4096,
            sha256="1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd",
        ),
        ParsedAttachment(
            filename_original="readme.txt",
            filename_safe="uuid_3.txt",
            content_type="text/plain",
            size=512,
            sha256="5678abcd5678abcd5678abcd5678abcd5678abcd5678abcd5678abcd5678abcd",
        ),
    ]

    analyzer = AttachmentAnalyzer()
    res = analyzer.analyze(attachments)

    assert res.total_count == 3
    assert res.high_risk_count >= 1

    exe_att = next(f for f in res.findings if f.filename_original == "invoice.pdf.exe")
    assert exe_att.is_executable is True
    assert exe_att.has_double_extension is True
    assert exe_att.risk_level in ("critical", "high")

    macro_att = next(f for f in res.findings if f.filename_original == "financial_macro.xlsm")
    assert macro_att.has_macro_indicator is True

    txt_att = next(f for f in res.findings if f.filename_original == "readme.txt")
    assert txt_att.is_executable is False
    assert txt_att.risk_level == "low"


def test_attachment_analyzer_magic_byte_disguised_executable():
    """
    Test that an attachment pretending to be a PDF or image (e.g. resume.pdf)
    with detected PE/DOS executable magic bytes is detected as a critical risk.
    """
    attachments = [
        ParsedAttachment(
            filename_original="resume.pdf",
            filename_safe="uuid_safe_1.pdf",
            content_type="application/pdf",
            size=2048,
            sha256="aabbccddeeff11223344556677889900aabbccddeeff11223344556677889900",
            mime_type_detected="application/x-dosexec",
        ),
        ParsedAttachment(
            filename_original="legit_document.pdf",
            filename_safe="uuid_safe_2.pdf",
            content_type="application/pdf",
            size=4096,
            sha256="11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
            mime_type_detected="application/pdf",
        ),
    ]

    analyzer = AttachmentAnalyzer()
    res = analyzer.analyze(attachments)

    disguised = next(f for f in res.findings if f.filename_original == "resume.pdf")
    assert disguised.is_executable is True
    assert disguised.mime_type_mismatch is True
    assert disguised.risk_level == "critical"
    assert any("executable" in reason.lower() for reason in disguised.detection_reasons)

    legit = next(f for f in res.findings if f.filename_original == "legit_document.pdf")
    assert legit.is_executable is False
    assert legit.mime_type_mismatch is False
    assert legit.risk_level == "low"

