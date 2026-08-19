"""Unit tests for Attachment Static Forensics & Archive Inspection."""

import zipfile
import io
from core.attachment_forensics import (
    analyze_single_attachment,
    calculate_entropy,
    detect_magic_bytes,
    check_double_extension,
)


def test_magic_bytes_detection():
    pe_payload = b"MZ\x90\x00\x03\x00\x00\x00"
    mime, desc = detect_magic_bytes(pe_payload)
    assert "application/x-dosexec" in mime
    assert "PE Executable" in desc

    pdf_payload = b"%PDF-1.5 \n%..."
    mime, desc = detect_magic_bytes(pdf_payload)
    assert "application/pdf" in mime


def test_double_extension_detection():
    assert check_double_extension("invoice.pdf.exe") is not None
    assert check_double_extension("statement.docx.lnk") is not None
    assert check_double_extension("report.pdf") is None


def test_file_masquerading():
    # File named invoice.pdf containing PE header
    fake_pdf = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 100
    res = analyze_single_attachment({"filename": "invoice.pdf"}, fake_pdf)
    assert res["is_risky"] is True
    assert any(f.get("category") == "file_masquerading" for f in res["findings"])


def test_safe_zip_archive_inspection():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("document.pdf", b"normal pdf data")
        zf.writestr("malicious_script.vbs", b"WScript.Echo 'payload'")

    zip_bytes = buf.getvalue()
    res = analyze_single_attachment({"filename": "archive.zip"}, zip_bytes)
    assert res["is_risky"] is True
    assert res["archive_details"]["is_archive"] is True
    assert "malicious_script.vbs" in res["archive_details"]["risky_files"]
