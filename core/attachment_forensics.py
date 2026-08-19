"""
Safe Attachment Forensics & Static Inspection Engine
----------------------------------------------------
Performs safe static inspection of email attachments: multi-hashing (SHA256/SHA1/MD5),
magic byte header verification, double extension detection, masquerading analysis,
entropy calculation, and archive inspection without execution.
"""

import math
import hashlib
from typing import Dict, Any, List, Optional, Tuple

from core.archive_inspector import inspect_zip_bytes, inspect_tar_bytes

# Magic Byte Signatures
MAGIC_SIGNATURES = [
    (b"MZ", "application/x-dosexec", "PE Executable (EXE/DLL/SCR)"),
    (b"%PDF", "application/pdf", "PDF Document"),
    (b"PK\x03\x04", "application/zip", "ZIP Archive / Office Document"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/x-ole-storage", "OLE2 Compound Document (Legacy Office/Macro)"),
    (b"\x7fELF", "application/x-executable", "Linux ELF Binary"),
    (b"\x52\x61\x72\x21\x1a\x07", "application/x-rar", "RAR Archive"),
    (b"\x37\x7a\xbc\xaf\x27\x1c", "application/x-7z-compressed", "7-Zip Archive"),
    (b"\x1f\x8b", "application/gzip", "GZIP Compressed File"),
    (b"{\\rtf", "application/rtf", "RTF Rich Text Format"),
]

# High-Risk Executable and Script Extensions
DANGEROUS_EXTENSIONS = {
    ".exe": "Windows Executable",
    ".scr": "Screensaver Executable",
    ".bat": "Batch Script",
    ".cmd": "Command Script",
    ".ps1": "PowerShell Script",
    ".vbs": "VBScript",
    ".vbe": "Encoded VBScript",
    ".js": "JavaScript",
    ".jse": "Encoded JavaScript",
    ".hta": "HTML Application",
    ".wsf": "Windows Script File",
    ".wsh": "Windows Script Host",
    ".lnk": "Windows Shortcut",
    ".iso": "Disk Image",
    ".img": "Disk Image",
    ".vhd": "Virtual Hard Disk",
    ".dll": "Dynamic Link Library",
    ".jar": "Java Executable Archive",
    ".docm": "Word Macro-Enabled Document",
    ".xlsm": "Excel Macro-Enabled Spreadsheet",
    ".pptm": "PowerPoint Macro-Enabled Presentation",
    ".html": "HTML Document / Phishing Lure",
    ".htm": "HTML Document / Phishing Lure",
    ".svg": "Scalable Vector Graphic (Potential JS Injection)",
}

BENIGN_OFFICE_EXTENSIONS = {".docx", ".xlsx", ".pptx", ".pdf", ".txt", ".csv", ".png", ".jpg", ".jpeg"}


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte array (0.0 to 8.0). High entropy (>7.2) indicates packing/encryption."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def detect_magic_bytes(payload: bytes) -> Tuple[Optional[str], Optional[str]]:
    """Inspect leading magic bytes to identify true file type."""
    if not payload:
        return None, None
    for sig, mime, desc in MAGIC_SIGNATURES:
        if payload.startswith(sig):
            return mime, desc
    return None, None


def check_double_extension(filename: str) -> Optional[str]:
    """Detect double extension spoofing (e.g. invoice.pdf.exe, report.docx.lnk)."""
    parts = filename.lower().split(".")
    if len(parts) >= 3:
        penultimate = f".{parts[-2]}"
        final = f".{parts[-1]}"
        if penultimate in BENIGN_OFFICE_EXTENSIONS and final in DANGEROUS_EXTENSIONS:
            return f"Double extension trick detected: fake '{penultimate}' masked by dangerous '{final}'"
    return None


def analyze_single_attachment(att_dict: Dict[str, Any], payload: Optional[bytes] = None) -> Dict[str, Any]:
    """
    Perform deep static analysis of an email attachment.
    """
    filename = att_dict.get("filename", "unknown")
    fn_lower = filename.lower()
    size = att_dict.get("size", len(payload) if payload else 0)

    # Compute hashes
    sha256 = att_dict.get("sha256")
    sha1 = None
    md5 = None
    if payload:
        sha256 = hashlib.sha256(payload).hexdigest()
        sha1 = hashlib.sha1(payload).hexdigest()
        md5 = hashlib.md5(payload).hexdigest()

    findings = []
    attachment_score = 0
    entropy = calculate_entropy(payload) if payload else None

    # 1. Magic bytes & true file type
    magic_mime, magic_desc = detect_magic_bytes(payload) if payload else (None, None)

    # 2. Dangerous Extension Check
    matched_danger_ext = None
    for ext, desc in DANGEROUS_EXTENSIONS.items():
        if fn_lower.endswith(ext):
            matched_danger_ext = ext
            findings.append({
                "flag": True, "weight": 30,
                "category": "dangerous_extension",
                "text": f"High-risk file extension '{ext}' ({desc}): {filename}"
            })
            attachment_score += 30
            break

    # 3. Double Extension Detection
    double_ext_warning = check_double_extension(filename)
    if double_ext_warning:
        findings.append({
            "flag": True, "weight": 35,
            "category": "double_extension",
            "text": f"{double_ext_warning} in file '{filename}'"
        })
        attachment_score += 35

    # 4. Masquerading / Magic Byte Mismatch
    if magic_desc and ("PE Executable" in magic_desc):
        if not (fn_lower.endswith(".exe") or fn_lower.endswith(".scr") or fn_lower.endswith(".dll")):
            findings.append({
                "flag": True, "weight": 45,
                "category": "file_masquerading",
                "text": f"POTENTIAL FILE MASQUERADING: Attachment '{filename}' has non-executable extension but contains PE Executable (MZ) header"
            })
            attachment_score += 45

    # 5. Shannon Entropy Warning
    if entropy and entropy >= 7.3 and size > 2048:
        findings.append({
            "flag": True, "weight": 15,
            "category": "high_entropy",
            "text": f"High Shannon entropy ({entropy}/8.0) detected — file may be packed, encrypted, or obfuscated"
        })
        attachment_score += 15

    # 6. Archive Inspection (if ZIP or TAR)
    archive_data = None
    if payload:
        if payload.startswith(b"PK\x03\x04") or fn_lower.endswith(".zip"):
            archive_data = inspect_zip_bytes(payload)
        elif fn_lower.endswith((".tar", ".tar.gz", ".tgz")):
            archive_data = inspect_tar_bytes(payload)

    if archive_data and archive_data.get("is_archive"):
        if archive_data.get("is_encrypted"):
            findings.append({
                "flag": True, "weight": 20,
                "category": "encrypted_archive",
                "text": f"Password-protected / encrypted archive detected in '{filename}' (often used to bypass gateway AV scanners)"
            })
            attachment_score += 20

        if archive_data.get("risky_files"):
            risky_list = ", ".join(archive_data["risky_files"][:4])
            findings.append({
                "flag": True, "weight": 35,
                "category": "archive_dangerous_content",
                "text": f"Archive contains dangerous executable/script files: {risky_list}"
            })
            attachment_score += 35

        if archive_data.get("nested_archives"):
            nested_list = ", ".join(archive_data["nested_archives"][:3])
            findings.append({
                "flag": True, "weight": 15,
                "category": "nested_archive",
                "text": f"Archive contains nested archives (nesting evasion): {nested_list}"
            })
            attachment_score += 15

    is_risky = attachment_score > 0

    return {
        "filename": filename,
        "size": size,
        "sha256": sha256,
        "sha1": sha1,
        "md5": md5,
        "magic_mime": magic_mime,
        "magic_description": magic_desc,
        "entropy": entropy,
        "is_risky": is_risky,
        "score": min(attachment_score, 100),
        "findings": findings,
        "archive_details": archive_data,
    }


def analyze_email_attachments(attachments: List[Dict[str, Any]],
                             payload_map: Optional[Dict[str, bytes]] = None) -> Dict[str, Any]:
    """
    Forensic evaluation of all attachments in an email message.
    """
    payload_map = payload_map or {}
    results = []
    total_score = 0
    risky_attachments = []

    for att in attachments:
        fn = att.get("filename", "unknown")
        payload = payload_map.get(fn)
        single_result = analyze_single_attachment(att, payload)
        results.append(single_result)
        if single_result["is_risky"]:
            risky_attachments.append(single_result)
            total_score += single_result["score"]

    findings = []
    if attachments and not risky_attachments:
        findings.append({
            "flag": False, "weight": 0,
            "category": "attachments_clean",
            "text": f"{len(attachments)} attachment(s) inspected, no high-risk extensions, magic mismatches, or macro indicators"
        })
    elif not attachments:
        findings.append({
            "flag": None, "weight": 0,
            "category": "no_attachments",
            "text": "No attachments found in email"
        })
    else:
        for r in risky_attachments:
            findings.extend(r["findings"])

    return {
        "total_attachments": len(attachments),
        "attachments": results,
        "risky_attachments": risky_attachments,
        "score": min(total_score, 100),
        "findings": findings,
    }
