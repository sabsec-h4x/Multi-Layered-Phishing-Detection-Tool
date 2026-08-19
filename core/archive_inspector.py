"""
Safe Archive Inspection Engine
------------------------------
Safely inspects ZIP and TAR archives in memory without disk extraction
to detect nested archives, hidden executables, scripts, LNKs, and password protection.
"""

import io
import zipfile
import tarfile
from typing import Dict, Any, List, Optional

DANGEROUS_ARCHIVE_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse",
    ".hta", ".wsf", ".wsh", ".lnk", ".iso", ".img", ".dll", ".sys", ".com",
    ".jar", ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".html", ".htm", ".svg"
}

NESTED_ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".iso"}

MAX_ARCHIVE_ENTRIES = 500
MAX_UNCOMPRESSED_TOTAL_BYTES = 50_000_000  # 50MB safety limit against zip bombs


def inspect_zip_bytes(payload: bytes) -> Dict[str, Any]:
    """Inspect in-memory ZIP bytes safely without extracting files to disk."""
    entries = []
    risky_files = []
    nested_archives = []
    is_encrypted = False
    total_uncompressed_size = 0

    try:
        with zipfile.ZipFile(io.BytesIO(payload), "r") as zf:
            infolist = zf.infolist()
            if len(infolist) > MAX_ARCHIVE_ENTRIES:
                return {
                    "is_archive": True,
                    "archive_type": "zip",
                    "error": f"Archive exceeds maximum safe entry limit ({len(infolist)} entries)",
                    "entries": [], "risky_files": [], "nested_archives": [], "is_encrypted": False,
                }

            for info in infolist:
                filename = info.filename
                size = info.file_size
                total_uncompressed_size += size
                if total_uncompressed_size > MAX_UNCOMPRESSED_TOTAL_BYTES:
                    return {
                        "is_archive": True,
                        "archive_type": "zip",
                        "error": "Archive uncompressed size exceeds maximum safety limit (potential decompression bomb)",
                        "entries": entries, "risky_files": risky_files, "nested_archives": nested_archives, "is_encrypted": is_encrypted,
                    }

                # Check encryption flag (bit 0 of flag_bits)
                if info.flag_bits & 0x1:
                    is_encrypted = True

                fn_lower = filename.lower()
                is_risky = any(fn_lower.endswith(ext) for ext in DANGEROUS_ARCHIVE_EXTENSIONS)
                is_nested = any(fn_lower.endswith(ext) for ext in NESTED_ARCHIVE_EXTENSIONS)

                entry_meta = {
                    "filename": filename,
                    "size": size,
                    "compressed_size": info.compress_size,
                    "is_dir": info.is_dir(),
                    "is_encrypted": bool(info.flag_bits & 0x1),
                    "is_risky": is_risky,
                }
                entries.append(entry_meta)

                if is_risky:
                    risky_files.append(filename)
                if is_nested and not info.is_dir():
                    nested_archives.append(filename)

        return {
            "is_archive": True,
            "archive_type": "zip",
            "total_files": len(entries),
            "total_uncompressed_size": total_uncompressed_size,
            "is_encrypted": is_encrypted,
            "entries": entries,
            "risky_files": risky_files,
            "nested_archives": nested_archives,
            "error": None,
        }
    except zipfile.BadZipFile:
        return {"is_archive": False, "archive_type": None, "error": "Not a valid ZIP file"}
    except Exception as e:
        return {"is_archive": True, "archive_type": "zip", "error": f"Failed to inspect ZIP: {e}"}


def inspect_tar_bytes(payload: bytes) -> Dict[str, Any]:
    """Inspect in-memory TAR bytes safely."""
    entries = []
    risky_files = []
    nested_archives = []
    total_uncompressed_size = 0

    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as tf:
            members = tf.getmembers()
            if len(members) > MAX_ARCHIVE_ENTRIES:
                return {
                    "is_archive": True,
                    "archive_type": "tar",
                    "error": f"Archive exceeds maximum safe entry limit ({len(members)} entries)",
                    "entries": [], "risky_files": [], "nested_archives": [], "is_encrypted": False,
                }

            for member in members:
                filename = member.name
                size = member.size
                total_uncompressed_size += size
                if total_uncompressed_size > MAX_UNCOMPRESSED_TOTAL_BYTES:
                    return {
                        "is_archive": True,
                        "archive_type": "tar",
                        "error": "Archive uncompressed size exceeds safety limit",
                        "entries": entries, "risky_files": risky_files, "nested_archives": nested_archives, "is_encrypted": False,
                    }

                fn_lower = filename.lower()
                is_risky = any(fn_lower.endswith(ext) for ext in DANGEROUS_ARCHIVE_EXTENSIONS)
                is_nested = any(fn_lower.endswith(ext) for ext in NESTED_ARCHIVE_EXTENSIONS)

                entry_meta = {
                    "filename": filename,
                    "size": size,
                    "is_dir": member.isdir(),
                    "is_risky": is_risky,
                }
                entries.append(entry_meta)

                if is_risky:
                    risky_files.append(filename)
                if is_nested and not member.isdir():
                    nested_archives.append(filename)

        return {
            "is_archive": True,
            "archive_type": "tar",
            "total_files": len(entries),
            "total_uncompressed_size": total_uncompressed_size,
            "is_encrypted": False,
            "entries": entries,
            "risky_files": risky_files,
            "nested_archives": nested_archives,
            "error": None,
        }
    except tarfile.TarError:
        return {"is_archive": False, "archive_type": None, "error": "Not a valid TAR file"}
    except Exception as e:
        return {"is_archive": True, "archive_type": "tar", "error": f"Failed to inspect TAR: {e}"}
