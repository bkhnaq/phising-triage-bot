"""
Attachment Analyzer Module
--------------------------
Extracts attachments from parsed emails, computes SHA-256 hashes,
and performs malware risk assessment based on file type analysis.

Detects high-risk attachment types:
  - Macro-enabled documents (.docm, .xlsm, .pptm, .dotm)
  - Executable files (.exe, .scr, .bat, .cmd, .ps1, .vbs, .js, .wsf, .msi)
  - Archive files (.zip, .rar, .7z, .tar, .gz)
  - HTML attachments (potential credential harvesting)
  - Disk image files (.iso, .img, .vhd)
  - Shortcut files (.lnk)

Usage:
    from email_analysis.attachment_analyzer import extract_attachments, assess_attachment_risk
    attachments = extract_attachments(email_data["raw_message"], save_dir="uploads")
    risk_findings = assess_attachment_risk(attachments)
"""

import hashlib
import logging
import os
import re
import unicodedata
from email.message import EmailMessage
from pathlib import Path

logger = logging.getLogger(__name__)

# ── High-risk file extension categories ──────────────────────

_RISK_EXTENSIONS: dict[str, dict] = {
    # Macro-enabled documents
    ".docm": {
        "category": "macro_document",
        "risk": 25,
        "description": "Macro-enabled Word document",
    },
    ".xlsm": {
        "category": "macro_document",
        "risk": 25,
        "description": "Macro-enabled Excel spreadsheet",
    },
    ".pptm": {
        "category": "macro_document",
        "risk": 25,
        "description": "Macro-enabled PowerPoint presentation",
    },
    ".dotm": {
        "category": "macro_document",
        "risk": 25,
        "description": "Macro-enabled Word template",
    },
    ".xlam": {
        "category": "macro_document",
        "risk": 25,
        "description": "Macro-enabled Excel add-in",
    },
    # Executable files
    ".exe": {"category": "executable", "risk": 30, "description": "Windows executable"},
    ".scr": {
        "category": "executable",
        "risk": 30,
        "description": "Windows screensaver (executable)",
    },
    ".bat": {
        "category": "executable",
        "risk": 25,
        "description": "Windows batch script",
    },
    ".cmd": {
        "category": "executable",
        "risk": 25,
        "description": "Windows command script",
    },
    ".ps1": {"category": "executable", "risk": 25, "description": "PowerShell script"},
    ".vbs": {
        "category": "executable",
        "risk": 25,
        "description": "Visual Basic script",
    },
    ".vbe": {
        "category": "executable",
        "risk": 25,
        "description": "Encoded Visual Basic script",
    },
    ".js": {"category": "executable", "risk": 20, "description": "JavaScript file"},
    ".jse": {
        "category": "executable",
        "risk": 20,
        "description": "Encoded JavaScript file",
    },
    ".wsf": {
        "category": "executable",
        "risk": 25,
        "description": "Windows Script File",
    },
    ".msi": {
        "category": "executable",
        "risk": 25,
        "description": "Windows installer package",
    },
    ".dll": {
        "category": "executable",
        "risk": 30,
        "description": "Dynamic link library",
    },
    ".com": {
        "category": "executable",
        "risk": 30,
        "description": "DOS/Windows executable",
    },
    ".pif": {
        "category": "executable",
        "risk": 30,
        "description": "Program information file",
    },
    # Archive files
    ".zip": {
        "category": "archive",
        "risk": 15,
        "description": "ZIP archive (may contain malware)",
    },
    ".rar": {
        "category": "archive",
        "risk": 15,
        "description": "RAR archive (may contain malware)",
    },
    ".7z": {
        "category": "archive",
        "risk": 15,
        "description": "7-Zip archive (may contain malware)",
    },
    ".tar": {"category": "archive", "risk": 10, "description": "TAR archive"},
    ".gz": {"category": "archive", "risk": 10, "description": "Gzip archive"},
    ".cab": {"category": "archive", "risk": 15, "description": "Cabinet archive"},
    # HTML attachments
    ".html": {
        "category": "html",
        "risk": 20,
        "description": "HTML file (possible credential harvesting)",
    },
    ".htm": {
        "category": "html",
        "risk": 20,
        "description": "HTML file (possible credential harvesting)",
    },
    ".hta": {
        "category": "html",
        "risk": 30,
        "description": "HTML Application (can execute code)",
    },
    ".svg": {
        "category": "html",
        "risk": 10,
        "description": "SVG file (may contain embedded scripts)",
    },
    # Disk images
    ".iso": {
        "category": "disk_image",
        "risk": 25,
        "description": "ISO disk image (bypasses MOTW)",
    },
    ".img": {"category": "disk_image", "risk": 25, "description": "Disk image file"},
    ".vhd": {"category": "disk_image", "risk": 25, "description": "Virtual hard disk"},
    ".vhdx": {
        "category": "disk_image",
        "risk": 25,
        "description": "Virtual hard disk (extended)",
    },
    # Shortcut files
    ".lnk": {
        "category": "shortcut",
        "risk": 25,
        "description": "Windows shortcut (can run arbitrary commands)",
    },
    ".url": {
        "category": "shortcut",
        "risk": 15,
        "description": "Internet shortcut file",
    },
    # Office with macros (legacy)
    ".doc": {
        "category": "legacy_office",
        "risk": 10,
        "description": "Legacy Word document (may contain macros)",
    },
    ".xls": {
        "category": "legacy_office",
        "risk": 10,
        "description": "Legacy Excel spreadsheet (may contain macros)",
    },
    ".ppt": {
        "category": "legacy_office",
        "risk": 10,
        "description": "Legacy PowerPoint (may contain macros)",
    },
    ".rtf": {
        "category": "legacy_office",
        "risk": 10,
        "description": "RTF document (may exploit vulnerabilities)",
    },
}

# Suspicious MIME types
_RISK_MIME_TYPES: dict[str, int] = {
    "application/x-msdownload": 30,
    "application/x-executable": 30,
    "application/x-msdos-program": 30,
    "application/vnd.ms-excel.sheet.macroEnabled.12": 25,
    "application/vnd.ms-word.document.macroEnabled.12": 25,
    "application/x-zip-compressed": 15,
    "application/javascript": 20,
    "text/html": 15,
    "application/hta": 30,
}


def extract_attachments(
    msg: EmailMessage,
    save_dir: str = "uploads",
) -> list[dict]:
    """
    Walk the MIME tree and pull out every attachment.

    Args:
        msg: The parsed EmailMessage object.
        save_dir: Directory where attachment files will be saved.

    Returns:
        List of dicts, each containing:
            - filename: original file name (or 'unknown_N')
            - content_type: MIME type
            - size_bytes: length of the raw payload
            - sha256: hex-digest of the payload
            - saved_path: path where the file was written to disk
    """
    os.makedirs(save_dir, exist_ok=True)

    attachments: list[dict] = []
    counter = 0

    for part in msg.walk():
        content_disposition = str(part.get("Content-Disposition", ""))
        if "attachment" not in content_disposition.lower():
            continue

        payload = part.get_payload(decode=True)
        if payload is None:
            continue

        # Convert payload to bytes if it's a Message object
        if isinstance(payload, bytes):
            payload_bytes = payload
        else:
            payload_bytes = str(payload).encode("utf-8")

        filename = part.get_filename() or f"unknown_{counter}"
        filename = _sanitize_filename(filename)
        counter += 1

        sha256_hash = compute_sha256(payload_bytes)
        saved_path = _safe_attachment_path(save_dir, filename, sha256_hash)

        with open(saved_path, "wb") as f:
            f.write(payload_bytes)

        attachment_info = {
            "filename": filename,
            "content_type": part.get_content_type(),
            "size_bytes": len(payload_bytes),
            "sha256": sha256_hash,
            "saved_path": str(saved_path),
        }
        attachments.append(attachment_info)

        logger.info(
            "Extracted attachment: %s (SHA256: %s, %d bytes)",
            filename,
            sha256_hash,
            len(payload_bytes),
        )

    logger.info("Total attachments extracted: %d", len(attachments))
    return attachments


def _sanitize_filename(filename: str) -> str:
    normalized = unicodedata.normalize("NFKC", filename)
    name_only = Path(normalized).name
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", name_only)
    return safe[:120] or "attachment.bin"


def _safe_attachment_path(save_dir: str, filename: str, sha256_hash: str) -> Path:
    base_dir = Path(save_dir).resolve()
    safe_name = _sanitize_filename(filename)
    destination = (base_dir / f"{sha256_hash}_{safe_name}").resolve()
    if destination.parent != base_dir:
        raise ValueError("Unsafe attachment path detected")
    return destination


def compute_sha256(data: bytes) -> str:
    """
    Compute the SHA-256 hash of raw bytes.

    Args:
        data: Raw bytes to hash.

    Returns:
        Hex-encoded SHA-256 digest string.
    """
    return hashlib.sha256(data).hexdigest()


def assess_attachment_risk(attachments: list[dict]) -> list[dict]:
    """
    Assess the malware risk of each attachment based on file extension
    and MIME type.

    Args:
        attachments: List of attachment dicts from extract_attachments().

    Returns:
        List of risk finding dicts with keys:
            filename, content_type, extension, category, description,
            risk_score, warnings.
    """
    findings: list[dict] = []

    for att in attachments:
        filename = att.get("filename", "unknown")
        content_type = att.get("content_type", "").lower()
        ext = Path(filename).suffix.lower()

        finding: dict = {
            "filename": filename,
            "content_type": content_type,
            "extension": ext,
            "category": "unknown",
            "description": "",
            "risk_score": 0,
            "warnings": [],
        }

        # Check file extension
        if ext in _RISK_EXTENSIONS:
            ext_info = _RISK_EXTENSIONS[ext]
            finding["category"] = ext_info["category"]
            finding["description"] = ext_info["description"]
            finding["risk_score"] = ext_info["risk"]
            finding["warnings"].append(
                f"⚠️ Suspicious attachment: {ext_info['description']}"
            )

            if ext_info["category"] == "macro_document":
                finding["warnings"].append("⚠️ Possible macro malware")
            elif ext_info["category"] == "executable":
                finding["warnings"].append("⚠️ Executable file attached")
            elif ext_info["category"] == "html":
                finding["warnings"].append(
                    "⚠️ HTML attachment (possible credential harvesting)"
                )
            elif ext_info["category"] == "disk_image":
                finding["warnings"].append(
                    "⚠️ Disk image may bypass Mark-of-the-Web protection"
                )
            elif ext_info["category"] == "archive":
                finding["warnings"].append("⚠️ Archive may contain hidden malware")

        # Check MIME type as secondary signal
        mime_risk = _RISK_MIME_TYPES.get(content_type, 0)
        if mime_risk > finding["risk_score"]:
            finding["risk_score"] = mime_risk
            finding["warnings"].append(f"⚠️ Suspicious MIME type: {content_type}")

        # Double extension detection (e.g., report.pdf.exe)
        name_without_ext = Path(filename).stem
        if "." in name_without_ext:
            inner_ext = Path(name_without_ext).suffix.lower()
            if inner_ext in (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".png"):
                finding["risk_score"] += 15
                finding["warnings"].append(
                    f"⚠️ Double extension detected: {filename} (social engineering)"
                )

        # Large file size check
        size = att.get("size_bytes", 0)
        if size > 10_000_000:  # > 10MB
            finding["warnings"].append(
                f"⚠️ Large attachment: {size / 1_000_000:.1f} MB"
            )

        if finding["warnings"]:
            findings.append(finding)
            logger.warning(
                "Attachment risk: %s (category=%s, risk=%d)",
                filename,
                finding["category"],
                finding["risk_score"],
            )

    return findings
