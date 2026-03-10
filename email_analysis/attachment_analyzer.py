"""
Attachment Analyzer Module
--------------------------
Extracts attachments from parsed emails and computes SHA-256 hashes.

Usage:
    from email_analysis.attachment_analyzer import extract_attachments
    attachments = extract_attachments(email_data["raw_message"], save_dir="uploads")
"""

import hashlib
import logging
import os
from email.message import EmailMessage
from pathlib import Path

logger = logging.getLogger(__name__)


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
            payload_bytes = str(payload).encode('utf-8')

        filename = part.get_filename() or f"unknown_{counter}"
        # Sanitize the filename to prevent path-traversal attacks
        filename = Path(filename).name
        counter += 1

        sha256_hash = compute_sha256(payload_bytes)
        saved_path = os.path.join(save_dir, f"{sha256_hash}_{filename}")

        with open(saved_path, "wb") as f:
            f.write(payload_bytes)

        attachment_info = {
            "filename": filename,
            "content_type": part.get_content_type(),
            "size_bytes": len(payload_bytes),
            "sha256": sha256_hash,
            "saved_path": saved_path,
        }
        attachments.append(attachment_info)

        logger.info(
            "Extracted attachment: %s (SHA256: %s, %d bytes)",
            filename,
            sha256_hash,
            len(payload),
        )

    logger.info("Total attachments extracted: %d", len(attachments))
    return attachments


def compute_sha256(data: bytes) -> str:
    """
    Compute the SHA-256 hash of raw bytes.

    Args:
        data: Raw bytes to hash.

    Returns:
        Hex-encoded SHA-256 digest string.
    """
    return hashlib.sha256(data).hexdigest()
