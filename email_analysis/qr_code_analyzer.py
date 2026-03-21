"""
QR Code Analyzer Module
-----------------------
Scans image attachments for QR codes and extracts embedded URLs.

Tries multiple backends in order:
  1. pyzbar (requires native zbar library)
  2. OpenCV QRCodeDetector (bundled in opencv-python)
  3. Falls back gracefully if neither is available

Usage:
    from email_analysis.qr_code_analyzer import scan_attachments_for_qr
    qr_results = scan_attachments_for_qr(attachments)
"""

import logging
import importlib.util
import re
from pathlib import Path
from urllib.parse import urlparse

import numpy as np
from PIL import Image

logger = logging.getLogger(__name__)

# ── Backend selection ────────────────────────────────────────

_BACKEND: str = "none"

try:
    from pyzbar.pyzbar import decode as _pyzbar_decode  # type: ignore[import-untyped]

    _BACKEND = "pyzbar"
except (ImportError, FileNotFoundError, OSError):
    if importlib.util.find_spec("cv2") is not None:
        _BACKEND = "opencv"
    else:
        logger.warning(
            "No QR decoding backend available. "
            "Install pyzbar (+ zbar DLL) or opencv-python."
        )

# MIME types we'll attempt to scan for QR codes
_IMAGE_TYPES = frozenset(
    {
        "image/png",
        "image/jpeg",
        "image/jpg",
        "image/gif",
        "image/bmp",
        "image/tiff",
        "image/webp",
    }
)

# Also match by file extension when content_type is generic
_IMAGE_EXTENSIONS = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".bmp",
        ".tiff",
        ".webp",
    }
)

# Simple URL pattern to validate decoded QR payloads
_URL_PATTERN = re.compile(r"^https?://", re.IGNORECASE)


def scan_attachments_for_qr(attachments: list[dict]) -> list[dict]:
    """
    Scan all image attachments for QR codes and extract data.

    Args:
        attachments: List of attachment dicts from attachment_analyzer
                     (must include 'saved_path', 'content_type', 'filename').

    Returns:
        List of QR finding dicts with keys:
            - filename:   source image file name
            - qr_data:    raw decoded string from the QR code
            - qr_type:    barcode type (e.g. 'QRCODE')
            - url:        extracted URL (if the data is a URL, else None)
            - domain:     domain of the URL (if applicable)
            - risk_score: base risk score for this finding
    """
    findings: list[dict] = []

    for attachment in attachments:
        if not _is_image(attachment):
            continue

        saved_path = attachment.get("saved_path", "")
        if not saved_path or not Path(saved_path).is_file():
            continue

        qr_items = _decode_qr(saved_path)
        for data, barcode_type in qr_items:
            finding: dict = {
                "filename": attachment.get("filename", "unknown"),
                "qr_data": data,
                "qr_type": barcode_type,
                "url": None,
                "domain": None,
                "risk_score": 10,  # base: QR code detected
            }

            if _URL_PATTERN.match(data):
                finding["url"] = data
                finding["domain"] = urlparse(data).netloc or None
                finding["risk_score"] = 15  # QR contains a URL

            findings.append(finding)
            logger.warning(
                "QR code found in %s: type=%s data=%s",
                attachment.get("filename"),
                barcode_type,
                data[:120],
            )

    logger.info(
        "QR scan complete: %d code(s) found in %d attachment(s)",
        len(findings),
        len(attachments),
    )
    return findings


def extract_qr_urls(qr_findings: list[dict]) -> list[dict]:
    """
    Extract URL dicts from QR findings so they can be fed into the
    existing url-analysis pipeline (VT, OTX, heuristics).

    Returns:
        List of url-info dicts compatible with url_extractor output:
            - url, domain, is_shortened, expanded_url, source
    """
    url_dicts: list[dict] = []
    seen: set[str] = set()

    for f in qr_findings:
        url = f.get("url")
        if not url or url in seen:
            continue
        seen.add(url)
        url_dicts.append(
            {
                "url": url,
                "domain": f.get("domain", ""),
                "is_shortened": False,
                "expanded_url": url,
                "source": "qr_code",
            }
        )

    return url_dicts


# ── Internal helpers ─────────────────────────────────────────


def _is_image(attachment: dict) -> bool:
    """Check whether an attachment is an image we can scan."""
    content_type = (attachment.get("content_type") or "").lower()
    if content_type in _IMAGE_TYPES:
        return True
    # Fallback to extension check
    filename = attachment.get("filename", "")
    return Path(filename).suffix.lower() in _IMAGE_EXTENSIONS


def _decode_qr(image_path: str) -> list[tuple[str, str]]:
    """
    Open an image and decode any QR / barcodes found inside it.

    Returns:
        List of (decoded_text, barcode_type) tuples.
    """
    if _BACKEND == "pyzbar":
        return _decode_pyzbar(image_path)
    if _BACKEND == "opencv":
        return _decode_opencv(image_path)
    return []


def _decode_pyzbar(image_path: str) -> list[tuple[str, str]]:
    """Decode using pyzbar."""
    results: list[tuple[str, str]] = []
    try:
        with Image.open(image_path) as img:
            scan_img: Image.Image = img
            if scan_img.mode not in ("L", "RGB"):
                scan_img = scan_img.convert("RGB")
            decoded = _pyzbar_decode(scan_img)
            for obj in decoded:
                data = obj.data.decode("utf-8", errors="replace")
                results.append((data, obj.type))
    except Exception as exc:
        logger.debug("pyzbar decode failed for %s: %s", image_path, exc)
    return results


def _decode_opencv(image_path: str) -> list[tuple[str, str]]:
    """Decode using OpenCV's QRCodeDetector."""
    results: list[tuple[str, str]] = []
    try:
        import cv2  # type: ignore[import-untyped]

        with Image.open(image_path) as img:
            scan_img: Image.Image = img
            if scan_img.mode not in ("L", "RGB"):
                scan_img = scan_img.convert("RGB")
            arr = np.array(scan_img)
            detector = cv2.QRCodeDetector()
            retval, decoded_info, points, straight_qrcode = (
                detector.detectAndDecodeMulti(arr)
            )
            if retval and decoded_info:
                for data in decoded_info:
                    if data:
                        results.append((data, "QRCODE"))
    except Exception as exc:
        logger.debug("OpenCV QR decode failed for %s: %s", image_path, exc)
    return results
