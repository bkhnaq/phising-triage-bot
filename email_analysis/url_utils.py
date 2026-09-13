"""URL canonicalization and obfuscation detection helpers."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from urllib.parse import unquote, urlparse, urlunparse

from email_analysis.domain_utils import domain_info
from scoring.config import weight

_ENCODED_DELIMITER_RE = re.compile(r"%(?:2f|5c|40|2e|3a)", re.IGNORECASE)
_SUSPICIOUS_KEYWORDS = {
    "login",
    "signin",
    "verify",
    "secure",
    "account",
    "password",
    "update",
    "confirm",
}


@dataclass(frozen=True)
class URLAnalysis:
    original_url: str
    normalized_url: str
    scheme: str
    domain: str
    registered_domain: str
    decoded_domain: str
    path: str
    decoded_path: str
    has_userinfo: bool
    is_ip_host: bool
    is_punycode: bool
    encoded_delimiters: bool
    suspicious_reasons: list[str]
    risk_score: int

    def to_dict(self) -> dict:
        return asdict(self)


def analyze_url(url: str) -> URLAnalysis:
    """Normalize a URL and flag common phishing obfuscation patterns."""
    raw = (url or "").strip()
    parsed = urlparse(raw)
    scheme = parsed.scheme.lower()
    domain_meta = domain_info(parsed.hostname or "")
    path = parsed.path or ""
    decoded_path = unquote(path)
    has_userinfo = bool(parsed.username or parsed.password or "@" in parsed.netloc)
    encoded_delimiters = bool(_ENCODED_DELIMITER_RE.search(raw))

    normalized_url = _normalize_url(parsed, domain_meta.ascii_host)
    suspicious_reasons: list[str] = []
    risk = 0

    if has_userinfo:
        suspicious_reasons.append("userinfo in URL hides the real host")
        risk += weight("url_userinfo")
    if domain_meta.is_ip:
        suspicious_reasons.append("IP address used as URL host")
        risk += weight("url_ip_host")
    if domain_meta.is_punycode:
        suspicious_reasons.append("punycode/IDN host")
        risk += weight("url_punycode")
    if encoded_delimiters:
        suspicious_reasons.append("encoded URL delimiter characters")
        risk += weight("url_encoded_host")

    keyword_hits = [
        keyword for keyword in _SUSPICIOUS_KEYWORDS if keyword in decoded_path.lower()
    ]
    if len(keyword_hits) >= 2:
        suspicious_reasons.append(
            f"credential-style path keywords: {', '.join(sorted(keyword_hits)[:4])}"
        )
        risk += weight("url_credential_path")

    return URLAnalysis(
        original_url=raw,
        normalized_url=normalized_url,
        scheme=scheme,
        domain=domain_meta.ascii_host,
        registered_domain=domain_meta.registered_domain,
        decoded_domain=domain_meta.unicode_host,
        path=path,
        decoded_path=decoded_path,
        has_userinfo=has_userinfo,
        is_ip_host=domain_meta.is_ip,
        is_punycode=domain_meta.is_punycode,
        encoded_delimiters=encoded_delimiters,
        suspicious_reasons=suspicious_reasons,
        risk_score=risk,
    )


def _normalize_url(parsed, ascii_host: str) -> str:
    scheme = parsed.scheme.lower()
    host = f"[{ascii_host}]" if ":" in ascii_host else ascii_host
    port = parsed.port
    include_port = port and not (
        (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    )
    netloc = f"{host}:{port}" if include_port else host
    if "@" in parsed.netloc:
        netloc = parsed.netloc.rsplit("@", 1)[0] + "@" + netloc
    # Preserve path escaping, query order, userinfo, parameters and fragment:
    # rewriting them can change the target or remove an IOC's phishing behavior.
    return urlunparse(
        (scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment)
    )
