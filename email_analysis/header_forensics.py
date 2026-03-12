"""
Header Forensics Module
-----------------------
Analyzes SMTP Received headers to reconstruct the relay chain and detect
network-level spoofing indicators.

Complements header_analyzer.py (which checks SPF/DKIM/DMARC and
header-level sender anomalies) by focusing on the SMTP routing layer:

  - Relay chain reconstruction from all Received headers
  - Origin IP extraction (first external-IP hop walking from oldest to newest)
  - IP geolocation via ip-api.com  (free tier — no API key required)
  - Hosting / datacenter detection  (ip-api.com ``hosting`` field)
  - Proxy / VPN detection           (ip-api.com ``proxy`` field)
  - Relay server domain vs declared sender domain mismatch

Risk scores produced by this module:
  +10  Origin IP belongs to a hosting/datacenter provider
  +15  Origin IP is a known proxy or VPN exit node
  +10  Relay server domain does not match the declared sender domain

Usage:
    from email_analysis.header_forensics import run_header_forensics
    result = run_header_forensics(email_data)
"""

import ipaddress
import logging
import re

import requests

logger = logging.getLogger(__name__)

# ── Geolocation API (ip-api.com, free tier, no key required) ─────────────────
_GEO_API = (
    "http://ip-api.com/json/{ip}"
    "?fields=status,country,countryCode,regionName,city,isp,org,as,asname,hosting,proxy"
)
_GEO_TIMEOUT = 5  # seconds

# ── Received-header parsing patterns ─────────────────────────────────────────
_FROM_HOST_RE = re.compile(r"from\s+(\S+)", re.IGNORECASE)
_BY_HOST_RE   = re.compile(r"\bby\s+(\S+)", re.IGNORECASE)
# Match an IPv4 address, optionally bracketed: [1.2.3.4] or 1.2.3.4
_IPV4_RE = re.compile(r"\[?((?:\d{1,3}\.){3}\d{1,3})\]?")

# ── Private / reserved IPv4 ranges ───────────────────────────────────────────
_PRIVATE_NETS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),  # CGNAT
]

# ── Known MTA relay services ──────────────────────────────────────────────────
# Relay through these is expected even when the From domain differs,
# so they are excluded from the domain-mismatch check.
_KNOWN_MTA_ROOTS: frozenset[str] = frozenset({
    "gmail.com", "google.com", "googlemail.com",
    "yahoo.com", "yahoodns.net",
    "outlook.com", "hotmail.com", "microsoft.com", "office365.com",
    "protonmail.ch", "protonmail.com",
    "sendgrid.net", "sendgrid.com",
    "mailgun.org", "mailgun.net",
    "amazonses.com", "amazonaws.com",
    "zoho.com", "zohomail.com",
    "icloud.com", "me.com",
    "fastmail.com", "fastmail.fm",
    "mailchimp.com", "mandrillapp.com",
    "postmarkapp.com",
    "sparkpostmail.com",
    "mx.example.com",
})


# ── Public API ────────────────────────────────────────────────────────────────

def run_header_forensics(email_data: dict) -> dict:
    """
    Analyze SMTP relay chain and return structured forensic findings.

    Args:
        email_data: Output from email_parser.parse_eml_file().

    Returns:
        Dict with keys:
          origin_ip, origin_country, origin_country_code, origin_city,
          origin_isp, origin_org, origin_is_hosting, origin_is_proxy,
          relay_chain (list of hop dicts), from_domain,
          spoofing_detected (bool), warnings (list[str]),
          risk_score (int), error (str|None).
    """
    result = _empty_result()
    try:
        headers: list[tuple[str, str]] = email_data.get("headers", [])
        from_raw: str = email_data.get("from", "")

        # ── Step 1: Build relay chain ─────────────────────────────────────
        relay_chain = _parse_received_chain(headers)
        result["relay_chain"] = relay_chain

        # ── Step 2: Identify origin IP ────────────────────────────────────
        origin_ip = _get_origin_ip(relay_chain)
        result["origin_ip"] = origin_ip

        # ── Step 3: Geolocate origin IP ───────────────────────────────────
        geo: dict = {}
        if origin_ip:
            geo = _geolocate_ip(origin_ip)
            result["origin_country"]      = geo.get("country", "Unknown")
            result["origin_country_code"] = geo.get("countryCode", "")
            result["origin_city"]         = geo.get("city", "")
            result["origin_isp"]          = geo.get("isp", "")
            result["origin_org"]          = geo.get("org", "")
            result["origin_asn"]          = geo.get("as", "")
            result["origin_asname"]       = geo.get("asname", "")
            result["origin_is_hosting"]   = bool(geo.get("hosting", False))
            result["origin_is_proxy"]     = bool(geo.get("proxy", False))

        # ── Step 4: Spoof / relay analysis ───────────────────────────────
        from_domain = _extract_from_domain(from_raw)
        result["from_domain"] = from_domain

        warnings, risk_score = _analyze_relay(from_domain, relay_chain, geo)
        result["warnings"]          = warnings
        result["spoofing_detected"] = bool(warnings)
        result["risk_score"]        = risk_score

        logger.info(
            "Header forensics: origin_ip=%s country=%s hosting=%s proxy=%s "
            "relay_hops=%d warnings=%d risk=%d",
            origin_ip or "none",
            result["origin_country"],
            result["origin_is_hosting"],
            result["origin_is_proxy"],
            len(relay_chain),
            len(warnings),
            risk_score,
        )

    except Exception:
        logger.exception("Header forensics failed")
        result["error"] = "Analysis failed — see bot logs"

    return result


# ── Relay chain parsing ───────────────────────────────────────────────────────

def _parse_received_chain(headers: list[tuple[str, str]]) -> list[dict]:
    """
    Parse all Received headers into a structured relay chain.

    Returned in document order (newest/last-hop first, origin last).
    Each hop dict contains: server, ip, by, raw.
    """
    chain: list[dict] = []
    for name, value in headers:
        if name.lower() == "received":
            chain.append(_parse_hop(value.strip()))
    return chain


def _parse_hop(raw: str) -> dict:
    """Parse a single Received header value into a structured hop dict."""
    # Collapse folded whitespace for easier regex matching.
    clean = re.sub(r"\s+", " ", raw)

    from_match = _FROM_HOST_RE.search(clean)
    by_match   = _BY_HOST_RE.search(clean)

    server    = from_match.group(1).rstrip(";,") if from_match else None
    by_server = by_match.group(1).rstrip(";,")   if by_match   else None

    # Extract the first IPv4 address present (usually inside parens after hostname).
    ip_match = _IPV4_RE.search(clean)
    ip = ip_match.group(1) if ip_match else None

    # Discard private / loopback IPs — not useful for origin analysis.
    if ip and _is_private_ip(ip):
        ip = None

    return {
        "server": server,
        "ip":     ip,
        "by":     by_server,
        "raw":    raw,
    }


def _get_origin_ip(relay_chain: list[dict]) -> str | None:
    """
    Return the origin IP — the first external IP when reading the chain
    from oldest hop to newest (i.e., reversed document order).
    """
    for hop in reversed(relay_chain):
        ip = hop.get("ip")
        if ip and not _is_private_ip(ip):
            return ip
    return None


def _is_private_ip(ip: str) -> bool:
    """Return True if the address is private, loopback, or CGNAT."""
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


# ── Geolocation ───────────────────────────────────────────────────────────────

def _geolocate_ip(ip: str) -> dict:
    """
    Query ip-api.com for country, city, ISP, and hosting/proxy metadata.

    Returns a dict with keys: country, countryCode, regionName, city,
    isp, org, hosting, proxy.  Returns {} on any failure so callers can
    safely use .get().
    """
    try:
        url = _GEO_API.format(ip=ip)
        resp = requests.get(url, timeout=_GEO_TIMEOUT)
        resp.raise_for_status()
        data: dict = resp.json()
        if data.get("status") != "success":
            logger.warning("ip-api returned non-success for %s: %s", ip, data.get("message"))
            return {}
        return data
    except requests.Timeout:
        logger.warning("Geolocation timeout for IP %s", ip)
        return {}
    except requests.RequestException as exc:
        logger.warning("Geolocation request failed for IP %s: %s", ip, exc)
        return {}


# ── Domain helpers ────────────────────────────────────────────────────────────

def _extract_from_domain(from_raw: str) -> str:
    """Extract and normalise the sending domain from a From header value."""
    match = re.search(r"@([\w.\-]+)", from_raw)
    return match.group(1).strip().lower().rstrip(".") if match else ""


def _root_domain(domain: str) -> str:
    """Return the registrable root+TLD (e.g., 'mail.paypal.com' → 'paypal.com')."""
    parts = domain.rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


# ── Relay analysis ────────────────────────────────────────────────────────────

def _analyze_relay(
    from_domain: str,
    relay_chain: list[dict],
    geo: dict,
) -> tuple[list[str], int]:
    """
    Run relay-level checks and return (warnings, total_risk_score).

    Checks performed:
      1. Origin IP is a hosting / datacenter address  → +10
      2. Origin IP is a proxy / VPN                   → +15
      3. Origin relay server domain ≠ From domain     → +10
      4. Country information (informational, no score)
    """
    warnings: list[str] = []
    risk = 0

    # ── 1. Hosting / datacenter origin ───────────────────────────────────
    if geo.get("hosting"):
        isp_label = geo.get("isp") or geo.get("org") or "unknown ISP"
        warnings.append(f"Origin IP is a hosting/datacenter address ({isp_label})")
        risk += 10

    # ── 2. Proxy / VPN origin ─────────────────────────────────────────────
    if geo.get("proxy"):
        warnings.append("Origin IP is a known proxy or VPN exit node")
        risk += 15

    # ── 3. Relay server domain mismatch ──────────────────────────────────
    if from_domain and relay_chain:
        from_root = _root_domain(from_domain)
        mismatches = _origin_relay_mismatch(from_root, relay_chain)
        if mismatches:
            warnings.append(
                f"Sender domain ({from_domain}) does not match "
                f"relay server(s): {', '.join(mismatches[:3])}"
            )
            risk += 10

    # ── 4. Country (informational only) ──────────────────────────────────
    country      = geo.get("country", "")
    country_code = geo.get("countryCode", "")
    if country:
        warnings.append(f"Origin IP geolocation: {country} ({country_code})")
        # No automatic risk score — the SOC analyst interprets this.

    return warnings, risk


def _origin_relay_mismatch(from_root: str, relay_chain: list[dict]) -> list[str]:
    """
    Return the origin relay server hostname if its root domain doesn't match
    the declared From domain root, and it's not a known MTA service.

    Only the ``origin`` server (oldest Received hop with a named server) is
    evaluated to avoid false positives from intermediate relay hops.
    """
    # Walk chain from oldest to newest to find origin server hostname.
    origin_server: str | None = None
    for hop in reversed(relay_chain):
        server = hop.get("server")
        if server and server.lower() not in ("localhost", "unknown"):
            origin_server = server.lower()
            break

    if not origin_server:
        return []

    server_root = _root_domain(origin_server)

    # Skip well-known relay services — expected mismatch, not suspicious.
    if server_root in _KNOWN_MTA_ROOTS:
        return []

    # Flag if From root domain is completely absent from origin server hostname.
    if from_root not in origin_server and server_root != from_root:
        return [origin_server]

    return []


# ── Zero-value result ─────────────────────────────────────────────────────────

def _empty_result() -> dict:
    """Return a safe zeroed-out result dict for the module."""
    return {
        "origin_ip":           None,
        "origin_country":      "Unknown",
        "origin_country_code": "",
        "origin_city":         "",
        "origin_isp":          "",
        "origin_org":          "",
        "origin_asn":          "",
        "origin_asname":       "",
        "origin_is_hosting":   False,
        "origin_is_proxy":     False,
        "relay_chain":         [],
        "from_domain":         "",
        "spoofing_detected":   False,
        "warnings":            [],
        "risk_score":          0,
        "error":               None,
    }
