"""
Report Generator Module (v3)
-----------------------------
Produces a professional SOC-grade phishing triage report.

Structure:
  THREAT SUMMARY
  EMAIL METADATA
  EMAIL AUTHENTICATION  /  HEADER FORENSICS
  SMTP RELAY ANALYSIS
  URL ANALYSIS
  DOMAIN INTELLIGENCE
  BRAND IMPERSONATION ANALYSIS  (unified)
  PHISHING LANGUAGE ANALYSIS
  CREDENTIAL HARVESTING DETECTION
  THREAT INTELLIGENCE  (VT, OTX, IP rep, passive DNS)
  AI PHISHING CLASSIFIER
  ATTACHMENTS  /  QR CODES
  RISK ASSESSMENT

Usage:
    from report.report_generator import generate_report
    text = generate_report(email_data, auth, urls, attachments, risk, ...)
"""

import logging
import re
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


# ── Error message sanitiser ──────────────────────────────────

_ERROR_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"HTTPConnectionPool|HTTPSConnectionPool", re.I), "Connection failed"),
    (re.compile(r"ConnectionError|ConnectTimeout", re.I), "Connection timed out"),
    (re.compile(r"Max retries exceeded", re.I), "Domain could not be resolved"),
    (re.compile(r"NameResolutionError|getaddrinfo failed|Name or service not known", re.I),
     "Domain could not be resolved"),
    (re.compile(r"ReadTimeout|read timed out", re.I), "Request timed out"),
    (re.compile(r"TooManyRedirects", re.I), "Too many redirects"),
    (re.compile(r"SSLError|SSL: CERTIFICATE_VERIFY_FAILED", re.I), "SSL certificate error"),
    (re.compile(r"ProxyError", re.I), "Proxy error"),
]


def _clean_error(raw: str | None) -> str:
    """Convert raw Python exception text into a human-readable message."""
    if not raw:
        return "Unknown error"
    for pattern, friendly in _ERROR_PATTERNS:
        if pattern.search(raw):
            return friendly
    # Fallback: return first 120 chars, strip tracebacks
    first_line = raw.strip().split("\n")[0][:120]
    return first_line


# ── Threat summary builder ───────────────────────────────────

def _build_threat_summary(
    risk: dict,
    brand_impersonation: dict | None,
    credential_harvesting: dict | None,
    language_analysis: dict | None,
    ai_verdict: dict | None,
    heuristics: dict | None,
    attachment_risks: list[dict] | None,
    domain_intelligence: dict | None,
) -> list[str]:
    """Produce a concise THREAT SUMMARY block."""

    # ── Determine attack type & target brand ─────────────────
    target_brand: str = ""
    techniques: list[str] = []
    goal: str = ""

    # Brand impersonation
    if brand_impersonation:
        domain_imp = brand_impersonation.get("domain_impersonation", [])
        if domain_imp:
            target_brand = domain_imp[0].get("brand", "").title()
            imp_type = domain_imp[0].get("type", "")
            if imp_type == "lookalike":
                techniques.append("Lookalike domain")
            elif imp_type == "domain_keyword":
                techniques.append("Brand keyword in domain")
        dn_spoof = brand_impersonation.get("display_name_spoofing", [])
        if dn_spoof and not target_brand:
            target_brand = dn_spoof[0].get("brand", "").title()
            techniques.append("Display name spoofing")

    # Homograph from heuristics
    if heuristics:
        if heuristics.get("homograph_brands"):
            techniques.append("Homograph attack")
            if not target_brand:
                target_brand = heuristics["homograph_brands"][0].get("brand", "").title()
        if heuristics.get("homograph"):
            techniques.append("IDN homograph")

    # Credential harvesting
    if credential_harvesting and credential_harvesting.get("detected"):
        goal = "Credential harvesting"

    # Attachment malware
    has_risky_attach = bool(attachment_risks and any(
        a.get("risk_score", 0) > 0 for a in attachment_risks
    ))

    # Language cues
    if language_analysis:
        cats = language_analysis.get("categories", {})
        if "credential_harvesting" in cats:
            goal = goal or "Credential harvesting"
        if "financial" in cats:
            goal = goal or "Financial fraud"
    if has_risky_attach:
        goal = goal or "Malware delivery"
    goal = goal or "Unknown"

    # Attack type label
    if target_brand:
        attack_type = "Brand impersonation phishing"
    elif credential_harvesting and credential_harvesting.get("detected"):
        attack_type = "Credential harvesting phishing"
    elif has_risky_attach:
        attack_type = "Malware delivery"
    elif ai_verdict and ai_verdict.get("verdict") == "phishing":
        attack_type = "Phishing email"
    elif ai_verdict and ai_verdict.get("verdict") == "suspicious":
        attack_type = "Suspicious email"
    else:
        attack_type = "Email under analysis"

    # Confidence
    indicator_count = 0
    if brand_impersonation and brand_impersonation.get("domain_impersonation"):
        indicator_count += 2
    if credential_harvesting and credential_harvesting.get("detected"):
        indicator_count += 2
    if language_analysis and language_analysis.get("total_matches", 0) > 0:
        indicator_count += 1
    if ai_verdict and ai_verdict.get("verdict") == "phishing":
        indicator_count += 2
    if domain_intelligence:
        if domain_intelligence.get("entropy_results"):
            indicator_count += 1
        if domain_intelligence.get("lookalike_results"):
            indicator_count += 1

    if indicator_count >= 5:
        confidence = "95%"
    elif indicator_count >= 3:
        confidence = "80%"
    elif indicator_count >= 2:
        confidence = "60%"
    elif indicator_count >= 1:
        confidence = "40%"
    else:
        confidence = "20%"

    verdict = risk.get("verdict", "LOW")

    lines: list[str] = [
        "━━━ THREAT SUMMARY ━━━",
        f"Type           : {attack_type}",
    ]
    if target_brand:
        lines.append(f"Target brand   : {target_brand}")
    if techniques:
        lines.append(f"Technique      : {' + '.join(dict.fromkeys(techniques))}")
    lines.append(f"Goal           : {goal}")
    lines.append(f"Confidence     : {confidence}")
    lines.append(f"Risk Level     : {verdict}")
    lines.append("")
    return lines


# ── Main report generator ────────────────────────────────────

def generate_report(
    email_data: dict,
    auth_results: dict,
    urls: list[dict],
    attachments: list[dict],
    risk: dict,
    vt_url_reports: list[dict],
    vt_hash_reports: list[dict],
    otx_reports: list[dict],
    heuristics: dict | None = None,
    qr_findings: list[dict] | None = None,
    ip_reputation: list[dict] | None = None,
    passive_dns: list[dict] | None = None,
    ai_verdict: dict | None = None,
    header_forensics: dict | None = None,
    display_name_spoofing: list[dict] | None = None,
    lookalike_domains: list[dict] | None = None,
    credential_harvesting: dict | None = None,
    language_analysis: dict | None = None,
    brand_impersonation: dict | None = None,
    attachment_risks: list[dict] | None = None,
    url_intelligence: dict | None = None,
    domain_intelligence: dict | None = None,
) -> str:
    """
    Generate a professional SOC-grade phishing triage report.

    Returns:
        A multi-line string ready for display.
    """
    lines: list[str] = []

    # ── Report header ────────────────────────────────────────
    lines.append("🔍 *PHISHING TRIAGE REPORT*")
    lines.append(f"Generated: {datetime.now(timezone.utc):%Y-%m-%d %H:%M:%S UTC}")
    lines.append("")

    # ── 1. THREAT SUMMARY ────────────────────────────────────
    lines.extend(_build_threat_summary(
        risk, brand_impersonation, credential_harvesting,
        language_analysis, ai_verdict, heuristics,
        attachment_risks, domain_intelligence,
    ))

    # ── 2. EMAIL METADATA ────────────────────────────────────
    lines.append("━━━ EMAIL METADATA ━━━")
    lines.append(f"Subject : {_esc(email_data.get('subject', 'N/A'))}")
    lines.append(f"From    : {_esc(email_data.get('from', 'N/A'))}")
    lines.append(f"To      : {_esc(email_data.get('to', 'N/A'))}")
    lines.append(f"Date    : {_esc(email_data.get('date', 'N/A'))}")
    lines.append("")

    # ── 3. EMAIL AUTHENTICATION ──────────────────────────────
    lines.append("━━━ EMAIL AUTHENTICATION ━━━")
    for check in ("spf", "dkim", "dmarc"):
        result = auth_results.get(check, {}).get("result", "none")
        icon = "✅" if result == "pass" else "❌"
        lines.append(f"{icon} {check.upper()}: {result}")

    # Inline header forensics
    forensics = auth_results.get("forensics", {})
    if forensics:
        lines.append("")
        if forensics.get("from_domain"):
            lines.append(f"From domain       : {forensics['from_domain']}")
        if forensics.get("return_path_domain"):
            lines.append(f"Return-Path domain: {forensics['return_path_domain']}")
        if forensics.get("reply_to_domain"):
            lines.append(f"Reply-To domain   : {forensics['reply_to_domain']}")
        if forensics.get("message_id_domain"):
            lines.append(f"Message-ID domain : {forensics['message_id_domain']}")
        lines.append(f"Received hops     : {forensics.get('received_hops', 0)}")

        findings = forensics.get("findings", [])
        if findings:
            for f in findings:
                lines.append(f"⚠️ {f.get('summary', 'Header anomaly')}")
                if f.get("details"):
                    lines.append(f"   {f['details']}")
        else:
            lines.append("✅ No suspicious header anomalies detected")
    lines.append("")

    # ── 4. SMTP RELAY ANALYSIS ───────────────────────────────
    if header_forensics and not header_forensics.get("error"):
        lines.append("━━━ SMTP RELAY ANALYSIS ━━━")

        origin_ip = header_forensics.get("origin_ip")
        lines.append(f"Origin IP  : {origin_ip or 'not detected'}")

        country = header_forensics.get("origin_country", "Unknown")
        cc      = header_forensics.get("origin_country_code", "")
        city    = header_forensics.get("origin_city", "")
        isp     = header_forensics.get("origin_isp", "")
        if country and country != "Unknown":
            loc_parts = [p for p in [city, country] if p]
            lines.append(f"Country    : {', '.join(loc_parts)} ({cc})")
        if isp:
            lines.append(f"ISP        : {isp}")
        asn = header_forensics.get("origin_asn", "")
        asname = header_forensics.get("origin_asname", "")
        if asn:
            lines.append(f"ASN        : {asn}")
        if asname:
            lines.append(f"ASN Name   : {asname}")
        if header_forensics.get("origin_is_hosting"):
            lines.append("             ⚠️ Hosting / datacenter address")
        if header_forensics.get("origin_is_proxy"):
            lines.append("             ⚠️ Proxy / VPN exit node")

        relay_chain: list[dict] = header_forensics.get("relay_chain", [])
        if relay_chain:
            lines.append("")
            lines.append("Relay Path:")
            for idx, hop in enumerate(relay_chain, 1):
                server = hop.get("server") or "(unknown)"
                ip_tag = ""
                if hop.get("ip"):
                    origin_mark = " ⭐ origin" if hop["ip"] == origin_ip else ""
                    ip_tag = f" ({hop['ip']}{origin_mark})"
                lines.append(f"  {idx}. {server}{ip_tag}")
        else:
            lines.append("Relay Path : no Received headers found")

        warnings = header_forensics.get("warnings", [])
        if warnings:
            lines.append("")
            for w in warnings:
                icon = "ℹ️" if w.startswith("Origin IP geolocation:") else "⚠️"
                lines.append(f"{icon} {w}")
        else:
            lines.append("✅ No suspicious relay indicators")
        lines.append("")
    elif header_forensics and header_forensics.get("error"):
        lines.append("━━━ SMTP RELAY ANALYSIS ━━━")
        lines.append("⚠️ Relay analysis unavailable")
        lines.append("")

    # ── 5. URL ANALYSIS ──────────────────────────────────────
    lines.append(f"━━━ URL ANALYSIS ({len(urls)}) ━━━")
    if urls:
        for u in urls:
            short_tag = " [SHORTENED]" if u.get("is_shortened") else ""
            lines.append(f"• {u['url']}{short_tag}")
            if u.get("is_shortened"):
                lines.append(f"  ↳ Expanded: {u.get('expanded_url', 'N/A')}")
    else:
        lines.append("  No URLs found.")

    # URL shortener findings
    if url_intelligence:
        shortener_findings = url_intelligence.get("shortener_findings", [])
        redirect_findings = url_intelligence.get("redirect_findings", [])
        suspicious_endpoints = url_intelligence.get("suspicious_endpoints", [])

        if shortener_findings:
            lines.append("")
            lines.append("URL Shorteners:")
            for f in shortener_findings:
                lines.append(f"  ⚠️ {f['domain']} → {f['url']}")
                if f.get("expanded_url") and f["expanded_url"] != f["url"]:
                    lines.append(f"     Expanded: {f['expanded_url']}")

        if redirect_findings:
            lines.append("")
            lines.append("Redirect Chains:")
            for f in redirect_findings:
                if f.get("error"):
                    lines.append(f"  • {f['url']}: {_clean_error(f['error'])}")
                else:
                    lines.append(f"  ⚠️ {f['url']}")
                    lines.append(f"     Hops: {f['hops']} → Final: {f.get('final_domain', '?')}")
                    for i, step in enumerate(f.get("chain", [])):
                        lines.append(f"     {i}. {step}")
                    if f.get("suspicious_intermediates"):
                        for si in f["suspicious_intermediates"]:
                            lines.append(f"     ⚠️ Suspicious intermediate: {si['domain']} ({si['reason']})")

        if suspicious_endpoints:
            lines.append("")
            lines.append("Suspicious Endpoints:")
            for f in suspicious_endpoints:
                lines.append(f"  ⚠️ Keywords: {', '.join(f.get('keywords', []))}")
                lines.append(f"     URL: {f['url']}")
    lines.append("")

    # ── 6. DOMAIN INTELLIGENCE ───────────────────────────────
    _has_domain_intel = False
    if domain_intelligence:
        whois_results = domain_intelligence.get("whois_results", [])
        dns_results = domain_intelligence.get("dns_results", [])
        entropy_results = domain_intelligence.get("entropy_results", [])

        if whois_results or dns_results or entropy_results:
            _has_domain_intel = True
            lines.append("━━━ DOMAIN INTELLIGENCE ━━━")

            for w in whois_results:
                lines.append(f"Domain: {w['domain']}")
                if w.get("error"):
                    lines.append("  WHOIS: lookup failed")
                else:
                    if w.get("created"):
                        warning = " ⚠️ Newly registered" if (w.get("age_days") or 999) < 30 else ""
                        lines.append(f"  Created   : {w['created']}{warning}")
                        lines.append(f"  Age       : {w['age_days']} day(s)")
                    if w.get("registrar"):
                        lines.append(f"  Registrar : {w['registrar']}")
                    if w.get("country"):
                        lines.append(f"  Country   : {w['country']}")
                    if w.get("name_servers"):
                        lines.append(f"  NS        : {', '.join(w['name_servers'][:4])}")
                lines.append("")

            if dns_results:
                lines.append("DNS Analysis:")
                for d in dns_results:
                    lines.append(f"  {d['domain']}:")
                    if d.get("a_records"):
                        lines.append(f"    A   : {', '.join(d['a_records'][:3])}")
                    if d.get("mx_records"):
                        mx_str = ", ".join(
                            f"{m['host']} (pri {m['priority']})" for m in d["mx_records"][:3]
                        )
                        lines.append(f"    MX  : {mx_str}")
                    else:
                        lines.append("    ⚠️ No MX records found")
                    if d.get("has_spf"):
                        lines.append("    ✅ SPF record found")
                    else:
                        lines.append("    ⚠️ No SPF record found")
                lines.append("")

            if entropy_results:
                lines.append("Entropy Analysis:")
                for e in entropy_results:
                    lines.append(f"  ⚠️ {e['domain']} — entropy: {e['entropy']} (high)")
                lines.append("")

    # Suspicious keywords from heuristics (unique to this module)
    if heuristics and heuristics.get("suspicious_keywords"):
        if not _has_domain_intel:
            lines.append("━━━ DOMAIN INTELLIGENCE ━━━")
        lines.append("Suspicious Domain Keywords:")
        for f in heuristics["suspicious_keywords"]:
            lines.append(f"  ⚠️ Keyword '{f['keyword']}' in {f['source']}")
        lines.append("")

    # ── 7. BRAND IMPERSONATION ANALYSIS (unified) ────────────
    _brand_lines = _build_unified_brand_section(
        brand_impersonation, heuristics, domain_intelligence,
    )
    if _brand_lines:
        lines.extend(_brand_lines)

    # ── 8. PHISHING LANGUAGE ANALYSIS ────────────────────────
    if language_analysis and language_analysis.get("total_matches", 0) > 0:
        lines.append("━━━ PHISHING LANGUAGE ANALYSIS ━━━")
        for cat_name, cat_info in language_analysis.get("categories", {}).items():
            matches_str = ", ".join(cat_info["matches"][:3])
            lines.append(f"⚠️ {cat_info['description']}")
            lines.append(f"   Detected: {matches_str}")
        lines.append("")

    # ── 9. CREDENTIAL HARVESTING DETECTION ───────────────────
    if credential_harvesting and credential_harvesting.get("detected"):
        lines.append("━━━ CREDENTIAL HARVESTING DETECTION ━━━")
        for finding_text in credential_harvesting.get("findings", []):
            lines.append(f"⚠️ {finding_text}")
        if credential_harvesting.get("post_endpoints"):
            for ep in credential_harvesting["post_endpoints"][:3]:
                lines.append(f"   POST endpoint: {ep}")
        lines.append("")

    # ── 10. THREAT INTELLIGENCE ──────────────────────────────
    _ti_header_shown = False

    # VirusTotal URL results
    if vt_url_reports:
        lines.append("━━━ THREAT INTELLIGENCE ━━━")
        _ti_header_shown = True
        lines.append("VirusTotal – URLs:")
        all_clean = True
        for r in vt_url_reports:
            if r.get("malicious", 0) > 0:
                all_clean = False
                lines.append(f"  🔴 {r.get('url', '?')} — {r['malicious']} engine(s) flagged malicious")
            elif r.get("error") and r["error"] != "submitted_for_analysis":
                lines.append(f"  ⚠️ {r.get('url', '?')} — scan unavailable")
            else:
                lines.append(f"  🟢 {r.get('url', '?')} — Clean")
        if all_clean:
            lines.append(
                "  ℹ️ Note: Newly registered phishing domains often appear clean "
                "in threat intelligence databases."
            )
        lines.append("")

    # VirusTotal Hash results
    if vt_hash_reports:
        if not _ti_header_shown:
            lines.append("━━━ THREAT INTELLIGENCE ━━━")
            _ti_header_shown = True
        lines.append("VirusTotal – File Hashes:")
        for r in vt_hash_reports:
            if r.get("malicious", 0) > 0:
                lines.append(f"  🔴 {r.get('sha256', '?')[:32]}… — {r['malicious']} engine(s)")
            else:
                lines.append(f"  🟢 {r.get('sha256', '?')[:32]}… — Clean / Unknown")
        lines.append("")

    # AlienVault OTX
    if otx_reports:
        if not _ti_header_shown:
            lines.append("━━━ THREAT INTELLIGENCE ━━━")
            _ti_header_shown = True
        lines.append("AlienVault OTX:")
        for r in otx_reports:
            identifier = r.get("domain") or (r.get("sha256", "?")[:32] + "…")
            count = r.get("pulse_count", 0)
            icon = "⚠️" if count > 0 else "🟢"
            lines.append(f"  {icon} {identifier}: {count} pulse(s)")
        lines.append("")

    # IP Reputation
    if ip_reputation:
        if not _ti_header_shown:
            lines.append("━━━ THREAT INTELLIGENCE ━━━")
            _ti_header_shown = True
        lines.append("IP Reputation:")
        for f in ip_reputation:
            abuse = f["abuseipdb"]
            spamhaus = f["spamhaus"]
            bl_icon = "🔴" if f["blacklisted"] else "🟢"
            lines.append(f"  {bl_icon} {f['ip']} (domain: {f['domain']})")
            if abuse.get("error"):
                lines.append(f"     AbuseIPDB: unavailable")
            else:
                lines.append(f"     AbuseIPDB: abuse score {abuse['abuse_score']}%")
                if abuse.get("total_reports"):
                    lines.append(f"     Reports: {abuse['total_reports']} | Country: {abuse.get('country', '?')}")
            if spamhaus.get("error"):
                lines.append(f"     Spamhaus: unavailable")
            elif spamhaus["listed"]:
                lines.append(f"     Spamhaus: ⚠️ LISTED in {spamhaus['zone']}")
            else:
                lines.append(f"     Spamhaus: not listed")
        lines.append("")

    # Passive DNS
    if passive_dns:
        has_pdns = any(f["domain_count"] > 0 or f.get("error") for f in passive_dns)
        if has_pdns:
            if not _ti_header_shown:
                lines.append("━━━ THREAT INTELLIGENCE ━━━")
                _ti_header_shown = True
            lines.append("Passive DNS:")
            for f in passive_dns:
                if f.get("error"):
                    lines.append(f"  • IP {f['ip']}: lookup unavailable")
                else:
                    flag = " ⚠️" if f["suspicious"] else ""
                    lines.append(f"  • IP {f['ip']}: {f['domain_count']} domain(s) hosted{flag}")
                    for d in f.get("sample_domains", [])[:5]:
                        lines.append(f"    → {d}")
            lines.append("")

    # ── 11. AI PHISHING CLASSIFIER ───────────────────────────
    if ai_verdict and not ai_verdict.get("error"):
        verdict_icons = {
            "phishing": "🔴",
            "suspicious": "🟡",
            "legitimate": "🟢",
        }
        v = ai_verdict["verdict"]
        icon = verdict_icons.get(v, "⚪")
        lines.append("━━━ AI PHISHING CLASSIFIER ━━━")
        lines.append(f"{icon} Verdict    : {v.upper()}")
        lines.append(f"  Confidence : {ai_verdict['confidence']:.0%}")
        if ai_verdict.get("reasons"):
            lines.append("  Reasons:")
            for reason in ai_verdict["reasons"]:
                lines.append(f"    – {reason}")
        lines.append("")

    # ── 12. ATTACHMENTS ──────────────────────────────────────
    lines.append(f"━━━ ATTACHMENTS ({len(attachments)}) ━━━")
    if attachments:
        for a in attachments:
            lines.append(f"• {a['filename']} ({a['content_type']}, {a['size_bytes']} bytes)")
            lines.append(f"  SHA256: {a['sha256']}")
    else:
        lines.append("  No attachments found.")

    if attachment_risks:
        lines.append("")
        lines.append("Attachment Risk Assessment:")
        for f in attachment_risks:
            for w in f.get("warnings", []):
                lines.append(f"  {w}")
            lines.append(f"  File: {f['filename']} ({f['content_type']})")
            lines.append(f"  Category: {f['category']} | Risk: +{f['risk_score']}")

    if qr_findings:
        lines.append("")
        lines.append(f"QR Codes Detected ({len(qr_findings)}):")
        for f in qr_findings:
            lines.append(f"  ⚠️ QR code in attachment: {f['filename']}")
            lines.append(f"     Type: {f['qr_type']}")
            if f.get("url"):
                lines.append(f"     Decoded URL: {f['url']}")
            else:
                lines.append(f"     Decoded data: {f['qr_data'][:120]}")
    lines.append("")

    # ── 13. RISK ASSESSMENT ──────────────────────────────────
    lines.append("━━━ RISK ASSESSMENT ━━━")
    verdict_icon = {
        "LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴",
    }.get(risk["verdict"], "⚪")
    lines.append(f"Score   : {risk['score']} / 100")
    lines.append(f"Verdict : {verdict_icon} {risk['verdict']}")
    lines.append("")
    lines.append("Scoring legend:")
    lines.append("  0–30  Low  |  30–60  Medium  |  60–80  High  |  80–100  Critical")
    lines.append("")
    if risk.get("breakdown"):
        lines.append("Indicator Breakdown:")
        for reason in risk["breakdown"]:
            lines.append(f"  – {reason}")
    lines.append("")
    lines.append("━━━ END OF REPORT ━━━")

    report_text = "\n".join(lines)
    logger.info("Report generated (%d chars)", len(report_text))
    return report_text


# ── Unified brand impersonation section ──────────────────────

def _build_unified_brand_section(
    brand_impersonation: dict | None,
    heuristics: dict | None,
    domain_intelligence: dict | None,
) -> list[str]:
    """
    Consolidate all brand-related findings into one unified section.

    Sources merged:
      - BrandDetector (domain_impersonation, display_name_spoofing, body_brand_mentions)
      - heuristics.homograph, heuristics.homograph_brands
      - domain_intelligence.lookalike_results
    """
    keyword_lines: list[str] = []
    homograph_lines: list[str] = []
    lookalike_lines: list[str] = []
    display_lines: list[str] = []
    body_lines: list[str] = []
    seen_brands: set[tuple[str, str]] = set()   # (brand, domain) dedup

    # --- BrandDetector results ---
    if brand_impersonation:
        for f in brand_impersonation.get("domain_impersonation", []):
            key = (f.get("brand", ""), f.get("domain", ""))
            if key in seen_brands:
                continue
            seen_brands.add(key)

            imp_type = f.get("type", "domain_keyword")
            if imp_type == "lookalike":
                lookalike_lines.append(
                    f"  Lookalike domain: {f['domain']} vs {f['brand']} ({f.get('detail', '')})"
                )
            else:
                keyword_lines.append(
                    f"  Brand keyword detected: {f['brand']} in {f['domain']}"
                )

        for f in brand_impersonation.get("display_name_spoofing", []):
            display_lines.append(
                f"  Display name spoofing: brand '{f['brand']}' (sender: {f['sender_domain']})"
            )

        for f in brand_impersonation.get("body_brand_mentions", [])[:3]:
            body_lines.append(
                f"  Brand '{f['brand']}' mentioned in body (sender: {f['sender_domain']})"
            )

    # --- Heuristic homograph findings ---
    if heuristics:
        for f in heuristics.get("homograph_brands", []):
            key = (f.get("brand", ""), f.get("original_domain", ""))
            if key in seen_brands:
                continue
            seen_brands.add(key)
            homograph_lines.append(
                f"  Homograph detected: {f['original_domain']} → {f['brand']} "
                f"(normalized: {f['normalized_domain']})"
            )

        for f in heuristics.get("homograph", []):
            decoded_info = f" (decoded: {f['decoded']})" if f.get("decoded") != f.get("domain") else ""
            homograph_lines.append(
                f"  IDN homograph attack: {f['domain']}{decoded_info} — {f.get('details', '')}"
            )

    # --- Domain intelligence lookalike ---
    if domain_intelligence:
        for la in domain_intelligence.get("lookalike_results", []):
            key = (la.get("brand", ""), la.get("domain", ""))
            if key in seen_brands:
                continue
            seen_brands.add(key)
            lookalike_lines.append(
                f"  Lookalike domain: {la['domain']} vs {la['brand']} (distance={la['distance']})"
            )

    # Build section only if there are findings
    all_subs = keyword_lines + homograph_lines + lookalike_lines + display_lines + body_lines
    if not all_subs:
        return []

    lines: list[str] = ["━━━ BRAND IMPERSONATION ANALYSIS ━━━"]

    if keyword_lines:
        lines.append("")
        lines.append("Brand Keyword Detection:")
        lines.extend(keyword_lines)

    if homograph_lines:
        lines.append("")
        lines.append("Homograph Detection:")
        lines.extend(homograph_lines)

    if lookalike_lines:
        lines.append("")
        lines.append("Lookalike Domain Detection:")
        lines.extend(lookalike_lines)

    if display_lines:
        lines.append("")
        lines.append("Display Name Spoofing:")
        lines.extend(display_lines)

    if body_lines:
        lines.append("")
        lines.append("Body Brand Mentions:")
        lines.extend(body_lines)

    lines.append("")
    return lines


def _esc(text: str) -> str:
    """Minimal escaping for Telegram Markdown compatibility."""
    return text.replace("_", "\\_").replace("*", "\\*")
