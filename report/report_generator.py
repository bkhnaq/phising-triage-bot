"""
Report Generator Module
-----------------------
Builds a human-readable phishing analysis report from all collected data.

The report is formatted as Markdown so it renders nicely inside Telegram
(using MarkdownV2 parse mode) and is also easy to read in plain text.

Usage:
    from report.report_generator import generate_report
    text = generate_report(email_data, auth, urls, attachments, risk, vt_urls, vt_hashes, otx)
"""

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


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
) -> str:
    """
    Generate a structured phishing analysis report.

    Returns:
        A multi-line string (Markdown-formatted).
    """
    lines: list[str] = []

    # ── Header ───────────────────────────────────────────────
    lines.append("🔍 *PHISHING TRIAGE REPORT*")
    lines.append(f"Generated: {datetime.now(timezone.utc):%Y-%m-%d %H:%M:%S UTC}")
    lines.append("")

    # ── Email Metadata ───────────────────────────────────────
    lines.append("━━━ EMAIL METADATA ━━━")
    lines.append(f"Subject : {_esc(email_data.get('subject', 'N/A'))}")
    lines.append(f"From    : {_esc(email_data.get('from', 'N/A'))}")
    lines.append(f"To      : {_esc(email_data.get('to', 'N/A'))}")
    lines.append(f"Date    : {_esc(email_data.get('date', 'N/A'))}")
    lines.append("")

    # ── Authentication ───────────────────────────────────────
    lines.append("━━━ EMAIL AUTHENTICATION ━━━")
    for check in ("spf", "dkim", "dmarc"):
        result = auth_results.get(check, {}).get("result", "none")
        icon = "✅" if result == "pass" else "❌"
        lines.append(f"{icon} {check.upper()}: {result}")
    lines.append("")

    # ── Header Forensics ─────────────────────────────────────
    forensics = auth_results.get("forensics", {})
    if forensics:
        lines.append("━━━ EMAIL HEADER FORENSICS ━━━")
        if forensics.get("from_domain"):
            lines.append(f"From domain      : {forensics['from_domain']}")
        if forensics.get("return_path_domain"):
            lines.append(f"Return-Path domain: {forensics['return_path_domain']}")
        if forensics.get("reply_to_domain"):
            lines.append(f"Reply-To domain  : {forensics['reply_to_domain']}")
        if forensics.get("message_id_domain"):
            lines.append(f"Message-ID domain: {forensics['message_id_domain']}")
        lines.append(f"Received hops    : {forensics.get('received_hops', 0)}")

        findings = forensics.get("findings", [])
        if findings:
            for f in findings:
                lines.append(f"⚠️ {f.get('summary', 'Header anomaly')} (+{f.get('risk_score', 0)})")
                if f.get("details"):
                    lines.append(f"   {f['details']}")
        else:
            lines.append("✅ No suspicious header anomalies detected")
        lines.append("")

    # ── SMTP Relay Forensics ──────────────────────────────────
    if header_forensics and not header_forensics.get("error"):
        lines.append("━━━ SMTP RELAY FORENSICS ━━━")

        origin_ip = header_forensics.get("origin_ip")
        lines.append(f"Origin IP  : {origin_ip}" if origin_ip else "Origin IP  : not detected")

        country = header_forensics.get("origin_country", "Unknown")
        cc      = header_forensics.get("origin_country_code", "")
        city    = header_forensics.get("origin_city", "")
        isp     = header_forensics.get("origin_isp", "")
        if country and country != "Unknown":
            loc_parts = [p for p in [city, country] if p]
            lines.append(f"Country    : {', '.join(loc_parts)} ({cc})")
        if isp:
            lines.append(f"ISP        : {isp}")
        if header_forensics.get("origin_is_hosting"):
            lines.append("               ⚠️ Hosting/datacenter address")
        if header_forensics.get("origin_is_proxy"):
            lines.append("               ⚠️ Proxy / VPN exit node")

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
        lines.append("━━━ SMTP RELAY FORENSICS ━━━")
        lines.append("⚠️ Relay forensics unavailable (analysis error)")
        lines.append("")

    # ── URLs ─────────────────────────────────────────────────
    lines.append(f"━━━ URLS FOUND ({len(urls)}) ━━━")
    if urls:
        for u in urls:
            short_tag = " [SHORTENED]" if u.get("is_shortened") else ""
            lines.append(f"• {u['url']}{short_tag}")
            if u.get("is_shortened"):
                lines.append(f"  ↳ Expanded: {u.get('expanded_url', 'N/A')}")
    else:
        lines.append("  No URLs found.")
    lines.append("")

    # ── VirusTotal URL Results ───────────────────────────────
    if vt_url_reports:
        lines.append("━━━ VIRUSTOTAL URL RESULTS ━━━")
        for r in vt_url_reports:
            status = (
                f"🔴 {r['malicious']} malicious"
                if r.get("malicious", 0) > 0
                else "🟢 Clean"
            )
            lines.append(f"• {r.get('url', '?')} → {status}")
        lines.append("")

    # ── Attachments ──────────────────────────────────────────
    lines.append(f"━━━ ATTACHMENTS ({len(attachments)}) ━━━")
    if attachments:
        for a in attachments:
            lines.append(f"• {a['filename']} ({a['content_type']}, {a['size_bytes']} bytes)")
            lines.append(f"  SHA256: {a['sha256']}")
    else:
        lines.append("  No attachments found.")
    lines.append("")

    # ── VirusTotal Hash Results ──────────────────────────────
    if vt_hash_reports:
        lines.append("━━━ VIRUSTOTAL HASH RESULTS ━━━")
        for r in vt_hash_reports:
            status = (
                f"🔴 {r['malicious']} malicious"
                if r.get("malicious", 0) > 0
                else "🟢 Clean / Unknown"
            )
            lines.append(f"• {r.get('sha256', '?')[:32]}… → {status}")
        lines.append("")

    # ── AlienVault OTX ───────────────────────────────────────
    if otx_reports:
        lines.append("━━━ ALIENVAULT OTX ━━━")
        for r in otx_reports:
            identifier = r.get("domain") or (r.get("sha256", "?")[:32] + "…")
            lines.append(f"• {identifier}: {r.get('pulse_count', 0)} pulse(s)")
        lines.append("")

    # ── Heuristic Findings ────────────────────────────────────
    if heuristics:
        # Brand impersonation
        bi = heuristics.get("brand_impersonation", [])
        if bi:
            lines.append("━━━ BRAND IMPERSONATION ━━━")
            for f in bi:
                lines.append(f"⚠️ '{f['brand']}' detected in suspicious domain: {f['domain']}")
            lines.append("")

        # Suspicious keywords
        sk = heuristics.get("suspicious_keywords", [])
        if sk:
            lines.append("━━━ SUSPICIOUS DOMAIN KEYWORDS ━━━")
            for f in sk:
                lines.append(f"⚠️ Keyword '{f['keyword']}' found in: {f['source']}")
            lines.append("")

        # Domain age
        da = heuristics.get("domain_age", [])
        if da:
            lines.append("━━━ DOMAIN AGE ━━━")
            for f in da:
                lines.append(f"• {f['domain']}")
                if f.get("error"):
                    lines.append(f"  lookup failed")
                elif f.get("created") is not None:
                    warning = " ⚠️" if f["risk_score"] > 0 else ""
                    lines.append(f"  Created: {f['created']}")
                    lines.append(f"  Age: {f['age_days']} day(s){warning}")
                    if f.get("registrar"):
                        lines.append(f"  Registrar: {f['registrar']}")
                    if f.get("name_servers"):
                        lines.append(f"  Name servers: {', '.join(f['name_servers'])}")
                else:
                    lines.append(f"  lookup failed")
            lines.append("")

        # URL shorteners
        us = heuristics.get("url_shorteners", [])
        if us:
            lines.append("━━━ URL SHORTENER DETECTED ━━━")
            for f in us:
                lines.append(f"⚠️ {f['domain']} detected → {f['url']}")
            lines.append("")

        # Homograph attacks (Cyrillic / IDN)
        hg = heuristics.get("homograph", [])
        if hg:
            lines.append("━━━ HOMOGRAPH DETECTION ━━━")
            for f in hg:
                decoded_info = f" (decoded: {f['decoded']})" if f['decoded'] != f['domain'] else ""
                lines.append(f"⚠️ Possible homograph attack: {f['domain']}{decoded_info}")
                lines.append(f"   Details: {f['details']}")
            lines.append("")

        # Homograph brand impersonation (ASCII look-alikes)
        hb = heuristics.get("homograph_brands", [])
        if hb:
            lines.append("━━━ HOMOGRAPH BRAND DETECTION ━━━")
            for f in hb:
                lines.append("⚠️ Possible brand impersonation detected")
                lines.append(f"   Original domain  : {f['original_domain']}")
                lines.append(f"   Normalized domain : {f['normalized_domain']}")
                lines.append(f"   Detected brand    : {f['brand']}")
            lines.append("")

        # Domain entropy
        de = heuristics.get("domain_entropy", [])
        if de:
            lines.append("━━━ DOMAIN ENTROPY ━━━")
            for f in de:
                lines.append(f"⚠️ High entropy domain: {f['domain']} (entropy = {f['entropy']})")
            lines.append("")

        # Redirect chains
        rc = heuristics.get("redirect_chains", [])
        if rc:
            lines.append("━━━ REDIRECT CHAIN ━━━")
            for f in rc:
                if f.get("error"):
                    lines.append(f"• {f['url']}: check failed ({f['error']})")
                else:
                    lines.append(f"⚠️ {f['url']} → {f['hops']} redirect(s) → {f['final_url']}")
                    for i, step in enumerate(f['chain']):
                        lines.append(f"   {i}. {step}")
            lines.append("")

    # ── QR Code Analysis ───────────────────────────────────────
    if qr_findings:
        lines.append(f"━━━ QR CODE ANALYSIS ({len(qr_findings)}) ━━━")
        for f in qr_findings:
            lines.append(f"⚠️ QR code detected in attachment: {f['filename']}")
            lines.append(f"   Type: {f['qr_type']}")
            if f.get("url"):
                lines.append(f"   Decoded URL: {f['url']}")
            else:
                lines.append(f"   Decoded data: {f['qr_data'][:120]}")
        lines.append("")
    # ── IP Reputation ─────────────────────────────────────────
    if ip_reputation:
        lines.append("━━━ IP REPUTATION ━━━")
        for f in ip_reputation:
            abuse = f["abuseipdb"]
            spamhaus = f["spamhaus"]
            bl_icon = "🔴" if f["blacklisted"] else "🟢"
            lines.append(f"{bl_icon} {f['ip']} (domain: {f['domain']})")

            # AbuseIPDB details
            if abuse.get("error"):
                lines.append(f"  AbuseIPDB: unavailable")
            else:
                lines.append(f"  AbuseIPDB: abuse score {abuse['abuse_score']}%")
                if abuse.get("total_reports"):
                    lines.append(f"  Reports: {abuse['total_reports']} | Country: {abuse.get('country', '?')}")
                if abuse.get("isp"):
                    lines.append(f"  ISP: {abuse['isp']}")

            # Spamhaus details
            if spamhaus.get("error"):
                lines.append(f"  Spamhaus: unavailable")
            elif spamhaus["listed"]:
                lines.append(f"  Spamhaus: ⚠️ LISTED in {spamhaus['zone']}")
            else:
                lines.append(f"  Spamhaus: not listed")
        lines.append("")

    # ── Passive DNS ───────────────────────────────────────────
    if passive_dns:
        has_findings = any(f["domain_count"] > 0 or f.get("error") for f in passive_dns)
        if has_findings:
            lines.append("━━━ PASSIVE DNS ━━━")
            for f in passive_dns:
                if f.get("error"):
                    lines.append(f"• IP {f['ip']}: lookup unavailable")
                else:
                    flag = " ⚠️" if f["suspicious"] else ""
                    lines.append(f"• IP {f['ip']}: {f['domain_count']} domain(s) hosted{flag}")
                    if f["sample_domains"]:
                        for d in f["sample_domains"][:5]:
                            lines.append(f"  → {d}")
            lines.append("")

    # ── AI Phishing Classifier ─────────────────────────────────
    if ai_verdict and not ai_verdict.get("error"):
        verdict_icons = {
            "phishing": "🔴",
            "suspicious": "🟡",
            "legitimate": "🟢",
        }
        v = ai_verdict["verdict"]
        icon = verdict_icons.get(v, "⚪")
        lines.append("━━━ AI PHISHING CLASSIFIER ━━━")
        lines.append(f"{icon} Verdict: {v.upper()}")
        lines.append(f"  Confidence: {ai_verdict['confidence']:.0%}")
        if ai_verdict.get("reasons"):
            lines.append("  Reasons:")
            for reason in ai_verdict["reasons"]:
                lines.append(f"    – {reason}")
        lines.append("")
    # ── Display Name Spoofing ─────────────────────────────────
    if display_name_spoofing:
        lines.append("━━━ DISPLAY NAME SPOOFING ━━━")
        for f in display_name_spoofing:
            lines.append(f"⚠️ Display name impersonates brand '{f['brand']}'")
            lines.append(f"   Sender domain: {f['sender_domain']}")
        lines.append("")

    # ── Lookalike Domain Detection ────────────────────────────
    if lookalike_domains:
        lines.append("━━━ DOMAIN LOOKALIKE DETECTION ━━━")
        for f in lookalike_domains:
            lines.append("⚠️ Lookalike domain detected")
            lines.append(f"   Domain: {f['domain']}")
            lines.append(f"   Similar brand: {f['brand']} (edit distance: {f['distance']})")
        lines.append("")

    # ── Risk Verdict ─────────────────────────────────────────
    lines.append("━━━ RISK ASSESSMENT ━━━")
    verdict_icon = {
        "LOW": "🟢",
        "MEDIUM": "🟡",
        "HIGH": "🟠",
        "CRITICAL": "🔴",
    }.get(risk["verdict"], "⚪")
    lines.append(f"Score  : {risk['score']} / 100")
    lines.append(f"Verdict: {verdict_icon} {risk['verdict']}")
    lines.append("")
    if risk.get("breakdown"):
        lines.append("Breakdown:")
        for reason in risk["breakdown"]:
            lines.append(f"  – {reason}")
    lines.append("")
    lines.append("━━━ END OF REPORT ━━━")

    report_text = "\n".join(lines)
    logger.info("Report generated (%d chars)", len(report_text))
    return report_text


def _esc(text: str) -> str:
    """Minimal escaping for Telegram Markdown compatibility."""
    return text.replace("_", "\\_").replace("*", "\\*")
