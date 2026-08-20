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

from email_analysis.domain_utils import registered_domain

logger = logging.getLogger(__name__)


# ── Error message sanitiser ──────────────────────────────────

_ERROR_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"HTTPConnectionPool|HTTPSConnectionPool", re.I), "Connection failed"),
    (re.compile(r"ConnectionError|ConnectTimeout", re.I), "Connection timed out"),
    (re.compile(r"Max retries exceeded", re.I), "Domain could not be resolved"),
    (
        re.compile(
            r"NameResolutionError|getaddrinfo failed|Name or service not known", re.I
        ),
        "Domain could not be resolved",
    ),
    (re.compile(r"ReadTimeout|read timed out", re.I), "Request timed out"),
    (re.compile(r"TooManyRedirects", re.I), "Too many redirects"),
    (
        re.compile(r"SSLError|SSL: CERTIFICATE_VERIFY_FAILED", re.I),
        "SSL certificate error",
    ),
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


def _recommended_actions(
    verdict: str,
    *,
    email_data: dict | None = None,
    auth_results: dict | None = None,
    urls: list[dict] | None = None,
    brand_impersonation: dict | None = None,
    credential_harvesting: dict | None = None,
    url_intelligence: dict | None = None,
    attachment_risks: list[dict] | None = None,
) -> list[str]:
    """Return evidence-driven SOC actions for the current message."""
    normalized = verdict.upper()
    actions: list[str] = []
    identity_findings = (brand_impersonation or {}).get("sender_identity_mismatch", [])
    if identity_findings:
        finding = identity_findings[0]
        actions.append("Treat the sender identity as unverified.")
        actions.append(
            f"Verify whether {finding.get('sender_domain', 'the sender domain')} is "
            "authorized to send for the claimed organization."
        )
        actions.append(
            f"Do not block {finding.get('expected_domain', 'the claimed brand domain')} "
            "or its subdomains based on this sample alone."
        )

    auth = auth_results or {}
    auth_unknown = any(
        str(auth.get(check, {}).get("result", "unknown")).lower() in {"unknown", "none"}
        for check in ("spf", "dkim", "dmarc")
    )
    missing_received = not auth.get("forensics", {}).get("received_hops")
    if auth_unknown or missing_received:
        actions.append(
            "Obtain the original message with full SMTP headers for authentication and relay analysis."
        )

    url_items = urls or []
    no_anchor_evidence = bool(url_items) and not any(
        item.get("link_target_comparison") in {"match", "mismatch"}
        for item in url_items
    )
    if no_anchor_evidence:
        actions.append(
            "Preserve the original HTML MIME part to compare displayed links with actual HREF destinations."
        )

    deceptive = any(
        int(item.get("risk_score", 0)) > 0
        for item in (url_intelligence or {}).get("deceptive_links", [])
    )
    credential_evidence = bool(
        credential_harvesting and credential_harvesting.get("detected")
    )
    if deceptive or credential_evidence:
        actions.append("Search proxy/DNS logs for users who accessed the destination.")
        actions.append(
            "If credentials may have been submitted, escalate for account containment and password reset."
        )

    if any(int(item.get("risk_score", 0)) > 0 for item in attachment_risks or []):
        actions.append(
            "Quarantine the attachment and review execution telemetry in an approved sandbox."
        )

    sender = (auth.get("forensics", {}) or {}).get("from_domain", "")
    subject = str((email_data or {}).get("subject", "")).strip()
    if sender or subject:
        search_terms = ", ".join(
            term
            for term in (
                f"sender {sender}" if sender else "",
                f"subject '{subject}'" if subject else "",
            )
            if term
        )
        actions.append(
            f"Search the mail environment for messages matching {search_terms}."
        )

    if normalized in {"CRITICAL", "HIGH"}:
        actions.insert(
            0, "Quarantine the message and block only confirmed malicious IOCs."
        )
    elif not actions:
        actions.append(
            "Retain normal monitoring and verify any unexpected request through a trusted channel."
        )
    return list(dict.fromkeys(actions))[:8]


def _collect_iocs(
    urls: list[dict],
    attachments: list[dict],
    url_intelligence: dict | None,
    sender_domain: str = "",
    brand_impersonation: dict | None = None,
    vt_url_reports: list[dict] | None = None,
    vt_hash_reports: list[dict] | None = None,
    otx_reports: list[dict] | None = None,
    attachment_risks: list[dict] | None = None,
) -> dict[str, list[tuple[str, str]]]:
    """Classify observables so trusted context is never exported as malicious."""
    groups: dict[str, list[tuple[str, str]]] = {
        "candidates": [],
        "contextual": [],
        "trusted": [],
    }
    seen: set[tuple[str, str, str]] = set()

    def add(group: str, kind: str, value: object) -> None:
        normalized = str(value or "").strip()
        key = (group, kind, normalized)
        if normalized and key not in seen and sum(map(len, groups.values())) < 30:
            seen.add(key)
            groups[group].append((kind, normalized))

    identity_findings = (brand_impersonation or {}).get("sender_identity_mismatch", [])
    suspicious_senders = {
        str(finding.get("sender_domain", "")) for finding in identity_findings
    }
    trusted_roots = {
        registered_domain(str(finding.get("expected_domain", "")))
        for finding in identity_findings
        if finding.get("expected_domain")
    }
    if sender_domain in suspicious_senders:
        add("candidates", "Sender domain", sender_domain)
    else:
        add("contextual", "Sender domain", sender_domain)

    for item in urls:
        url = item.get("normalized_url") or item.get("expanded_url") or item.get("url")
        domain = str(item.get("domain") or item.get("registered_domain") or "")
        root = registered_domain(domain)
        add(
            "contextual",
            "URL",
            url,
        )
        add("contextual", "URL domain", domain)
        if root in trusted_roots:
            add("trusted", "Brand domain", root)

    if url_intelligence:
        for finding in url_intelligence.get("deceptive_links", []):
            if int(finding.get("risk_score", 0)) > 0:
                add("candidates", "Deceptive-link URL", finding.get("url"))
                add("candidates", "Deceptive-link domain", finding.get("actual_domain"))
        for finding in url_intelligence.get("redirect_findings", []):
            add("contextual", "Redirect destination", finding.get("final_url"))
            add("contextual", "Redirect domain", finding.get("final_domain"))
        for finding in url_intelligence.get("shortener_findings", []):
            add("contextual", "Expanded URL", finding.get("expanded_url"))
            add("contextual", "Expanded domain", finding.get("expanded_domain"))

    for report in vt_url_reports or []:
        if int(report.get("malicious", 0)) > 0:
            add("candidates", "Known-malicious URL", report.get("url"))
    for report in vt_hash_reports or []:
        if int(report.get("malicious", 0)) > 0:
            add("candidates", "Known-malicious SHA-256", report.get("sha256"))
    for report in otx_reports or []:
        if int(report.get("pulse_count", 0)) > 0:
            value = report.get("sha256") or report.get("url") or report.get("domain")
            add("candidates", "OTX indicator", value)

    risky_names = {
        str(finding.get("filename", ""))
        for finding in attachment_risks or []
        if int(finding.get("risk_score", 0)) > 0
    }
    for attachment in attachments:
        group = (
            "candidates" if attachment.get("filename") in risky_names else "contextual"
        )
        add(group, "Attachment SHA-256", attachment.get("sha256"))
    return groups


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
    url_intelligence: dict | None = None,
) -> list[str]:
    """Produce a concise THREAT SUMMARY block."""

    # ── Determine attack type & target brand ─────────────────
    target_brand = ""
    impersonation = ""
    primary_indicator = ""
    theme = "Unknown"
    goal = "Unknown"
    sender_identity_mismatch = False

    # Brand impersonation
    if brand_impersonation:
        identity_mismatches = brand_impersonation.get("sender_identity_mismatch", [])
        if identity_mismatches:
            sender_identity_mismatch = True
            target_brand = identity_mismatches[0].get("claimed_organization", "")
            impersonation = identity_mismatches[0].get("claimed_identity", "")
            primary_indicator = "Sender-domain mismatch"
        domain_imp = brand_impersonation.get("domain_impersonation", [])
        if domain_imp and not target_brand:
            target_brand = domain_imp[0].get("brand", "").title()
            imp_type = domain_imp[0].get("type", "")
            if imp_type == "lookalike":
                primary_indicator = primary_indicator or "Lookalike domain"
            elif imp_type == "domain_keyword":
                primary_indicator = primary_indicator or "Brand keyword in domain"
        dn_spoof = brand_impersonation.get("display_name_spoofing", [])
        if dn_spoof and not target_brand:
            target_brand = dn_spoof[0].get("brand", "").title()
            primary_indicator = "Display-name mismatch"

    # Homograph from heuristics
    if heuristics:
        if heuristics.get("homograph_brands"):
            primary_indicator = primary_indicator or "Homograph domain"
            if not target_brand:
                target_brand = (
                    heuristics["homograph_brands"][0].get("brand", "").title()
                )
        if heuristics.get("homograph"):
            primary_indicator = primary_indicator or "IDN homograph"

    deceptive_links = [
        finding
        for finding in (url_intelligence or {}).get("deceptive_links", [])
        if int(finding.get("risk_score", 0)) > 0
    ]
    if deceptive_links:
        primary_indicator = "Displayed URL differs from actual HREF"

    # Credential harvesting
    if credential_harvesting and credential_harvesting.get("detected"):
        goal = "Likely credential theft"

    # Attachment malware
    has_risky_attach = bool(
        attachment_risks and any(a.get("risk_score", 0) > 0 for a in attachment_risks)
    )

    # Language cues
    if language_analysis:
        cats = language_analysis.get("categories", {})
        if {
            "credential_harvesting",
            "account_verification",
            "password_expiration",
        } & set(cats):
            goal = "Likely credential theft"
        if "financial" in cats:
            goal = "Likely financial fraud"
        if "password_expiration" in cats and "account_verification" in cats:
            theme = "Account expiration / reactivation"
        elif "password_expiration" in cats:
            theme = "Password expiration"
        elif "account_verification" in cats:
            theme = "Account verification / reactivation"
        elif "financial" in cats:
            theme = "Invoice / payment request"
    if has_risky_attach:
        goal = "Likely malware delivery" if goal == "Unknown" else goal

    # Attack type label
    credential_context = goal == "Likely credential theft"
    if credential_context:
        attack_type = "Credential phishing"
    elif "financial" in (language_analysis or {}).get("categories", {}):
        attack_type = "Invoice/payment phishing"
    elif has_risky_attach:
        attack_type = "Malware delivery"
    elif sender_identity_mismatch or target_brand:
        attack_type = "Organization impersonation"
    elif ai_verdict and ai_verdict.get("verdict") == "phishing":
        attack_type = "Generic phishing"
    else:
        attack_type = "Unknown"

    verdict = risk.get("verdict", "LOW")
    overall_confidence = float(risk.get("confidence", 0.0))
    completeness = int(risk.get("data_completeness", 0))

    lines: list[str] = [
        "━━━ THREAT SUMMARY ━━━",
        f"Type                  : {attack_type}",
        f"Theme                 : {theme}",
    ]
    if target_brand:
        lines.append(f"Target brand          : {target_brand}")
    if impersonation:
        lines.append(f"Impersonation         : {impersonation}")
    lines.append(f"Goal                  : {goal}")
    if primary_indicator:
        lines.append(f"Primary indicator     : {primary_indicator}")
    lines.append("")
    lines.append(f"Risk Level            : {verdict}")
    lines.append(f"Risk Score            : {risk.get('score', 0)} / 100")
    lines.append(f"Verdict Confidence    : {overall_confidence:.0%}")
    lines.append(f"Evidence Completeness : {completeness}%")
    for note in risk.get("confidence_notes", [])[:2]:
        lines.append(f"  ℹ️ {note}")
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
    landing_pages: list[dict] | None = None,
    evidence_bundle: dict | None = None,
    analysis_limits: dict | None = None,
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
    lines.extend(
        _build_threat_summary(
            risk,
            brand_impersonation,
            credential_harvesting,
            language_analysis,
            ai_verdict,
            heuristics,
            attachment_risks,
            domain_intelligence,
            url_intelligence,
        )
    )

    # ── 2. EMAIL METADATA ────────────────────────────────────
    lines.append("━━━ EMAIL METADATA ━━━")
    lines.append(f"Subject : {_esc(email_data.get('subject') or 'not available')}")
    lines.append(f"From    : {_esc(email_data.get('from') or 'not available')}")
    lines.append(f"To      : {_esc(email_data.get('to') or 'not available')}")
    lines.append(f"Date    : {_esc(email_data.get('date') or 'not available')}")
    lines.append("")

    # ── 3. EMAIL AUTHENTICATION ──────────────────────────────
    lines.append("━━━ EMAIL AUTHENTICATION ━━━")
    for check in ("spf", "dkim", "dmarc"):
        auth_item = auth_results.get(check, {})
        result = str(auth_item.get("result", "unknown")).lower()
        if result == "pass":
            icon = "✅"
        elif result in {"none", "unknown"}:
            icon = "➖"
        elif result == "softfail":
            icon = "⚠️"
        else:
            icon = "❌"
        detail = str(auth_item.get("details", "")).strip()
        suffix = f" — {detail}" if result == "unknown" and detail else ""
        lines.append(f"{icon} {check.upper()}: {result.upper()}{suffix}")

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
                icon = "⚠️" if int(f.get("risk_score", 0)) > 0 else "➖"
                lines.append(f"{icon} {f.get('summary', 'Header finding')}")
                if f.get("details"):
                    lines.append(f"   {f['details']}")
        else:
            lines.append("✅ No suspicious header anomalies detected")
    lines.append("")

    # ── 4. SMTP RELAY ANALYSIS ───────────────────────────────
    if header_forensics and not header_forensics.get("error"):
        lines.append("━━━ SMTP RELAY ANALYSIS ━━━")

        relay_chain: list[dict] = header_forensics.get("relay_chain", [])
        if not relay_chain:
            lines.append("➖ Relay analysis unavailable")
            lines.append("Reason: No Received headers available.")
            lines.append("The message route cannot be validated.")
            lines.append("")
        else:
            origin_ip = header_forensics.get("origin_ip")
            lines.append(f"Origin IP  : {origin_ip or 'not detected'}")

            country = header_forensics.get("origin_country", "Unknown")
            cc = header_forensics.get("origin_country_code", "")
            city = header_forensics.get("origin_city", "")
            isp = header_forensics.get("origin_isp", "")
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

            lines.append("")
            lines.append("Relay Path:")
            for idx, hop in enumerate(relay_chain, 1):
                server = hop.get("server") or "(unknown)"
                ip_tag = ""
                if hop.get("ip"):
                    origin_mark = " ⭐ origin" if hop["ip"] == origin_ip else ""
                    ip_tag = f" ({hop['ip']}{origin_mark})"
                lines.append(f"  {idx}. {server}{ip_tag}")
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
    if analysis_limits and analysis_limits.get("urls_truncated"):
        lines.append(
            "⚠️ URL analysis limited to the first "
            f"{analysis_limits.get('max_urls', 0)} indicators"
        )
    if urls:
        for u in urls:
            short_tag = " [SHORTENED]" if u.get("is_shortened") else ""
            lines.append(f"• {u['url']}{short_tag}")
            if u.get("is_shortened"):
                lines.append(f"  ↳ Expanded: {u.get('expanded_url', 'N/A')}")
            for warning in u.get("url_warnings", [])[:3]:
                lines.append(f"  ⚠️ {warning}")
        deceptive_links = [
            finding
            for finding in (url_intelligence or {}).get("deceptive_links", [])
            if int(finding.get("risk_score", 0)) > 0
        ]
        tracking_mismatches = [
            finding
            for finding in (url_intelligence or {}).get("deceptive_links", [])
            if finding.get("requires_redirect_validation")
        ]
        if deceptive_links:
            lines.append("")
            lines.append("🔴 Deceptive hyperlink detected")
            for finding in deceptive_links[:3]:
                lines.append(f"  Displayed: {finding.get('displayed_url', '?')}")
                lines.append(f"  Actual destination: {finding.get('url', '?')}")
                lines.append("  Displayed domain != actual HREF domain")
                lines.append("  Risk: Credential phishing / deceptive link")
        elif tracking_mismatches:
            lines.append("")
            lines.append("ℹ️ Displayed URL uses a known tracking intermediary")
            lines.append(
                "   Final destination must be validated before classification."
            )
        elif not any(
            item.get("link_target_comparison") in {"match", "mismatch"} for item in urls
        ):
            lines.append("")
            lines.append("➖ Displayed URL vs HREF: unavailable")
            lines.append("   No HTML anchor metadata is present in this message.")
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
                    lines.append(f"  ➖ Redirect analysis unavailable: {f['url']}")
                    lines.append(f"     Reason: {_clean_error(f['error'])}")
                else:
                    lines.append(f"  ⚠️ {f['url']}")
                    lines.append(
                        f"     Hops: {f['hops']} → Final: {f.get('final_domain', '?')}"
                    )
                    for i, step in enumerate(f.get("chain", [])):
                        lines.append(f"     {i}. {step}")
                    if f.get("suspicious_intermediates"):
                        for si in f["suspicious_intermediates"]:
                            lines.append(
                                f"     ⚠️ Suspicious intermediate: {si['domain']} ({si['reason']})"
                            )

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
                    lines.append("  WHOIS: lookup unavailable")
                else:
                    if w.get("created"):
                        warning = (
                            " ⚠️ Newly registered"
                            if (w.get("age_days") or 999) < 30
                            else ""
                        )
                        lines.append(f"  Created   : {w['created']}{warning}")
                        lines.append(f"  Age       : {w['age_days']} day(s)")
                    if w.get("registrar"):
                        lines.append(f"  Registrar : {w['registrar']}")
                    if w.get("country"):
                        lines.append(f"  Country   : {w['country']}")
                    if w.get("name_servers"):
                        lines.append(
                            f"  NS        : {', '.join(w['name_servers'][:4])}"
                        )
                lines.append("")

            if dns_results:
                lines.append("DNS Analysis:")
                for d in dns_results:
                    lines.append(f"  {d['domain']}:")
                    if d.get("a_records"):
                        lines.append(f"    A   : {', '.join(d['a_records'][:3])}")
                    elif d.get("record_status", {}).get("A") in {
                        "unavailable",
                        "error",
                        "not_checked",
                    }:
                        lines.append("    ➖ A lookup unavailable")
                    if d.get("mx_records"):
                        mx_str = ", ".join(
                            f"{m['host']} (pri {m['priority']})"
                            for m in d["mx_records"][:3]
                        )
                        lines.append(f"    MX  : {mx_str}")
                    else:
                        mx_status = d.get("record_status", {}).get("MX", "unknown")
                        if mx_status == "absent":
                            lines.append("    ➖ No MX records published")
                        elif mx_status == "nxdomain":
                            lines.append("    ⚠️ Domain does not exist (NXDOMAIN)")
                        else:
                            lines.append("    ➖ MX lookup unavailable")
                    if d.get("has_spf"):
                        lines.append("    ✅ SPF record found")
                    else:
                        txt_status = d.get("record_status", {}).get("TXT", "unknown")
                        if txt_status in {"ok", "absent"}:
                            lines.append("    ➖ No SPF policy found")
                        else:
                            lines.append("    ➖ SPF lookup unavailable")
                    if d.get("has_dmarc"):
                        lines.append("    ✅ DMARC policy found")
                    elif d.get("dmarc_status") in {"ok", "absent"}:
                        lines.append("    ➖ No DMARC policy published")
                    else:
                        lines.append("    ➖ DMARC lookup unavailable")
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
        lines.append("URL Keyword Context (weak evidence):")
        for f in heuristics["suspicious_keywords"]:
            lines.append(f"  ℹ️ Keyword '{f['keyword']}' in {f['source']}")
        lines.append("")

    # ── 7. BRAND IMPERSONATION ANALYSIS (unified) ────────────
    _brand_lines = _build_unified_brand_section(
        brand_impersonation,
        heuristics,
        domain_intelligence,
    )
    if _brand_lines:
        lines.extend(_brand_lines)

    # ── 8. PHISHING LANGUAGE ANALYSIS ────────────────────────
    if language_analysis and language_analysis.get("total_matches", 0) > 0:
        lines.append("━━━ PHISHING LANGUAGE ANALYSIS ━━━")
        for cat_name, cat_info in language_analysis.get("categories", {}).items():
            matches_str = ", ".join(cat_info["matches"][:3])
            icon = "ℹ️" if cat_name in {"urgency", "call_to_action"} else "⚠️"
            lines.append(f"{icon} {cat_info['description']}")
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
    risky_landing_pages = [
        page for page in (landing_pages or []) if int(page.get("risk_score", 0)) > 0
    ]
    if risky_landing_pages:
        lines.append("━━━ LANDING PAGE INTELLIGENCE ━━━")
        for page in risky_landing_pages[:5]:
            lines.append(f"⚠️ {page.get('final_url') or page.get('url')}")
            if page.get("title"):
                lines.append(f"   Title: {_esc(page['title'])}")
            for finding in page.get("findings", [])[:4]:
                lines.append(f"   {finding}")
            lines.append(f"   Risk: +{page.get('risk_score', 0)}")
        lines.append("")

    _ti_header_shown = False

    # VirusTotal URL results
    if vt_url_reports:
        lines.append("━━━ THREAT INTELLIGENCE ━━━")
        _ti_header_shown = True
        lines.append("VirusTotal – URLs:")
        unavailable_count = 0
        no_known_threat_count = 0
        for r in vt_url_reports:
            if r.get("malicious", 0) > 0:
                lines.append(
                    f"  🔴 {r.get('url', '?')} — {r['malicious']} engine(s) flagged malicious"
                )
            elif r.get("error") and r["error"] != "submitted_for_analysis":
                unavailable_count += 1
                lines.append(f"  ➖ {r.get('url', '?')} — lookup unavailable")
            elif r.get("error") == "submitted_for_analysis":
                lines.append(f"  ➖ {r.get('url', '?')} — analysis pending")
            else:
                no_known_threat_count += 1
                lines.append(
                    f"  ➖ {r.get('url', '?')} — No known malicious reputation detected"
                )
        young_domain = any(
            item.get("age_days") is not None and int(item["age_days"]) < 30
            for item in (domain_intelligence or {}).get("whois_results", [])
        )
        if no_known_threat_count and young_domain:
            lines.append(
                "  ℹ️ Newly registered domains may not yet appear in threat-intelligence feeds."
            )
        if unavailable_count:
            lines.append(
                "  ℹ️ Note: unavailable threat-intel scans are treated as missing "
                "evidence, not proof of safety."
            )
        if no_known_threat_count and (brand_impersonation or {}).get(
            "sender_identity_mismatch"
        ):
            lines.append(
                "  ℹ️ URL reputation does not reduce the sender-impersonation finding."
            )
            lines.append(
                "     A benign destination does not make the email trustworthy."
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
                lines.append(
                    f"  🔴 {r.get('sha256', '?')[:32]}… — {r['malicious']} engine(s)"
                )
            elif r.get("error"):
                lines.append(f"  ➖ {r.get('sha256', '?')[:32]}… — lookup unavailable")
            else:
                lines.append(
                    f"  ➖ {r.get('sha256', '?')[:32]}… — No known malicious reputation detected"
                )
        lines.append("")

    # AlienVault OTX
    if otx_reports:
        if not _ti_header_shown:
            lines.append("━━━ THREAT INTELLIGENCE ━━━")
            _ti_header_shown = True
        lines.append("AlienVault OTX:")
        for r in otx_reports:
            identifier = (
                r.get("domain") or r.get("url") or (r.get("sha256", "?")[:32] + "…")
            )
            if r.get("error"):
                lines.append(f"  ➖ {identifier}: lookup unavailable")
                continue
            count = r.get("pulse_count", 0)
            if count > 0:
                lines.append(f"  ⚠️ {identifier}: {count} pulse(s)")
            else:
                lines.append(f"  ➖ {identifier}: No known malicious reputation")
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
            bl_icon = "🔴" if f["blacklisted"] else "➖"
            lines.append(f"  {bl_icon} {f['ip']} (domain: {f['domain']})")
            if abuse.get("error"):
                lines.append("     AbuseIPDB: unavailable")
            else:
                lines.append(f"     AbuseIPDB: abuse score {abuse['abuse_score']}%")
                if abuse.get("total_reports"):
                    lines.append(
                        f"     Reports: {abuse['total_reports']} | Country: {abuse.get('country', '?')}"
                    )
            if spamhaus.get("error"):
                lines.append("     Spamhaus: unavailable")
            elif spamhaus["listed"]:
                lines.append(f"     Spamhaus: ⚠️ LISTED in {spamhaus['zone']}")
            else:
                lines.append("     Spamhaus: no known listing")
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
                    lines.append(f"  ➖ IP {f['ip']}: lookup unavailable")
                else:
                    flag = " ⚠️" if f["suspicious"] else ""
                    lines.append(
                        f"  • IP {f['ip']}: {f['domain_count']} domain(s) hosted{flag}"
                    )
                    for d in f.get("sample_domains", [])[:5]:
                        lines.append(f"    → {d}")
            lines.append("")

    # ── 11. AI PHISHING CLASSIFIER ───────────────────────────
    if ai_verdict:
        lines.append("━━━ AI PHISHING CLASSIFIER ━━━")
        provider = ai_verdict.get("provider")
        if provider:
            fallback = " (fallback)" if ai_verdict.get("fallback_used") else ""
            lines.append(f"  Provider   : {_esc(str(provider))}{fallback}")
        if ai_verdict.get("model"):
            lines.append(f"  Model      : {_esc(str(ai_verdict['model']))}")
        if ai_verdict.get("error"):
            lines.append(
                "  AI analysis unavailable; deterministic evidence was still evaluated."
            )
            lines.append("")
        else:
            verdict_icons = {
                "phishing": "🔴",
                "suspicious": "🟡",
                "legitimate": "🟢",
            }
            v = ai_verdict.get("verdict", "unknown")
            icon = verdict_icons.get(v, "⚪")
            lines.append(f"{icon} Verdict    : {v.upper()}")
            lines.append(
                f"  Model confidence : {ai_verdict.get('confidence', 0.0):.0%}"
            )
            lines.append(
                "  Role       : supporting evidence; not the sole verdict source"
            )
            if ai_verdict.get("reasons"):
                lines.append("  Reasons:")
                for reason in ai_verdict["reasons"]:
                    lines.append(f"    – {reason}")
            lines.append("")

    lines.append("━━━ OBSERVABLES / IOC SUMMARY ━━━")
    sender_domain = auth_results.get("forensics", {}).get("from_domain", "")
    iocs = _collect_iocs(
        urls,
        attachments,
        url_intelligence,
        sender_domain,
        brand_impersonation,
        vt_url_reports,
        vt_hash_reports,
        otx_reports,
        attachment_risks,
    )
    if iocs["candidates"]:
        lines.append("Suspicious IOC candidates:")
        for kind, value in iocs["candidates"]:
            lines.append(f"⚠️ {kind}: {value}")
    else:
        lines.append("Suspicious IOC candidates: none confirmed")
        if not iocs["contextual"] and not iocs["trusted"]:
            lines.append("No IOCs extracted from the available evidence.")
    if iocs["contextual"]:
        lines.append("")
        lines.append("Contextual / observed infrastructure:")
        for kind, value in iocs["contextual"]:
            lines.append(f"• {kind}: {value}")
    if iocs["trusted"]:
        lines.append("")
        lines.append(
            "Trusted / brand infrastructure (do not block from this sample alone):"
        )
        for kind, value in iocs["trusted"]:
            lines.append(f"ℹ️ {kind}: {value}")
    lines.append("")

    if evidence_bundle:
        correlations = evidence_bundle.get("correlations", [])
        evidence = evidence_bundle.get("evidence", [])
        if correlations or evidence:
            lines.append("━━━ CORRELATED FINDINGS ━━━")
            for c in correlations[:5]:
                icon = "🔴" if c.get("severity") == "high" else "⚠️"
                lines.append(f"{icon} {c.get('summary', 'Correlated signal')}")
                if c.get("evidence"):
                    lines.append("Evidence:")
                    for item in c["evidence"][:5]:
                        lines.append(f"  • {item}")
                confidence_label = (
                    "HIGH" if float(c.get("confidence", 0.0)) >= 0.80 else "MEDIUM"
                )
                lines.append(f"Confidence: {confidence_label}")
                lines.append("")
            if evidence:
                lines.append("Evidence provenance:")
                top = sorted(
                    evidence,
                    key=lambda item: int(item.get("risk_delta", 0)),
                    reverse=True,
                )[:6]
                for item in top:
                    lines.append(
                        f"  • [{item.get('source')}] {item.get('summary')} "
                        f"({item.get('state')}, +{item.get('risk_delta', 0)})"
                    )
            lines.append("")

    # ── 12. ATTACHMENTS ──────────────────────────────────────
    lines.append(f"━━━ ATTACHMENTS ({len(attachments)}) ━━━")
    if analysis_limits and analysis_limits.get("attachments_truncated"):
        lines.append(
            "⚠️ Attachment analysis limited to the first "
            f"{analysis_limits.get('max_attachments', 0)} attachments"
        )
    if attachments:
        for a in attachments:
            lines.append(
                f"• {a['filename']} ({a['content_type']}, {a['size_bytes']} bytes)"
            )
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
        "INCONCLUSIVE": "⚪",
        "LOW": "🟢",
        "MEDIUM": "🟡",
        "SUSPICIOUS": "🟠",
        "HIGH": "🟠",
        "CRITICAL": "🔴",
    }.get(risk["verdict"], "⚪")
    lines.append(f"Score   : {risk['score']} / 100")
    lines.append(f"Verdict : {verdict_icon} {risk['verdict']}")
    if "data_completeness" in risk:
        lines.append(f"Evidence completeness : {risk['data_completeness']} / 100")
    lines.append("")
    lines.append("Scoring legend:")
    lines.append(
        "  0–24 Low | 25–44 Medium | 45–64 Suspicious | 65–84 High | 85–100 Critical"
    )
    lines.append("")
    if risk.get("category_details"):
        labels = {
            "auth checks": "Authentication / relay",
            "URL behavior": "URL / web",
            "brand impersonation": "Identity / impersonation",
            "content/language": "Content / social engineering",
            "threat intelligence": "Threat intelligence",
            "AI / ML": "AI / ML",
            "attachment/malware": "Attachment / malware",
            "correlation": "Correlated findings",
            "ESP detection": "Legitimate ESP context",
        }
        lines.append("Category Contributions:")
        for category, detail in risk["category_details"].items():
            raw = int(detail.get("raw_subtotal", 0))
            effective = int(detail.get("effective_contribution", 0))
            suppressed = int(detail.get("suppressed_duplicate_weight", 0))
            if raw == 0 and effective == 0:
                continue
            lines.append(f"  {labels.get(category, category)}:")
            lines.append(f"    Raw subtotal               : {raw}")
            lines.append(
                f"    Category maximum           : {detail.get('category_maximum', 0)}"
            )
            lines.append(f"    Effective contribution     : {effective}")
            if suppressed:
                lines.append(f"    Suppressed duplicate weight: {suppressed}")
        reconciliation = risk.get("score_reconciliation", {})
        if reconciliation:
            lines.append(
                "  Effective total before overall limit: "
                f"{reconciliation.get('raw_effective_total', risk['score'])}"
            )
            lines.append(f"  Final score                      : {risk['score']}")
        if int(reconciliation.get("suppressed_overall_weight", 0)) > 0:
            lines.append(
                "  Overall 100-point limit suppressed: "
                f"{reconciliation['suppressed_overall_weight']}"
            )
        lines.append("")
    if risk.get("breakdown"):
        lines.append("Raw Evidence Breakdown:")
        for reason in risk["breakdown"]:
            lines.append(f"  – {reason}")
    if risk.get("completeness_breakdown"):
        lines.append("")
        lines.append("Evidence Gaps:")
        for gap in risk["completeness_breakdown"][:8]:
            lines.append(f"  ➖ {gap}")
    lines.append("")
    lines.append("━━━ RECOMMENDED SOC ACTIONS ━━━")
    for action in _recommended_actions(
        str(risk.get("verdict", "LOW")),
        email_data=email_data,
        auth_results=auth_results,
        urls=urls,
        brand_impersonation=brand_impersonation,
        credential_harvesting=credential_harvesting,
        url_intelligence=url_intelligence,
        attachment_risks=attachment_risks,
    ):
        lines.append(f"• {action}")
    lines.append("Human validation and an approved sandbox may still be required.")
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
    identity_lines: list[str] = []
    seen_brands: set[tuple[str, str]] = set()  # (brand, domain) dedup

    # --- BrandDetector results ---
    if brand_impersonation:
        for f in brand_impersonation.get("sender_identity_mismatch", []):
            identity_lines.extend(
                [
                    "⚠️ Sender identity mismatch",
                    f"  Claimed organization : {f.get('claimed_organization', '?')}",
                    f"  Claimed identity     : {f.get('claimed_identity') or 'not explicit'}",
                    f"  Sender domain        : {f.get('sender_domain', '?')}",
                    f"  Expected domain      : {f.get('expected_domain', '?')}",
                    "  Risk                 : impersonation / brand spoofing",
                ]
            )
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
            decoded_info = (
                f" (decoded: {f['decoded']})"
                if f.get("decoded") != f.get("domain")
                else ""
            )
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
    all_subs = identity_lines + (
        keyword_lines + homograph_lines + lookalike_lines + display_lines + body_lines
    )
    if not all_subs:
        return []

    lines: list[str] = ["━━━ BRAND IMPERSONATION ANALYSIS ━━━"]

    if identity_lines:
        lines.extend(identity_lines)

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
