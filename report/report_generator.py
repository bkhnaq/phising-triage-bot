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

from email_analysis.analysis_environment import normalize_analysis_environment
from email_analysis.observables import collect_observables, group_observables
from scoring.config import AuthState, SourceStatus, ThreatIntelStatus

logger = logging.getLogger(__name__)

_FINDING_CATEGORY_LABELS = {
    "authentication_relay": "Authentication / Relay",
    "url_web": "URL / Web",
    "identity_impersonation": "Identity / Impersonation",
    "content_social": "Content / Social Engineering",
    "threat_intelligence": "Threat Intelligence",
    "attachment_malware": "Attachment / Malware",
}

_FINDING_TO_RISK_CATEGORY = {
    "authentication_relay": "auth checks",
    "url_web": "URL behavior",
    "identity_impersonation": "brand impersonation",
    "content_social": "content/language",
    "threat_intelligence": "threat intelligence",
    "attachment_malware": "attachment/malware",
}

_RISK_CATEGORY_LABELS = {
    "auth checks": "Authentication / Relay",
    "URL behavior": "URL / Web",
    "brand impersonation": "Identity / Impersonation",
    "content/language": "Content / Social Engineering",
    "threat intelligence": "Threat Intelligence",
    "attachment/malware": "Attachment / Malware",
    "AI / ML": "AI / ML",
    "Cross-category Confirmation": "Cross-category Confirmation",
}


def _display_category(value: object) -> str:
    normalized = str(value or "Unknown")
    return _FINDING_CATEGORY_LABELS.get(
        normalized, _RISK_CATEGORY_LABELS.get(normalized, normalized)
    )


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
    confidence: float = 0.0,
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
        AuthState.parse(
            auth.get(check, {}).get("state")
            or auth.get(check, {}).get("result", "unknown")
        )
        is AuthState.UNKNOWN
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
        actions.append(
            "Search proxy/DNS logs for users who accessed the actual HREF destination."
        )
        actions.append("Determine whether any users submitted credentials.")
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

    if (
        normalized in {"PHISHING", "BEC", "MALWARE"} and confidence >= 0.80
    ) or normalized in {"HIGH", "CRITICAL"}:
        actions.insert(
            0,
            "Quarantine the message and search for matching copies across the mail environment.",
        )
    elif normalized == "SUSPICIOUS" and confidence < 0.70:
        actions.insert(0, "Escalate the message for human review before containment.")
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
) -> dict[str, list[dict]]:
    """Compatibility wrapper around the globally deduplicated IOC registry."""
    return group_observables(
        collect_observables(
            urls=urls,
            attachments=attachments,
            url_intelligence=url_intelligence,
            sender_domain=sender_domain,
            brand_impersonation=brand_impersonation,
            vt_url_reports=vt_url_reports,
            vt_hash_reports=vt_hash_reports,
            otx_reports=otx_reports,
            attachment_risks=attachment_risks,
        )
    )


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
    email_data: dict | None = None,
    auth_results: dict | None = None,
    analysis_environment: dict | None = None,
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
        if not deceptive_links:
            primary_indicator = "Credential-collection form in email HTML"

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

    context_text = " ".join(
        str((email_data or {}).get(key, ""))
        for key in ("subject", "from", "body_text", "body_html")
    ).lower()
    account_context = bool(
        {"credential_harvesting", "account_verification", "password_expiration"}
        & set((language_analysis or {}).get("categories", {}))
    )
    if account_context and any(
        token in context_text
        for token in ("university", "college", "campus", "student", "faculty")
    ):
        theme = "University / IT account verification"
    elif account_context and any(
        token in context_text
        for token in ("microsoft 365", "office 365", "outlook", "onedrive", "teams")
    ):
        theme = "Microsoft 365 / account verification"
    elif "payroll" in context_text:
        theme = "Payroll"
    elif any(
        token in context_text for token in ("dropbox", "google drive", "sharepoint")
    ):
        theme = "Cloud storage"
    elif any(token in context_text for token in ("delivery", "shipment", "parcel")):
        theme = "Delivery"
    elif any(token in context_text for token in ("human resources", " hr ")):
        theme = "HR"

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

    if not primary_indicator:
        if credential_harvesting and credential_harvesting.get("detected"):
            primary_indicator = "Credential-collection form in email HTML"
        elif has_risky_attach:
            primary_indicator = "Suspicious attachment"
        elif any(
            AuthState.parse(
                (auth_results or {}).get(check, {}).get("state")
                or (auth_results or {}).get(check, {}).get("result")
            )
            is AuthState.FAIL
            for check in ("spf", "dmarc")
        ):
            primary_indicator = "Sender authentication failure"

    verdict = risk.get("verdict", "UNKNOWN")
    risk_severity = risk.get("risk_severity", risk.get("risk_level", "LOW"))
    overall_confidence = float(risk.get("confidence", 0.0))
    completeness = int(risk.get("data_completeness", 0))

    lines: list[str] = [
        "━━━ THREAT SUMMARY ━━━",
        f"Classification        : {attack_type.title()}",
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
    lines.append(f"Verdict               : {verdict}")
    lines.append(f"Verdict Confidence    : {overall_confidence:.0%}")
    lines.append("")
    lines.append(f"Risk Severity         : {risk_severity}")
    lines.append(f"Risk Score            : {risk.get('score', 0)} / 100")
    lines.append(f"Applicable Evidence Coverage : {completeness}%")
    environment = normalize_analysis_environment(analysis_environment)
    environment_type = str(environment["type"])
    if environment_type in {"TEST", "LAB"}:
        lines.append(f"Environment           : {environment_type}")
        lines.append("Operational Use       : NON-PRODUCTION / SIMULATED RESPONSE ONLY")
    elif environment_type == "MIXED":
        lines.append("Environment           : MIXED")
        lines.append("Operational Use       : PER-OBSERVABLE EXPORT CONTROL REQUIRED")
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
    lab_mode: bool = False,
    observables: list[dict] | None = None,
    analysis_environment: dict | None = None,
    verbosity: str = "DEBUG",
) -> str:
    """
    Generate a professional SOC-grade phishing triage report.

    Returns:
        A multi-line string ready for display.
    """
    lines: list[str] = []
    explain = str(verbosity or "DEBUG").strip().upper() in {"DEBUG", "EXPLAIN"}
    environment = normalize_analysis_environment(analysis_environment)
    environment_type = str(environment["type"])

    # ── Report header ────────────────────────────────────────
    lines.append("🔍 *PHISHING TRIAGE REPORT*")
    lines.append(f"Generated: {datetime.now(timezone.utc):%Y-%m-%d %H:%M:%S UTC}")
    lines.append("")

    if environment_type in {"TEST", "LAB", "MIXED"}:
        lines.append(f"━━━ {environment_type} ENVIRONMENT DETECTED ━━━")
        for reason in environment.get("reasons", [])[:4]:
            lines.append(f"• {reason}")
        lines.append(
            "The verdict evaluates phishing behavior; export safety is determined per observable."
        )
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
            email_data,
            auth_results,
            environment,
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
        elif result == "none":
            icon = "ℹ️"
        elif result == "unknown":
            icon = "➖"
        elif result == "softfail":
            icon = "⚠️"
        else:
            icon = "❌"
        detail = str(auth_item.get("details", "")).strip()
        suffix = f" — {detail}" if result == "unknown" and detail else ""
        lines.append(f"{icon} {check.upper()}: {result.upper()}{suffix}")

    if auth_results.get("testing_headers"):
        lines.append("")
        lines.append("ℹ️ Security/testing-related custom header observed.")
        lines.append(
            "   This header is attacker-controlled and is not treated as proof of safety."
        )

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
                if (
                    f.get("type") == "message_id_mismatch"
                    and int(f.get("risk_score", 0)) == 0
                ):
                    lines.append(
                        "   Informational only; contribution +0. "
                        "Legitimate ESP/mailer infrastructure commonly uses a different domain."
                    )
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

            ip_classification = header_forensics.get("origin_ip_classification", "")
            if ip_classification:
                lines.append(f"IP Classification: {ip_classification}")
            if (
                header_forensics.get("geolocation_status")
                == SourceStatus.NOT_APPLICABLE.value
            ):
                lines.append("Geolocation: Not applicable")
                lines.append(
                    "Reputation : Not applicable for real-world threat intelligence"
                )

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
                lines.append(f"  Actual HREF destination: {finding.get('url', '?')}")
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
                if f.get("status") == SourceStatus.NOT_APPLICABLE.value:
                    lines.append(f"  ℹ️ Redirect analysis not applicable: {f['url']}")
                    lines.append(
                        f"     Reason: {f.get('reason', 'special-use resource')}"
                    )
                elif f.get("error"):
                    lines.append(f"  ➖ Redirect analysis unavailable: {f['url']}")
                    lines.append(f"     Reason: {_clean_error(f['error'])}")
                elif int(f.get("hops", 0)) <= 0:
                    lines.append(f"  ℹ️ No HTTP redirect observed: {f['url']}")
                else:
                    lines.append(
                        f"  Redirect source: {f.get('redirect_source', f['url'])}"
                    )
                    lines.append(
                        "  Redirect destination: "
                        f"{f.get('redirect_destination', f.get('final_url', '?'))}"
                    )
                    for i, step in enumerate(f.get("redirect_chain", []), 1):
                        status_code = step.get("status_code")
                        suffix = (
                            "Final destination"
                            if step.get("final")
                            else (
                                f"HTTP {status_code}"
                                if status_code
                                else "HTTP redirect observed"
                            )
                        )
                        lines.append(f"     {i}. {step.get('url', '?')} — {suffix}")
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
        randomness_results = domain_intelligence.get(
            "randomness_results", entropy_results
        )

        if whois_results or dns_results or randomness_results:
            _has_domain_intel = True
            lines.append("━━━ DOMAIN INTELLIGENCE ━━━")

            for w in whois_results:
                lines.append(f"Domain: {w['domain']}")
                if w.get("status") == SourceStatus.NOT_APPLICABLE.value:
                    classification = w.get("special_use", {}).get(
                        "classification", "Reserved special-use domain"
                    )
                    lines.append(f"  ℹ️ {classification}")
                    lines.append(
                        "  DNS/WHOIS enrichment is not applicable for reputation purposes."
                    )
                elif w.get("error"):
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
                    if d.get("status") == SourceStatus.NOT_APPLICABLE.value:
                        lines.append("    ℹ️ Reserved special-use domain")
                        lines.append("    DNS reputation: Not applicable")
                        continue
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

            if randomness_results:
                lines.append("Domain Randomness Analysis:")
                compact_test_randomness = (
                    not explain
                    and all(
                        str(item.get("domain", "")).lower().endswith(".test")
                        for item in randomness_results
                    )
                    and all(
                        int(item.get("risk_score", 0)) == 0
                        for item in randomness_results
                    )
                )
                if compact_test_randomness:
                    lines.append(
                        "  ℹ️ Reserved .test domains analyzed; "
                        "no randomized-domain risk contribution (+0)."
                    )
                else:
                    for e in randomness_results:
                        icon = "⚠️" if int(e.get("risk_score", 0)) > 0 else "ℹ️"
                        lines.append(
                            f"  {icon} {e['domain']} — "
                            f"{e.get('description', 'analyzed')}"
                        )
                        lines.append(
                            f"     Entropy: {e.get('entropy', 0)} | "
                            f"Contribution: +{e.get('risk_score', 0)}"
                        )
                        if e.get("meaningful_tokens"):
                            lines.append(
                                "     Meaningful tokens: "
                                + ", ".join(e["meaningful_tokens"])
                            )
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
            status = str(r.get("status") or r.get("state", "")).upper()
            if status == ThreatIntelStatus.NOT_APPLICABLE.value:
                lines.append(f"  ℹ️ {r.get('url', '?')} — reputation not applicable")
            elif r.get("malicious", 0) > 0:
                lines.append(
                    f"  🔴 {r.get('url', '?')} — {r['malicious']} engine(s) flagged malicious"
                )
            elif status == ThreatIntelStatus.NOT_FOUND.value:
                lines.append(f"  ➖ {r.get('url', '?')} — no record found")
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
        if no_known_threat_count:
            lines.append(
                "  ℹ️ No known malicious reputation is not evidence of safety."
            )
        lines.append("")

    # VirusTotal Hash results
    if vt_hash_reports:
        if not _ti_header_shown:
            lines.append("━━━ THREAT INTELLIGENCE ━━━")
            _ti_header_shown = True
        lines.append("VirusTotal – File Hashes:")
        for r in vt_hash_reports:
            status = str(r.get("status") or r.get("state", "")).upper()
            if status == ThreatIntelStatus.NOT_APPLICABLE.value:
                lines.append(
                    f"  ℹ️ {r.get('sha256', '?')[:32]}… — reputation not applicable"
                )
            elif r.get("malicious", 0) > 0:
                lines.append(
                    f"  🔴 {r.get('sha256', '?')[:32]}… — {r['malicious']} engine(s)"
                )
            elif status == ThreatIntelStatus.NOT_FOUND.value:
                lines.append(f"  ➖ {r.get('sha256', '?')[:32]}… — no record found")
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
            status = str(r.get("status") or r.get("state", "")).upper()
            if status == ThreatIntelStatus.NOT_APPLICABLE.value:
                lines.append(f"  ℹ️ {identifier}: reputation not applicable")
                continue
            if status == ThreatIntelStatus.NOT_FOUND.value:
                lines.append(f"  ➖ {identifier}: no record found")
                continue
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
            if (
                str(f.get("status", "")).upper()
                == ThreatIntelStatus.NOT_APPLICABLE.value
            ):
                lines.append(
                    f"  ℹ️ {f['ip']} — {f.get('classification', 'special-use IP')}"
                )
                lines.append("     Geolocation: Not applicable")
                lines.append(
                    "     Reputation: Not applicable for real-world threat intelligence"
                )
                continue
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
    iocs = (
        group_observables(observables)
        if observables is not None
        else _collect_iocs(
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
    )
    has_test_context = environment_type in {"TEST", "LAB", "MIXED"}
    if environment_type in {"TEST", "LAB"}:
        lines.append("IOC Environment: TEST / LAB")
        lines.append("Operational usability: NON-PRODUCTION")
        lines.append("")
    elif environment_type == "MIXED":
        lines.append("IOC Environment: MIXED")
        lines.append("Operational usability: PER-OBSERVABLE EXPORT POLICY")
        lines.append("")
    elif environment_type == "PRODUCTION":
        lines.append("IOC Environment: PRODUCTION")
        lines.append("")

    def render_observable(prefix: str, item: dict) -> None:
        lines.append(f"{prefix} {item.get('label', 'Observable')}:")
        lines.append(f"  {item.get('value', '')}")
        if environment_type == "MIXED":
            lines.append(
                "  Environment: "
                f"{str(item.get('environment', 'unknown')).upper()} | "
                f"Exportable: {str(bool(item.get('exportable'))).lower()}"
            )

    if iocs["confirmed"]:
        lines.append("Confirmed malicious IOCs:")
        for item in iocs["confirmed"]:
            render_observable("🔴", item)
        lines.append("")
    if iocs["suspicious"]:
        lines.append("Suspicious Observables:")
        for item in iocs["suspicious"]:
            render_observable("⚠️", item)
        lines.append("")
    if iocs["candidates"]:
        lines.append("Suspicious IOC Candidates:")
        for item in iocs["candidates"]:
            render_observable("•", item)
    else:
        lines.append("Suspicious IOC Candidates: none")
        if not iocs["confirmed"] and not iocs["contextual"] and not iocs["trusted"]:
            lines.append("No IOCs extracted from the available evidence.")
    if iocs["contextual"]:
        lines.append("")
        lines.append("Contextual / Observed Infrastructure:")
        for item in iocs["contextual"]:
            render_observable("•", item)
    if iocs["trusted"]:
        lines.append("")
        lines.append(
            "Trusted / brand infrastructure (do not block from this sample alone):"
        )
        for item in iocs["trusted"]:
            render_observable("ℹ️", item)
    if has_test_context:
        lines.append("")
        lines.append("Operational Note:")
        lines.append(
            "Reserved testing indicators are not exportable. Production observables, if present, retain their own independent export policy."
        )
    lines.append("")

    if evidence_bundle:
        correlations = evidence_bundle.get("correlations", [])
        evidence = evidence_bundle.get("evidence", [])
        if correlations or evidence:
            lines.append("━━━ CORRELATED FINDINGS ━━━")
            evidence_by_id = {str(item.get("id", "")): item for item in evidence}
            for c in correlations[:5]:
                icon = "🔴" if str(c.get("severity", "")).upper() == "HIGH" else "⚠️"
                lines.append(f"{icon} {c.get('summary', 'Correlated signal')}")
                finding_category = str(c.get("category", ""))
                lines.append(
                    "Category: "
                    f"{_FINDING_CATEGORY_LABELS.get(finding_category, finding_category or 'Unknown')}"
                )
                lines.append(f"Severity: {str(c.get('severity', 'MEDIUM')).upper()}")
                confidence_label = (
                    "HIGH" if float(c.get("confidence", 0.0)) >= 0.80 else "MEDIUM"
                )
                lines.append(f"Confidence: {confidence_label}")
                lines.append(
                    f"Score contribution: +{int(c.get('score_contribution', c.get('risk_score', 0)))}"
                )
                consumed = [
                    evidence_by_id[evidence_id]
                    for evidence_id in c.get("consumed_evidence", [])
                    if evidence_id in evidence_by_id
                ]
                if consumed:
                    lines.append("Consumed evidence:")
                    for item in consumed[:8]:
                        lines.append(f"  ✓ {item.get('summary', 'Evidence')}")
                supporting_context = [
                    item
                    for item in evidence
                    if item.get("scoring_state") == "SUPPORTING"
                    and item.get("consumed_by") == c.get("type")
                ]
                if supporting_context:
                    lines.append("Supporting URL context:")
                    for item in supporting_context[:8]:
                        lines.append(
                            f"  ✓ {item.get('summary', 'Context')} (contribution +0)"
                        )
                category_detail = risk.get("category_details", {}).get(
                    _FINDING_TO_RISK_CATEGORY.get(finding_category, finding_category),
                    {},
                )
                independent = [
                    item
                    for item in category_detail.get("items", [])
                    if item.get("kind") == "primitive"
                    and int(item.get("contribution", 0)) > 0
                    and item.get("state") != "SUPPORTING"
                ]
                if independent:
                    lines.append("Independent related evidence:")
                    for item in independent[:4]:
                        lines.append(
                            f"  ✓ {item.get('label', 'Evidence')} "
                            f"(+{item.get('contribution', 0)})"
                        )
                lines.append("")
            for finding in risk.get("cross_category_findings", [])[:10]:
                active = finding.get("status") == "ACTIVE"
                lines.append(f"{'🔴' if active else '➖'} {finding.get('summary')}")
                lines.append("Type: Cross-category confirmation")
                if not active:
                    lines.append(
                        "Status: SUPPRESSED → covered by "
                        f"{finding.get('suppressed_by', 'higher-priority confirmation')}"
                    )
                else:
                    lines.append("Independent categories:")
                    for category in finding.get("independent_categories", []):
                        lines.append(f"  ✓ {_display_category(category)}")
                    if finding.get("supporting_categories"):
                        lines.append("Supporting categories:")
                        for category in finding["supporting_categories"]:
                            lines.append(f"  ✓ {_display_category(category)}")
                    lines.append(
                        f"Score contribution: +{finding.get('score_contribution', 0)}"
                    )
                ai_agreement = finding.get("ai_agreement")
                if ai_agreement:
                    lines.append("AI agreement:")
                    lines.append(
                        f"  ✓ {ai_agreement.get('verdict', 'UNKNOWN')} "
                        f"{float(ai_agreement.get('confidence', 0.0)):.0%}"
                    )
                    lines.append("  Role: confidence support only")
                    lines.append("  Score impact on correlation: +0")
                lines.append("")
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
        lines.append("  Analyzer result: NONE_PRESENT (no attachments found).")

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
    severity = str(risk.get("risk_severity", risk.get("risk_level", "LOW")))
    reconciliation = risk.get("score_reconciliation", {})
    pre_calibration = int(
        reconciliation.get("pre_calibration_score", risk.get("score", 0))
    )
    critical_gate = reconciliation.get("critical_evidence_gate", {})
    verdict_icon = {
        "UNKNOWN": "⚪",
        "BENIGN": "🟢",
        "LIKELY_BENIGN": "🟢",
        "SUSPICIOUS": "🟠",
        "PHISHING": "🔴",
        "BEC": "🔴",
        "MALWARE": "🔴",
        "SPAM": "🟡",
    }.get(risk["verdict"], "⚪")
    lines.append(f"Pre-calibration score : {pre_calibration} / 100")
    if critical_gate:
        lines.append("")
        lines.append("Critical Evidence Gate:")
        lines.append(f"Status : {critical_gate.get('status', 'NOT_EVALUATED')}")
        lines.append("")
        lines.append("Reason:")
        lines.append(str(critical_gate.get("reason", "No reason available.")))
        if critical_gate.get("status") == "MET" and critical_gate.get("confirmations"):
            lines.append("Evidence:")
            for confirmation in critical_gate["confirmations"]:
                lines.append(f"  • {confirmation}")
        if critical_gate.get("applied"):
            lines.append(
                f"Critical severity cap : {critical_gate.get('score_cap', 84)}"
            )
    lines.append("")
    lines.append(f"Final score : {risk['score']} / 100")
    lines.append(f"Severity    : {severity}")
    lines.append(f"Verdict     : {verdict_icon} {risk['verdict']}")
    if "data_completeness" in risk:
        lines.append(
            "Applicable Evidence Coverage : "
            f"{risk['data_completeness']}% of applicable analysis sources"
        )
    lines.append("")
    lines.append("Scoring legend:")
    lines.append(
        "  0–24 Low | 25–44 Moderate | 45–64 Elevated | 65–84 High | 85–100 Critical"
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
            "ESP detection": "Legitimate ESP context",
            "Cross-category Confirmation": "Cross-category confirmation",
        }
        lines.append("Category Contributions:")
        for category, detail in risk["category_details"].items():
            raw = int(detail.get("primitive_raw_subtotal", 0))
            effective = int(detail.get("effective_contribution", 0))
            cap_suppressed = int(detail.get("suppressed_by_category_cap", 0))
            if raw == 0 and effective == 0:
                continue
            if explain:
                lines.append(f"  {labels.get(category, category)}:")
                for item in detail.get("items", [])[:8]:
                    item_state = str(item.get("state", "ACTIVE"))
                    state_suffix = (
                        f" [{item_state} → {item.get('suppressed_by')}]"
                        if item_state == "SUPPRESSED"
                        else (
                            f" [SUPPORTING → {item.get('supporting_for', 'context')}]"
                            if item_state == "SUPPORTING"
                            else ""
                        )
                    )
                    lines.append(
                        f"    {item.get('label', 'Evidence'):<42} "
                        f"+{int(item.get('contribution', 0))}{state_suffix}"
                    )
                lines.append("    " + "-" * 50)
                lines.append(
                    f"    Effective                                {effective} / "
                    f"{detail.get('category_maximum', 0)}"
                )
                if cap_suppressed:
                    lines.append(
                        f"    Category-cap suppression                  {cap_suppressed}"
                    )
            else:
                lines.append(
                    f"  {labels.get(category, category)}: {effective} / "
                    f"{detail.get('category_maximum', 0)}"
                )
        if reconciliation:
            lines.append(
                "  Effective categories + modifiers: "
                f"{reconciliation.get('raw_effective_total', risk['score'])}"
            )
            lines.append(
                "  Pre-calibration score          : "
                f"{reconciliation.get('pre_calibration_score', risk['score'])}"
            )
            lines.append(f"  Final score                    : {risk['score']}")
        if int(reconciliation.get("suppressed_overall_weight", 0)) > 0:
            lines.append(
                "  Overall 100-point limit suppressed: "
                f"{reconciliation['suppressed_overall_weight']}"
            )
        lines.append("")
    if explain and evidence_bundle and evidence_bundle.get("evidence"):
        lines.append("Raw Evidence Breakdown:")
        for item in sorted(
            evidence_bundle["evidence"],
            key=lambda evidence: int(evidence.get("risk_delta", 0)),
            reverse=True,
        ):
            score = int(item.get("risk_delta", 0))
            state = str(item.get("scoring_state", "INFORMATIONAL"))
            suffix = f"(+{score} raw)" if score else "(+0 raw)"
            if state == "CONSUMED":
                state = f"CONSUMED → {item.get('consumed_by', 'finding')}"
            elif state == "SUPPORTING":
                state = f"SUPPORTING → {item.get('consumed_by', 'context')}"
            lines.append(f"  – {item.get('summary', 'Evidence')} {suffix} [{state}]")
    elif explain and risk.get("breakdown"):
        lines.append("Raw Evidence Breakdown:")
        for reason in risk["breakdown"]:
            lines.append(f"  – {reason}")
    if risk.get("completeness_breakdown"):
        lines.append("")
        lines.append("Evidence Gaps:")
        for gap in risk["completeness_breakdown"][:8]:
            lines.append(f"  ➖ {gap}")
    if explain and risk.get("evidence_coverage"):
        lines.append("")
        lines.append("Applicable Evidence Coverage Sources:")
        for source, details in risk["evidence_coverage"].items():
            status = str(details.get("status"))
            if source == "attachments" and status == SourceStatus.NONE_PRESENT.value:
                status = "ANALYZED — NONE_PRESENT"
            elif (
                source == "html_analysis" and status == SourceStatus.NONE_PRESENT.value
            ):
                status = "ANALYZED — NONE_PRESENT"
            lines.append(
                f"  • {source.replace('_', ' ').title()}: {status} "
                f"(weight {details.get('weight', 0)})"
            )
        lines.append("  ℹ️ NOT_APPLICABLE sources are excluded from coverage scoring.")
    lines.append("")
    lines.append("━━━ RECOMMENDED SOC ACTIONS ━━━")
    actions = _recommended_actions(
        str(risk.get("verdict", "LOW")),
        confidence=float(risk.get("confidence", 0.0)),
        email_data=email_data,
        auth_results=auth_results,
        urls=urls,
        brand_impersonation=brand_impersonation,
        credential_harvesting=credential_harvesting,
        url_intelligence=url_intelligence,
        attachment_risks=attachment_risks,
    )
    if environment_type in {"TEST", "LAB"}:
        lines.append("Lab/Test Context:")
        lines.append(
            "This sample uses reserved testing infrastructure. The IOC values below must not be deployed into production blocking or detection systems."
        )
        lines.append("")
        lines.append("Simulated Production Response:")
        for action in actions:
            simulated = action.replace(
                "Quarantine the message", "Quarantine the equivalent message"
            )
            lines.append(f"• {simulated}")
        lines.append("")
        lines.append("Operational Safety:")
        lines.append("• Do not block reserved *.test domains.")
        lines.append("• Do not block TEST-NET documentation addresses.")
        lines.append(
            "• Do not export test IOC values to production SIEM/SOAR/EDR/mail gateways."
        )
    else:
        if environment_type == "MIXED":
            lines.append("Mixed Environment Context:")
            lines.append(
                "Apply response actions to production-eligible observables only; reserved test values remain non-exportable."
            )
        for action in actions:
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
