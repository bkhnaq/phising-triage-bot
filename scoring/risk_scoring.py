"""
Risk Scoring Engine (v3)
-------------------------
Deduplicated, weighted multi-layer scoring system that combines all
detection indicators into a single 0–100 risk score with verdict.

Each indicator contributes to the score ONCE — overlapping legacy and
comprehensive detection modules are reconciled so that the same signal
(e.g. brand impersonation) is never double-counted.

Score ranges:
   0–30  LOW
  30–60  MEDIUM
  60–80  HIGH
  80–100 CRITICAL

Usage:
    from scoring.risk_scoring import calculate_risk
    result = calculate_risk(auth_results, url_reports, hash_reports, otx_reports, ...)
"""

import logging

from config.settings import RISK_HIGH_THRESHOLD, RISK_MEDIUM_THRESHOLD

logger = logging.getLogger(__name__)

# ── Weight configuration ─────────────────────────────────────
_WEIGHTS = {
    "spf_fail": 15,
    "dkim_fail": 15,
    "dmarc_fail": 20,
    "malicious_url": 20,       # per URL flagged malicious
    "suspicious_url": 10,      # per URL flagged suspicious
    "shortened_url": 5,        # per shortened URL found
    "malicious_hash": 25,      # per file hash flagged malicious
    "otx_pulse_hit": 10,       # if any OTX pulses reference the indicator
}


def calculate_risk(
    auth_results: dict,
    url_reports: list[dict],
    hash_reports: list[dict],
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
) -> dict:
    """
    Calculate a risk score and verdict for an email.

    Args:
        auth_results:  Output from header_analyzer.analyze_headers().
        url_reports:   List of VirusTotal URL reports.
        hash_reports:  List of VirusTotal file-hash reports.
        otx_reports:   List of AlienVault OTX reports (domains + hashes).
        heuristics:    Output from heuristic_analyzer.run_heuristics().
        qr_findings:   Output from qr_code_analyzer.scan_attachments_for_qr().
        ip_reputation: Output from ip_reputation.check_ip_reputation().
        passive_dns:   Output from passive_dns.check_passive_dns().
        ai_verdict:    Output from ai_classifier.classify_email().
        header_forensics: Output from header_forensics.run_header_forensics().

    Returns:
        Dict with: score (int 0-100), verdict (str), breakdown (list of reasons).
    """
    score = 0
    breakdown: list[str] = []

    # ── 1. Email authentication ──────────────────────────────
    for check, weight_key in [("spf", "spf_fail"), ("dkim", "dkim_fail"), ("dmarc", "dmarc_fail")]:
        result = auth_results.get(check, {}).get("result", "none")
        if result in ("fail", "softfail", "none"):
            score += _WEIGHTS[weight_key]
            breakdown.append(f"{check.upper()} {result} (+{_WEIGHTS[weight_key]})")

    # Header forensics (domain mismatches, sender anomalies, hop anomalies)
    for finding in auth_results.get("forensics", {}).get("findings", []):
        pts = int(finding.get("risk_score", 0))
        if pts > 0:
            score += pts
            breakdown.append(
                f"Header forensic: {finding.get('summary', 'anomaly')} "
                f"({finding.get('details', 'n/a')}) (+{pts})"
            )

    # ── 2. URL analysis (VirusTotal) ────────────────────────────
    for report in url_reports:
        if report.get("malicious", 0) > 0:
            score += _WEIGHTS["malicious_url"]
            breakdown.append(
                f"Malicious URL: {report.get('url', '?')} "
                f"({report['malicious']} engines) (+{_WEIGHTS['malicious_url']})"
            )
        elif report.get("suspicious", 0) > 0:
            score += _WEIGHTS["suspicious_url"]
            breakdown.append(
                f"Suspicious URL: {report.get('url', '?')} (+{_WEIGHTS['suspicious_url']})"
            )

    # ── 3. Attachment hashes (VirusTotal) ─────────────────────
    for report in hash_reports:
        if report.get("malicious", 0) > 0:
            score += _WEIGHTS["malicious_hash"]
            breakdown.append(
                f"Malicious attachment: {report.get('sha256', '?')[:16]}… "
                f"({report['malicious']} engines) (+{_WEIGHTS['malicious_hash']})"
            )

    # ── 4. AlienVault OTX ────────────────────────────────────
    for report in otx_reports:
        if report.get("pulse_count", 0) > 0:
            score += _WEIGHTS["otx_pulse_hit"]
            identifier = report.get("domain") or report.get("sha256", "?")[:16]
            breakdown.append(
                f"OTX pulses for {identifier}: {report['pulse_count']} "
                f"(+{_WEIGHTS['otx_pulse_hit']})"
            )

    # ── 5. Heuristic detections (ONLY non-overlapping) ───────
    #
    # The following heuristic sub-categories overlap with
    # comprehensive modules and are SKIPPED here:
    #   brand_impersonation  → covered by section 11 (BrandDetector)
    #   homograph_brands     → covered by section 11 (BrandDetector)
    #   domain_entropy       → covered by section 14 (domain_intelligence)
    #   domain_age           → covered by section 14 (domain_intelligence)
    #   url_shorteners       → covered by section 13 (url_intelligence)
    #   redirect_chains      → covered by section 13 (url_intelligence)
    #
    # Scored here: suspicious_keywords, homograph (IDN / Cyrillic)
    if heuristics:
        for finding in heuristics.get("suspicious_keywords", []):
            pts = finding["risk_score"]
            score += pts
            breakdown.append(
                f"Suspicious keyword '{finding['keyword']}' in {finding['source']} (+{pts})"
            )

        for finding in heuristics.get("homograph", []):
            pts = finding["risk_score"]
            score += pts
            breakdown.append(
                f"Homograph attack: {finding['domain']} ({finding['details']}) (+{pts})"
            )

    # ── 6. QR code findings ──────────────────────────────────
    if qr_findings:
        for finding in qr_findings:
            pts = finding["risk_score"]
            score += pts
            label = finding.get("url") or finding["qr_data"][:60]
            breakdown.append(
                f"QR code in {finding['filename']}: {label} (+{pts})"
            )

        qr_urls_set = {f["url"] for f in qr_findings if f.get("url")}
        for report in url_reports:
            if report.get("url") in qr_urls_set and report.get("malicious", 0) > 0:
                score += 30
                breakdown.append(
                    f"Malicious QR URL: {report['url']} "
                    f"({report['malicious']} engines) (+30)"
                )

    # ── 7. IP reputation ─────────────────────────────────────
    if ip_reputation:
        for finding in ip_reputation:
            pts = finding["risk_score"]
            if pts > 0:
                score += pts
                abuse = finding["abuseipdb"]["abuse_score"]
                spamhaus = "yes" if finding["spamhaus"]["listed"] else "no"
                breakdown.append(
                    f"Blacklisted IP: {finding['ip']} "
                    f"(abuse={abuse}%, spamhaus={spamhaus}) (+{pts})"
                )

    # ── 8. Passive DNS ───────────────────────────────────────
    if passive_dns:
        for finding in passive_dns:
            pts = finding["risk_score"]
            if pts > 0:
                score += pts
                breakdown.append(
                    f"Suspicious hosting: IP {finding['ip']} hosts "
                    f"{finding['domain_count']} domain(s) (+{pts})"
                )

    # ── 9. AI classifier ────────────────────────────────────
    if ai_verdict:
        pts = ai_verdict.get("risk_score", 0)
        if pts > 0:
            score += pts
            breakdown.append(
                f"AI verdict: {ai_verdict['verdict']} "
                f"(confidence={ai_verdict['confidence']:.0%}) (+{pts})"
            )

    # ── 10. SMTP relay chain forensics ──────────────────────
    if header_forensics and not header_forensics.get("error"):
        pts = header_forensics.get("risk_score", 0)
        if pts > 0:
            score += pts
            for warning in header_forensics.get("warnings", []):
                if warning.startswith("Origin IP geolocation:"):
                    continue
                breakdown.append(f"Relay forensic: {warning}")
            breakdown.append(f"SMTP relay forensics total (+{pts})")

    # ── 11. Brand impersonation (comprehensive — single source of truth)
    if brand_impersonation:
        for finding in brand_impersonation.get("domain_impersonation", []):
            pts = finding["risk_score"]
            score += pts
            breakdown.append(
                f"Brand impersonation: {finding['brand']} "
                f"({finding['detail']}) (+{pts})"
            )

        for finding in brand_impersonation.get("display_name_spoofing", []):
            pts = finding["risk_score"]
            score += pts
            breakdown.append(
                f"Display name spoofing: brand '{finding['brand']}', "
                f"sender {finding['sender_domain']} (+{pts})"
            )

    # ── 12. Credential harvesting ────────────────────────────
    if credential_harvesting and credential_harvesting.get("detected"):
        pts = credential_harvesting.get("risk_score", 0)
        if pts > 0:
            score += pts
            for cf in credential_harvesting.get("findings", [])[:3]:
                breakdown.append(f"Credential form: {cf}")
            breakdown.append(f"Credential harvesting total (+{pts})")

    # ── 13. URL intelligence (single source for shorteners + redirects)
    if url_intelligence:
        for finding in url_intelligence.get("shortener_findings", []):
            pts = finding.get("risk_score", 0)
            if pts > 0:
                score += pts
                breakdown.append(
                    f"URL shortener: {finding['domain']} → "
                    f"{finding.get('expanded_domain', '?')} (+{pts})"
                )
        for finding in url_intelligence.get("redirect_findings", []):
            pts = finding.get("risk_score", 0)
            if pts > 0:
                score += pts
                breakdown.append(
                    f"URL redirect: {finding['url']} → {finding.get('hops', 0)} hop(s) "
                    f"→ {finding.get('final_domain', '?')} (+{pts})"
                )
        for finding in url_intelligence.get("suspicious_endpoints", []):
            pts = finding.get("risk_score", 0)
            if pts > 0:
                score += pts
                breakdown.append(
                    f"Suspicious endpoint: {', '.join(finding.get('keywords', []))} in URL (+{pts})"
                )

    # ── 14. Domain intelligence (single source for WHOIS, entropy, lookalike)
    if domain_intelligence:
        for w in domain_intelligence.get("whois_results", []):
            pts = w.get("risk_score", 0)
            if pts > 0:
                score += pts
                age = w.get("age_days", "?")
                breakdown.append(
                    f"Young domain: {w['domain']} ({age}d old) (+{pts})"
                )

        for e in domain_intelligence.get("entropy_results", []):
            pts = e.get("risk_score", 0)
            if pts > 0:
                score += pts
                breakdown.append(
                    f"High-entropy domain: {e['domain']} "
                    f"(entropy={e['entropy']}) (+{pts})"
                )

        for la in domain_intelligence.get("lookalike_results", []):
            pts = la.get("risk_score", 0)
            if pts > 0:
                score += pts
                breakdown.append(
                    f"Lookalike domain: {la['domain']} → {la['brand']} "
                    f"(distance={la['distance']}) (+{pts})"
                )

    # ── 15. Language analysis ────────────────────────────────
    if language_analysis and language_analysis.get("risk_score", 0) > 0:
        pts = language_analysis["risk_score"]
        score += pts
        for s in language_analysis.get("summary", [])[:3]:
            breakdown.append(f"Language: {s}")
        breakdown.append(f"Phishing language total (+{pts})")

    # ── 16. Attachment risk assessment ───────────────────────
    if attachment_risks:
        for finding in attachment_risks:
            pts = finding["risk_score"]
            score += pts
            breakdown.append(
                f"Risky attachment: {finding['filename']} "
                f"({finding['description']}) (+{pts})"
            )

    # ── Cap at 100 ───────────────────────────────────────────
    score = min(score, 100)

    # ── Verdict (updated thresholds) ─────────────────────────
    if score >= 80:
        verdict = "CRITICAL"
    elif score >= 60:
        verdict = "HIGH"
    elif score >= 30:
        verdict = "MEDIUM"
    else:
        verdict = "LOW"

    logger.info("Risk score: %d/100 – Verdict: %s", score, verdict)
    return {"score": score, "verdict": verdict, "breakdown": breakdown}
