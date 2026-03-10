"""
Risk Scoring Module
-------------------
Combines all analysis indicators into a single 0-100 risk score
and a verdict: LOW / MEDIUM / HIGH / CRITICAL.

Scoring weights (adjustable):
  - Email auth failures (SPF/DKIM/DMARC)
  - Malicious URLs detected by VirusTotal
  - Shortened / obfuscated URLs
  - Malicious attachment hashes
  - AlienVault OTX pulse hits

Usage:
    from scoring.risk_scoring import calculate_risk
    result = calculate_risk(auth_results, url_reports, hash_reports, otx_reports)
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

    # ── 2. URL analysis ──────────────────────────────────────
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

    # ── 3. Shortened URLs ────────────────────────────────────
    # url_reports may carry an 'is_shortened' flag from the url_extractor step
    for report in url_reports:
        if report.get("is_shortened"):
            score += _WEIGHTS["shortened_url"]
            breakdown.append(
                f"Shortened URL detected: {report.get('url', '?')} (+{_WEIGHTS['shortened_url']})"
            )

    # ── 4. Attachment hashes ─────────────────────────────────
    for report in hash_reports:
        if report.get("malicious", 0) > 0:
            score += _WEIGHTS["malicious_hash"]
            breakdown.append(
                f"Malicious attachment: {report.get('sha256', '?')[:16]}… "
                f"({report['malicious']} engines) (+{_WEIGHTS['malicious_hash']})"
            )

    # ── 5. AlienVault OTX ────────────────────────────────────
    for report in otx_reports:
        if report.get("pulse_count", 0) > 0:
            score += _WEIGHTS["otx_pulse_hit"]
            identifier = report.get("domain") or report.get("sha256", "?")[:16]
            breakdown.append(
                f"OTX pulses for {identifier}: {report['pulse_count']} "
                f"(+{_WEIGHTS['otx_pulse_hit']})"
            )

    # ── 6. Heuristic detections ──────────────────────────────
    if heuristics:
        for finding in heuristics.get("brand_impersonation", []):
            pts = finding["risk_score"]
            score += pts
            breakdown.append(
                f"Brand impersonation: '{finding['brand']}' in {finding['domain']} (+{pts})"
            )

        for finding in heuristics.get("suspicious_keywords", []):
            pts = finding["risk_score"]
            score += pts
            breakdown.append(
                f"Suspicious keyword '{finding['keyword']}' in {finding['source']} (+{pts})"
            )

        for finding in heuristics.get("domain_age", []):
            pts = finding["risk_score"]
            if pts > 0:
                score += pts
                age = finding.get("age_days", "?")
                breakdown.append(
                    f"Young domain: {finding['domain']} (created: {finding.get('created', 'N/A')}, {age}d old) (+{pts})"
                )

        for finding in heuristics.get("url_shorteners", []):
            pts = finding["risk_score"]
            score += pts
            breakdown.append(
                f"URL shortener: {finding['domain']} (+{pts})"
            )

        for finding in heuristics.get("homograph", []):
            pts = finding["risk_score"]
            score += pts
            breakdown.append(
                f"Homograph attack: {finding['domain']} ({finding['details']}) (+{pts})"
            )

        for finding in heuristics.get("homograph_brands", []):
            pts = finding["risk_score"]
            score += pts
            breakdown.append(
                f"Homograph brand: '{finding['brand']}' in {finding['original_domain']} "
                f"(normalized: {finding['normalized_domain']}) (+{pts})"
            )

        for finding in heuristics.get("domain_entropy", []):
            pts = finding["risk_score"]
            score += pts
            breakdown.append(
                f"High-entropy domain: {finding['domain']} "
                f"(entropy={finding['entropy']}) (+{pts})"
            )

        for finding in heuristics.get("redirect_chains", []):
            pts = finding["risk_score"]
            if pts > 0:
                score += pts
                breakdown.append(
                    f"Redirect chain: {finding['url']} → {finding['hops']} hop(s) (+{pts})"
                )

    # ── 7. QR code findings ─────────────────────────────────
    if qr_findings:
        for finding in qr_findings:
            pts = finding["risk_score"]
            score += pts
            label = finding.get("url") or finding["qr_data"][:60]
            breakdown.append(
                f"QR code in {finding['filename']}: {label} (+{pts})"
            )

        # Extra penalty: check if any QR URL was flagged malicious by VT
        qr_urls_set = {f["url"] for f in qr_findings if f.get("url")}
        for report in url_reports:
            if report.get("url") in qr_urls_set and report.get("malicious", 0) > 0:
                score += 30
                breakdown.append(
                    f"Malicious QR URL: {report['url']} "
                    f"({report['malicious']} engines) (+30)"
                )

    # ── 8. IP reputation ─────────────────────────────────────
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

    # ── 9. Passive DNS ───────────────────────────────────────
    if passive_dns:
        for finding in passive_dns:
            pts = finding["risk_score"]
            if pts > 0:
                score += pts
                breakdown.append(
                    f"Suspicious hosting: IP {finding['ip']} hosts "
                    f"{finding['domain_count']} domain(s) (+{pts})"
                )

    # ── 10. AI classifier ────────────────────────────────────
    if ai_verdict:
        pts = ai_verdict.get("risk_score", 0)
        if pts > 0:
            score += pts
            breakdown.append(
                f"AI verdict: {ai_verdict['verdict']} "
                f"(confidence={ai_verdict['confidence']:.0%}) (+{pts})"
            )

    # ── 11. SMTP relay chain forensics ──────────────────────
    if header_forensics and not header_forensics.get("error"):
        pts = header_forensics.get("risk_score", 0)
        if pts > 0:
            score += pts
            # Emit one breakdown item per scored warning
            for warning in header_forensics.get("warnings", []):
                # Skip pure geo-info lines (no score assigned to them)
                if warning.startswith("Origin IP geolocation:"):
                    continue
                breakdown.append(f"Relay forensic: {warning}")
            # Append the cumulative score once
            breakdown.append(f"SMTP relay forensics total (+{pts})")

    # ── 12. Display name spoofing ────────────────────────────
    if display_name_spoofing:
        for finding in display_name_spoofing:
            pts = finding["risk_score"]
            score += pts
            breakdown.append(
                f"Display name spoofing: brand '{finding['brand']}', "
                f"sender domain {finding['sender_domain']} (+{pts})"
            )

    # ── 13. Lookalike domain detection ───────────────────────
    if lookalike_domains:
        for finding in lookalike_domains:
            pts = finding["risk_score"]
            score += pts
            breakdown.append(
                f"Lookalike domain: {finding['domain']} resembles "
                f"'{finding['brand']}' (distance={finding['distance']}) (+{pts})"
            )

    # ── Cap at 100 ───────────────────────────────────────────
    score = min(score, 100)

    # ── Verdict ──────────────────────────────────────────────
    if score >= 90:
        verdict = "CRITICAL"
    elif score >= RISK_HIGH_THRESHOLD:
        verdict = "HIGH"
    elif score >= RISK_MEDIUM_THRESHOLD:
        verdict = "MEDIUM"
    else:
        verdict = "LOW"

    logger.info("Risk score: %d/100 – Verdict: %s", score, verdict)
    return {"score": score, "verdict": verdict, "breakdown": breakdown}
