"""
Phishing Detection Pipeline
-----------------------------
Modular orchestrator that runs all detection layers and produces
a complete phishing analysis result.

Pipeline stages:
  1. email_parser       – Parse .eml file
  2. header_analyzer    – SPF/DKIM/DMARC + header forensics
  3. header_forensics   – SMTP relay chain + GeoIP + ASN
  4. url_extractor      – Extract URLs from body
  5. url_intelligence   – Shortener detection + redirect chains
  6. domain_intelligence – WHOIS + DNS + entropy + lookalike
  7. brand_impersonation – Comprehensive brand detection
  8. html_form_detector – Credential harvesting in HTML
  9. language_analyzer  – Phishing language patterns
  10. attachment_analyzer – Extract + risk-assess attachments
  11. qr_code_analyzer  – QR code scanning
  12. threat_intelligence – VT + OTX + AbuseIPDB + passive DNS
  13. ai_classifier     – LLM-based classification
  14. risk_scoring      – Weighted score computation
  15. report_generator  – Structured report output

Usage:
    from email_analysis.pipeline import PhishingPipeline
    pipeline = PhishingPipeline()
    result = pipeline.analyze_file("path/to/email.eml")
    result = pipeline.analyze_raw(raw_email_text)
"""

import logging
import tempfile
import os
from pathlib import Path

from config.settings import UPLOAD_DIR

logger = logging.getLogger(__name__)


class PhishingPipeline:
    """Modular phishing detection pipeline orchestrator."""

    def __init__(self, upload_dir: str | None = None):
        self.upload_dir = upload_dir or UPLOAD_DIR
        os.makedirs(self.upload_dir, exist_ok=True)

    def analyze_file(self, eml_path: str) -> dict:
        """
        Run the full analysis pipeline on an .eml file.

        Args:
            eml_path: Path to the .eml file on disk.

        Returns:
            Complete analysis result dict with all findings and report.
        """
        logger.info("Pipeline started for %s", eml_path)

        # Stage 1: Parse email
        from email_analysis.email_parser import parse_eml_file

        email_data = parse_eml_file(eml_path)

        return self._run_pipeline(email_data)

    def analyze_raw(self, raw_email: str) -> dict:
        """
        Run the full analysis pipeline on raw email text.

        Args:
            raw_email: Raw email content as string.

        Returns:
            Complete analysis result dict with all findings and report.
        """
        # Write to temp file and parse
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".eml", dir=self.upload_dir, delete=False, encoding="utf-8"
        ) as f:
            f.write(raw_email)
            temp_path = f.name

        try:
            from email_analysis.email_parser import parse_eml_file

            email_data = parse_eml_file(temp_path)
            return self._run_pipeline(email_data)
        finally:
            try:
                os.unlink(temp_path)
            except OSError:
                pass

    def _run_pipeline(self, email_data: dict) -> dict:
        """Run all pipeline stages on parsed email data."""
        from email_analysis.header_analyzer import analyze_headers
        from email_analysis.header_forensics import run_header_forensics
        from email_analysis.url_extractor import extract_urls
        from email_analysis.url_intelligence import analyze_urls as url_intel_analyze
        from email_analysis.domain_intelligence import analyze_domain_intelligence
        from email_analysis.brand_impersonation import BrandDetector
        from email_analysis.html_form_detector import detect_credential_harvesting
        from email_analysis.language_analyzer import analyze_language
        from email_analysis.attachment_analyzer import (
            extract_attachments,
            assess_attachment_risk,
        )
        from email_analysis.qr_code_analyzer import (
            scan_attachments_for_qr,
            extract_qr_urls,
        )
        from email_analysis.heuristic_analyzer import run_heuristics
        from email_analysis.ai_classifier import classify_email
        from email_analysis.phishing_rules import (
            detect_display_name_spoofing,
            detect_lookalike_domains,
        )
        from threat_intel.virustotal_checker import check_url as vt_check_url
        from threat_intel.virustotal_checker import check_file_hash as vt_check_hash
        from threat_intel.alienvault_checker import check_domain as otx_check_domain
        from threat_intel.alienvault_checker import check_file_hash as otx_check_hash
        from threat_intel.ip_reputation import check_ip_reputation
        from threat_intel.passive_dns import check_passive_dns
        from scoring.risk_scoring import calculate_risk
        from report.report_generator import generate_report

        attachments: list[dict] = []
        try:
            # Stage 2: Email authentication headers
            auth_results = analyze_headers(email_data["headers"])

            # Stage 3: SMTP relay chain forensics
            header_forensics = run_header_forensics(email_data)

            # Stage 4: URL extraction
            urls = extract_urls(email_data["body_text"], email_data["body_html"])

            # Stage 5: URL intelligence (shorteners + redirect chains)
            url_intel = url_intel_analyze(urls)

            # Stage 6: Extract unique domains for domain intelligence
            seen_domains: set[str] = set()
            all_domains: list[str] = []
            for u in urls:
                domain = u.get("domain", "")
                if domain and domain not in seen_domains:
                    seen_domains.add(domain)
                    all_domains.append(domain)

            domain_intel = analyze_domain_intelligence(all_domains)

            # Stage 7: Brand impersonation detection
            brand_detector = BrandDetector()
            brand_results = brand_detector.analyze(
                urls,
                from_header=email_data.get("from", ""),
                body_text=email_data.get("body_text", ""),
            )

            # Stage 8: HTML credential harvesting detection
            credential_harvesting = detect_credential_harvesting(
                email_data.get("body_html", "")
            )

            # Stage 9: Language analysis
            body_text = email_data.get("body_text") or ""
            if not body_text and email_data.get("body_html"):
                import html
                import re

                body_text = re.sub(r"<[^>]+>", " ", email_data["body_html"])
                body_text = html.unescape(body_text)
                body_text = re.sub(r"\s+", " ", body_text).strip()

            language_results = analyze_language(
                body_text, email_data.get("subject", "")
            )

            # Stage 10: Attachment extraction + risk assessment
            attachments = extract_attachments(
                email_data["raw_message"], save_dir=self.upload_dir
            )
            attachment_risks = assess_attachment_risk(attachments)

            # Stage 11: QR code scanning
            qr_findings = scan_attachments_for_qr(attachments)
            qr_urls = extract_qr_urls(qr_findings)

            # Stage 12: Threat intelligence
            vt_url_reports: list[dict] = []
            for u in urls:
                target = u.get("expanded_url", u["url"])
                report = vt_check_url(target)
                report["url"] = u["url"]
                report["is_shortened"] = u.get("is_shortened", False)
                vt_url_reports.append(report)

            for qu in qr_urls:
                target = qu["url"]
                report = vt_check_url(target)
                report["url"] = target
                report["is_shortened"] = False
                vt_url_reports.append(report)
                domain = qu.get("domain", "")
                if domain and domain not in seen_domains:
                    seen_domains.add(domain)
                    all_domains.append(domain)

            vt_hash_reports = [vt_check_hash(a["sha256"]) for a in attachments]

            otx_reports: list[dict] = []
            for domain in all_domains:
                otx_reports.append(otx_check_domain(domain))
            for a in attachments:
                otx_reports.append(otx_check_hash(a["sha256"]))

            ip_reputation = check_ip_reputation(all_domains)
            passive_dns = check_passive_dns(ip_reputation)
            heuristics = run_heuristics(urls + qr_urls)

            display_name_spoofing = detect_display_name_spoofing(
                email_data.get("from", "")
            )
            lookalike_domains = detect_lookalike_domains(urls + qr_urls)

            # Stage 13: AI Classifier
            rule_findings = self._build_rule_findings(
                auth_results,
                heuristics,
                header_forensics,
                credential_harvesting,
                language_results,
                brand_results,
                attachment_risks,
                url_intel,
            )
            ai_verdict = classify_email(email_data, urls + qr_urls, rule_findings)

            # Stage 14: Risk scoring
            risk = calculate_risk(
                auth_results,
                vt_url_reports,
                vt_hash_reports,
                otx_reports,
                heuristics,
                qr_findings,
                ip_reputation,
                passive_dns,
                ai_verdict,
                header_forensics=header_forensics,
                display_name_spoofing=display_name_spoofing,
                lookalike_domains=lookalike_domains,
                credential_harvesting=credential_harvesting,
                language_analysis=language_results,
                brand_impersonation=brand_results,
                attachment_risks=attachment_risks,
                url_intelligence=url_intel,
                domain_intelligence=domain_intel,
            )

            # Stage 15: Report generation
            report_text = generate_report(
                email_data,
                auth_results,
                urls,
                attachments,
                risk,
                vt_url_reports,
                vt_hash_reports,
                otx_reports,
                heuristics=heuristics,
                qr_findings=qr_findings,
                ip_reputation=ip_reputation,
                passive_dns=passive_dns,
                ai_verdict=ai_verdict,
                header_forensics=header_forensics,
                display_name_spoofing=display_name_spoofing,
                lookalike_domains=lookalike_domains,
                credential_harvesting=credential_harvesting,
                language_analysis=language_results,
                brand_impersonation=brand_results,
                attachment_risks=attachment_risks,
                url_intelligence=url_intel,
                domain_intelligence=domain_intel,
            )

            logger.info(
                "Pipeline complete: score=%d verdict=%s",
                risk["score"],
                risk["verdict"],
            )

            return {
                "email_data": {
                    "subject": email_data.get("subject"),
                    "from": email_data.get("from"),
                    "to": email_data.get("to"),
                    "date": email_data.get("date"),
                    "message_id": email_data.get("message_id"),
                },
                "auth_results": auth_results,
                "header_forensics": header_forensics,
                "urls": urls,
                "url_intelligence": url_intel,
                "domain_intelligence": domain_intel,
                "brand_impersonation": brand_results,
                "credential_harvesting": credential_harvesting,
                "language_analysis": language_results,
                "attachments": attachments,
                "attachment_risks": attachment_risks,
                "qr_findings": qr_findings,
                "vt_url_reports": vt_url_reports,
                "vt_hash_reports": vt_hash_reports,
                "otx_reports": otx_reports,
                "ip_reputation": ip_reputation,
                "passive_dns": passive_dns,
                "heuristics": heuristics,
                "display_name_spoofing": display_name_spoofing,
                "lookalike_domains": lookalike_domains,
                "ai_verdict": ai_verdict,
                "risk": risk,
                "report": report_text,
            }
        finally:
            for attachment in attachments:
                saved_path = attachment.get("saved_path")
                if not saved_path:
                    continue
                try:
                    Path(saved_path).unlink(missing_ok=True)
                except OSError:
                    logger.debug("Could not clean attachment artifact: %s", saved_path)

    @staticmethod
    def _build_rule_findings(
        auth_results: dict,
        heuristics: dict | None,
        header_forensics: dict | None,
        credential_harvesting: dict | None,
        language_analysis: dict | None,
        brand_results: dict | None,
        attachment_risks: list[dict] | None,
        url_intelligence: dict | None = None,
    ) -> list[str]:
        """Build concise rule-based findings for AI classifier context."""
        findings: list[str] = []

        # Auth status findings
        for check in ("spf", "dkim", "dmarc"):
            result = auth_results.get(check, {}).get("result", "none")
            if result in ("fail", "softfail"):
                findings.append(f"{check.upper()} {result}")
            elif result == "none":
                findings.append(f"{check.upper()} unavailable")

        # Header forensics findings
        for h in auth_results.get("forensics", {}).get("findings", []):
            summary = h.get("summary", "Header anomaly")
            findings.append(summary)

        # SMTP relay chain forensics
        if header_forensics:
            for w in header_forensics.get("warnings", []):
                if not w.startswith("Origin IP geolocation:"):
                    findings.append(w)

        # Heuristic findings
        if heuristics:
            for f in heuristics.get("homograph_brands", [])[:3]:
                findings.append(
                    f"Homograph brand: {f['brand']} in {f['original_domain']}"
                )
            for f in heuristics.get("suspicious_keywords", [])[:3]:
                findings.append(f"Suspicious keyword: {f['keyword']}")
            for f in heuristics.get("brand_impersonation", [])[:3]:
                findings.append(f"Brand impersonation: {f['brand']} in {f['domain']}")

        # Credential harvesting
        if credential_harvesting and credential_harvesting.get("detected"):
            for cf in credential_harvesting.get("findings", [])[:3]:
                findings.append(cf)

        # Language patterns
        if language_analysis and language_analysis.get("total_matches", 0) > 0:
            for s in language_analysis.get("summary", [])[:3]:
                findings.append(s)

        # Brand impersonation (comprehensive)
        if brand_results:
            for f in brand_results.get("domain_impersonation", [])[:2]:
                findings.append(f"Brand domain: {f['brand']} in {f['domain']}")
            for f in brand_results.get("display_name_spoofing", [])[:2]:
                findings.append(f"Display name spoofing: {f['brand']}")

        # Attachment risks
        if attachment_risks:
            for f in attachment_risks[:3]:
                findings.append(f"Risky attachment: {f['filename']} ({f['category']})")

        # ESP/tracking context (helps avoid classifying known marketing trackers as malicious by default)
        if url_intelligence:
            for f in url_intelligence.get("esp_findings", [])[:3]:
                provider = f.get("provider", "ESP")
                if f.get("is_tracking"):
                    findings.append(f"Known ESP tracking URL: {provider}")
                else:
                    findings.append(f"Known ESP infrastructure: {provider}")

        # Deduplicate
        deduped: list[str] = []
        seen: set[str] = set()
        for item in findings:
            if item not in seen:
                seen.add(item)
                deduped.append(item)
        return deduped[:20]
