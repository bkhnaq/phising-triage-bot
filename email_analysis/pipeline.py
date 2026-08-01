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
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, TypeVar

from config.settings import (
    MAX_ATTACHMENTS_PER_EMAIL,
    MAX_URLS_PER_EMAIL,
    THREAT_INTEL_MAX_WORKERS,
    UPLOAD_DIR,
)

logger = logging.getLogger(__name__)
T = TypeVar("T")


class PhishingPipeline:
    """Modular phishing detection pipeline orchestrator."""

    def __init__(self, upload_dir: str | None = None, analysis_id: str | None = None):
        self.upload_dir = upload_dir or UPLOAD_DIR
        self.analysis_id = analysis_id or uuid.uuid4().hex[:12]
        os.makedirs(self.upload_dir, exist_ok=True)

    def analyze_file(self, eml_path: str) -> dict:
        """
        Run the full analysis pipeline on an .eml file.

        Args:
            eml_path: Path to the .eml file on disk.

        Returns:
            Complete analysis result dict with all findings and report.
        """
        logger.info("Pipeline started id=%s file=%s", self.analysis_id, eml_path)

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
        from email_analysis.url_extractor import count_unique_urls, extract_urls
        from email_analysis.url_intelligence import analyze_urls as url_intel_analyze
        from email_analysis.domain_intelligence import analyze_domain_intelligence
        from email_analysis.brand_impersonation import BrandDetector
        from email_analysis.html_form_detector import detect_credential_harvesting
        from email_analysis.landing_page_analyzer import analyze_landing_pages
        from email_analysis.language_analyzer import analyze_language
        from email_analysis.attachment_analyzer import (
            assess_attachment_risk,
            count_attachments,
            extract_attachments,
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
        from threat_intel.alienvault_checker import check_url as otx_check_url
        from threat_intel.alienvault_checker import check_file_hash as otx_check_hash
        from threat_intel.ip_reputation import check_ip_reputation
        from threat_intel.passive_dns import check_passive_dns
        from email_analysis.correlation import build_evidence_bundle
        from scoring.risk_scoring import calculate_risk
        from report.report_generator import generate_report

        attachments: list[dict] = []
        try:
            # Stage 2: Email authentication headers
            auth_results = analyze_headers(email_data["headers"])

            # Stage 3: SMTP relay chain forensics
            header_forensics = run_header_forensics(email_data)

            # Stage 4: URL extraction
            raw_url_count = count_unique_urls(
                email_data.get("body_text", ""), email_data.get("body_html", "")
            )
            urls = extract_urls(
                email_data.get("body_text", ""),
                email_data.get("body_html", ""),
                max_urls=MAX_URLS_PER_EMAIL,
            )

            # Stage 5: HTML credential harvesting detection
            credential_harvesting = detect_credential_harvesting(
                email_data.get("body_html", "")
            )

            # Stage 6: Language analysis
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

            # Stage 7: Attachment extraction + risk assessment
            attachment_count = count_attachments(email_data["raw_message"])
            attachments = extract_attachments(
                email_data["raw_message"],
                save_dir=self.upload_dir,
                max_attachments=MAX_ATTACHMENTS_PER_EMAIL,
            )
            attachment_risks = assess_attachment_risk(attachments)

            analysis_limits = {
                "urls_truncated": raw_url_count > MAX_URLS_PER_EMAIL,
                "attachments_truncated": (attachment_count > MAX_ATTACHMENTS_PER_EMAIL),
                "max_urls": MAX_URLS_PER_EMAIL,
                "max_attachments": MAX_ATTACHMENTS_PER_EMAIL,
            }

            # Stage 8: QR code scanning
            qr_findings = scan_attachments_for_qr(attachments)
            qr_urls = extract_qr_urls(qr_findings)

            all_urls, qr_urls_truncated = self._merge_bounded_url_lists(
                urls, qr_urls, max_urls=MAX_URLS_PER_EMAIL
            )
            analysis_limits["urls_truncated"] = (
                analysis_limits["urls_truncated"] or qr_urls_truncated
            )
            all_domains = self._extract_unique_domains(all_urls)

            # Stage 9: URL intelligence (shorteners + redirect chains)
            url_intel = url_intel_analyze(all_urls)

            # Stage 10: Domain intelligence
            domain_intel = analyze_domain_intelligence(all_domains)

            # Stage 11: Brand impersonation detection
            brand_detector = BrandDetector()
            brand_results = brand_detector.analyze(
                all_urls,
                from_header=email_data.get("from", ""),
                body_text=email_data.get("body_text", ""),
            )

            # Stage 12: Threat intelligence
            url_indicators = self._build_url_indicators(all_urls, url_intel)
            attachment_hashes = self._extract_unique_hashes(attachments)

            vt_url_reports = self._run_parallel(
                url_indicators,
                lambda indicator: self._check_vt_url_indicator(indicator, vt_check_url),
            )
            vt_hash_reports = self._run_parallel(attachment_hashes, vt_check_hash)

            otx_url_reports = self._run_parallel(
                url_indicators,
                lambda indicator: self._check_otx_url_indicator(
                    indicator, otx_check_url
                ),
            )
            otx_domain_reports = self._run_parallel(all_domains, otx_check_domain)
            otx_hash_reports = self._run_parallel(attachment_hashes, otx_check_hash)
            otx_reports = otx_domain_reports + otx_url_reports + otx_hash_reports

            ip_reputation = check_ip_reputation(all_domains)
            passive_dns = check_passive_dns(ip_reputation)
            landing_pages = analyze_landing_pages(all_urls)
            heuristics = run_heuristics(all_urls)

            display_name_spoofing = detect_display_name_spoofing(
                email_data.get("from", "")
            )
            lookalike_domains = detect_lookalike_domains(all_urls)

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
            ai_verdict = classify_email(email_data, all_urls, rule_findings)

            evidence_bundle = build_evidence_bundle(
                auth_results=auth_results,
                urls=all_urls,
                vt_url_reports=vt_url_reports,
                vt_hash_reports=vt_hash_reports,
                otx_reports=otx_reports,
                credential_harvesting=credential_harvesting,
                brand_impersonation=brand_results,
                language_analysis=language_results,
                attachment_risks=attachment_risks,
                landing_pages=landing_pages,
                domain_intelligence=domain_intel,
            )

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
                landing_pages=landing_pages,
                evidence_bundle=evidence_bundle,
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
                landing_pages=landing_pages,
                evidence_bundle=evidence_bundle,
                analysis_limits=analysis_limits,
            )

            logger.info(
                "Pipeline complete id=%s score=%d verdict=%s",
                self.analysis_id,
                risk["score"],
                risk["verdict"],
            )

            return {
                "analysis_id": self.analysis_id,
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
                "landing_pages": landing_pages,
                "heuristics": heuristics,
                "display_name_spoofing": display_name_spoofing,
                "lookalike_domains": lookalike_domains,
                "ai_verdict": ai_verdict,
                "evidence_bundle": evidence_bundle,
                "risk": risk,
                "analysis_limits": analysis_limits,
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

    def _run_parallel(self, items: list[T], worker: Callable[[T], dict]) -> list[dict]:
        """Run independent lookup tasks with stable result ordering."""
        if not items:
            return []

        max_workers = max(1, min(THREAT_INTEL_MAX_WORKERS, len(items)))
        results: list[dict | None] = [None] * len(items)

        with ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix=f"ti-{self.analysis_id[:6]}",
        ) as executor:
            future_to_index = {
                executor.submit(worker, item): idx for idx, item in enumerate(items)
            }
            for future in as_completed(future_to_index):
                idx = future_to_index[future]
                try:
                    results[idx] = future.result()
                except Exception:
                    logger.exception(
                        "Parallel lookup failed id=%s item=%r",
                        self.analysis_id,
                        items[idx],
                    )

        return [result for result in results if result is not None]

    @staticmethod
    def _merge_url_lists(*groups: list[dict]) -> list[dict]:
        """Merge URL finding lists while preserving first-seen order."""
        merged: list[dict] = []
        seen: set[str] = set()
        for group in groups:
            for item in group:
                url = item.get("url", "")
                if not url or url in seen:
                    continue
                seen.add(url)
                merged.append(item)
        return merged

    @staticmethod
    def _merge_bounded_url_lists(
        *groups: list[dict], max_urls: int
    ) -> tuple[list[dict], bool]:
        """Merge URL findings and apply one shared total-analysis limit."""
        merged = PhishingPipeline._merge_url_lists(*groups)
        limit = max(0, max_urls)
        return merged[:limit], len(merged) > limit

    @staticmethod
    def _extract_unique_domains(urls: list[dict]) -> list[str]:
        seen: set[str] = set()
        domains: list[str] = []
        for item in urls:
            domain = str(item.get("domain", "")).lower().split(":", 1)[0].strip()
            if not domain or domain in seen:
                continue
            seen.add(domain)
            domains.append(domain)
        return domains

    @staticmethod
    def _extract_unique_hashes(attachments: list[dict]) -> list[str]:
        seen: set[str] = set()
        hashes: list[str] = []
        for attachment in attachments:
            sha256 = str(attachment.get("sha256", "")).strip().lower()
            if not sha256 or sha256 in seen:
                continue
            seen.add(sha256)
            hashes.append(sha256)
        return hashes

    @staticmethod
    def _build_url_indicators(
        urls: list[dict], url_intelligence: dict | None = None
    ) -> list[dict]:
        indicators: list[dict] = []
        seen_lookup_urls: set[str] = set()
        lookup_overrides = PhishingPipeline._url_lookup_overrides(url_intelligence)
        for item in urls:
            source_url = item.get("url", "")
            lookup_url = (
                lookup_overrides.get(source_url)
                or item.get("expanded_url")
                or source_url
            )
            if not lookup_url or lookup_url in seen_lookup_urls:
                continue
            seen_lookup_urls.add(lookup_url)
            indicators.append(
                {
                    "source_url": source_url,
                    "lookup_url": lookup_url,
                    "is_shortened": bool(item.get("is_shortened", False)),
                    "source": item.get("source", "body"),
                }
            )
        return indicators

    @staticmethod
    def _url_lookup_overrides(url_intelligence: dict | None) -> dict[str, str]:
        """Prefer final landing URLs for reputation lookups when known."""
        if not url_intelligence:
            return {}

        overrides: dict[str, str] = {}

        for finding in url_intelligence.get("shortener_findings", []):
            source_url = finding.get("url", "")
            expanded_url = finding.get("expanded_url", "")
            if source_url and expanded_url and expanded_url != source_url:
                overrides[source_url] = expanded_url

        for finding in url_intelligence.get("redirect_findings", []):
            if finding.get("error"):
                continue
            source_url = finding.get("source_url") or finding.get("url", "")
            final_url = finding.get("final_url", "")
            if source_url and final_url and final_url != source_url:
                overrides[source_url] = final_url

        return overrides

    @staticmethod
    def _check_vt_url_indicator(
        indicator: dict, checker: Callable[[str], dict]
    ) -> dict:
        report = checker(indicator["lookup_url"])
        report["url"] = indicator["source_url"]
        if indicator["lookup_url"] != indicator["source_url"]:
            report["lookup_url"] = indicator["lookup_url"]
        report["is_shortened"] = indicator["is_shortened"]
        report["source"] = indicator["source"]
        return report

    @staticmethod
    def _check_otx_url_indicator(
        indicator: dict,
        checker: Callable[[str], dict],
    ) -> dict:
        report = checker(indicator["lookup_url"])
        report["url"] = indicator["source_url"]
        if indicator["lookup_url"] != indicator["source_url"]:
            report["lookup_url"] = indicator["lookup_url"]
        report["source"] = indicator["source"]
        return report

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
