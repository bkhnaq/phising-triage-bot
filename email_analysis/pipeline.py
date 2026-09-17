"""Intrinsic email detection and IOC extraction, followed by Wazuh JSONL output."""

import logging
import tempfile
import os
import uuid
from pathlib import Path
from typing import Any

from config.settings import (
    MAX_ATTACHMENTS_PER_EMAIL,
    MAX_URLS_PER_EMAIL,
    UPLOAD_DIR,
)

logger = logging.getLogger(__name__)


class PhishingPipeline:
    """Modular phishing detection pipeline orchestrator."""

    def __init__(
        self,
        upload_dir: str | None = None,
        analysis_id: str | None = None,
        *,
        lab_mode: bool | None = None,
        report_verbosity: str = "DEBUG",
        events_jsonl_path: str | None = None,
    ):
        from config.settings import EVENTS_JSONL_PATH, LAB_MODE

        self.events_jsonl_path = (
            EVENTS_JSONL_PATH if events_jsonl_path is None else events_jsonl_path
        )
        self.upload_dir = upload_dir or UPLOAD_DIR
        self.analysis_id = analysis_id or uuid.uuid4().hex[:12]
        self.lab_mode = LAB_MODE if lab_mode is None else lab_mode
        self.report_verbosity = report_verbosity
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
        raw_bytes = raw_email.encode("utf-8")
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb", suffix=".eml", dir=self.upload_dir, delete=False
            ) as f:
                temp_path = f.name
                f.write(raw_bytes)
            from email_analysis.email_parser import parse_eml_file

            email_data = parse_eml_file(temp_path)
            return self._run_pipeline(email_data)
        finally:
            try:
                if temp_path is not None:
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
        from email_analysis.correlation import build_evidence_bundle
        from scoring.risk_scoring import calculate_risk
        from report.report_generator import generate_report
        from email_analysis.observables import collect_observables
        from email_analysis.analysis_environment import classify_analysis_environment
        from output.siem import build_siem_event
        from output.jsonl import append_event

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
            admitted_urls = {item.get("url") for item in all_urls}
            qr_findings = [
                finding
                for finding in qr_findings
                if not finding.get("url") or finding.get("url") in admitted_urls
            ]
            analysis_limits["urls_truncated"] = (
                analysis_limits["urls_truncated"] or qr_urls_truncated
            )
            # Stage 9: Static URL analysis
            url_intel = url_intel_analyze(all_urls)
            all_domains = self._collect_context_domains(
                auth_results, all_urls, url_intel
            )

            # Stage 10: Static domain analysis
            domain_intel = analyze_domain_intelligence(all_domains)

            # Stage 11: Brand impersonation detection
            brand_detector = BrandDetector()
            brand_results = brand_detector.analyze(
                all_urls,
                from_header=email_data.get("from", ""),
                body_text=body_text,
                recipient_header=email_data.get("to", ""),
            )

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
                credential_harvesting=credential_harvesting,
                brand_impersonation=brand_results,
                language_analysis=language_results,
                attachment_risks=attachment_risks,
                domain_intelligence=domain_intel,
                ai_verdict=ai_verdict,
                url_intelligence=url_intel,
                header_forensics=header_forensics,
                heuristics=heuristics,
                qr_findings=qr_findings,
            )

            # Stage 14: Risk scoring
            risk = calculate_risk(
                auth_results,
                heuristics=heuristics,
                qr_findings=qr_findings,
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
                evidence_bundle=evidence_bundle,
                email_data=email_data,
                urls=all_urls,
                attachments=attachments,
            )

            observables = collect_observables(
                urls=all_urls,
                attachments=attachments,
                url_intelligence=url_intel,
                email_data=email_data,
                header_forensics=header_forensics,
                lab_mode=self.lab_mode,
                sender_domain=auth_results.get("forensics", {}).get("from_domain", ""),
                brand_impersonation=brand_results,
                attachment_risks=attachment_risks,
                origin_ip=str(header_forensics.get("origin_ip") or ""),
            )
            analysis_environment = classify_analysis_environment(
                observables, lab_mode=self.lab_mode
            )

            # Stage 15: Report generation
            report_text = generate_report(
                email_data,
                auth_results,
                all_urls,
                attachments,
                risk,
                heuristics=heuristics,
                qr_findings=qr_findings,
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
                evidence_bundle=evidence_bundle,
                analysis_limits=analysis_limits,
                lab_mode=self.lab_mode,
                observables=observables,
                analysis_environment=analysis_environment,
                verbosity=self.report_verbosity,
            )

            logger.info(
                "Pipeline complete id=%s score=%d verdict=%s",
                self.analysis_id,
                risk["score"],
                risk["verdict"],
            )

            result: dict[str, Any] = {
                "analysis_id": self.analysis_id,
                "email_data": {
                    "subject": email_data.get("subject"),
                    "from": email_data.get("from"),
                    "to": email_data.get("to"),
                    "date": email_data.get("date"),
                    "message_id": email_data.get("message_id"),
                    "return_path": email_data.get("return_path", ""),
                    "reply_to": email_data.get("reply_to", ""),
                    "received": email_data.get("received", []),
                    "mime_parts": email_data.get("mime_parts", []),
                },
                "auth_results": auth_results,
                "header_forensics": header_forensics,
                "urls": all_urls,
                "url_intelligence": url_intel,
                "domain_intelligence": domain_intel,
                "brand_impersonation": brand_results,
                "credential_harvesting": credential_harvesting,
                "language_analysis": language_results,
                "attachments": attachments,
                "attachment_risks": attachment_risks,
                "qr_findings": qr_findings,
                "heuristics": heuristics,
                "display_name_spoofing": display_name_spoofing,
                "lookalike_domains": lookalike_domains,
                "ai_verdict": ai_verdict,
                "evidence_bundle": evidence_bundle,
                "observables": observables,
                "analysis_environment": analysis_environment,
                "risk": risk,
                "analysis_limits": analysis_limits,
                "report": report_text,
            }
            event = build_siem_event(result)
            result["siem_event"] = event
            result["event_id"] = event["event_id"]
            result["event_output"] = {
                "status": "DISABLED",
                "path": self.events_jsonl_path,
            }
            if self.events_jsonl_path:
                try:
                    append_event(event, self.events_jsonl_path)
                    result["event_output"]["status"] = "WRITTEN"
                except OSError:
                    logger.exception(
                        "SIEM event append failed event_id=%s", event["event_id"]
                    )
                    result["event_output"].update(
                        status="FAILED",
                        error="Could not append SIEM event; inspect application logs",
                    )
            return result
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
    def _collect_context_domains(
        auth_results: dict,
        urls: list[dict],
        url_intelligence: dict | None,
    ) -> list[str]:
        """Collect sender/path/URL domains in SOC investigation priority order."""
        candidates: list[str] = []
        forensics = auth_results.get("forensics", {})
        for key in ("from_domain", "reply_to_domain", "return_path_domain"):
            candidates.append(str(forensics.get(key, "")))
        candidates.extend(str(item.get("domain", "")) for item in urls)
        seen: set[str] = set()
        domains: list[str] = []
        for candidate in candidates:
            from email_analysis.domain_utils import domain_info

            domain = domain_info(candidate).ascii_host
            if domain and domain not in seen:
                seen.add(domain)
                domains.append(domain)
        return domains

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
            result = auth_results.get(check, {}).get("result", "unknown")
            if result in ("fail", "softfail"):
                findings.append(f"{check.upper()} {result}")
            elif result in ("none", "unknown"):
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
            for f in brand_results.get("sender_identity_mismatch", [])[:2]:
                findings.append(
                    "Sender identity mismatch: "
                    f"{f.get('sender_domain', '?')} vs {f.get('expected_domain', '?')}"
                )
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
            for f in url_intelligence.get("deceptive_links", [])[:2]:
                findings.append(
                    "Deceptive hyperlink: "
                    f"{f.get('displayed_domain', '?')} displayed, "
                    f"{f.get('actual_domain', '?')} opened"
                )
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
