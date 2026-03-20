import unittest

from scoring.risk_scoring import calculate_risk


class RiskScoringRefactorTests(unittest.TestCase):
    def _auth(
        self,
        spf: str = "pass",
        dkim: str = "pass",
        dmarc: str = "pass",
        from_domain: str = "example.com",
        missing_received: bool = False,
        extra_findings: list[dict] | None = None,
    ) -> dict:
        findings = list(extra_findings or [])
        if missing_received:
            findings.append({
                "type": "missing_received_headers",
                "summary": "No Received headers found",
                "risk_score": 0,
                "evidence_state": "none",
            })

        return {
            "spf": {"result": spf},
            "dkim": {"result": dkim},
            "dmarc": {"result": dmarc},
            "forensics": {
                "from_domain": from_domain,
                "findings": findings,
            },
        }

    def test_legitimate_marketing_email_via_bluehornet(self) -> None:
        auth_results = self._auth(
            spf="none",
            dkim="none",
            dmarc="none",
            from_domain="news.chase.com",
            missing_received=True,
        )

        result = calculate_risk(
            auth_results=auth_results,
            url_reports=[
                {
                    "url": "https://dr.bluehornet.com/ct/12345",
                    "malicious": 0,
                    "suspicious": 0,
                }
            ],
            hash_reports=[],
            otx_reports=[{"domain": "bluehornet.com", "pulse_count": 0}],
            language_analysis={
                "categories": {
                    "urgency": {
                        "risk_score": 2,
                        "match_count": 2,
                        "matches": ["urgent", "act now"],
                    }
                },
                "total_matches": 2,
                "risk_score": 2,
                "summary": ["Urgency / time-pressure language"],
            },
            brand_impersonation={
                "domain_impersonation": [],
                "display_name_spoofing": [],
                "body_brand_mentions": [
                    {
                        "brand": "chase",
                        "sender_domain": "news.chase.com",
                        "risk_score": 0,
                    }
                ],
            },
            url_intelligence={
                "shortener_findings": [],
                "redirect_findings": [
                    {
                        "source_url": "https://dr.bluehornet.com/ct/12345",
                        "url": "https://dr.bluehornet.com/ct/12345",
                        "hops": 1,
                        "final_domain": "offers.chase.com",
                        "risk_score": 0,
                        "is_esp_tracking": True,
                        "suspicious_landing": False,
                    }
                ],
                "suspicious_endpoints": [],
                "esp_findings": [
                    {
                        "url": "https://dr.bluehornet.com/ct/12345",
                        "provider": "BlueHornet",
                        "is_tracking": True,
                        "risk_adjustment": -8,
                        "final_domain": "offers.chase.com",
                        "suspicious_landing": False,
                    }
                ],
                "risk_score": 0,
            },
        )

        self.assertLess(result["risk_score"], 45)
        self.assertNotIn(result["verdict"], {"HIGH", "CRITICAL"})
        self.assertLessEqual(result["data_completeness"], 60)
        self.assertLessEqual(result["confidence"], 0.65)
        self.assertLess(result["category_scores"]["ESP detection"], 0)

    def test_missing_headers_only_is_inconclusive(self) -> None:
        auth_results = self._auth(
            spf="none",
            dkim="none",
            dmarc="none",
            from_domain="",
            missing_received=True,
        )

        result = calculate_risk(
            auth_results=auth_results,
            url_reports=[],
            hash_reports=[],
            otx_reports=[],
        )

        self.assertLessEqual(result["risk_score"], 10)
        self.assertEqual(result["verdict"], "INCONCLUSIVE")
        self.assertLess(result["data_completeness"], 60)

    def test_phishing_email_with_real_brand_spoofing(self) -> None:
        auth_results = self._auth(
            spf="fail",
            dkim="fail",
            dmarc="fail",
            from_domain="secure-chase-alerts.com",
            missing_received=False,
            extra_findings=[
                {
                    "type": "return_path_mismatch",
                    "summary": "Return-Path domain differs",
                    "risk_score": 15,
                }
            ],
        )

        result = calculate_risk(
            auth_results=auth_results,
            url_reports=[
                {
                    "url": "https://secure-chase-alerts.com/login/verify",
                    "malicious": 6,
                    "suspicious": 0,
                }
            ],
            hash_reports=[{"sha256": "deadbeef", "malicious": 4}],
            otx_reports=[{"domain": "secure-chase-alerts.com", "pulse_count": 3}],
            header_forensics={
                "error": None,
                "risk_score": 15,
                "warnings": ["Origin IP is a known proxy or VPN exit node"],
            },
            credential_harvesting={
                "detected": True,
                "risk_score": 20,
                "findings": ["Password form posts to external domain"],
            },
            language_analysis={
                "categories": {
                    "threats": {"risk_score": 10, "match_count": 2},
                    "credential_harvesting": {"risk_score": 12, "match_count": 2},
                },
                "total_matches": 4,
                "risk_score": 22,
            },
            brand_impersonation={
                "domain_impersonation": [
                    {
                        "brand": "chase",
                        "domain": "secure-chase-alerts.com",
                        "detail": "Brand keyword in domain",
                        "risk_score": 25,
                    }
                ],
                "display_name_spoofing": [
                    {
                        "brand": "chase",
                        "sender_domain": "secure-chase-alerts.com",
                        "risk_score": 20,
                    }
                ],
                "body_brand_mentions": [],
            },
            attachment_risks=[
                {
                    "filename": "invoice.zip",
                    "description": "Archive with executable payload",
                    "risk_score": 15,
                }
            ],
            url_intelligence={
                "shortener_findings": [],
                "redirect_findings": [
                    {
                        "source_url": "https://secure-chase-alerts.com/login/verify",
                        "url": "https://secure-chase-alerts.com/login/verify",
                        "hops": 2,
                        "final_domain": "secure-chase-alerts.com",
                        "risk_score": 15,
                        "is_esp_tracking": False,
                        "suspicious_landing": True,
                    }
                ],
                "suspicious_endpoints": [
                    {
                        "url": "https://secure-chase-alerts.com/login/verify",
                        "keywords": ["login", "verify"],
                        "risk_score": 10,
                    }
                ],
                "esp_findings": [],
                "risk_score": 25,
            },
        )

        self.assertGreaterEqual(result["risk_score"], 70)
        self.assertIn(result["verdict"], {"HIGH", "CRITICAL"})
        self.assertGreaterEqual(result["confidence"], 0.70)
        self.assertGreaterEqual(result["data_completeness"], 80)

    def test_esp_tracking_url_with_safe_context(self) -> None:
        auth_results = self._auth(
            spf="pass",
            dkim="pass",
            dmarc="pass",
            from_domain="newsletters.example.com",
            missing_received=False,
        )

        result = calculate_risk(
            auth_results=auth_results,
            url_reports=[
                {
                    "url": "https://mailchi.mp/acme/spring-sale",
                    "malicious": 0,
                    "suspicious": 0,
                }
            ],
            hash_reports=[],
            otx_reports=[{"domain": "mailchi.mp", "pulse_count": 0}],
            url_intelligence={
                "shortener_findings": [],
                "redirect_findings": [
                    {
                        "source_url": "https://mailchi.mp/acme/spring-sale",
                        "url": "https://mailchi.mp/acme/spring-sale",
                        "hops": 1,
                        "final_domain": "www.example.com",
                        "risk_score": 0,
                        "is_esp_tracking": True,
                        "suspicious_landing": False,
                    }
                ],
                "suspicious_endpoints": [],
                "esp_findings": [
                    {
                        "url": "https://mailchi.mp/acme/spring-sale",
                        "provider": "Mailchimp",
                        "is_tracking": True,
                        "risk_adjustment": -8,
                        "final_domain": "www.example.com",
                        "suspicious_landing": False,
                    }
                ],
                "risk_score": 0,
            },
        )

        self.assertLessEqual(result["risk_score"], 20)
        self.assertEqual(result["verdict"], "LOW")
        self.assertGreaterEqual(result["data_completeness"], 90)
        self.assertLess(result["category_scores"]["ESP detection"], 0)

    def test_suspicious_redirect_mismatch_from_esp_tracking(self) -> None:
        auth_results = self._auth(
            spf="pass",
            dkim="pass",
            dmarc="pass",
            from_domain="chase.com",
            missing_received=False,
        )

        result = calculate_risk(
            auth_results=auth_results,
            url_reports=[
                {
                    "url": "https://dr.bluehornet.com/ct/999",
                    "malicious": 0,
                    "suspicious": 0,
                }
            ],
            hash_reports=[],
            otx_reports=[],
            brand_impersonation={
                "domain_impersonation": [],
                "display_name_spoofing": [],
                "body_brand_mentions": [
                    {
                        "brand": "chase",
                        "sender_domain": "chase.com",
                        "risk_score": 0,
                    }
                ],
            },
            url_intelligence={
                "shortener_findings": [],
                "redirect_findings": [
                    {
                        "source_url": "https://dr.bluehornet.com/ct/999",
                        "url": "https://dr.bluehornet.com/ct/999",
                        "hops": 2,
                        "final_domain": "secure-login-chase-alerts.com",
                        "risk_score": 12,
                        "is_esp_tracking": True,
                        "suspicious_landing": True,
                    }
                ],
                "suspicious_endpoints": [
                    {
                        "url": "https://secure-login-chase-alerts.com/verify/login",
                        "keywords": ["verify", "login"],
                        "risk_score": 10,
                    }
                ],
                "esp_findings": [
                    {
                        "url": "https://dr.bluehornet.com/ct/999",
                        "provider": "BlueHornet",
                        "is_tracking": True,
                        "risk_adjustment": -8,
                        "final_domain": "secure-login-chase-alerts.com",
                        "suspicious_landing": True,
                    }
                ],
                "risk_score": 12,
            },
        )

        self.assertGreaterEqual(result["risk_score"], 25)
        self.assertIn(result["verdict"], {"MEDIUM", "SUSPICIOUS", "HIGH"})
        self.assertNotEqual(result["verdict"], "LOW")


class TestPhishingPipelineIntegration(unittest.TestCase):
    """Integration tests that run the full phishing pipeline on raw RFC822 samples."""

    @classmethod
    def setUpClass(cls) -> None:
        """Initialize one shared pipeline and force deterministic no-key intel behavior."""
        from email_analysis.pipeline import PhishingPipeline
        from threat_intel import alienvault_checker, ip_reputation, passive_dns, virustotal_checker

        cls._orig_keys = {
            "vt": virustotal_checker.VIRUSTOTAL_API_KEY,
            "otx": alienvault_checker.ALIENVAULT_OTX_API_KEY,
            "abuse": ip_reputation.ABUSEIPDB_API_KEY,
            "st": passive_dns.SECURITYTRAILS_API_KEY,
        }

        # Keep integration tests deterministic and offline-friendly.
        virustotal_checker.VIRUSTOTAL_API_KEY = ""
        alienvault_checker.ALIENVAULT_OTX_API_KEY = ""
        ip_reputation.ABUSEIPDB_API_KEY = ""
        passive_dns.SECURITYTRAILS_API_KEY = ""

        cls.pipeline = PhishingPipeline()

    @classmethod
    def tearDownClass(cls) -> None:
        """Restore API key module constants after integration tests complete."""
        from threat_intel import alienvault_checker, ip_reputation, passive_dns, virustotal_checker

        virustotal_checker.VIRUSTOTAL_API_KEY = cls._orig_keys["vt"]
        alienvault_checker.ALIENVAULT_OTX_API_KEY = cls._orig_keys["otx"]
        ip_reputation.ABUSEIPDB_API_KEY = cls._orig_keys["abuse"]
        passive_dns.SECURITYTRAILS_API_KEY = cls._orig_keys["st"]

    def test_bluehornet_chase_false_positive(self) -> None:
        """
        Verify BlueHornet marketing-style traffic is suppressed as a false positive.

        This sample intentionally has low completeness (auth none + stripped Received)
        while still containing a Chase mention and urgency language. It should not
        escalate to CRITICAL and must carry BlueHornet ESP evidence.
        """
        raw_email = self._build_bluehornet_chase_email()
        result = self.pipeline.analyze_raw(raw_email)

        risk = result["risk"]
        confidence_pct = float(risk.get("confidence", 0.0)) * 100
        score = int(risk.get("score", 0))
        verdict = str(risk.get("verdict", ""))

        providers = [
            str(f.get("provider", ""))
            for f in result.get("url_intelligence", {}).get("esp_findings", [])
        ]

        self.assertNotEqual(verdict, "CRITICAL")
        self.assertIn(verdict, ["LOW", "INCONCLUSIVE", "INFORMATIONAL"])
        self.assertTrue(any(p.lower() == "bluehornet" for p in providers))
        self.assertLess(confidence_pct, 60)
        self.assertLess(score, 80)

        # Ensure suppression signals are present and applied.
        self.assertIn("category_scores", risk)
        self.assertIn("ESP detection", risk["category_scores"])
        self.assertLess(risk["category_scores"]["ESP detection"], 0)
        self.assertGreater(len(result.get("url_intelligence", {}).get("esp_findings", [])), 0)

    def test_spearphishing_true_positive(self) -> None:
        """
        Verify a high-confidence spearphishing pattern is escalated to CRITICAL.

        The sample includes full headers, failing auth, PayPal impersonation,
        suspicious credential-harvesting HTML, and an unknown login destination.
        """
        raw_email = self._build_spearphishing_email()
        result = self.pipeline.analyze_raw(raw_email)

        risk = result["risk"]
        confidence_pct = float(risk.get("confidence", 0.0)) * 100
        score = int(risk.get("score", 0))

        redirect_findings = result.get("url_intelligence", {}).get("redirect_findings", [])
        self.assertTrue(any(
            "secure-notice-paypal-login-verify.com" in (
                str(f.get("final_domain", "")) or str(f.get("url", ""))
            )
            for f in redirect_findings
        ))

        # If WHOIS age is available in this environment, enforce the expected young-domain signal.
        whois_results = result.get("domain_intelligence", {}).get("whois_results", [])
        target_domain = "secure-notice-paypal-login-verify.com"
        target_whois = next((w for w in whois_results if w.get("domain") == target_domain), None)
        if target_whois and target_whois.get("age_days") is not None:
            self.assertLess(int(target_whois["age_days"]), 30)

        self.assertEqual(risk.get("verdict"), "CRITICAL")
        self.assertGreater(confidence_pct, 75)
        self.assertGreaterEqual(score, 80)

    def test_ambiguous_unknown_esp(self) -> None:
        """
        Verify unknown-ESP ambiguous traffic is not downgraded to LOW/INCONCLUSIVE.

        Scenario: full headers, SPF none + DKIM pass, brand mention + urgency,
        and no whitelist ESP match. Expected outcome is elevated suspicion.
        """
        raw_email = self._build_ambiguous_unknown_esp_email()
        result = self.pipeline.analyze_raw(raw_email)

        risk = result["risk"]
        verdict = str(risk.get("verdict", ""))

        self.assertIn(verdict, ["HIGH", "SUSPICIOUS"])
        self.assertNotIn(verdict, ["INCONCLUSIVE", "LOW"])

        providers = [
            str(f.get("provider", ""))
            for f in result.get("url_intelligence", {}).get("esp_findings", [])
        ]
        self.assertFalse(any(p for p in providers))

    @staticmethod
    def _build_bluehornet_chase_email() -> str:
        return "\n".join([
            "From: Weekly Rewards <offers@mailer.bluehornet.com>",
            "To: user@example.com",
            "Subject: Chase rewards update",
            "Date: Fri, 20 Mar 2026 10:12:00 +0000",
            "Message-ID: <bluehornet-marketing-1@mailer.bluehornet.com>",
            "MIME-Version: 1.0",
            "Authentication-Results: mx.example.net; spf=none smtp.mailfrom=mailer.bluehornet.com; dkim=none; dmarc=none",
            "Content-Type: text/plain; charset=\"utf-8\"",
            "",
            "Hello,",
            "Chase cardmembers: this is your last chance for bonus rewards.",
            "Don't delay, this limited time promotion ends soon.",
            "http://dr.bluehornet.com/ct/1695126:1754535170:m:3:110926158:D299E7CA9CD982C5AFDE3E6BD4AFA968",
            "",
        ])

    @staticmethod
    def _build_spearphishing_email() -> str:
        return "\n".join([
            "From: PayPal Security Team <alerts@paypal-security-mailer.com>",
            "To: user@example.com",
            "Reply-To: support@paypal-helpdesk-center.com",
            "Return-Path: <bounce@transaction-alert-mailer.com>",
            "Subject: PayPal account restricted - immediate action required",
            "Date: Fri, 20 Mar 2026 11:20:00 +0000",
            "Message-ID: <pp-urgent-9931@mailer-gateway-untrusted.net>",
            "Received: from smtp-gateway.targetmail.net (smtp-gateway.targetmail.net [198.51.100.42]) by mx.enterprise.org with ESMTPS id abc123; Fri, 20 Mar 2026 11:20:01 +0000",
            "Received: from mx.secure-notice-paypal-login-verify.com (mx.secure-notice-paypal-login-verify.com [203.0.113.50]) by smtp-gateway.targetmail.net with ESMTP id def456; Fri, 20 Mar 2026 11:19:59 +0000",
            "Authentication-Results: mx.enterprise.org; spf=fail smtp.mailfrom=paypal-security-mailer.com; dkim=fail header.d=paypal-security-mailer.com; dmarc=fail header.from=paypal-security-mailer.com",
            "MIME-Version: 1.0",
            "Content-Type: text/html; charset=\"utf-8\"",
            "",
            "<html><body>",
            "<p>PayPal account will be suspended within 24 hours.</p>",
            "<p>This is your last warning. Do not delay and verify immediately.</p>",
            "<p><a href=\"http://secure-notice-paypal-login-verify.com/login/verify/account\">Verify account</a></p>",
            "<form method=\"POST\" action=\"http://secure-notice-paypal-login-verify.com/session/validate\">",
            "<input type=\"text\" name=\"email\" />",
            "<input type=\"password\" name=\"password\" />",
            "<input type=\"hidden\" name=\"token\" value=\"1\" />",
            "<button type=\"submit\">Sign in</button>",
            "</form>",
            "</body></html>",
            "",
        ])

    @staticmethod
    def _build_ambiguous_unknown_esp_email() -> str:
        return "\n".join([
            "From: Chase Notification Desk <notify@chase-alerts-mailer.net>",
            "To: user@example.com",
            "Subject: Chase digital notice",
            "Date: Fri, 20 Mar 2026 13:05:00 +0000",
            "Message-ID: <ambiguous-unknown-esp-2026@chase-alerts-mailer.net>",
            "Received: from relay.mail-route.example (relay.mail-route.example [198.51.100.12]) by mx.enterprise.org with ESMTPS id ghi789; Fri, 20 Mar 2026 13:05:02 +0000",
            "Received: from sender.chase-alerts-mailer.net (sender.chase-alerts-mailer.net [198.51.100.55]) by relay.mail-route.example with ESMTP id jkl012; Fri, 20 Mar 2026 13:04:58 +0000",
            "Authentication-Results: mx.enterprise.org; spf=none smtp.mailfrom=chase-alerts-mailer.net; dkim=pass header.d=chase-alerts-mailer.net; dmarc=pass header.from=chase-alerts-mailer.net",
            "MIME-Version: 1.0",
            "Content-Type: text/plain; charset=\"utf-8\"",
            "",
            "Chase security message: immediate action may be required.",
            "Limited time notice, last chance to confirm your account details.",
            "http://chase-alerts-mailer.net/click/confirm/login/verify",
            "",
        ])


if __name__ == "__main__":
    unittest.main()
