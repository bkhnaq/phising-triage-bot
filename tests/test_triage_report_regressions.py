from types import SimpleNamespace

from email_analysis import domain_intelligence, url_intelligence
from email_analysis.brand_impersonation import BrandDetector
from email_analysis.correlation import build_evidence_bundle
from email_analysis.email_parser import parse_eml_file
from email_analysis.header_analyzer import analyze_headers
from email_analysis.url_extractor import extract_urls
from report.report_generator import generate_report
from scoring.risk_scoring import calculate_risk


def test_missing_auth_headers_are_unknown_not_none() -> None:
    result = analyze_headers([("From", "sender@example.test")])

    assert result["spf"]["result"] == "unknown"
    assert result["dkim"]["result"] == "unknown"
    assert result["dmarc"]["result"] == "unknown"
    assert "insufficient" in result["spf"]["details"]


def test_sender_identity_mismatch_requires_url_and_contact_domain() -> None:
    urls = extract_urls("Visit https://netbadge.virginia.edu/reactivate")
    body = (
        "Reactivate your account with the University Help Desk. "
        "Contact 4help@virginia.edu. The University of Virginia"
    )

    result = BrandDetector().analyze(
        urls,
        from_header="alerts@srv98.main-hosting.eu",
        body_text=body,
    )

    finding = result["sender_identity_mismatch"][0]
    assert finding["sender_domain"] == "srv98.main-hosting.eu"
    assert finding["expected_domain"] == "virginia.edu"
    assert finding["risk_score"] == 20


def test_deceptive_html_anchor_compares_displayed_url_with_href(monkeypatch) -> None:
    monkeypatch.setattr(url_intelligence, "OFFLINE_MODE", True)
    urls = extract_urls(
        body_html=(
            '<a href="https://collector.evil.test/login">'
            "https://netbadge.virginia.edu/myaccount/reactivation.html</a>"
        )
    )

    actual = next(item for item in urls if item["domain"] == "collector.evil.test")
    assert actual["link_target_comparison"] == "mismatch"
    assert actual["deceptive_hyperlink"] is True

    intel = url_intelligence.analyze_urls(urls)
    assert intel["deceptive_links"][0]["risk_score"] == 30


def test_report_does_not_mark_missing_relay_data_clean() -> None:
    auth = analyze_headers([("From", "sender@example.test")])
    report = generate_report(
        email_data={"from": "sender@example.test"},
        auth_results=auth,
        urls=extract_urls("https://example.test/account"),
        attachments=[],
        risk={
            "score": 0,
            "verdict": "INCONCLUSIVE",
            "confidence": 0.2,
            "data_completeness": 20,
        },
        vt_url_reports=[],
        vt_hash_reports=[],
        otx_reports=[],
        header_forensics={"relay_chain": [], "warnings": [], "error": None},
    )

    assert "SPF: UNKNOWN" in report
    assert "Relay analysis unavailable" in report
    assert "The message route cannot be validated" in report
    assert "No suspicious relay indicators" not in report
    assert "Displayed URL vs HREF: unavailable" in report


def test_dns_timeout_is_not_reported_as_record_absence(monkeypatch) -> None:
    class NoAnswer(Exception):
        pass

    class NXDOMAIN(Exception):
        pass

    class NoNameservers(Exception):
        pass

    class Timeout(Exception):
        pass

    class Resolver:
        timeout = 0
        lifetime = 0

        def resolve(self, _domain: str, record_type: str):
            if record_type == "MX":
                raise Timeout
            if record_type == "TXT":
                raise NoAnswer
            return ["192.0.2.10"] if record_type == "A" else []

    fake_resolver = SimpleNamespace(
        Resolver=Resolver,
        NoAnswer=NoAnswer,
        NXDOMAIN=NXDOMAIN,
        NoNameservers=NoNameservers,
        Timeout=Timeout,
    )
    domain_intelligence._DNS_CACHE.clear()
    monkeypatch.setattr(domain_intelligence, "OFFLINE_MODE", False)
    monkeypatch.setattr(domain_intelligence, "dns_resolver", fake_resolver)

    result = domain_intelligence.dns_lookup("example.test")

    assert result["record_status"]["MX"] == "unavailable"
    assert result["record_status"]["TXT"] == "absent"
    assert result["error"] is None


def test_scoring_reconciles_category_caps_without_negative_adjustments() -> None:
    result = calculate_risk(
        auth_results={
            "spf": {"result": "unknown"},
            "dkim": {"result": "unknown"},
            "dmarc": {"result": "unknown"},
        },
        url_reports=[],
        hash_reports=[],
        otx_reports=[],
        heuristics={
            "suspicious_keywords": [
                {"keyword": "account", "risk_score": 15, "source": "url"}
            ]
        },
        language_analysis={
            "categories": {
                "urgency": {"risk_score": 3},
                "credential_harvesting": {"risk_score": 5},
                "authority": {"risk_score": 6},
            }
        },
        ai_verdict={"verdict": "phishing", "confidence": 1.0},
    )

    assert result["score"] == 28
    assert result["category_details"]["content/language"] == {
        "raw_subtotal": 12,
        "category_maximum": 15,
        "effective_contribution": 12,
        "suppressed_duplicate_weight": 0,
    }
    assert result["category_details"]["AI / ML"]["effective_contribution"] == 15
    assert (
        sum(
            detail["effective_contribution"]
            for detail in result["category_details"].values()
        )
        == result["score_reconciliation"]["raw_effective_total"]
    )
    assert result["score_reconciliation"]["final_score"] == result["score"]
    assert not any("Category cap applied" in item for item in result["breakdown"])


def test_legitimate_sender_does_not_trigger_identity_mismatch() -> None:
    urls = extract_urls("Visit https://netbadge.virginia.edu/reactivate")
    result = BrandDetector().analyze(
        urls,
        from_header="helpdesk@virginia.edu",
        recipient_header="student@virginia.edu",
        body_text="University of Virginia Help Desk account reactivation",
    )

    assert result["sender_identity_mismatch"] == []


def test_known_tracking_href_is_context_not_deceptive_risk(monkeypatch) -> None:
    monkeypatch.setattr(url_intelligence, "OFFLINE_MODE", True)
    urls = extract_urls(
        body_html=(
            '<a href="https://click.mailchimp.com/track/campaign">'
            "https://example.org/newsletter</a>"
        )
    )

    intel = url_intelligence.analyze_urls(urls)
    finding = intel["deceptive_links"][0]
    assert finding["state"] == "contextual"
    assert finding["risk_score"] == 0
    assert finding["requires_redirect_validation"] is True


def test_ai_is_supporting_evidence_and_cannot_create_high_risk_alone() -> None:
    result = calculate_risk(
        auth_results={
            "spf": {"result": "unknown"},
            "dkim": {"result": "unknown"},
            "dmarc": {"result": "unknown"},
        },
        url_reports=[],
        hash_reports=[],
        otx_reports=[],
        ai_verdict={"verdict": "phishing", "confidence": 1.0},
    )

    assert result["category_scores"]["AI / ML"] == 15
    assert result["score"] == 15
    assert result["verdict"] not in {"HIGH", "CRITICAL"}
    assert any(
        "limited independent evidence" in note.lower()
        for note in result["confidence_notes"]
    )


def test_mime_parser_preserves_plain_html_and_part_provenance(tmp_path) -> None:
    sample = tmp_path / "multipart.eml"
    sample.write_bytes(
        b"From: sender@example.test\r\n"
        b"To: analyst@example.test\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/alternative; boundary=demo\r\n\r\n"
        b"--demo\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
        b"Visible text\r\n"
        b"--demo\r\nContent-Type: text/html; charset=utf-8\r\n\r\n"
        b"<a href='https://evil.test'>https://example.test</a>\r\n"
        b"--demo--\r\n"
    )

    parsed = parse_eml_file(str(sample))

    assert "Visible text" in parsed["body_text"]
    assert "https://evil.test" in parsed["body_html"]
    assert {part["content_type"] for part in parsed["mime_parts"]} == {
        "text/plain",
        "text/html",
    }


def test_normalized_evidence_correlates_identity_and_credential_lure() -> None:
    bundle = build_evidence_bundle(
        auth_results={
            "spf": {"result": "unknown"},
            "dkim": {"result": "unknown"},
            "dmarc": {"result": "unknown"},
        },
        urls=[],
        vt_url_reports=[],
        vt_hash_reports=[],
        otx_reports=[],
        credential_harvesting=None,
        brand_impersonation={
            "sender_identity_mismatch": [
                {
                    "sender_domain": "mailer.example",
                    "risk_score": 20,
                    "detail": "Expected university.example",
                }
            ],
            "domain_impersonation": [],
        },
        language_analysis={
            "categories": {
                "account_verification": {
                    "risk_score": 5,
                    "description": "Account verification",
                    "matches": ["reactivate your account"],
                },
                "authority": {
                    "risk_score": 6,
                    "description": "Authority language",
                    "matches": ["help desk"],
                },
            }
        },
        attachment_risks=[],
        landing_pages=[],
        domain_intelligence=None,
    )

    correlation = bundle["correlations"][0]
    assert correlation["type"] == "organization_credential_phishing"
    assert correlation["risk_score"] == 15
    assert correlation["confidence"] == 0.90
    assert all(
        {
            "id",
            "name",
            "category",
            "source",
            "severity",
            "confidence",
            "risk_weight",
            "status",
            "evidence",
        }
        <= finding.keys()
        for finding in bundle["evidence"]
    )
