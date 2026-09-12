from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from email.message import EmailMessage
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import uuid

import pytest
import requests

from email_analysis import ai_classifier
from email_analysis.correlation import build_evidence_bundle
from email_analysis.observables import collect_observables
from email_analysis.pipeline import PhishingPipeline
from email_analysis.url_extractor import extract_urls
from output.jsonl import append_event, serialize_event
from output.siem import build_siem_event
from scoring.risk_scoring import calculate_risk

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def no_network(monkeypatch):
    calls = []

    def deny(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("Intrinsic email analysis attempted network access")

    monkeypatch.setattr(socket, "getaddrinfo", deny)
    monkeypatch.setattr(socket.socket, "connect", deny)
    monkeypatch.setattr(requests.sessions.Session, "request", deny)
    monkeypatch.setattr(ai_classifier, "LOCAL_AI_ENABLED", True)
    monkeypatch.setattr(ai_classifier, "AI_GROQ_FALLBACK", False)
    monkeypatch.setattr(ai_classifier, "OFFLINE_MODE", False)
    monkeypatch.setattr(ai_classifier, "classify_email_local", lambda *_: {
        "verdict": "phishing", "confidence": 0.98, "error": None,
        "provider": "local", "model": "jhu-clsp/mmBERT-small",
    })
    yield calls
    assert calls == []


def _assert_wazuh_types(value):
    if isinstance(value, list):
        assert all(isinstance(item, (str, int, float, bool)) or item is None for item in value)
    elif isinstance(value, dict):
        for item in value.values():
            _assert_wazuh_types(item)


def test_pipeline_emits_one_event_per_email_without_network(no_network, tmp_path):
    log = tmp_path / "events.jsonl"
    pipeline = PhishingPipeline(upload_dir=str(tmp_path / "uploads"), events_jsonl_path=str(log))
    first = pipeline.analyze_file(str(ROOT / "samples/phishing_test_sample.eml"))
    second = pipeline.analyze_file(str(ROOT / "samples/phishing_test_sample.eml"))
    events = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
    assert len(events) == 2
    assert events == [first["siem_event"], second["siem_event"]]
    assert events[0]["event_id"] != events[1]["event_id"]
    for result, event in zip((first, second), events):
        assert uuid.UUID(event["event_id"]).version == 4
        assert result["event_output"]["status"] == "WRITTEN"
        assert event["risk"]["initial_verdict"] == "PHISHING"
        assert event["risk"]["base_score"] >= 60
        assert event["ai"]["model"] == "jhu-clsp/mmBERT-small"
        assert event["ai"]["role"] == "supporting_evidence"
        assert event["url_analysis"]["deceptive_link"] is True
        assert {"sender_auth_alignment_failure", "credential_lure_deceptive_link", "multi_signal_credential_phishing"} <= set(event["correlated_findings"])
        assert all(item["environment"] == "TEST" and item["exportable"] is False for item in event["observable_metadata"].values())
        assert "final_score" not in serialize_event(result)
        assert not {"whois", "dns", "virustotal", "otx", "redirect"} & event["evidence_coverage"]["sources"].keys()
        assert "DOMAIN INTELLIGENCE" not in result["report"]
        assert "THREAT INTELLIGENCE" not in result["report"]
        assert "RECOMMENDED SOC ACTIONS" not in result["report"]
        _assert_wazuh_types(event)


def test_public_shorteners_and_public_origin_never_trigger_enrichment(no_network, tmp_path):
    raw = "From: sender@public-mail.com\nTo: user@public-mail.com\nReceived: from relay.public-mail.com ([8.8.8.8]) by mx.public-mail.com\n\nhttps://bit.ly/abc https://public-mail.com/login"
    result = PhishingPipeline(upload_dir=str(tmp_path), events_jsonl_path="").analyze_raw(raw)
    assert result["url_intelligence"]["shortener_findings"]
    assert "8.8.8.8" in result["siem_event"]["observables"]["ips"]
    assert "redirect_findings" not in result["url_intelligence"]
    assert "whois_results" not in result["domain_intelligence"]


@pytest.mark.parametrize("displayed", ["https://safe.test/account", "https://evil.test/account", "https://sub.evil.test/login"])
def test_displayed_destination_mismatch_includes_path_and_subdomain(displayed):
    urls = extract_urls(body_html=f'<a href="https://evil.test/login">{displayed}</a>')
    assert next(item for item in urls if item["url"] == "https://evil.test/login")["deceptive_link"] is True


def test_ioc_export_preserves_url_semantics_and_ipv6():
    url = "https://trusted.test@[2001:db8::7]:444/a%2Fb;param?token=x%2By&x=1&x=2#login"
    records = collect_observables(urls=extract_urls(url), attachments=[], url_intelligence=None)
    record = next(item for item in records if item["type"] == "url")
    assert record["value"] == url
    assert record["environment"] == "TEST"
    assert record["exportable"] is False
    assert any(item["type"] == "ip" and item["value"] == "2001:db8::7" for item in records)


def test_observables_include_headers_body_qr_and_attachment_hashes(no_network, monkeypatch, tmp_path):
    from email_analysis import qr_code_analyzer

    monkeypatch.setattr(qr_code_analyzer, "scan_attachments_for_qr", lambda _: [{
        "filename": "invoice.bin", "qr_type": "QRCODE", "qr_data": "https://qr.test/login",
        "url": "https://qr.test/login", "domain": "qr.test", "risk_score": 15,
    }])
    message = EmailMessage()
    for name, value in {
        "From": "sender@sender.test", "To": "recipient@recipient.test",
        "Reply-To": "support@reply.test", "Return-Path": "bounce@return.test",
        "Message-ID": "<id@message.test>", "Subject": "Attachment evidence",
        "Received": "from relay.test ([203.0.113.8]) by mx.test",
    }.items():
        message[name] = value
    message.set_content("Contact help@body.test. IP 192.0.2.6 and IPv6 2001:db8::2")
    message.add_attachment(b"inert payload", maintype="application", subtype="octet-stream", filename="invoice.bin")
    result = PhishingPipeline(upload_dir=str(tmp_path), events_jsonl_path="").analyze_raw(message.as_string())
    values = result["siem_event"]["observables"]
    assert {"sender.test", "reply.test", "return.test", "message.test", "body.test", "qr.test"} <= set(values["domains"])
    assert {"sender@sender.test", "support@reply.test", "bounce@return.test", "help@body.test"} <= set(values["emails"])
    assert {"203.0.113.8", "192.0.2.6", "2001:db8::2"} <= set(values["ips"])
    assert "https://qr.test/login" in values["urls"]
    assert values["hashes"] == [hashlib.sha256(b"inert payload").hexdigest()]
    assert values["filenames"] == ["invoice.bin"]
    assert not list(tmp_path.glob("*.bin"))


def test_all_available_hash_algorithms_are_exported_without_lookup():
    records = collect_observables(urls=[], attachments=[{"filename": "a.bin", "md5": "a" * 32, "sha1": "b" * 40, "sha256": "c" * 64}], url_intelligence=None)
    assert {item["type"] for item in records} == {"filename", "md5", "sha1", "sha256"}


def test_no_silent_fifty_observable_cap():
    records = collect_observables(urls=extract_urls(" ".join(f"https://site-{n}.test/login" for n in range(50))), attachments=[{"filename": "a.bin", "sha256": "a" * 64}], url_intelligence=None)
    assert len(records) == 102


def test_legacy_external_evidence_has_no_score_verdict_or_coverage_effect():
    auth = {check: {"result": "pass"} for check in ("spf", "dkim", "dmarc")}
    baseline = calculate_risk(auth)
    enriched = calculate_risk(auth, [{"malicious": 50}], [{"malicious": 50}], [{"pulse_count": 50}], ip_reputation=[{"risk_score": 90}], passive_dns=[{"risk_score": 90}], domain_intelligence={"whois_results": [{"age_days": 1, "risk_score": 90}], "dns_results": [{"risk_score": 90}]}, landing_pages=[{"risk_score": 90, "password_fields": 3}])
    assert baseline == enriched
    bundle = build_evidence_bundle(auth_results=auth, urls=[], credential_harvesting=None, brand_impersonation=None, language_analysis=None, attachment_risks=[], domain_intelligence=None, vt_url_reports=[{"state": "malicious", "malicious": 50}])
    assert not any(item["category"] == "threat_intel" for item in bundle["evidence"])


def test_ai_and_repeated_credential_keywords_cannot_decide_phishing(no_network, tmp_path):
    body = " ".join(f"https://service.test/login/verify/account/{n}" for n in range(40))
    result = PhishingPipeline(upload_dir=str(tmp_path), events_jsonl_path="").analyze_raw("Subject: Reference links\n\n" + body)
    assert result["risk"]["initial_verdict"] == "BENIGN"
    assert result["risk"]["base_score"] <= 12


def test_jsonl_write_failure_keeps_analysis_and_event_for_retry(no_network, tmp_path):
    blocked = tmp_path / "not-a-directory"
    blocked.write_text("x", encoding="utf-8")
    result = PhishingPipeline(upload_dir=str(tmp_path / "uploads"), events_jsonl_path=str(blocked / "events.jsonl")).analyze_file(str(ROOT / "samples/phishing-en.eml"))
    assert result["event_output"]["status"] == "FAILED"
    assert result["siem_event"]["event_id"]
    assert result["report"]


def test_event_round_trip_is_deterministic_and_has_no_emoji(no_network, tmp_path):
    result = PhishingPipeline(upload_dir=str(tmp_path), events_jsonl_path="").analyze_raw("Subject: Urgent 🔥\n\nPlease read")
    event = result["siem_event"]
    assert serialize_event(event) == serialize_event(build_siem_event(result))
    assert "🔥" not in json.dumps(event, ensure_ascii=False)
    assert json.loads(serialize_event(event)) == event
    _assert_wazuh_types(event)


def test_jsonl_parallel_threads_and_processes_do_not_interleave(tmp_path):
    path = tmp_path / "events.jsonl"
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda i: append_event({"id": f"thread-{i}", "text": "x\ny" * 1000}, path), range(20)))
    program = "from output.jsonl import append_event; import sys; [append_event({'id': sys.argv[2] + '-' + str(i), 'text': 'x' * 10000}, sys.argv[1]) for i in range(10)]"
    children = [subprocess.Popen([sys.executable, "-c", program, str(path), str(i)], cwd=ROOT, env=os.environ.copy()) for i in range(4)]
    for child in children:
        assert child.wait(timeout=30) == 0
    events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert len(events) == len({event["id"] for event in events}) == 60
