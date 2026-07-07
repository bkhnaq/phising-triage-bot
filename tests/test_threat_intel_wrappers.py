from urllib.parse import quote

import requests


class FakeResponse:
    def __init__(self, payload=None, status_code: int = 200):
        self._payload = payload if payload is not None else {}
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code} error")

    def json(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


def test_alienvault_url_lookup_encodes_and_caches(monkeypatch) -> None:
    from threat_intel import alienvault_checker as otx

    otx._URL_CACHE.clear()
    monkeypatch.setattr(otx, "ALIENVAULT_OTX_API_KEY", "otx-key")
    monkeypatch.setattr(otx, "OFFLINE_MODE", False)

    calls: list[str] = []

    def fake_get(url, **kwargs):
        calls.append(url)
        return FakeResponse(
            {
                "pulse_info": {
                    "count": 2,
                    "pulses": [{"name": "Pulse A"}, {"name": "Pulse B"}],
                }
            }
        )

    monkeypatch.setattr(otx.requests, "get", fake_get)

    target = "https://example.com/login?a=1&b=2"
    first = otx.check_url(target)
    first["pulses"].append("caller mutation")
    second = otx.check_url(target)

    assert calls == [f"{otx._BASE_URL}/indicators/url/{quote(target, safe='')}/general"]
    assert second["pulse_count"] == 2
    assert second["pulses"] == ["Pulse A", "Pulse B"]


def test_alienvault_malformed_json_returns_error(monkeypatch) -> None:
    from threat_intel import alienvault_checker as otx

    otx._DOMAIN_CACHE.clear()
    monkeypatch.setattr(otx, "ALIENVAULT_OTX_API_KEY", "otx-key")
    monkeypatch.setattr(otx, "OFFLINE_MODE", False)
    monkeypatch.setattr(
        otx.requests,
        "get",
        lambda *args, **kwargs: FakeResponse(ValueError("bad json")),
    )

    result = otx.check_domain("example.com")

    assert result["pulse_count"] == 0
    assert "bad json" in result["error"]


def test_virustotal_url_404_submits_for_analysis(monkeypatch) -> None:
    from threat_intel import virustotal_checker as vt

    vt._URL_CACHE.clear()
    monkeypatch.setattr(vt, "VIRUSTOTAL_API_KEY", "vt-key")
    monkeypatch.setattr(vt, "OFFLINE_MODE", False)

    posts: list[str] = []

    def fake_get(*args, **kwargs):
        return FakeResponse(status_code=404)

    def fake_post(url, **kwargs):
        posts.append(url)
        return FakeResponse({"data": {"id": "analysis-id"}})

    monkeypatch.setattr(vt.requests, "get", fake_get)
    monkeypatch.setattr(vt.requests, "post", fake_post)

    result = vt.check_url("https://example.com")

    assert result["error"] == "submitted_for_analysis"
    assert posts == [f"{vt._BASE_URL}/urls"]


def test_virustotal_hash_timeout_returns_error(monkeypatch) -> None:
    from threat_intel import virustotal_checker as vt

    vt._HASH_CACHE.clear()
    monkeypatch.setattr(vt, "VIRUSTOTAL_API_KEY", "vt-key")
    monkeypatch.setattr(vt, "OFFLINE_MODE", False)

    def fake_get(*args, **kwargs):
        raise requests.Timeout("slow")

    monkeypatch.setattr(vt.requests, "get", fake_get)

    result = vt.check_file_hash("a" * 64)

    assert result["malicious"] == 0
    assert "slow" in result["error"]


def test_passive_dns_caches_securitytrails(monkeypatch) -> None:
    from threat_intel import passive_dns

    passive_dns._SECURITYTRAILS_CACHE.clear()
    monkeypatch.setattr(passive_dns, "SECURITYTRAILS_API_KEY", "st-key")
    monkeypatch.setattr(passive_dns, "OFFLINE_MODE", False)

    calls = 0

    def fake_get(*args, **kwargs):
        nonlocal calls
        calls += 1
        return FakeResponse(
            {
                "record_count": 1,
                "records": [{"hostname": "example.com"}],
            }
        )

    monkeypatch.setattr(passive_dns.requests, "get", fake_get)

    first = passive_dns._query_securitytrails("203.0.113.10")
    first["sample_domains"].append("mutated.example")
    second = passive_dns._query_securitytrails("203.0.113.10")

    assert calls == 1
    assert second["sample_domains"] == ["example.com"]


def test_abuseipdb_malformed_json_returns_error(monkeypatch) -> None:
    from threat_intel import ip_reputation

    ip_reputation._ABUSE_CACHE.clear()
    monkeypatch.setattr(ip_reputation, "ABUSEIPDB_API_KEY", "abuse-key")
    monkeypatch.setattr(ip_reputation, "OFFLINE_MODE", False)
    monkeypatch.setattr(
        ip_reputation.requests,
        "get",
        lambda *args, **kwargs: FakeResponse(ValueError("bad json")),
    )

    result = ip_reputation._check_abuseipdb("203.0.113.10")

    assert result["abuse_score"] == 0
    assert "bad json" in result["error"]
