from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit

import pytest
import requests

from email_analysis import safe_http
from email_analysis.safe_http import SafeHTTPResponse

PUBLIC_IP = "93.184.216.34"


def test_landing_page_uses_safe_fetch(monkeypatch) -> None:
    from email_analysis import landing_page_analyzer as landing

    calls: list[tuple[str, dict]] = []
    landing._CACHE.clear()
    monkeypatch.setattr(landing, "OFFLINE_MODE", False)
    monkeypatch.setattr(
        requests,
        "get",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("direct requests.get is forbidden")
        ),
    )
    monkeypatch.setattr(
        requests,
        "head",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("direct requests.head is forbidden")
        ),
    )

    def fake_fetch(url: str, **kwargs) -> SafeHTTPResponse:
        calls.append((url, kwargs))
        return SafeHTTPResponse(
            url=url,
            status_code=200,
            headers={"content-type": "text/html; charset=utf-8"},
            body=b"<title>Account Login</title>",
            history=(),
        )

    monkeypatch.setattr(landing, "fetch_url", fake_fetch, raising=False)

    assert landing.analyze_landing_page("https://public.test/")["state"] == (
        "suspicious"
    )
    assert calls == [
        (
            "https://public.test/",
            {"method": "GET", "max_bytes": safe_http.SAFE_HTTP_MAX_BYTES},
        )
    ]


def test_landing_page_decodes_declared_windows_1252_charset(monkeypatch) -> None:
    from email_analysis import landing_page_analyzer as landing

    landing._CACHE.clear()
    monkeypatch.setattr(landing, "OFFLINE_MODE", False)
    monkeypatch.setattr(
        landing,
        "fetch_url",
        lambda url, **_kwargs: SafeHTTPResponse(
            url=url,
            status_code=200,
            headers={"content-type": "text/html; charset=windows-1252"},
            body="<title>Café Account Login</title>".encode("windows-1252"),
            history=(),
        ),
    )

    result = landing.analyze_landing_page("https://public.test/windows-1252")

    assert result["title"] == "Café Account Login"
    assert result["state"] == "suspicious"


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "http://user:pass@example.com/",
        "http://127.0.0.1/admin",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
    ],
)
def test_fetch_url_blocks_unsafe_targets(monkeypatch, url: str) -> None:
    monkeypatch.setattr(
        safe_http,
        "_resolve_addresses",
        lambda _host, _port: ("127.0.0.1",),
    )
    with pytest.raises(safe_http.SafeHTTPError) as exc:
        safe_http.fetch_url(url)
    assert exc.value.code == "blocked_target"


def test_redirect_target_is_revalidated(monkeypatch) -> None:
    monkeypatch.setattr(
        safe_http,
        "_resolve_addresses",
        lambda host, _port: (PUBLIC_IP,) if host == "public.test" else ("127.0.0.1",),
    )
    monkeypatch.setattr(
        safe_http,
        "_open_pinned",
        lambda *_args, **_kwargs: (302, {"location": "http://internal.test/"}, b""),
    )
    with pytest.raises(safe_http.SafeHTTPError) as exc:
        safe_http.fetch_url("https://public.test/")
    assert exc.value.code == "blocked_target"


def test_connection_uses_only_validated_ip(monkeypatch) -> None:
    seen: list[str] = []
    monkeypatch.setattr(
        safe_http,
        "_resolve_addresses",
        lambda _host, _port: (PUBLIC_IP,),
    )

    def fake_open(_method, _parsed, ip, _max_bytes, **_kwargs):
        seen.append(ip)
        return 200, {"content-type": "text/plain"}, b"ok"

    monkeypatch.setattr(safe_http, "_open_pinned", fake_open)
    response = safe_http.fetch_url("https://public.test/")
    assert response.body == b"ok"
    assert seen == [PUBLIC_IP]


def test_mixed_public_and_private_dns_answers_are_blocked(monkeypatch) -> None:
    monkeypatch.setattr(
        safe_http,
        "_resolve_addresses",
        lambda _host, _port: (PUBLIC_IP, "10.0.0.8"),
    )
    with pytest.raises(safe_http.SafeHTTPError) as exc:
        safe_http.fetch_url("https://public.test/")
    assert exc.value.code == "blocked_target"


def test_malformed_port_is_rejected(monkeypatch) -> None:
    monkeypatch.setattr(
        safe_http,
        "_resolve_addresses",
        lambda _host, _port: (PUBLIC_IP,),
    )
    with pytest.raises(safe_http.SafeHTTPError) as exc:
        safe_http.fetch_url("https://public.test:not-a-port/")
    assert exc.value.code == "invalid_url"


def test_fetch_url_sanitizes_malformed_initial_url_without_resolving(
    monkeypatch,
) -> None:
    def unexpected_resolution(*_args, **_kwargs):
        pytest.fail("malformed URLs must be rejected before DNS resolution")

    monkeypatch.setattr(safe_http, "_resolve_addresses", unexpected_resolution)

    with pytest.raises(safe_http.SafeHTTPError) as exc:
        safe_http.fetch_url("http://[::1")

    assert exc.value.code == "invalid_url"
    assert str(exc.value) == "Invalid URL"


def test_fetch_url_sanitizes_idna_resolution_failure(monkeypatch) -> None:
    def invalid_idna(_host: str, _port: int) -> tuple[str, ...]:
        raise UnicodeError("idna detail must not reach callers")

    monkeypatch.setattr(safe_http, "_resolve_addresses", invalid_idna)

    with pytest.raises(safe_http.SafeHTTPError) as exc:
        safe_http.fetch_url("https://" + "a" * 64 + ".test/")

    assert exc.value.code == "dns_error"
    assert str(exc.value) == "Domain could not be resolved"


def test_fetch_url_sanitizes_malformed_redirect_target(monkeypatch) -> None:
    monkeypatch.setattr(
        safe_http,
        "_resolve_addresses",
        lambda _host, _port: (PUBLIC_IP,),
    )
    monkeypatch.setattr(
        safe_http,
        "_open_pinned",
        lambda *_args, **_kwargs: (302, {"location": "http://[::1"}, b""),
    )

    with pytest.raises(safe_http.SafeHTTPError) as exc:
        safe_http.fetch_url("https://public.test/")

    assert exc.value.code == "invalid_url"
    assert str(exc.value) == "Invalid URL"


def test_fetch_rejects_max_bytes_above_hard_ceiling_before_io(monkeypatch) -> None:
    def unexpected_io(*_args, **_kwargs):
        pytest.fail("oversized max_bytes reached an I/O boundary")

    monkeypatch.setattr(safe_http, "_resolve_addresses", unexpected_io)
    monkeypatch.setattr(safe_http, "_open_pinned", unexpected_io)

    with pytest.raises(safe_http.SafeHTTPError) as exc:
        safe_http.fetch_url("https://public.test/", max_bytes=80_001)
    assert exc.value.code == "invalid_limit"


def test_ten_redirects_are_allowed(monkeypatch) -> None:
    calls = 0
    monkeypatch.setattr(
        safe_http,
        "_resolve_addresses",
        lambda _host, _port: (PUBLIC_IP,),
    )

    def fake_open(_method, _parsed, _ip, _max_bytes, **_kwargs):
        nonlocal calls
        calls += 1
        if calls <= 10:
            return 302, {"location": f"/hop/{calls}"}, b""
        return 200, {"content-type": "text/plain"}, b"ok"

    monkeypatch.setattr(safe_http, "_open_pinned", fake_open)
    response = safe_http.fetch_url("https://public.test/")
    assert response.url == "https://public.test/hop/10"
    assert response.body == b"ok"
    assert len(response.history) == 10
    assert calls == 11


def test_eleventh_redirect_is_rejected(monkeypatch) -> None:
    calls = 0
    monkeypatch.setattr(
        safe_http,
        "_resolve_addresses",
        lambda _host, _port: (PUBLIC_IP,),
    )

    def fake_open(_method, _parsed, _ip, _max_bytes, **_kwargs):
        nonlocal calls
        calls += 1
        return 302, {"location": f"/hop/{calls}"}, b""

    monkeypatch.setattr(safe_http, "_open_pinned", fake_open)
    with pytest.raises(safe_http.SafeHTTPError) as exc:
        safe_http.fetch_url("https://public.test/")
    assert exc.value.code == "too_many_redirects"
    assert calls == 11


def test_open_pinned_rejects_80001_decoded_bytes_and_closes_transport(
    monkeypatch,
) -> None:
    seen: dict[str, Any] = {}

    class FakeResponse:
        status = 200
        headers = {"content-type": "text/plain"}

        def read(self, amount: int, *, decode_content: bool) -> bytes:
            seen.setdefault("reads", []).append((amount, decode_content))
            return b"x" * amount

        def close(self) -> None:
            seen["response_closed"] = True

    class FakePool:
        def __init__(self, host: str, **kwargs: Any) -> None:
            seen["pool"] = (host, kwargs)

        def urlopen(self, method: str, target: str, **kwargs: Any) -> FakeResponse:
            seen["request"] = (method, target, kwargs)
            return FakeResponse()

        def close(self) -> None:
            seen["pool_closed"] = True

    monkeypatch.setattr(safe_http, "HTTPConnectionPool", FakePool)
    with pytest.raises(safe_http.SafeHTTPError) as exc:
        safe_http._open_pinned(
            "GET", urlsplit("http://public.test/path"), PUBLIC_IP, 80_000
        )
    assert exc.value.code == "too_large"
    assert sum(amount for amount, _decoded in seen["reads"]) == 80_001
    assert all(decoded is True for _amount, decoded in seen["reads"])
    assert seen["response_closed"] is True
    assert seen["pool_closed"] is True


def test_fetch_url_uses_one_monotonic_deadline_across_redirects(monkeypatch) -> None:
    clock = [0.0]
    resolution_timeouts: list[float] = []
    connection_timeouts: list[float] = []
    calls = 0

    monkeypatch.setattr(safe_http, "_monotonic", lambda: clock[0])

    def resolve(_host: str, _port: int, timeout_seconds: float) -> tuple[str, ...]:
        resolution_timeouts.append(timeout_seconds)
        clock[0] += 1.0
        return (PUBLIC_IP,)

    def open_pinned(
        _method: str,
        _parsed: Any,
        _ip: str,
        _max_bytes: int,
        *,
        timeout_seconds: float,
        deadline: float,
    ) -> tuple[int, dict[str, str], bytes]:
        nonlocal calls
        assert deadline == 6.0
        connection_timeouts.append(timeout_seconds)
        calls += 1
        clock[0] += 2.0
        return 302, {"location": f"/hop-{calls}"}, b""

    monkeypatch.setattr(safe_http, "_resolve_addresses_with_timeout", resolve)
    monkeypatch.setattr(safe_http, "_open_pinned", open_pinned)

    with pytest.raises(safe_http.SafeHTTPError) as exc:
        safe_http.fetch_url("https://public.test/")

    assert exc.value.code == "timeout"
    assert resolution_timeouts == [6.0, 3.0]
    assert connection_timeouts == [5.0, 2.0]
    assert calls == 2


def test_open_pinned_refreshes_read_timeout_until_total_deadline(monkeypatch) -> None:
    clock = [0.0]
    seen: list[float] = []

    class FakeSocket:
        timeout = 0.0

        def settimeout(self, timeout_seconds: float) -> None:
            self.timeout = timeout_seconds
            seen.append(timeout_seconds)

    class FakeResponse:
        status = 200
        headers = {"content-type": "text/plain"}

        def __init__(self) -> None:
            self.socket = FakeSocket()
            self.connection = SimpleNamespace(sock=self.socket)

        def read(self, _amount: int, *, decode_content: bool) -> bytes:
            assert decode_content is True
            simulated_chunk_delay = 2.5
            if simulated_chunk_delay > self.socket.timeout:
                clock[0] += self.socket.timeout
                raise TimeoutError("slow body")
            clock[0] += simulated_chunk_delay
            return b"x"

        def close(self) -> None:
            pass

    class FakePool:
        def __init__(self, host: str, **_kwargs: Any) -> None:
            pass

        def urlopen(self, *_args: Any, **_kwargs: Any) -> FakeResponse:
            return FakeResponse()

        def close(self) -> None:
            pass

    monkeypatch.setattr(safe_http, "_monotonic", lambda: clock[0])
    monkeypatch.setattr(safe_http, "HTTPConnectionPool", FakePool)

    with pytest.raises(safe_http.SafeHTTPError) as exc:
        safe_http._open_pinned(
            "GET",
            urlsplit("http://public.test/"),
            PUBLIC_IP,
            80_000,
            timeout_seconds=6.0,
            deadline=6.0,
        )

    assert exc.value.code == "timeout"
    assert clock[0] == 6.0
    assert seen == [6.0, 3.5, 1.0]


def test_https_pool_preserves_hostname_and_sends_only_relative_target(
    monkeypatch,
) -> None:
    seen: dict[str, Any] = {}
    ssl_context = object()

    class FakeResponse:
        status = 200
        headers = {"content-type": "text/plain"}

        def __init__(self) -> None:
            self.reads = 0

        def read(self, amount: int, *, decode_content: bool) -> bytes:
            seen["read"] = (amount, decode_content)
            self.reads += 1
            return b"ok" if self.reads == 1 else b""

        def close(self) -> None:
            seen["response_closed"] = True

    class FakePool:
        def __init__(self, host: str, **kwargs: Any) -> None:
            seen["pool"] = (host, kwargs)

        def urlopen(self, method: str, target: str, **kwargs: Any) -> FakeResponse:
            seen["request"] = (method, target, kwargs)
            return FakeResponse()

        def close(self) -> None:
            seen["pool_closed"] = True

    monkeypatch.setattr(safe_http, "HTTPSConnectionPool", FakePool)
    monkeypatch.setattr(safe_http.ssl, "create_default_context", lambda: ssl_context)

    status, headers, body = safe_http._open_pinned(
        "GET",
        urlsplit("https://Public.Test:8443/a/path?q=1#fragment"),
        PUBLIC_IP,
        80_000,
    )

    assert (status, headers, body) == (200, {"content-type": "text/plain"}, b"ok")
    pool_host, pool_options = seen["pool"]
    assert pool_host == PUBLIC_IP
    assert pool_options["port"] == 8443
    assert pool_options["server_hostname"] == "public.test"
    assert pool_options["assert_hostname"] == "public.test"
    assert pool_options["ssl_context"] is ssl_context
    method, target, request_options = seen["request"]
    assert (method, target) == ("GET", "/a/path?q=1")
    assert request_options["headers"] == {
        "Host": "Public.Test:8443",
        "User-Agent": "Phishing-Triage-SafeFetcher/1.0",
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.1",
    }
    assert request_options["redirect"] is False
    assert request_options["retries"] is False
    assert request_options["preload_content"] is False
    assert request_options["decode_content"] is True
    assert seen["response_closed"] is True
    assert seen["pool_closed"] is True
