"""HTTP fetching with SSRF-resistant DNS validation and address pinning."""

from __future__ import annotations

import ipaddress
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import SplitResult, urljoin, urlsplit, urlunsplit

from urllib3 import HTTPConnectionPool, HTTPSConnectionPool

from config.settings import (
    SAFE_HTTP_MAX_BYTES,
    SAFE_HTTP_MAX_REDIRECTS,
    SAFE_HTTP_TIMEOUT_SECONDS,
)


_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


@dataclass(frozen=True)
class SafeHTTPResponse:
    url: str
    status_code: int
    headers: dict[str, str]
    body: bytes
    history: tuple[str, ...]


class SafeHTTPError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _resolve_addresses(host: str, port: int) -> tuple[str, ...]:
    """Resolve a host once and return its unique stream-socket addresses."""
    resolved = socket.getaddrinfo(
        host,
        port,
        family=socket.AF_UNSPEC,
        type=socket.SOCK_STREAM,
    )
    addresses = (address[0] for *_metadata, address in resolved if isinstance(address[0], str))
    return tuple(dict.fromkeys(addresses))


def _validate_target(url: str) -> tuple[SplitResult, tuple[str, ...]]:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise SafeHTTPError("blocked_target", "Only HTTP(S) URLs are allowed")
    if parsed.username is not None or parsed.password is not None:
        raise SafeHTTPError("blocked_target", "URL credentials are not allowed")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise SafeHTTPError("invalid_url", "Invalid URL port") from exc
    addresses = _resolve_addresses(parsed.hostname, port)
    if not addresses or any(
        not ipaddress.ip_address(address).is_global for address in addresses
    ):
        raise SafeHTTPError("blocked_target", "Target address is not public")
    return parsed, addresses


def _open_pinned(
    method: str,
    parsed: SplitResult,
    ip: str,
    max_bytes: int,
) -> tuple[int, dict[str, str], bytes]:
    """Open one request directly to a previously validated IP address."""
    hostname = parsed.hostname
    if hostname is None:  # Defensive: callers normally pass a validated URL.
        raise SafeHTTPError("invalid_url", "URL hostname is missing")

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if parsed.scheme == "https":
        pool: HTTPConnectionPool = HTTPSConnectionPool(
            host=ip,
            port=port,
            timeout=SAFE_HTTP_TIMEOUT_SECONDS,
            ssl_context=ssl.create_default_context(),
            server_hostname=hostname,
            assert_hostname=hostname,
        )
    else:
        pool = HTTPConnectionPool(
            host=ip,
            port=port,
            timeout=SAFE_HTTP_TIMEOUT_SECONDS,
        )

    request_target = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    headers = {
        "Host": parsed.netloc,
        "User-Agent": "Phishing-Triage-SafeFetcher/1.0",
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.1",
    }

    try:
        response = pool.urlopen(
            method,
            request_target,
            headers=headers,
            redirect=False,
            retries=False,
            preload_content=False,
            decode_content=True,
        )
        try:
            body = response.read(max_bytes + 1, decode_content=True)
            if len(body) > max_bytes:
                raise SafeHTTPError("too_large", "Response body exceeds size limit")
            response_headers = {
                str(name).lower(): str(value) for name, value in response.headers.items()
            }
            return int(response.status), response_headers, body
        finally:
            response.close()
    finally:
        pool.close()


def fetch_url(
    url: str,
    *,
    method: str = "GET",
    max_bytes: int = SAFE_HTTP_MAX_BYTES,
) -> SafeHTTPResponse:
    """Fetch an HTTP(S) URL while validating and pinning every redirect hop."""
    current_url = url
    history: list[str] = []

    while True:
        parsed, addresses = _validate_target(current_url)
        status_code, headers, body = _open_pinned(
            method,
            parsed,
            addresses[0],
            max_bytes,
        )
        location = headers.get("location")
        if status_code not in _REDIRECT_STATUSES or not location:
            return SafeHTTPResponse(
                url=current_url,
                status_code=status_code,
                headers=headers,
                body=body,
                history=tuple(history),
            )

        if len(history) >= SAFE_HTTP_MAX_REDIRECTS:
            raise SafeHTTPError("too_many_redirects", "Too many redirects")
        history.append(current_url)
        current_url = urljoin(current_url, location)
