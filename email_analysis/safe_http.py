"""HTTP fetching with SSRF-resistant DNS validation and address pinning."""

from __future__ import annotations

import ipaddress
from queue import Full, Queue
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import SplitResult, urljoin, urlsplit, urlunsplit

from urllib3 import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import HTTPError, TimeoutError as Urllib3TimeoutError
from urllib3.util import Timeout

from config.settings import (
    SAFE_HTTP_MAX_BYTES,
    SAFE_HTTP_MAX_REDIRECTS,
    SAFE_HTTP_TIMEOUT_SECONDS,
)

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_SAFE_HTTP_HARD_MAX_BYTES = 80_000
_RESPONSE_READ_CHUNK_BYTES = 16 * 1024
_DNS_WORKER_COUNT = 2
_DNS_QUEUE_MAXSIZE = _DNS_WORKER_COUNT
_monotonic = time.monotonic


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


@dataclass
class _DNSResolution:
    host: str
    port: int
    done: threading.Event = field(default_factory=threading.Event)
    result: tuple[str, ...] | None = None
    error: Exception | None = None
    cancelled: bool = False


_dns_queue: Queue[_DNSResolution] = Queue(maxsize=_DNS_QUEUE_MAXSIZE)
_dns_workers_started = False
_dns_workers_lock = threading.Lock()


def _resolve_addresses(host: str, port: int) -> tuple[str, ...]:
    """Resolve a host once and return its unique stream-socket addresses."""
    resolved = socket.getaddrinfo(
        host,
        port,
        family=socket.AF_UNSPEC,
        type=socket.SOCK_STREAM,
    )
    addresses = (
        address[0] for *_metadata, address in resolved if isinstance(address[0], str)
    )
    return tuple(dict.fromkeys(addresses))


def _dns_worker() -> None:
    """Run bounded DNS jobs without letting a blocking resolver stall callers."""
    while True:
        resolution = _dns_queue.get()
        try:
            if resolution.cancelled:
                continue
            try:
                resolution.result = _resolve_addresses(resolution.host, resolution.port)
            except Exception as exc:  # Normalized at the caller-facing boundary.
                resolution.error = exc
        finally:
            resolution.done.set()
            _dns_queue.task_done()


def _start_dns_workers() -> None:
    """Start a fixed daemon DNS pool once, avoiding unbounded resolver threads."""
    global _dns_workers_started
    with _dns_workers_lock:
        if _dns_workers_started:
            return
        for index in range(_DNS_WORKER_COUNT):
            worker = threading.Thread(
                target=_dns_worker,
                name=f"safe-http-dns-{index}",
                daemon=True,
            )
            worker.start()
        _dns_workers_started = True


def _resolve_addresses_with_timeout(
    host: str,
    port: int,
    timeout_seconds: float,
) -> tuple[str, ...]:
    """Resolve through a bounded daemon pool and wait no longer than remaining time."""
    if timeout_seconds <= 0:
        raise SafeHTTPError("timeout", "Request deadline exceeded")

    _start_dns_workers()
    resolution = _DNSResolution(host=host, port=port)
    try:
        _dns_queue.put_nowait(resolution)
    except Full as exc:
        raise SafeHTTPError("timeout", "Request deadline exceeded") from exc

    if not resolution.done.wait(timeout_seconds):
        resolution.cancelled = True
        raise SafeHTTPError("timeout", "Request deadline exceeded")
    if resolution.error is not None:
        raise resolution.error
    return resolution.result or ()


def _remaining_seconds(deadline: float) -> float:
    remaining = deadline - _monotonic()
    if remaining <= 0:
        raise SafeHTTPError("timeout", "Request deadline exceeded")
    return remaining


def _validate_target(
    url: str,
    *,
    timeout_seconds: float,
) -> tuple[SplitResult, tuple[str, ...]]:
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        if parsed.scheme not in {"http", "https"} or not hostname:
            raise SafeHTTPError("blocked_target", "Only HTTP(S) URLs are allowed")
        if parsed.username is not None or parsed.password is not None:
            raise SafeHTTPError("blocked_target", "URL credentials are not allowed")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except SafeHTTPError:
        raise
    except (TypeError, UnicodeError, ValueError) as exc:
        raise SafeHTTPError("invalid_url", "Invalid URL") from exc

    try:
        addresses = _resolve_addresses_with_timeout(hostname, port, timeout_seconds)
        if not addresses or any(
            not ipaddress.ip_address(address).is_global for address in addresses
        ):
            raise SafeHTTPError("blocked_target", "Target address is not public")
    except SafeHTTPError:
        raise
    except (OSError, UnicodeError, ValueError) as exc:
        raise SafeHTTPError("dns_error", "Domain could not be resolved") from exc
    return parsed, addresses


def _open_pinned(
    method: str,
    parsed: SplitResult,
    ip: str,
    max_bytes: int,
    *,
    timeout_seconds: float | None = None,
    deadline: float | None = None,
) -> tuple[int, dict[str, str], bytes]:
    """Open one request directly to a previously validated IP address."""
    if timeout_seconds is None:
        timeout_seconds = float(SAFE_HTTP_TIMEOUT_SECONDS)
    if deadline is None:
        deadline = _monotonic() + timeout_seconds

    hostname = parsed.hostname
    if hostname is None:  # Defensive: callers normally pass a validated URL.
        raise SafeHTTPError("invalid_url", "URL hostname is missing")

    pool: HTTPConnectionPool | HTTPSConnectionPool | None = None
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        initial_timeout = min(timeout_seconds, _remaining_seconds(deadline))
        transport_timeout = Timeout(
            total=initial_timeout,
            connect=initial_timeout,
            read=initial_timeout,
        )
        if parsed.scheme == "https":
            pool = HTTPSConnectionPool(
                host=ip,
                port=port,
                timeout=transport_timeout,
                ssl_context=ssl.create_default_context(),
                server_hostname=hostname,
                assert_hostname=hostname,
            )
        else:
            pool = HTTPConnectionPool(
                host=ip,
                port=port,
                timeout=transport_timeout,
            )

        request_target = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        headers = {
            "Host": parsed.netloc,
            "User-Agent": "Phishing-Triage-SafeFetcher/1.0",
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.1",
        }
        request_timeout_seconds = _remaining_seconds(deadline)
        response = pool.urlopen(
            method,
            request_target,
            headers=headers,
            redirect=False,
            retries=False,
            preload_content=False,
            decode_content=True,
            timeout=Timeout(
                total=request_timeout_seconds,
                connect=request_timeout_seconds,
                read=request_timeout_seconds,
            ),
        )
        try:
            body = bytearray()
            while True:
                remaining = _remaining_seconds(deadline)
                _set_response_read_timeout(response, remaining)
                chunk = response.read(
                    min(_RESPONSE_READ_CHUNK_BYTES, max_bytes + 1 - len(body)),
                    decode_content=True,
                )
                _remaining_seconds(deadline)
                if not chunk:
                    break
                body.extend(chunk)
                if len(body) > max_bytes:
                    raise SafeHTTPError("too_large", "Response body exceeds size limit")
            response_headers = {
                str(name).lower(): str(value)
                for name, value in response.headers.items()
            }
            return int(response.status), response_headers, bytes(body)
        finally:
            response.close()
    except SafeHTTPError:
        raise
    except (Urllib3TimeoutError, TimeoutError, socket.timeout) as exc:
        raise SafeHTTPError("timeout", "Request deadline exceeded") from exc
    except (HTTPError, OSError, ssl.SSLError) as exc:
        raise SafeHTTPError("network_error", "Network request failed") from exc
    finally:
        if pool is not None:
            pool.close()


def _set_response_read_timeout(response: Any, timeout_seconds: float) -> None:
    """Refresh the socket read timeout before every decoded-body chunk."""
    connection = getattr(response, "connection", None)
    sock = getattr(connection, "sock", None)
    settimeout = getattr(sock, "settimeout", None)
    if callable(settimeout):
        settimeout(timeout_seconds)


def fetch_url(
    url: str,
    *,
    method: str = "GET",
    max_bytes: int = SAFE_HTTP_MAX_BYTES,
) -> SafeHTTPResponse:
    """Fetch an HTTP(S) URL while validating and pinning every redirect hop."""
    if max_bytes < 0 or max_bytes > _SAFE_HTTP_HARD_MAX_BYTES:
        raise SafeHTTPError("invalid_limit", "Response byte limit exceeds hard maximum")

    current_url = url
    history: list[str] = []
    deadline = _monotonic() + SAFE_HTTP_TIMEOUT_SECONDS

    while True:
        parsed, addresses = _validate_target(
            current_url,
            timeout_seconds=_remaining_seconds(deadline),
        )
        status_code, headers, body = _open_pinned(
            method,
            parsed,
            addresses[0],
            max_bytes,
            timeout_seconds=_remaining_seconds(deadline),
            deadline=deadline,
        )
        _remaining_seconds(deadline)
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
        try:
            current_url = urljoin(current_url, location)
        except (TypeError, UnicodeError, ValueError) as exc:
            raise SafeHTTPError("invalid_url", "Invalid URL") from exc
