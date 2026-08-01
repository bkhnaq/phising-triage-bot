# SOC Input and Network Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make email-controlled network access, API uploads, Telegram uploads, and expensive pipeline work safely bounded without changing the single-process application architecture.

**Architecture:** Add one reusable pinned-IP HTTP client for every email-controlled URL and keep fixed vendor API clients unchanged. Enforce limits at the API boundary and before expensive pipeline fan-out, then offload Telegram analysis to a worker thread. Preserve the existing `PhishingPipeline` entry points and response shapes.

**Tech Stack:** Python 3.12/3.13, urllib3, FastAPI/Starlette, python-telegram-bot, pytest, Ruff, Black, mypy, Bandit.

## Global Constraints

- Keep one application and one shared `PhishingPipeline`; add no Redis, queue, database, microservice, proxy, or dashboard.
- Preserve `PhishingPipeline.analyze_file(str) -> dict` and `PhishingPipeline.analyze_raw(str) -> dict`.
- Local mmBERT remains the first AI choice; do not retrain or recalibrate it.
- `OFFLINE_MODE=true` must prevent every email-controlled network request.
- Default maximum email/request size remains 10 MiB (`10485760` bytes).
- Analyze at most 50 unique URLs and 25 attachments from one email; report when either collection is truncated.
- Fetch at most 80,000 decoded response bytes per untrusted URL, follow at most 10 redirects, and use a 6-second timeout.
- Test behavior through fakes/mocks; tests must never contact live URLs.

---

## File Structure

- Create `email_analysis/safe_http.py`: URL validation, DNS validation, pinned-IP connection, redirect and byte limits.
- Create `tests/test_safe_http.py`: isolated SSRF and safe-fetch contract tests.
- Modify `config/settings.py`: strict parsers and bounded-work settings.
- Modify `.env.example`: document safe defaults and make Groq fallback opt-in.
- Modify `email_analysis/url_extractor.py`: bounded extraction and safe shortener expansion.
- Modify `email_analysis/url_intelligence.py`: safe expansion and redirect-chain inspection.
- Modify `email_analysis/landing_page_analyzer.py`: bounded landing-page fetches.
- Modify `email_analysis/heuristic_analyzer.py`: remove duplicate network redirect fetches.
- Modify `email_analysis/attachment_analyzer.py`: bounded attachment extraction metadata.
- Modify `email_analysis/pipeline.py`: enforce collection bounds and expose truncation state.
- Modify `report/report_generator.py`: show collection-limit notices.
- Create `api/body_limit.py`: small ASGI receive wrapper for request-body limits.
- Create `tests/test_api_body_limit.py`: direct ASGI tests for declared and streamed body limits.
- Modify `api/routes.py`: body limiter, streaming uploads, constant-time key checks, bounded rate state.
- Modify `bot/telegram_handler.py`: post-download size check and thread offload.
- Modify `tests/test_api_bot_safety.py`, `tests/test_logic_intelligence.py`, and `tests/test_pipeline_helpers.py`: regression coverage.

### Task 1: Strict, documented runtime limits

**Files:**
- Modify: `config/settings.py`
- Modify: `.env.example`
- Create: `tests/test_settings.py`

**Interfaces:**
- Produces: `_get_bool(name: str, default: bool) -> bool`
- Produces: `_get_int(name: str, default: int, *, minimum: int, maximum: int | None = None) -> int`
- Produces settings: `MAX_RAW_EMAIL_CHARS`, `MAX_URLS_PER_EMAIL`, `MAX_ATTACHMENTS_PER_EMAIL`, `SAFE_HTTP_MAX_BYTES`, `SAFE_HTTP_TIMEOUT_SECONDS`, `SAFE_HTTP_MAX_REDIRECTS`, and `RATE_LIMIT_MAX_CLIENTS`.

- [ ] **Step 1: Write failing strict-parser tests**

```python
import pytest

from config import settings


def test_get_bool_rejects_typo(monkeypatch) -> None:
    monkeypatch.setenv("FEATURE_FLAG", "treu")
    with pytest.raises(ValueError, match="FEATURE_FLAG must be a boolean"):
        settings._get_bool("FEATURE_FLAG", False)


def test_get_int_enforces_closed_range(monkeypatch) -> None:
    monkeypatch.setenv("PORT", "70000")
    with pytest.raises(ValueError, match="PORT must be between 1 and 65535"):
        settings._get_int("PORT", 8000, minimum=1, maximum=65535)
```

- [ ] **Step 2: Run the focused tests and confirm RED**

Run: `.\.venv\Scripts\python.exe -m pytest -q tests/test_settings.py`

Expected: FAIL because `_get_int` is not defined and invalid booleans are silently treated as false.

- [ ] **Step 3: Implement strict parsing and validate related settings**

```python
_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off"})


def _get_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise ValueError(f"{name} must be a boolean (true/false)")


def _get_int(
    name: str,
    default: int,
    *,
    minimum: int,
    maximum: int | None = None,
) -> int:
    raw = os.getenv(name)
    try:
        value = int(raw) if raw is not None else default
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if value < minimum or (maximum is not None and value > maximum):
        upper = f" and {maximum}" if maximum is not None else ""
        raise ValueError(f"{name} must be between {minimum}{upper}")
    return value
```

Use `_get_int` for the port, rate limits, upload limit, cache TTL, worker count,
and local model length. Reject `ENV` outside `{"dev", "prod"}`, reject log
levels outside `{"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}`, and
require `0 <= RISK_MEDIUM_THRESHOLD < RISK_HIGH_THRESHOLD <= 100`.

Set exact portfolio defaults:

```python
MAX_RAW_EMAIL_CHARS = _get_int(
    "MAX_RAW_EMAIL_CHARS", 10 * 1024 * 1024, minimum=1
)
MAX_URLS_PER_EMAIL = _get_int("MAX_URLS_PER_EMAIL", 50, minimum=1, maximum=500)
MAX_ATTACHMENTS_PER_EMAIL = _get_int(
    "MAX_ATTACHMENTS_PER_EMAIL", 25, minimum=1, maximum=100
)
SAFE_HTTP_MAX_BYTES = _get_int("SAFE_HTTP_MAX_BYTES", 80_000, minimum=1)
SAFE_HTTP_TIMEOUT_SECONDS = _get_int(
    "SAFE_HTTP_TIMEOUT_SECONDS", 6, minimum=1, maximum=30
)
SAFE_HTTP_MAX_REDIRECTS = _get_int(
    "SAFE_HTTP_MAX_REDIRECTS", 10, minimum=0, maximum=20
)
RATE_LIMIT_MAX_CLIENTS = _get_int(
    "RATE_LIMIT_MAX_CLIENTS", 10_000, minimum=1, maximum=100_000
)
AI_GROQ_FALLBACK = _get_bool("AI_GROQ_FALLBACK", False)
```

- [ ] **Step 4: Document every new setting and opt-in cloud fallback**

Add these exact active values to `.env.example`:

```dotenv
AI_GROQ_FALLBACK=false
MAX_RAW_EMAIL_CHARS=10485760
MAX_URLS_PER_EMAIL=50
MAX_ATTACHMENTS_PER_EMAIL=25
SAFE_HTTP_MAX_BYTES=80000
SAFE_HTTP_TIMEOUT_SECONDS=6
SAFE_HTTP_MAX_REDIRECTS=10
RATE_LIMIT_MAX_CLIENTS=10000
```

- [ ] **Step 5: Run tests and commit**

Run: `.\.venv\Scripts\python.exe -m pytest -q tests/test_settings.py tests/test_ai_classifier_routing.py`

Expected: PASS.

```powershell
git add config/settings.py .env.example tests/test_settings.py
git commit -m "fix: validate runtime safety limits"
```

### Task 2: Pinned-IP safe HTTP client

**Files:**
- Create: `email_analysis/safe_http.py`
- Create: `tests/test_safe_http.py`

**Interfaces:**
- Produces: `SafeHTTPError(code: str, message: str)` with public `.code`.
- Produces: immutable `SafeHTTPResponse(url: str, status_code: int, headers: dict[str, str], body: bytes, history: tuple[str, ...])`.
- Produces: `fetch_url(url: str, *, method: str = "GET", max_bytes: int = SAFE_HTTP_MAX_BYTES) -> SafeHTTPResponse`.
- Internal injection seam: `_resolve_addresses(host: str, port: int) -> tuple[str, ...]` and `_open_pinned(method: str, parsed: SplitResult, ip: str, max_bytes: int) -> tuple[int, dict[str, str], bytes]`.

- [ ] **Step 1: Write failing URL-policy tests**

```python
import pytest

from email_analysis import safe_http


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
```

- [ ] **Step 2: Write failing redirect and DNS-pinning tests**

```python
def test_redirect_target_is_revalidated(monkeypatch) -> None:
    monkeypatch.setattr(
        safe_http,
        "_resolve_addresses",
        lambda host, _port: ("93.184.216.34",) if host == "public.test" else ("127.0.0.1",),
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
        lambda _host, _port: ("93.184.216.34",),
    )

    def fake_open(_method, _parsed, ip, _max_bytes):
        seen.append(ip)
        return 200, {"content-type": "text/plain"}, b"ok"

    monkeypatch.setattr(safe_http, "_open_pinned", fake_open)
    response = safe_http.fetch_url("https://public.test/")
    assert response.body == b"ok"
    assert seen == ["93.184.216.34"]
```

- [ ] **Step 3: Run tests and confirm RED**

Run: `.\.venv\Scripts\python.exe -m pytest -q tests/test_safe_http.py`

Expected: FAIL because `email_analysis.safe_http` does not exist.

- [ ] **Step 4: Implement URL validation, resolution, and manual redirects**

Implement the public flow exactly around these types:

```python
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
    if not addresses or any(not ipaddress.ip_address(ip).is_global for ip in addresses):
        raise SafeHTTPError("blocked_target", "Target address is not public")
    return parsed, addresses
```

`fetch_url` must validate every redirect with `urljoin`, never pass
`redirect=True`, never resolve inside `_open_pinned`, and raise `too_large` after
reading `max_bytes + 1` decoded bytes or `too_many_redirects` after the exact
configured limit.

- [ ] **Step 5: Implement pinned urllib3 connections**

For HTTPS, construct `HTTPSConnectionPool` with the validated IP as `host`, the
original hostname as both `server_hostname` and `assert_hostname`, and an
`ssl.create_default_context()` context. For HTTP, use `HTTPConnectionPool` with
the validated IP. Send only a relative request target and these headers:

```python
headers = {
    "Host": original_host_header,
    "User-Agent": "Phishing-Triage-SafeFetcher/1.0",
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.1",
}
```

Call `pool.urlopen(..., redirect=False, retries=False, preload_content=False,
decode_content=True)`, read at most `max_bytes + 1`, close the response, and
close the pool in `finally`. This bypasses ambient HTTP proxy and `.netrc`
configuration and prevents a second DNS lookup.

- [ ] **Step 6: Add size/error tests, run quality checks, and commit**

Add tests asserting an 80,001-byte fake response raises `code == "too_large"`,
mixed public/private DNS answers are blocked, malformed ports are rejected, and
ten redirects are allowed while the eleventh fails.

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_safe_http.py
.\.venv\Scripts\python.exe -m ruff check email_analysis/safe_http.py tests/test_safe_http.py
.\.venv\Scripts\python.exe -m mypy email_analysis/safe_http.py --ignore-missing-imports --disable-error-code=import-untyped
```

Expected: all PASS.

```powershell
git add email_analysis/safe_http.py tests/test_safe_http.py
git commit -m "fix: block SSRF in email URL fetches"
```

### Task 3: Route every email-controlled request through safe HTTP

**Files:**
- Modify: `email_analysis/url_extractor.py`
- Modify: `email_analysis/url_intelligence.py`
- Modify: `email_analysis/landing_page_analyzer.py`
- Modify: `email_analysis/heuristic_analyzer.py`
- Modify: `tests/test_logic_intelligence.py`
- Modify: `tests/test_safe_http.py`

**Interfaces:**
- Consumes: `fetch_url(...) -> SafeHTTPResponse` and `SafeHTTPError` from Task 2.
- Produces: existing public URL functions with unchanged return shapes.

- [ ] **Step 1: Write failing integration tests**

```python
def test_landing_page_uses_safe_fetch(monkeypatch) -> None:
    from email_analysis import landing_page_analyzer as landing

    calls: list[str] = []
    monkeypatch.setattr(landing, "OFFLINE_MODE", False)
    monkeypatch.setattr(
        landing,
        "fetch_url",
        lambda url, **_kwargs: calls.append(url)
        or SafeHTTPResponse(
            url=url,
            status_code=200,
            headers={"content-type": "text/html; charset=utf-8"},
            body=b"<title>Account Login</title>",
            history=(),
        ),
    )
    assert landing.analyze_landing_page("https://public.test/")["state"] == "suspicious"
    assert calls == ["https://public.test/"]
```

Also patch `requests.get` and `requests.head` to raise `AssertionError` in tests
for `url_extractor`, `url_intelligence`, landing pages, and heuristic redirect
analysis. The tested functions must complete using only the fake `fetch_url`.

- [ ] **Step 2: Run tests and confirm RED**

Run: `.\.venv\Scripts\python.exe -m pytest -q tests/test_logic_intelligence.py tests/test_safe_http.py`

Expected: FAIL because the URL modules still call `requests` directly.

- [ ] **Step 3: Replace direct email-controlled network calls**

Use `fetch_url(..., method="HEAD", max_bytes=0)` for shortener expansion and
redirect-only inspection. Use `fetch_url(..., method="GET",
max_bytes=SAFE_HTTP_MAX_BYTES)` for landing pages. Translate `SafeHTTPError`
into the existing friendly `error` fields; use the error code rather than raw
socket exception text.

For redirect chains, derive fields from the response contract:

```python
chain = list(response.history) + [response.url]
result["chain"] = chain
result["hops"] = len(response.history)
result["final_url"] = response.url
```

Remove `requests` imports from all four modules. Remove the network-backed
`check_redirect_chain` call from `run_heuristics`; set
`"redirect_chains": []` there because `url_intelligence` already performs the
same check once and supplies it to scoring/reporting.

- [ ] **Step 4: Run regression tests and commit**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_safe_http.py tests/test_logic_intelligence.py tests/test_risk_scoring_refactor.py
rg -n "requests\.(get|head)" email_analysis/url_extractor.py email_analysis/url_intelligence.py email_analysis/landing_page_analyzer.py email_analysis/heuristic_analyzer.py
```

Expected: tests PASS and `rg` returns no matches.

```powershell
git add email_analysis/url_extractor.py email_analysis/url_intelligence.py email_analysis/landing_page_analyzer.py email_analysis/heuristic_analyzer.py tests/test_logic_intelligence.py tests/test_safe_http.py
git commit -m "refactor: centralize safe URL analysis"
```

### Task 4: Bound URL and attachment work in the pipeline

**Files:**
- Modify: `email_analysis/url_extractor.py`
- Modify: `email_analysis/attachment_analyzer.py`
- Modify: `email_analysis/pipeline.py`
- Modify: `report/report_generator.py`
- Modify: `tests/test_pipeline_helpers.py`
- Modify: `tests/test_logic_intelligence.py`

**Interfaces:**
- Produces: `extract_urls(..., max_urls: int | None = None) -> list[dict]`.
- Produces: `extract_attachments(..., max_attachments: int | None = None) -> list[dict]`.
- Produces result field: `analysis_limits: {"urls_truncated": bool, "attachments_truncated": bool, "max_urls": int, "max_attachments": int}`.
- Extends `generate_report(..., analysis_limits: dict | None = None) -> str` additively.

- [ ] **Step 1: Write failing bounded-work tests**

```python
def test_url_extraction_stops_before_expensive_expansion(monkeypatch) -> None:
    from email_analysis import url_extractor

    expanded: list[str] = []
    monkeypatch.setattr(
        url_extractor,
        "_expand_url",
        lambda url: expanded.append(url) or url,
    )
    body = " ".join(f"https://bit.ly/{index}" for index in range(5))
    urls = url_extractor.extract_urls(body, max_urls=2)
    assert len(urls) == 2
    assert len(expanded) == 2


def test_report_discloses_truncated_evidence() -> None:
    report = generate_report(
        email_data={}, auth_results={}, urls=[], attachments=[],
        risk={"score": 0, "verdict": "LOW"}, vt_url_reports=[],
        vt_hash_reports=[], otx_reports=[],
        analysis_limits={
            "urls_truncated": True, "attachments_truncated": False,
            "max_urls": 50, "max_attachments": 25,
        },
    )
    assert "URL analysis limited to the first 50 indicators" in report
```

- [ ] **Step 2: Run tests and confirm RED**

Run: `.\.venv\Scripts\python.exe -m pytest -q tests/test_pipeline_helpers.py tests/test_logic_intelligence.py`

Expected: FAIL because limits and report metadata do not exist.

- [ ] **Step 3: Apply limits before expensive operations**

Sort/deduplicate raw URL strings, calculate `total_urls`, then slice before URL
normalization or expansion. In attachment extraction, increment
`total_attachments` for MIME parts with a disposition and stop saving after the
limit. Keep existing list return types; the pipeline calculates the truncation
booleans before calling these functions:

```python
raw_url_count = count_unique_urls(
    email_data.get("body_text", ""), email_data.get("body_html", "")
)
attachment_count = count_attachments(email_data["raw_message"])
urls = extract_urls(..., max_urls=MAX_URLS_PER_EMAIL)
attachments = extract_attachments(
    ..., max_attachments=MAX_ATTACHMENTS_PER_EMAIL
)
analysis_limits = {
    "urls_truncated": raw_url_count > MAX_URLS_PER_EMAIL,
    "attachments_truncated": attachment_count > MAX_ATTACHMENTS_PER_EMAIL,
    "max_urls": MAX_URLS_PER_EMAIL,
    "max_attachments": MAX_ATTACHMENTS_PER_EMAIL,
}
```

Add pure `count_unique_urls(...) -> int` and `count_attachments(message) -> int`
helpers beside their extractors. Limit merged QR URLs to the same URL maximum.
Return `analysis_limits` in the pipeline result and pass it into the report.

- [ ] **Step 4: Run focused/full regression tests and commit**

Run: `.\.venv\Scripts\python.exe -m pytest -q tests/test_pipeline_helpers.py tests/test_logic_intelligence.py tests/test_report_ai_provider.py`

Expected: PASS.

```powershell
git add email_analysis/url_extractor.py email_analysis/attachment_analyzer.py email_analysis/pipeline.py report/report_generator.py tests/test_pipeline_helpers.py tests/test_logic_intelligence.py
git commit -m "fix: bound per-email analysis work"
```

### Task 5: Bound API bodies, uploads, authentication, and rate state

**Files:**
- Create: `api/body_limit.py`
- Modify: `api/routes.py`
- Create: `tests/test_api_body_limit.py`
- Modify: `tests/test_api_bot_safety.py`

**Interfaces:**
- Produces: `RequestBodyLimitMiddleware(app, max_body_size: int)` ASGI middleware.
- Produces: `_prune_rate_limit_buckets(now: float) -> None` under the existing lock.
- Preserves both analysis endpoint response models and error envelope.

- [ ] **Step 1: Write failing API boundary tests**

```python
def test_rate_limit_state_is_bounded(monkeypatch) -> None:
    client, routes = _client_with_auth(monkeypatch)
    monkeypatch.setattr(routes, "RATE_LIMIT_MAX_CLIENTS", 2)
    routes._rate_limit_buckets.update({
        "old-a": deque([0.0]), "old-b": deque([0.0]), "old-c": deque([0.0])
    })
    routes._prune_rate_limit_buckets(1_000.0)
    assert len(routes._rate_limit_buckets) <= 2
```

Add an upload fake whose `read(size)` records sizes; assert no call uses
`size == -1`, a six-byte upload against a five-byte limit returns 413, and no
temporary file remains.

In `tests/test_api_body_limit.py`, drive the ASGI middleware directly so the
configured limit is not affected by FastAPI import timing:

```python
def test_streamed_body_over_limit_returns_413() -> None:
    sent: list[dict] = []
    incoming = [
        {"type": "http.request", "body": b"123", "more_body": True},
        {"type": "http.request", "body": b"456", "more_body": False},
    ]

    async def receive() -> dict:
        return incoming.pop(0)

    async def send(message: dict) -> None:
        sent.append(message)

    async def downstream(_scope, wrapped_receive, downstream_send) -> None:
        while (message := await wrapped_receive()).get("more_body", False):
            pass
        await downstream_send({"type": "http.response.start", "status": 204, "headers": []})
        await downstream_send({"type": "http.response.body", "body": b""})

    middleware = RequestBodyLimitMiddleware(downstream, max_body_size=5)
    scope = {"type": "http", "method": "POST", "path": "/", "headers": []}
    asyncio.run(middleware(scope, receive, send))
    assert sent[0]["status"] == 413
```

Add a second direct test with `Content-Length: 6` and a five-byte limit;
downstream must not be called:

```python
def test_declared_body_over_limit_short_circuits() -> None:
    sent: list[dict] = []
    called = False

    async def receive() -> dict:
        raise AssertionError("body must not be read")

    async def send(message: dict) -> None:
        sent.append(message)

    async def downstream(_scope, _receive, _send) -> None:
        nonlocal called
        called = True

    middleware = RequestBodyLimitMiddleware(downstream, max_body_size=5)
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/",
        "headers": [(b"content-length", b"6")],
    }
    asyncio.run(middleware(scope, receive, send))
    assert sent[0]["status"] == 413
    assert called is False
```

Also add this regression to `tests/test_api_bot_safety.py`:

```python
def test_validation_error_does_not_echo_email_input(monkeypatch) -> None:
    client, _routes = _client_with_auth(monkeypatch)
    response = client.post(
        "/analyze_email",
        headers={"X-API-Key": "test-key"},
        json={"email_raw": {"secret": "do-not-echo"}},
    )
    assert response.status_code == 422
    assert "do-not-echo" not in response.text
```

- [ ] **Step 2: Run tests and confirm RED**

Run: `.\.venv\Scripts\python.exe -m pytest -q tests/test_api_body_limit.py tests/test_api_bot_safety.py`

Expected: FAIL because raw bodies are not bounded, uploads use `read()` without
a size, and pruning is absent.

- [ ] **Step 3: Add the ASGI receive limiter**

Implement middleware that counts bytes from every `http.request` message and
returns the existing JSON 413 envelope when the cumulative count exceeds
`MAX_UPLOAD_SIZE_BYTES`. It must also reject a numeric `Content-Length` larger
than the maximum before calling the downstream app. Do not use
`BaseHTTPMiddleware`; wrap the ASGI `receive` callable so chunked bodies are
also covered.

Add it once with:

```python
app.add_middleware(
    RequestBodyLimitMiddleware,
    max_body_size=MAX_UPLOAD_SIZE_BYTES,
)
```

Keep the endpoint-level limits as defense in depth and set
`EmailAnalysisRequest.email_raw = Field(..., min_length=1,
max_length=MAX_RAW_EMAIL_CHARS)`.

Sanitize Pydantic errors so raw email input is never reflected:

```python
details = [
    {key: value for key, value in error.items() if key != "input"}
    for error in exc.errors()
]
```

- [ ] **Step 4: Stream uploads and harden API key/rate state**

Replace `content = await file.read()` with:

```python
written = 0
with open(save_path, "wb") as destination:
    while chunk := await file.read(64 * 1024):
        written += len(chunk)
        if written > MAX_UPLOAD_SIZE_BYTES:
            raise HTTPException(status_code=413, detail=UPLOAD_TOO_LARGE)
        destination.write(chunk)
```

Use `secrets.compare_digest(provided_key, API_KEY)` for authentication. During
rate-limit pruning, delete empty expired buckets; if the map still exceeds
`RATE_LIMIT_MAX_CLIENTS`, remove the bucket with the oldest final timestamp.
Prune before allocating a new client bucket.

- [ ] **Step 5: Run API regression tests and commit**

Run: `.\.venv\Scripts\python.exe -m pytest -q tests/test_api_body_limit.py tests/test_api_bot_safety.py -W error`

Expected: PASS.

```powershell
git add api/body_limit.py api/routes.py tests/test_api_body_limit.py tests/test_api_bot_safety.py
git commit -m "fix: bound API input and limiter state"
```

### Task 6: Keep Telegram responsive and verify downloaded size

**Files:**
- Modify: `bot/telegram_handler.py`
- Modify: `tests/test_api_bot_safety.py`

**Interfaces:**
- Consumes: existing `_run_analysis(eml_path: str, analysis_id: str | None) -> str`.
- Produces: `_validate_downloaded_size(path: Path, maximum: int) -> None` raising `ValueError` when oversized.

- [ ] **Step 1: Write failing handler tests**

Create minimal fake message/document/file objects and assert:

```python
import pytest


def test_downloaded_file_size_is_checked(tmp_path: Path) -> None:
    from bot.telegram_handler import _validate_downloaded_size

    path = tmp_path / "mail.eml"
    path.write_bytes(b"123456")
    with pytest.raises(ValueError, match="too large"):
        _validate_downloaded_size(path, 5)


def test_analysis_keeps_event_loop_responsive(monkeypatch, tmp_path: Path) -> None:
    from types import SimpleNamespace
    import time
    from bot import telegram_handler as handler

    class FakeTelegramFile:
        async def download_to_drive(self, path: str) -> None:
            Path(path).write_bytes(b"From: a@example.test\n\nHello")

    class FakeDocument:
        file_name = "mail.eml"
        file_size = 32

        async def get_file(self) -> FakeTelegramFile:
            return FakeTelegramFile()

    class FakeMessage:
        document = FakeDocument()

        def __init__(self) -> None:
            self.replies: list[str] = []

        async def reply_text(self, text: str, **_kwargs) -> None:
            self.replies.append(text)

    message = FakeMessage()
    update = SimpleNamespace(
        message=message,
        effective_chat=SimpleNamespace(id=42),
    )
    path = tmp_path / "mail.eml"
    events: list[str] = []

    def slow_analysis(_path: str, _analysis_id: str) -> str:
        events.append("analysis-start")
        time.sleep(0.15)
        events.append("analysis-end")
        return "report"

    monkeypatch.setattr(handler, "ALLOWED_CHAT_IDS", [])
    monkeypatch.setattr(handler, "_safe_upload_path", lambda *_args, **_kwargs: path)
    monkeypatch.setattr(handler, "_run_analysis", slow_analysis)

    async def scenario() -> None:
        analysis = asyncio.create_task(handler.handle_document(update, None))
        while "analysis-start" not in events:
            await asyncio.sleep(0)
        await asyncio.sleep(0.02)
        events.append("heartbeat")
        await analysis

    asyncio.run(scenario())

    assert events.index("heartbeat") < events.index("analysis-end")
    assert message.replies[-1] == "report"
    assert not path.exists()
```

- [ ] **Step 2: Run tests and confirm RED**

Run: `.\.venv\Scripts\python.exe -m pytest -q tests/test_api_bot_safety.py`

Expected: FAIL because `_validate_downloaded_size` is absent and `_run_analysis`
runs directly.

- [ ] **Step 3: Implement size verification and thread offload**

```python
def _validate_downloaded_size(path: Path, maximum: int) -> None:
    if path.stat().st_size > maximum:
        raise ValueError(f"Downloaded file is too large (maximum {maximum} bytes)")
```

Move the download itself into the cleanup-protected `try`, place validation
immediately after it, and replace the direct analysis call with:

```python
report_text = await asyncio.to_thread(
    _run_analysis,
    str(local_path),
    analysis_id,
)
```

Return a friendly “file too large” message for `ValueError`; retain the generic
failure message for other exceptions and always unlink the file.

- [ ] **Step 4: Run regressions and commit**

Run: `.\.venv\Scripts\python.exe -m pytest -q tests/test_api_bot_safety.py -W error`

Expected: PASS.

```powershell
git add bot/telegram_handler.py tests/test_api_bot_safety.py
git commit -m "fix: keep Telegram analysis responsive"
```

### Task 7: Full hardening verification

**Files:**
- Modify only files required by formatter or type-check fixes discovered here.

**Interfaces:**
- Consumes all interfaces from Tasks 1–6.
- Produces a clean security/reliability baseline for the demo plan.

- [ ] **Step 1: Run the full automated gate**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests -W error
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m black --check api bot config email_analysis ml report scoring threat_intel main.py tests
.\.venv\Scripts\python.exe -m mypy api bot config email_analysis ml report scoring threat_intel --ignore-missing-imports --disable-error-code=import-untyped
.\.venv\Scripts\python.exe -m bandit -r api bot config email_analysis ml report scoring threat_intel -lll
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m pip_audit
```

Expected: every command exits 0.

- [ ] **Step 2: Fix only failures caused by this plan and rerun the gate**

Use Black for formatting changes. For every semantic failure, first add or
strengthen a focused regression test, observe it fail, then apply the smallest
fix. Do not refactor unrelated modules.

- [ ] **Step 3: Commit verification-only corrections if any**

```powershell
git status --short
git add .env.example api/body_limit.py api/routes.py bot/telegram_handler.py config/settings.py email_analysis/attachment_analyzer.py email_analysis/heuristic_analyzer.py email_analysis/landing_page_analyzer.py email_analysis/pipeline.py email_analysis/safe_http.py email_analysis/url_extractor.py email_analysis/url_intelligence.py report/report_generator.py tests/test_api_body_limit.py tests/test_api_bot_safety.py tests/test_logic_intelligence.py tests/test_pipeline_helpers.py tests/test_safe_http.py tests/test_settings.py
git commit -m "test: finalize input hardening checks"
```

If `git status --short` is empty, do not create an empty commit.
