# Repository Audit Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the reproducible quality, dependency-security, deprecation, and API error-disclosure defects found by the repository audit.

**Architecture:** Keep the existing application structure unchanged. Constrain vulnerable or newly-required dependencies at the requirements boundary, update deprecated FastAPI status aliases in place, sanitize server-side exceptions at the HTTP boundary, and format the one drifted module.

**Tech Stack:** Python 3.12+, FastAPI, Starlette, pytest, Black, pip-audit

## Global Constraints

- Preserve existing public success-response behavior.
- Do not expose raw exception messages in HTTP 500 responses.
- Do not perform unrelated dependency upgrades or refactors.
- Do not commit or push changes; leave the reviewed diff in the workspace.

---

### Task 1: Dependency and deprecation cleanup

**Files:**
- Modify: `requirements.txt`
- Modify: `requirements-dev.txt`
- Modify: `api/routes.py`
- Test: `tests/test_api_bot_safety.py`

**Interfaces:**
- Consumes: Starlette `TestClient`, FastAPI `status`, Uvicorn's Click dependency.
- Produces: A development environment with `httpx2`, Click 8.3.3 or newer, and warning-free API tests.

- [x] **Step 1: Confirm the warning and vulnerability gates fail**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests -W error
.\.venv\Scripts\python.exe -m pip_audit
```

Expected: pytest fails on the deprecated `httpx` TestClient fallback; pip-audit reports `PYSEC-2026-2132` for Click 8.3.1.

- [x] **Step 2: Add the minimal dependency constraints**

Add `click>=8.3.3,<9` to production requirements because Uvicorn uses Click at runtime. Add `httpx2>=2.0,<3` to development requirements because Starlette's TestClient uses it.

- [x] **Step 3: Update deprecated status aliases**

Use `status.HTTP_422_UNPROCESSABLE_CONTENT` for validation errors and `status.HTTP_413_CONTENT_TOO_LARGE` for oversized uploads. Numeric HTTP behavior remains 422 and 413.

- [x] **Step 4: Refresh the local environment and verify**

Run:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest -q tests -W error
.\.venv\Scripts\python.exe -m pip_audit
```

Expected: both verification commands exit 0 with no warnings or vulnerabilities.

### Task 2: Sanitize API analysis failures

**Files:**
- Modify: `tests/test_api_bot_safety.py`
- Modify: `api/routes.py`

**Interfaces:**
- Consumes: `POST /analyze_email` and the standard API error envelope.
- Produces: HTTP 500 responses with a generic client message while retaining exception details in server logs.

- [x] **Step 1: Write the failing regression test**

Add a fake `PhishingPipeline` whose `analyze_raw` raises `RuntimeError("sensitive-token")`. Post a valid raw email and assert status 500, error code `http_error`, message `Analysis failed`, and absence of `sensitive-token` from the serialized response.

- [x] **Step 2: Run the test to verify it fails**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_api_bot_safety.py::test_analysis_failure_does_not_expose_exception_details
```

Expected: FAIL because the current response includes `sensitive-token`.

- [x] **Step 3: Implement the minimal sanitization**

Keep `logger.exception(...)` calls intact, but replace exception-derived HTTP details with `Analysis failed`. Return `Internal server error` from the catch-all exception handler.

- [x] **Step 4: Verify the regression and API suite**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_api_bot_safety.py::test_analysis_failure_does_not_expose_exception_details
.\.venv\Scripts\python.exe -m pytest -q tests/test_api_bot_safety.py -W error
```

Expected: both commands exit 0.

### Task 3: Restore formatting and run the complete gate

**Files:**
- Modify: `scoring/risk_scoring.py`
- Modify: `tests/test_risk_scoring_refactor.py`

**Interfaces:**
- Consumes: Existing scoring behavior.
- Produces: Black-formatted source with no logic changes.

- [x] **Step 1: Apply Black to the drifted files**

Run:

```powershell
.\.venv\Scripts\python.exe -m black scoring/risk_scoring.py tests/test_risk_scoring_refactor.py
```

- [x] **Step 2: Run all repository verification**

Run:

```powershell
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m black --check api bot config email_analysis report scoring threat_intel main.py
.\.venv\Scripts\python.exe -m mypy api bot config email_analysis report scoring threat_intel --ignore-missing-imports --disable-error-code=import-untyped --check-untyped-defs
.\.venv\Scripts\python.exe -m pytest -q tests -W error
.\.venv\Scripts\python.exe -m bandit -r api bot config email_analysis report scoring threat_intel -lll
.\.venv\Scripts\python.exe -m pip_audit
.\.venv\Scripts\python.exe main.py --healthcheck
git diff --check
```

Expected at this checkpoint: every command exits 0; pytest reports 34 passing tests and no warnings.

### Task 4: Preserve catch-all exception details in server logs

**Files:**
- Modify: `tests/test_api_bot_safety.py`
- Modify: `api/routes.py`

**Interfaces:**
- Consumes: The FastAPI catch-all exception handler.
- Produces: A generic HTTP 500 response for clients and a log record carrying the original exception for operators.

- [x] **Step 1: Write and run the failing regression test**

Call `unhandled_exception_handler` with `RuntimeError("sensitive-token")`. Assert the response excludes that token and the emitted log record's `exc_info` contains the exact exception.

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_api_bot_safety.py::test_unhandled_exception_is_sanitized_and_logged
```

Expected: FAIL because `logger.exception` is called outside an active `except` block and records `(None, None, None)`.

- [x] **Step 2: Pass the original exception explicitly to logging**

Call `logger.error` with `exc_info=(type(exc), exc, exc.__traceback__)`.

- [x] **Step 3: Verify the regression and full gate**

Re-run the targeted test followed by the complete verification commands from Task 3. Expected: the targeted test passes and pytest reports 35 passing tests.
