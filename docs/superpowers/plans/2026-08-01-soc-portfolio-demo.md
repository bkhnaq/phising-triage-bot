# SOC Portfolio Demo Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give a recruiter a safe, one-command English/Vietnamese demonstration of the real pipeline and produce a concise analyst-oriented report.

**Architecture:** Add a CLI adapter around the existing `PhishingPipeline`, commit four inert RFC 5322 samples, and make only additive report/API improvements. Telegram and API behavior remain available and the CLI requires no token or API key.

**Tech Stack:** Python 3.12/3.13, argparse, pathlib, existing FastAPI and analysis pipeline, pytest.

## Global Constraints

- Keep one application and one shared pipeline; the CLI must call `PhishingPipeline.analyze_file`.
- Samples may use only reserved `.test` domains and documentation IP ranges; no live malicious URL or payload.
- Offline demo mode must perform no network requests.
- Keep the promoted bilingual mmBERT classifier optional and local-first; do not commit weights or retrain it.
- Preserve current bot/API commands and API response compatibility.
- Do not add a dashboard, database, queue, or case-management feature.

---

## File Structure

- Create `cli.py`: argument parser and file-analysis command.
- Modify `main.py`: delegate command selection to the parser while preserving existing modes.
- Create `samples/legitimate-en.eml`, `samples/phishing-en.eml`, `samples/legitimate-vi.eml`, and `samples/phishing-vi.eml`: inert demo corpus.
- Create `tests/test_cli.py`: CLI result, exit, output, and compatibility tests.
- Create `tests/test_samples.py`: parseability, safety, and broad score-order smoke tests.
- Modify `report/report_generator.py`: response actions, AI availability, and analyst disclaimer.
- Modify `api/routes.py`: additive AI provenance and analysis-limit response fields.
- Modify `tests/test_report_ai_provider.py` and `tests/test_api_bot_safety.py`: report/API contract tests.

### Task 1: Cross-platform analyze CLI

**Files:**
- Create: `cli.py`
- Modify: `main.py`
- Create: `tests/test_cli.py`

**Interfaces:**
- Produces: `build_parser() -> argparse.ArgumentParser`.
- Produces: `run_cli(argv: Sequence[str] | None = None) -> int`.
- Produces command: `python main.py --analyze PATH [--offline] [--output PATH]`.
- Preserves commands: `python main.py`, `python main.py --api`, and `python main.py --healthcheck`.

- [ ] **Step 1: Write failing parser and analyze tests**

```python
from pathlib import Path
import sys
import types

from cli import run_cli


def test_analyze_prints_pipeline_report(monkeypatch, tmp_path: Path, capsys) -> None:
    sample = tmp_path / "mail.eml"
    sample.write_text("From: a@example.test\n\nHello", encoding="utf-8")

    fake_pipeline = types.ModuleType("email_analysis.pipeline")

    class FakePipeline:
        def analyze_file(self, path: str) -> dict:
            assert path == str(sample.resolve())
            return {"report": "SOC REPORT"}

    fake_pipeline.PhishingPipeline = FakePipeline
    monkeypatch.setitem(sys.modules, "email_analysis.pipeline", fake_pipeline)

    assert run_cli(["--analyze", str(sample)]) == 0
    assert capsys.readouterr().out.strip() == "SOC REPORT"
```

Add tests for nonexistent/non-`.eml` input returning exit code 2, `--output`
writing UTF-8, `--offline` setting `config.settings.OFFLINE_MODE` before pipeline
import, and mutually exclusive `--api`, `--healthcheck`, and `--analyze` modes.

- [ ] **Step 2: Run tests and confirm RED**

Run: `.\.venv\Scripts\python.exe -m pytest -q tests/test_cli.py`

Expected: FAIL because `cli.py` does not exist.

- [ ] **Step 3: Implement the parser and analyze adapter**

Use one mutually exclusive group:

```python
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SOC phishing email triage")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--api", action="store_true", help="start the REST API")
    mode.add_argument("--healthcheck", action="store_true")
    mode.add_argument("--analyze", type=Path, metavar="EMAIL.eml")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--output", type=Path, metavar="REPORT.md")
    return parser
```

`run_cli` must resolve and validate the input, set
`config.settings.OFFLINE_MODE = True` when requested, lazily import the
pipeline, print the report unless `--output` is supplied, and return 0 for
success, 1 for analysis/runtime errors, or 2 for usage/input errors. `main.py`
must call `sys.exit(run_cli())`; startup credential validation applies only to
bot and API modes.

- [ ] **Step 4: Run CLI tests and commit**

Run: `.\.venv\Scripts\python.exe -m pytest -q tests/test_cli.py tests/test_api_bot_safety.py -W error`

Expected: PASS.

```powershell
git add cli.py main.py tests/test_cli.py
git commit -m "feat: add local email analysis CLI"
```

### Task 2: Safe bilingual demonstration samples

**Files:**
- Create: `samples/legitimate-en.eml`
- Create: `samples/phishing-en.eml`
- Create: `samples/legitimate-vi.eml`
- Create: `samples/phishing-vi.eml`
- Create: `tests/test_samples.py`

**Interfaces:**
- Consumes: `PhishingPipeline.analyze_file` and CLI from Task 1.
- Produces: four parseable, inert sample messages.

- [ ] **Step 1: Write failing sample-safety tests**

```python
from email_analysis.email_parser import parse_eml_file


SAMPLES = Path(__file__).parents[1] / "samples"


@pytest.mark.parametrize(
    "name",
    ["legitimate-en.eml", "phishing-en.eml", "legitimate-vi.eml", "phishing-vi.eml"],
)
def test_sample_is_parseable_and_inert(name: str) -> None:
    path = SAMPLES / name
    parsed = parse_eml_file(str(path))
    assert parsed["subject"]
    raw = path.read_text(encoding="utf-8").lower()
    for url in re.findall(r"https?://[^\s<>]+", raw):
        assert urlsplit(url.rstrip(">\"')).hostname.endswith(".test")
```

Add an offline pipeline test with local AI monkeypatched unavailable; assert
each result has `risk`, `report`, and `analysis_id`, and each phishing score is
greater than its same-language legitimate score. Do not assert exact scores or
verdict labels.

- [ ] **Step 2: Run tests and confirm RED**

Run: `.\.venv\Scripts\python.exe -m pytest -q tests/test_samples.py`

Expected: FAIL because the sample files do not exist.

- [ ] **Step 3: Create the four RFC 5322 samples**

Legitimate samples must use aligned `From`, `Return-Path`, `Message-ID`, and
passing `Authentication-Results`, neutral meeting/status language, and no
attachment. Phishing samples must use failed SPF/DKIM/DMARC evidence, a
display-name mismatch, urgent credential/payment language, and an inert URL
such as `https://microsoft-login-review.test/account/verify`. Vietnamese
samples must use natural Vietnamese subjects and body copy rather than literal
word-for-word English translations.

Every sample must include these minimum headers:

```text
From: Display Name <sender@domain.test>
To: analyst@example.test
Subject: ...
Date: Fri, 1 Aug 2026 09:00:00 +0700
Message-ID: <sample-id@domain.test>
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
```

Use these exact bodies and aligned authentication patterns, changing only
folding required by the email parser:

`samples/legitimate-en.eml`:

```text
From: IT Operations <it-operations@northwind.test>
To: analyst@example.test
Subject: Scheduled maintenance completed
Date: Fri, 1 Aug 2026 09:00:00 +0700
Message-ID: <legitimate-en@northwind.test>
Return-Path: <it-operations@northwind.test>
Authentication-Results: mx.example.test; spf=pass smtp.mailfrom=northwind.test; dkim=pass header.d=northwind.test; dmarc=pass header.from=northwind.test
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

The scheduled mail gateway maintenance is complete. No action is required.
```

`samples/phishing-en.eml`:

```text
From: Microsoft Security <alert@account-review.test>
To: analyst@example.test
Subject: Urgent: verify your password now
Date: Fri, 1 Aug 2026 09:05:00 +0700
Message-ID: <phishing-en@account-review.test>
Return-Path: <bounce@account-review.test>
Reply-To: helpdesk@credential-review.test
Authentication-Results: mx.example.test; spf=fail smtp.mailfrom=account-review.test; dkim=fail header.d=account-review.test; dmarc=fail header.from=account-review.test
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Your mailbox will be disabled today. Verify your password immediately at https://microsoft-login-review.test/account/verify or access will be lost.
```

`samples/legitimate-vi.eml`:

```text
From: Phòng Vận hành CNTT <vanhanh@congty-mau.test>
To: analyst@example.test
Subject: Đã hoàn tất bảo trì hệ thống
Date: Fri, 1 Aug 2026 09:10:00 +0700
Message-ID: <legitimate-vi@congty-mau.test>
Return-Path: <vanhanh@congty-mau.test>
Authentication-Results: mx.example.test; spf=pass smtp.mailfrom=congty-mau.test; dkim=pass header.d=congty-mau.test; dmarc=pass header.from=congty-mau.test
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit

Đợt bảo trì cổng thư điện tử đã hoàn tất. Anh/chị không cần thực hiện thêm thao tác nào.
```

`samples/phishing-vi.eml`:

```text
From: Bộ phận Microsoft 365 <canhbao@kiemtra-taikhoan.test>
To: analyst@example.test
Subject: Khẩn cấp: xác minh mật khẩu ngay hôm nay
Date: Fri, 1 Aug 2026 09:15:00 +0700
Message-ID: <phishing-vi@kiemtra-taikhoan.test>
Return-Path: <bounce@kiemtra-taikhoan.test>
Reply-To: hotro@xacminh-thongtin.test
Authentication-Results: mx.example.test; spf=fail smtp.mailfrom=kiemtra-taikhoan.test; dkim=fail header.d=kiemtra-taikhoan.test; dmarc=fail header.from=kiemtra-taikhoan.test
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit

Hộp thư của anh/chị sẽ bị khóa hôm nay. Hãy xác minh mật khẩu ngay tại https://dangnhap-microsoft.test/tai-khoan/xac-minh để tránh mất quyền truy cập.
```

- [ ] **Step 4: Run sample/CLI smoke tests and commit**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_samples.py tests/test_cli.py -W error
$env:OFFLINE_MODE='true'; $env:LOCAL_AI_ENABLED='false'; .\.venv\Scripts\python.exe main.py --analyze samples/phishing-vi.eml --offline
```

Expected: tests PASS and the command prints a complete report without requiring
a Telegram token, API key, or network access.

```powershell
git add samples tests/test_samples.py
git commit -m "test: add safe bilingual SOC demo emails"
```

### Task 3: Analyst actions and transparent AI state

**Files:**
- Modify: `report/report_generator.py`
- Modify: `api/routes.py`
- Modify: `tests/test_report_ai_provider.py`
- Modify: `tests/test_api_bot_safety.py`

**Interfaces:**
- Produces report section `RECOMMENDED SOC ACTIONS` based only on the final risk verdict.
- Produces report section `IOC SUMMARY` deduplicating URL/domain/SHA-256 indicators already present in the result.
- Produces a visible `AI PHISHING CLASSIFIER` unavailable state when `ai_verdict.error` exists.
- Additively exposes `provider`, `model`, and `fallback_used` in API `ai_verdict`.
- Additively exposes `analysis_limits` in `AnalysisResponse`.

- [ ] **Step 1: Write failing report/API tests**

```python
def _minimal_report(**overrides) -> str:
    arguments = {
        "email_data": {}, "auth_results": {}, "urls": [], "attachments": [],
        "risk": {"score": 0, "verdict": "LOW"}, "vt_url_reports": [],
        "vt_hash_reports": [], "otx_reports": [],
    }
    arguments.update(overrides)
    return generate_report(**arguments)


def test_high_risk_report_has_containment_actions() -> None:
    report = _minimal_report(
        risk={"score": 90, "verdict": "CRITICAL"},
        ai_verdict={"error": "local artifact unavailable", "provider": "none"},
    )
    assert "RECOMMENDED SOC ACTIONS" in report
    assert "IOC SUMMARY" in report
    assert "Quarantine the message" in report
    assert "AI analysis unavailable" in report
    assert "Human validation" in report


def test_api_returns_ai_provenance_additively() -> None:
    response = routes._build_response(
        {"risk": {"score": 0, "verdict": "LOW"},
         "ai_verdict": {"verdict": "legitimate", "confidence": 0.9,
                        "provider": "local", "model": "mmbert", "fallback_used": False},
         "analysis_limits": {"urls_truncated": False}},
        request_id="rid",
    )
    assert response.ai_verdict["provider"] == "local"
    assert response.analysis_limits == {"urls_truncated": False}
```

- [ ] **Step 2: Run tests and confirm RED**

Run: `.\.venv\Scripts\python.exe -m pytest -q tests/test_report_ai_provider.py tests/test_api_bot_safety.py`

Expected: FAIL because the actions, unavailable state, and additive API fields
are absent.

- [ ] **Step 3: Implement compact verdict-driven actions**

Add a pure helper:

```python
def _recommended_actions(verdict: str) -> list[str]:
    if verdict in {"CRITICAL", "HIGH"}:
        return [
            "Quarantine the message and block confirmed malicious IOCs.",
            "Check whether recipients clicked links, opened attachments, or entered credentials.",
            "Reset exposed credentials and review related endpoint/sign-in telemetry when applicable.",
        ]
    if verdict in {"SUSPICIOUS", "MEDIUM", "INCONCLUSIVE"}:
        return [
            "Validate the sender through a trusted channel before acting.",
            "Review unresolved URLs or attachments in an approved sandbox.",
        ]
    return ["No immediate containment; retain normal monitoring and verify unexpected requests."]
```

Render this before `END OF REPORT`, followed by: `Human validation and an
approved sandbox may still be required.` When `ai_verdict` has an error, render
provider/model if present plus `AI analysis unavailable; deterministic evidence
was still evaluated.` Never render the raw exception string.

Build the IOC summary only from already extracted values: normalized/final URL
and registered domain from `urls`/`url_intelligence`, plus attachment SHA-256.
Deduplicate while preserving first-seen order, show at most 20 indicators, and
render `No IOCs extracted` when empty. Do not add another network lookup.

Extend the Pydantic model and `_build_response` only with defaulted/additive
fields. Change the FastAPI description from “Enterprise-grade” to
“Multi-layer phishing triage for SOC analysts.”

- [ ] **Step 4: Run report/API regressions and commit**

Run: `.\.venv\Scripts\python.exe -m pytest -q tests/test_report_ai_provider.py tests/test_api_bot_safety.py tests/test_risk_scoring_refactor.py -W error`

Expected: PASS.

```powershell
git add report/report_generator.py api/routes.py tests/test_report_ai_provider.py tests/test_api_bot_safety.py
git commit -m "feat: make SOC report actions explicit"
```

### Task 4: Portfolio demo verification

**Files:**
- Modify only files required by failures caused by Tasks 1–3.

**Interfaces:**
- Consumes all demo interfaces above.
- Produces four repeatable demo commands and a clean test baseline.

- [ ] **Step 1: Run all four demos in deterministic mode**

```powershell
$env:OFFLINE_MODE='true'
$env:LOCAL_AI_ENABLED='false'
.\.venv\Scripts\python.exe main.py --analyze samples/legitimate-en.eml --offline --output artifacts/demo-legitimate-en.md
.\.venv\Scripts\python.exe main.py --analyze samples/phishing-en.eml --offline --output artifacts/demo-phishing-en.md
.\.venv\Scripts\python.exe main.py --analyze samples/legitimate-vi.eml --offline --output artifacts/demo-legitimate-vi.md
.\.venv\Scripts\python.exe main.py --analyze samples/phishing-vi.eml --offline --output artifacts/demo-phishing-vi.md
```

Expected: each command exits 0, each report contains `PHISHING TRIAGE REPORT`,
`RISK ASSESSMENT`, and `RECOMMENDED SOC ACTIONS`, and phishing scores exceed
same-language legitimate scores.

- [ ] **Step 2: Run the full automated gate**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests -W error
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m black --check api bot config email_analysis ml report scoring threat_intel main.py cli.py tests
.\.venv\Scripts\python.exe -m mypy api bot cli.py config email_analysis ml report scoring threat_intel --ignore-missing-imports --disable-error-code=import-untyped
```

Expected: all commands exit 0.

- [ ] **Step 3: Commit only necessary verification corrections**

```powershell
git status --short
git add api/routes.py cli.py main.py report/report_generator.py samples tests/test_api_bot_safety.py tests/test_cli.py tests/test_report_ai_provider.py tests/test_samples.py
git commit -m "test: finalize portfolio demo"
```

Do not commit generated reports under `artifacts/`, and do not create an empty
commit when the working tree is clean.
