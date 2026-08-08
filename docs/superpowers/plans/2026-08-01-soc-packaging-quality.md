# SOC Packaging and Documentation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the completed SOC portfolio project safe to package, straightforward to verify in CI, and understandable in English or Vietnamese.

**Architecture:** Keep one Dockerfile with a build argument for optional CPU local-AI dependencies, exclude all local/private material from the build context, and add lightweight CI smoke coverage. Rewrite documentation around the CLI-first demo while retaining bot, API, and model-training references.

**Tech Stack:** Docker, GitHub Actions, pip requirements, Markdown, pytest, Python 3.12/3.13.

## Global Constraints

- Keep one Dockerfile and one application; add no Compose stack or infrastructure service.
- Never copy `.env`, Git metadata, local worktrees, model/data artifacts, uploads, caches, logs, or virtual environments into Docker context.
- Model weights remain outside Git and are mounted read-only for Docker demos.
- A core Docker build must work without downloading PyTorch; a documented AI build may install CPU PyTorch.
- README is concise English; `docs/README.vi.md` provides equivalent Vietnamese guidance.
- Documentation must state measured model results and the synthetic Vietnamese limitation accurately.

---

## File Structure

- Create `.dockerignore`: explicit private/large context exclusions.
- Modify `Dockerfile`: optional CPU local-AI dependency build argument and safe runtime defaults.
- Modify `requirements.txt`: use headless OpenCV for server/CLI environments.
- Modify `.github/workflows/ci.yml`: Python 3.12/3.13 quality matrix, CLI smoke, core Docker build.
- Rewrite `README.md`: English recruiter-facing project page.
- Create `docs/README.vi.md`: Vietnamese counterpart.
- Modify `SECURITY.md`: safe sample handling and supported-use boundary.

### Task 1: Safe and optional-AI Docker packaging

**Files:**
- Create: `.dockerignore`
- Modify: `Dockerfile`
- Modify: `requirements.txt`

**Interfaces:**
- Produces build: `docker build --build-arg INSTALL_LOCAL_AI=false -t phishing-triage-bot:core .`.
- Produces build: `docker build --build-arg INSTALL_LOCAL_AI=true -t phishing-triage-bot:ai .`.
- Runtime model mount remains `/app/artifacts/models/phishing-mmbert`.

- [ ] **Step 1: Record the approved configuration-only TDD exception**

The user approved behavior-level verification instead of source-text unit
tests for Docker configuration. Do not add a test that reads Dockerfile or
`.dockerignore` strings. Verification is the real Docker build and container
health check in Step 4 and the CI build in Task 2.

- [ ] **Step 2: Add exact Docker context exclusions**

Create `.dockerignore` containing:

```dockerignore
.git/
.github/
.env
.venv/
.worktrees/
.mypy_cache/
.pytest_cache/
.ruff_cache/
__pycache__/
*.py[cod]
artifacts/
data/
uploads/
logs/
*.log
.vscode/
.idea/
docs/superpowers/
```

- [ ] **Step 3: Add the optional CPU-AI build path**

Before copying source code, copy `requirements-ml-runtime.txt`, declare
`ARG INSTALL_LOCAL_AI=false`, and install runtime AI dependencies only when it
is true. Install CPU Torch from the official CPU wheel index first, then install
the remaining runtime requirements with Torch already satisfied:

```dockerfile
COPY requirements.txt requirements-ml-runtime.txt ./
ARG INSTALL_LOCAL_AI=false
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && if [ "$INSTALL_LOCAL_AI" = "true" ]; then \
         pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu "torch>=2.11,<2.14" \
         && pip install --no-cache-dir -r requirements-ml-runtime.txt; \
       fi
```

Retain the non-root user and health check. Replace `opencv-python` with
`opencv-python-headless>=4.8,<5` in `requirements.txt` so the container needs no
desktop GUI libraries.

- [ ] **Step 4: Run dependency checks and real Docker behavior**

```powershell
.\.venv\Scripts\python.exe -m pip check
docker info
docker build --build-arg INSTALL_LOCAL_AI=false -t phishing-triage-bot:core .
docker run --rm --env TELEGRAM_ENABLED=false phishing-triage-bot:core python main.py --healthcheck
```

Expected: dependency checks PASS. If `docker info` reports no daemon, record
that the build is deferred and rely on the CI build in Task 2; do not claim a
local Docker build passed.

- [ ] **Step 5: Commit**

```powershell
git add .dockerignore Dockerfile requirements.txt
git commit -m "build: add safe optional AI container"
```

### Task 2: Portfolio-sized CI coverage

**Files:**
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes samples and CLI from the demo plan.
- Produces matrix test coverage for Python 3.12 and 3.13 plus one core Docker build.

- [ ] **Step 1: Validate current workflow assumptions locally**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests -W error
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m black --check api bot config email_analysis ml report scoring threat_intel main.py cli.py tests
```

Expected: all commands exit 0 before the workflow is edited.

- [ ] **Step 2: Add the exact CI matrix and smoke steps**

Set the quality job strategy and interpreter to:

```yaml
strategy:
  fail-fast: false
  matrix:
    python-version: ["3.12", "3.13"]

steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-python@v5
    with:
      python-version: ${{ matrix.python-version }}
      cache: pip
```

Keep Ruff, Black, mypy, pytest `-W error`, Bandit, and pip-audit. Add after
tests:

```yaml
- name: Offline CLI smoke test
  env:
    OFFLINE_MODE: "true"
    LOCAL_AI_ENABLED: "false"
  run: python main.py --analyze samples/phishing-en.eml --offline
```

Add an independent `docker-core` job using checkout and:

```yaml
- name: Build core image
  run: docker build --build-arg INSTALL_LOCAL_AI=false -t phishing-triage-bot:ci .
```

Keep the existing pre-commit configuration: its Ruff and Black versions already
satisfy the repository's development requirement ranges.

- [ ] **Step 3: Parse and inspect workflow diff**

Run:

```powershell
git diff --check
Select-String -Path .github/workflows/ci.yml -Pattern '3.12|3.13|Offline CLI smoke|docker build'
```

Expected: no whitespace errors and all four patterns are present.

- [ ] **Step 4: Commit**

```powershell
git add .github/workflows/ci.yml
git commit -m "ci: verify portfolio demo on supported Python"
```

### Task 3: Concise English and Vietnamese project documentation

**Files:**
- Rewrite: `README.md`
- Create: `docs/README.vi.md`
- Modify: `SECURITY.md`

**Interfaces:**
- Consumes the final CLI, samples, limits, local-AI behavior, Docker arguments, and measured metrics.
- Produces reciprocal language links and copy-pasteable demo commands.

- [ ] **Step 1: Record the approved human-documentation TDD exception**

The user approved review and runnable-command verification for human prose.
Do not add brittle tests that assert README wording. Verify reciprocal local
links with `Test-Path` and run the documented demo command in Step 4.

- [ ] **Step 2: Rewrite the English README around the recruiter journey**

Use these headings in this order:

```markdown
# Phishing Triage Assistant for SOC Analysts
[Tiếng Việt](docs/README.vi.md)

## Why This Project
## Five-Minute Demo
## Example Triage Output
## SOC Investigation Coverage
## How the Pipeline Works
## Local English–Vietnamese AI
## Installation
## Telegram Bot
## REST API
## Docker
## Testing and Security Controls
## Model Results and Limitations
## Responsible Use
## License
```

The five-minute demo must use a virtual environment, core requirements, and
this credential-free command:

```powershell
.\.venv\Scripts\python.exe main.py --analyze samples/phishing-en.eml --offline
```

Include a compact table mapping features to SOC skills: header/authentication
analysis, IOC extraction, URL/attachment triage, threat intelligence,
explainable scoring, local bilingual ML, secure API/bot handling, and reporting.
State the measured English macro-F1 `0.9812` and synthetic Vietnamese macro-F1
`0.8789`, including the already documented recall/FPR values. Say explicitly
that synthetic Vietnamese results do not establish production accuracy.

Under the local-AI and Docker sections, state that weights are intentionally
not stored in Git, preserve the concise `ml.prepare_data`, `ml.train_mmbert`,
and `ml.promote` reproduction commands from the current README, and include
this read-only mount example:

```powershell
docker build --build-arg INSTALL_LOCAL_AI=true -t phishing-triage-bot:ai .
docker run --rm --env-file .env -v "${PWD}/artifacts/models/phishing-mmbert:/app/artifacts/models/phishing-mmbert:ro" phishing-triage-bot:ai
```

- [ ] **Step 3: Create equivalent natural Vietnamese documentation**

Use these headings:

```markdown
# Trợ lý phân tích phishing dành cho SOC
[English](../README.md)

## Mục tiêu đồ án
## Demo trong năm phút
## Ví dụ báo cáo
## Năng lực SOC được thể hiện
## Pipeline hoạt động như thế nào
## AI local Anh–Việt
## Cài đặt
## Telegram Bot
## REST API
## Docker
## Kiểm thử và kiểm soát bảo mật
## Kết quả model và giới hạn
## Sử dụng có trách nhiệm
## Giấy phép
```

Translate meaning naturally, retain exact commands/variable names/metrics, and
use “dữ liệu tiếng Việt tổng hợp” for the synthetic-evaluation limitation.

- [ ] **Step 4: Expand the security boundary and verify documentation behavior**

Add `Supported Use` and `Handling Suspicious Samples` sections to
`SECURITY.md`. State that the project performs static triage, does not detonate
malware, samples must remain inert, unknown attachments should be opened only
in an approved sandbox, and secrets/model data must not be committed.

Run the actual link targets and documented quick demo:

```powershell
if (-not (Test-Path docs/README.vi.md)) { throw 'Missing Vietnamese README' }
if (-not (Test-Path README.md)) { throw 'Missing English README' }
$env:OFFLINE_MODE='true'
$env:LOCAL_AI_ENABLED='false'
.\.venv\Scripts\python.exe main.py --analyze samples/phishing-en.eml --offline
git diff --check
```

Expected: both reciprocal link targets exist, the documented demo exits 0
with a complete report, and no whitespace errors exist.

- [ ] **Step 5: Commit**

```powershell
git add README.md docs/README.vi.md SECURITY.md
git commit -m "docs: present SOC portfolio in English and Vietnamese"
```

### Task 4: Final repository verification

**Files:**
- Modify only files required by failures caused by this plan.

**Interfaces:**
- Consumes the completed security, demo, and packaging plans.
- Produces the final verified portfolio repository.

- [ ] **Step 1: Run the complete local gate from a clean environment**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests -W error
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m black --check api bot cli.py config email_analysis ml report scoring threat_intel main.py tests
.\.venv\Scripts\python.exe -m mypy api bot cli.py config email_analysis ml report scoring threat_intel --ignore-missing-imports --disable-error-code=import-untyped
.\.venv\Scripts\python.exe -m bandit -r api bot config email_analysis ml report scoring threat_intel -lll
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe -m pip_audit
git diff --check
git status --short
```

Expected: all checks exit 0 and only intentional plan-tracking edits, if any,
remain.

- [ ] **Step 2: Run local-AI smoke inference with the promoted artifact**

```powershell
$env:OFFLINE_MODE='true'
$env:LOCAL_AI_ENABLED='true'
.\.venv\Scripts\python.exe main.py --analyze samples/phishing-vi.eml --offline --output artifacts/final-demo-vi.md
Select-String -Path artifacts/final-demo-vi.md -Pattern 'Provider   : local|Model      : jhu-clsp/mmBERT-small'
```

Expected: command exits 0 and both local provider/model lines are found. The
generated report stays ignored and is not committed.

- [ ] **Step 3: Build the core container when Docker is available**

```powershell
docker info
docker build --build-arg INSTALL_LOCAL_AI=false -t phishing-triage-bot:final .
docker run --rm --env TELEGRAM_ENABLED=false phishing-triage-bot:final python main.py --healthcheck
```

Expected: when a daemon is available, build and health check exit 0. When no
daemon is available, report the exact limitation and use the GitHub Actions
Docker job as the required build gate.

- [ ] **Step 4: Review commits and working tree**

```powershell
git log --oneline --decorate -15
git status --short --branch
```

Expected: focused commits correspond to the plans, no secret or model artifact
is tracked, and the working tree is clean.
