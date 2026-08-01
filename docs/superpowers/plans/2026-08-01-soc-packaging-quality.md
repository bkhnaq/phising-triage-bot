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
- Create `tests/test_packaging.py`: static packaging safeguards.
- Modify `.github/workflows/ci.yml`: Python 3.12/3.13 quality matrix, CLI smoke, core Docker build.
- Rewrite `README.md`: English recruiter-facing project page.
- Create `docs/README.vi.md`: Vietnamese counterpart.
- Modify `SECURITY.md`: safe sample handling and supported-use boundary.

### Task 1: Safe and optional-AI Docker packaging

**Files:**
- Create: `.dockerignore`
- Modify: `Dockerfile`
- Modify: `requirements.txt`
- Create: `tests/test_packaging.py`

**Interfaces:**
- Produces build: `docker build --build-arg INSTALL_LOCAL_AI=false -t phishing-triage-bot:core .`.
- Produces build: `docker build --build-arg INSTALL_LOCAL_AI=true -t phishing-triage-bot:ai .`.
- Runtime model mount remains `/app/artifacts/models/phishing-mmbert`.

- [ ] **Step 1: Write failing packaging tests**

```python
from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_dockerignore_excludes_private_and_large_state() -> None:
    patterns = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    required = {".env", ".git", ".venv", ".worktrees", "artifacts", "data", "uploads", "logs"}
    assert required <= {line.strip().rstrip("/") for line in patterns}


def test_dockerfile_has_optional_local_ai_build() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "ARG INSTALL_LOCAL_AI=false" in dockerfile
    assert "requirements-ml-runtime.txt" in dockerfile
    assert "download.pytorch.org/whl/cpu" in dockerfile
    assert "USER botuser" in dockerfile
```

- [ ] **Step 2: Run tests and confirm RED**

Run: `.\.venv\Scripts\python.exe -m pytest -q tests/test_packaging.py`

Expected: FAIL because `.dockerignore` does not exist and the Dockerfile has no
optional AI install path.

- [ ] **Step 3: Add exact Docker context exclusions**

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

- [ ] **Step 4: Add the optional CPU-AI build path**

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

- [ ] **Step 5: Run tests, dependency check, and available Docker build**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_packaging.py
.\.venv\Scripts\python.exe -m pip check
docker info
docker build --build-arg INSTALL_LOCAL_AI=false -t phishing-triage-bot:core .
```

Expected: Python checks PASS. If `docker info` reports no daemon, record that
the build is deferred and rely on the CI build in Task 2; do not claim a local
Docker build passed.

- [ ] **Step 6: Commit**

```powershell
git add .dockerignore Dockerfile requirements.txt tests/test_packaging.py
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
- Modify: `tests/test_packaging.py`

**Interfaces:**
- Consumes the final CLI, samples, limits, local-AI behavior, Docker arguments, and measured metrics.
- Produces reciprocal language links and copy-pasteable demo commands.

- [ ] **Step 1: Write failing documentation contract tests**

```python
def test_readmes_link_each_other_and_document_demo() -> None:
    english = (ROOT / "README.md").read_text(encoding="utf-8")
    vietnamese = (ROOT / "docs" / "README.vi.md").read_text(encoding="utf-8")
    for text in (english, vietnamese):
        assert "samples/phishing-en.eml" in text
        assert "--analyze" in text
        assert "0.9812" in text
        assert "0.8789" in text
        assert "synthetic" in text.lower() or "tổng hợp" in text.lower()
    assert "docs/README.vi.md" in english
    assert "../README.md" in vietnamese
```

- [ ] **Step 2: Run test and confirm RED**

Run: `.\.venv\Scripts\python.exe -m pytest -q tests/test_packaging.py`

Expected: FAIL because the Vietnamese README and CLI demo documentation are
absent.

- [ ] **Step 3: Rewrite the English README around the recruiter journey**

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

- [ ] **Step 4: Create equivalent natural Vietnamese documentation**

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

- [ ] **Step 5: Expand the security boundary**

Add `Supported Use` and `Handling Suspicious Samples` sections to
`SECURITY.md`. State that the project performs static triage, does not detonate
malware, samples must remain inert, unknown attachments should be opened only
in an approved sandbox, and secrets/model data must not be committed.

- [ ] **Step 6: Run doc contract and link checks, then commit**

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_packaging.py
rg -n "docs/README.vi.md|samples/phishing-en.eml|0.9812|0.8789" README.md docs/README.vi.md
git diff --check
```

Expected: tests PASS, each required term appears in both language documents,
and no whitespace errors exist.

```powershell
git add README.md docs/README.vi.md SECURITY.md tests/test_packaging.py
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
