# SOC Portfolio Hardening Design

## Goal

Turn the existing phishing triage bot into a polished, credible portfolio
project for Cybersecurity/SOC roles. The finished repository should be easy to
run and demonstrate, make its investigation logic understandable to an
interviewer, and handle untrusted email input safely enough for a local demo or
small single-host deployment.

The project remains a SOC triage assistant. It is not presented as an
enterprise detection platform or as a fully autonomous phishing decision
system.

## Intended Audience

- SOC analysts and cybersecurity interviewers evaluating the workflow.
- Developers running a local demonstration on Windows, Linux, or Docker.
- A small trusted team using either the Telegram bot or REST API on one host.

## Current Baseline

- The repository has one shared analysis pipeline used by Telegram and
  FastAPI.
- The pipeline covers email parsing, authentication results, header
  forensics, URL and redirect analysis, attachments, QR codes, threat
  intelligence, explainable risk scoring, and Markdown reporting.
- A promoted `jhu-clsp/mmBERT-small` artifact provides local English and
  Vietnamese classification. AI is one signal among several and does not
  replace deterministic evidence.
- The current baseline passes 194 tests, Ruff, Black, mypy, Bandit, and
  dependency auditing.
- Model weights, training data, runtime uploads, and secrets are intentionally
  excluded from Git.

## Design Principles

1. Prefer a reliable demo over enterprise infrastructure.
2. Keep one application and one analysis pipeline; do not introduce Redis,
   queues, databases, microservices, or a web dashboard.
3. Preserve explainability: every verdict must remain traceable to evidence.
4. Treat local AI as a useful SOC signal, not the sole source of truth.
5. Add controls only where they fix an observed correctness, security, or
   usability problem.
6. Keep existing commands and configuration compatible where practical.

## Functional Flow

1. An analyst supplies an RFC 5322 `.eml` message through Telegram, the REST
   API, or a new local CLI command.
2. The shared pipeline parses the message and inspects sender alignment,
   SPF/DKIM/DMARC evidence, relay headers, URLs, redirects, landing pages,
   attachments, QR codes, and available threat-intelligence results.
3. The promoted local mmBERT classifier evaluates English or Vietnamese text
   and returns its verdict and confidence. The scoring engine combines this
   with deterministic evidence rather than accepting it as a final decision.
4. The application produces an analyst-oriented report containing the risk
   score, verdict, evidence, extracted IOCs, AI provenance, limitations, and
   recommended response actions.

Telegram and FastAPI continue to call the same in-process pipeline. No
additional runtime service is required.

## Essential Security and Reliability Work

### Safe analysis of untrusted URLs

All network requests made to URLs extracted from an email will use one shared
safe-fetch component. Threat-intelligence requests to fixed vendor endpoints
remain separate.

The safe-fetch component will:

- accept only HTTP and HTTPS URLs;
- reject credentials embedded in a URL;
- resolve the target and reject loopback, private, link-local, multicast,
  reserved, unspecified, and otherwise non-global addresses;
- pin the connection to an address that passed validation so a second DNS
  answer cannot redirect the connection internally;
- follow redirects manually, validating every hop;
- ignore ambient proxy and credential configuration;
- apply connect/read timeouts, redirect limits, and response-byte limits; and
- return a small structured result for success, blocked targets, and network
  failures without exposing internal exception details.

URL expansion, redirect-chain inspection, landing-page inspection, and the
legacy redirect heuristic will reuse this component. `OFFLINE_MODE=true` will
continue to prevent all such requests.

### Bounded untrusted input

- Add an ASGI request-body limit so JSON and multipart requests are rejected
  before an unbounded body is accumulated.
- Stream `UploadFile` content to a temporary file in bounded chunks and stop
  as soon as the configured maximum is exceeded.
- Apply a matching character limit to raw-email JSON input.
- Bound the number of URLs, attachments, redirect hops, and landing pages sent
  through expensive analysis stages. Reports will state when evidence was
  truncated.
- Keep temporary-file cleanup in `finally` paths.

### Responsive Telegram handling

- Retain the early Telegram metadata size check.
- Verify the downloaded file's actual size before analysis.
- Run the synchronous analysis pipeline in a worker thread so Telegram's event
  loop remains responsive.
- Preserve sanitized filenames, authorization checks, message splitting, and
  cleanup behavior.

### Small API and configuration fixes

- Compare API keys with a constant-time function.
- Keep a bounded, expiring in-memory rate-limit map appropriate for a
  single-process portfolio application.
- Validate boolean values, ports, positive limits, risk thresholds, log level,
  and environment name at startup with actionable errors.
- Keep `/health` lightweight and retain the existing CLI health check. The
  startup validation and CLI health check will verify configuration, writable
  temporary storage, and the configured local model artifact without
  contacting external vendors. A separate readiness subsystem is unnecessary
  for this single-host portfolio application.
- Do not add distributed rate limiting, reverse-proxy logic, metrics servers,
  or authentication systems beyond the existing API key.

## Local AI Policy

The existing bilingual local classifier remains a highlighted feature.

- Local inference remains first choice when enabled and its promoted artifact
  is available.
- The application must continue to start and perform deterministic triage when
  the optional ML dependencies or artifact are unavailable; the report must
  clearly identify that AI was not checked.
- Cloud fallback is optional and explicitly configured. Portfolio/demo
  configuration defaults to local-only so email content is not unexpectedly
  sent to a third party.
- Existing artifact checksum, provenance, label-map, threshold, and
  safetensors validation remains intact.
- No retraining or threshold tuning is included in this hardening pass. The
  documented Vietnamese evaluation remains a synthetic rollout signal, not a
  claim of real-world production accuracy.

## Portfolio and Demo Experience

### Local CLI

Add a cross-platform command that analyzes one `.eml` file and writes or prints
the same report used by Telegram and FastAPI. It must work without Telegram or
API credentials and support offline demonstrations.

The CLI is the primary interview demo path because it minimizes setup and
external dependencies. Existing bot, API, and health-check modes remain
available.

### Safe samples

Commit four fictional `.eml` samples:

- legitimate English;
- phishing English;
- legitimate Vietnamese; and
- phishing Vietnamese.

Samples will use reserved `.test` domains, documentation IP ranges, inert
attachment content, and no live malicious infrastructure. Automated smoke
tests will confirm each sample is parseable and that the phishing/legitimate
pairs produce the intended broad risk ordering without overfitting tests to an
exact score.

### Analyst-oriented report

Keep the current Markdown report but make the interview-visible summary
consistent:

- verdict and score;
- top evidence and why it matters;
- extracted IOCs;
- local/cloud AI provider, model, confidence, and availability state;
- recommended containment or verification actions; and
- a short reminder that human validation and sandboxing may still be needed.

The API response contract will remain backward compatible unless a missing
field is strictly additive.

## Packaging and Documentation

- Add `.dockerignore` so secrets, Git history, virtual environments, training
  data, promoted artifacts, uploads, caches, and local worktrees never enter
  the build context.
- Keep one Dockerfile and document commands for bot or API mode. Provide a
  clear optional local-AI build/install path without baking the 316 MB private
  artifact into Git.
- Keep `README.md` as concise English project documentation and add a linked
  Vietnamese guide with equivalent quick-start, demo, architecture, security,
  model-metric, and limitation information.
- Replace unnecessarily long setup prose with a fast demo path, a feature
  table mapped to SOC skills, a compact architecture view, a sample report,
  and troubleshooting.
- Document how the model artifact is produced or mounted. Do not claim that a
  fresh clone includes weights that are intentionally ignored.
- Expand the security policy with the supported-use boundary and safe handling
  expectations for suspicious samples.

## Verification Strategy

Implementation will follow test-driven development. New focused tests will
cover:

- direct and redirected SSRF attempts, including DNS rebinding behavior;
- allowed public HTTP/HTTPS destinations through mocked transports;
- response-size, redirect, request-body, raw-email, URL-count, and upload
  limits;
- Telegram actual-size enforcement, thread offloading, and cleanup;
- API-key comparison behavior and bounded rate-limit state;
- invalid configuration values and CLI health-check states;
- CLI success/error exits and safe bilingual samples; and
- Docker-context exclusions and documentation commands where practical.

Final verification will run the full test suite with warnings treated as
errors, formatting, linting, type checking, Bandit, dependency auditing, CLI
smoke demonstrations, and a Docker build if a Docker daemon is available.

## Acceptance Criteria

The work is complete when:

1. English and Vietnamese sample emails can be analyzed locally with one
   documented command.
2. Telegram, API, and CLI use the shared pipeline and leave no temporary files
   after success or failure.
3. Email-controlled network requests cannot reach local or non-global
   addresses, including through redirects or DNS answer changes.
4. Untrusted request, file, URL, redirect, page, and attachment work is
   explicitly bounded.
5. The Telegram handler does not block its event loop during analysis.
6. The promoted local artifact still loads and reports its model/provider when
   present, while deterministic triage remains usable when it is absent.
7. Existing public interfaces remain compatible, and all old and new checks
   pass.
8. A recruiter can understand the architecture, security decisions, local-AI
   role, measured results, and limitations from the English or Vietnamese
   documentation without reading the implementation first.

## Explicit Non-goals

- Multi-user tenancy, SSO, RBAC, audit-log storage, or a database.
- Redis, task queues, microservices, Kubernetes, or horizontal scaling.
- A web dashboard or case-management interface.
- Automatic malware execution, detonation, or browser sandboxing.
- Training a new model, collecting production email, or claiming production
  Vietnamese accuracy.
- Publishing model weights or repository changes to external services as part
  of this implementation.
