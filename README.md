# Phishing Triage Assistant for SOC Analysts

[Tiếng Việt](docs/README.vi.md)

## Why This Project

This is a portfolio-scale cybersecurity project for triaging suspicious RFC 5322 email files. It gives an analyst a repeatable, explainable risk assessment without pretending to be a replacement for a mail gateway, sandbox, or human incident responder.

The same analysis pipeline is available through a credential-free CLI, a Telegram bot, and a FastAPI service. The project is deliberately local-first, bounded, and easy to demonstrate in an interview.

## Five-Minute Demo

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:OFFLINE_MODE='true'
$env:LOCAL_AI_ENABLED='false'
.\.venv\Scripts\python.exe main.py --analyze samples/phishing-en.eml --offline
```

The four inert samples in [`samples/`](samples) use only reserved `.test` domains. Try the Vietnamese sample too:

```powershell
.\.venv\Scripts\python.exe main.py --analyze samples/phishing-vi.eml --offline --output artifacts\demo-phishing-vi.md
```

## Example Triage Output

The report contains an analyst-friendly threat summary, authentication evidence, IOC summary, score explanation, and verdict-driven next actions:

```text
RISK ASSESSMENT
Score   : 100 / 100
Verdict : CRITICAL

RECOMMENDED SOC ACTIONS
• Quarantine the message and block confirmed malicious IOCs.
• Check whether recipients clicked links, opened attachments, or entered credentials.
```

## SOC Investigation Coverage

| Capability | SOC skill demonstrated |
|---|---|
| Header and SPF/DKIM/DMARC analysis | Email authentication triage |
| IOC extraction and summary | URL, domain, and SHA-256 handling |
| URL, redirect, QR, and attachment triage | Phishing and malware investigation |
| VirusTotal, OTX, IP reputation, passive DNS | Threat-intelligence enrichment |
| Explainable weighted scoring | Evidence correlation and prioritization |
| Local English–Vietnamese classifier | Safe local ML inference and provenance |
| Hardened API and Telegram ingestion | Input validation, SSRF defenses, rate limits, cleanup |
| SOC report and recommended actions | Analyst communication and incident response |

## How the Pipeline Works

1. Parse a `.eml` file and recover headers/body safely.
2. Check authentication, header anomalies, display-name spoofing, and language signals.
3. Extract bounded URLs, QR URLs, attachments, and SHA-256 hashes.
4. Perform bounded URL/domain/threat-intel analysis; `--offline` prevents network enrichment.
5. Combine deterministic evidence and optional AI output into an explainable score and report.

Network URL fetching rejects private/mixed DNS answers, pins validated public IPs, revalidates redirects, bounds data/redirects/deadlines, and failure-contains malformed input.

## Local English–Vietnamese AI

The optional local-first classifier uses a promoted `jhu-clsp/mmBERT-small` artifact. Weights are intentionally not stored in Git. When the artifact or ML dependencies are unavailable, the report exposes that AI is unavailable while deterministic evidence still runs.

Latest verified local run (seed 42, 9 August 2026):

| Test slice | Macro F1 | Phishing recall | False-positive rate |
|---|---:|---:|---:|
| English (1,506 emails) | 0.9888 | 0.9847 | 0.0076 |
| Synthetic Vietnamese (100 emails) | 0.8800 | 0.8600 | 0.1000 |

Vietnamese metrics use locally translated synthetic emails; they demonstrate a reproducible bilingual evaluation path, not production accuracy on real Vietnamese mail.

After installing `requirements-ml.txt`, reproduce the data and first candidate with:

```powershell
python -m ml.prepare_data --source public --raw-dir data/raw --output-dir data/processed/phishing --seed 42
python -m ml.train_baseline --data-dir data/processed/phishing --output-dir artifacts/baseline-full --seed 42
python -m ml.augment_vietnamese_local --input data/processed/phishing/train.jsonl --output data/processed/phishing/train.vi.jsonl --cache-dir artifacts/augmentation-cache-local --split train --max-records 500 --max-source-chars 2000 --seed 42
python -m ml.augment_vietnamese_local --input data/processed/phishing/validation.jsonl --output data/processed/phishing/validation.vi.jsonl --cache-dir artifacts/augmentation-cache-local --split validation --max-records 200 --max-source-chars 2000 --seed 42
python -m ml.augment_vietnamese_local --input data/processed/phishing/test.jsonl --output data/processed/phishing/test.vi.jsonl --cache-dir artifacts/augmentation-cache-local --split test --max-records 100 --max-source-chars 2000 --seed 42
python -m ml.train_mmbert --data-dir data/processed/phishing --output-dir artifacts/mmbert-candidate --train-augmentation data/processed/phishing/train.vi.jsonl --validation-augmentation data/processed/phishing/validation.vi.jsonl --test-augmentation data/processed/phishing/test.vi.jsonl --max-length 256 --epochs 1 --seed 42
python -m ml.promote manifest --candidate artifacts/mmbert-candidate
python -m ml.train_mmbert --data-dir data/processed/phishing --initial-model-dir artifacts/mmbert-candidate --output-dir artifacts/mmbert-candidate-v2 --train-augmentation data/processed/phishing/train.vi.jsonl --train-augmentation data/processed/phishing/train.vi.jsonl --train-augmentation data/processed/phishing/train.vi.jsonl --train-augmentation data/processed/phishing/train.vi.jsonl --validation-augmentation data/processed/phishing/validation.vi.jsonl --test-augmentation data/processed/phishing/test.vi.jsonl --max-length 256 --epochs 1 --learning-rate 3e-6 --seed 42
python -m ml.promote manifest --candidate artifacts/mmbert-candidate-v2
python -m ml.promote promote --candidate artifacts/mmbert-candidate-v2 --target artifacts/models/phishing-mmbert --baseline-metrics artifacts/baseline-full/metrics.json
```

Promotion is intentionally refused unless English performance beats the baseline and both language slices meet recall/FPR gates. A failed candidate remains available for an auditable low-learning-rate warm start rather than replacing the active model.

## Installation

Core CLI/API/bot dependencies:

```powershell
pip install -r requirements.txt
pip install -r requirements-dev.txt  # optional quality tooling
```

For optional local inference, install a compatible Torch wheel for the host, then:

```powershell
pip install -r requirements-ml-runtime.txt
```

Copy `.env.example` to `.env` only when using external services, the bot, API authentication, or a local model artifact. The offline CLI demo needs no token or API key.

## Telegram Bot

Set `TELEGRAM_TOKEN` in `.env` and run:

```powershell
python main.py
```

The bot accepts `.eml` files, checks metadata and actual downloaded size, offloads analysis from the event loop, and deletes temporary files after processing.

## REST API

Start the API with `API_KEY` configured (or use `ENV=dev` for local-only testing):

```powershell
python main.py --api
```

Protected endpoints return a request ID and an `X-Request-ID` header. `POST /analyze_email` and `POST /analyze_file` return report text, risk evidence, AI provider/model provenance, and analysis-limit metadata.

## Docker

The core image excludes secrets, artifacts, datasets, uploads, caches, and worktrees from the build context. It does not download PyTorch:

```powershell
docker build --build-arg INSTALL_LOCAL_AI=false -t phishing-triage-bot:core .
docker run --rm --env TELEGRAM_ENABLED=false phishing-triage-bot:core python main.py --healthcheck
```

Build the optional CPU local-AI image and mount weights read-only:

```powershell
docker build --build-arg INSTALL_LOCAL_AI=true -t phishing-triage-bot:ai .
docker run --rm --env-file .env -v "${PWD}/artifacts/models/phishing-mmbert:/app/artifacts/models/phishing-mmbert:ro" phishing-triage-bot:ai
```

## Testing and Security Controls

```powershell
python -m pytest -q tests -W error
python -m ruff check .
python -m black --check api bot cli.py config email_analysis ml report scoring threat_intel main.py tests
python -m mypy api bot cli.py config email_analysis ml report scoring threat_intel --ignore-missing-imports --disable-error-code=import-untyped
python -m bandit -r api bot config email_analysis ml report scoring threat_intel -lll
python -m pip_audit
```

GitHub Actions runs this quality/security gate on Python 3.12 and 3.13, plus an offline CLI smoke test and core Docker build.

## Model Results and Limitations

The promoted evaluation measured English macro-F1 **0.9812**, phishing recall **0.9761**, and false-positive rate **0.0141**. Its synthetic Vietnamese evaluation measured macro-F1 **0.8789**, recall **0.94**, and false-positive rate **0.1818**.

Synthetic Vietnamese results are useful for regression evaluation only; they do not establish production accuracy. Model output is one input to the deterministic, explainable SOC triage evidence and must be human-validated.

## Responsible Use

Use this project for defensive triage, education, and controlled testing. Do not use it to detonate malware, automatically punish users, or make high-impact decisions without approved investigation and human review. See [SECURITY.md](SECURITY.md) for sample and secret-handling guidance.

## License

MIT. See [LICENSE](LICENSE).
