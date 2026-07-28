# 🔍 Automated Phishing Triage Bot

A SOC (Security Operations Center) automation tool that analyzes suspicious phishing emails forwarded by analysts via Telegram and returns a structured security report.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                       Telegram Chat                              │
│              SOC analyst uploads .eml file                       │
└──────────────────────┬───────────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────────┐
│  bot/telegram_handler.py                                         │
│  • Receives the file                                             │
│  • Orchestrates the analysis pipeline                            │
│  • Sends the report back                                         │
└──────────────────────┬───────────────────────────────────────────┘
                       │
         ┌─────────────┼─────────────┐
         ▼             ▼             ▼
┌────────────┐ ┌─────────────┐ ┌──────────────┐
│ email_     │ │ threat_     │ │ scoring/     │
│ analysis/  │ │ intel/      │ │ risk_scoring │
│            │ │             │ │              │
│ • parser   │ │ • VirusTotal│ │ • Weighted   │
│ • headers  │ │ • AlienVault│ │   score 0-100│
│ • URLs     │ │   OTX       │ │ • Verdict    │
│ • attach.  │ │ • AbuseIPDB │ │              │
│ • QR codes │ │ • Security- │ │              │
│ • AI class.│ │   Trails    │ │              │
└────────────┘ └─────────────┘ └──────┬───────┘
                                      │
                                      ▼
                              ┌──────────────┐
                              │ report/      │
                              │ report_gen.  │
                              │              │
                              │ • Markdown   │
                              │   report     │
                              └──────────────┘
```

## Project Structure

```
phishing-triage-bot/
├── main.py                          # Entry point – starts the bot
├── config/
│   └── settings.py                  # Loads env vars & configuration
├── bot/
│   └── telegram_handler.py          # Telegram bot commands & file handler
├── email_analysis/
│   ├── email_parser.py              # Parses .eml files
│   ├── header_analyzer.py           # SPF / DKIM / DMARC checks
│   ├── header_forensics.py          # SMTP relay chain forensics
│   ├── url_extractor.py             # Extracts & expands URLs
│   ├── attachment_analyzer.py       # Extracts attachments, SHA-256 hashes
│   ├── heuristic_analyzer.py        # Brand impersonation, keywords, domain age
│   ├── homograph_analyzer.py        # Unicode / Cyrillic homograph detection
│   ├── qr_code_analyzer.py          # QR code scanning in image attachments
│   ├── ai_classifier.py             # Local-first AI routing + Groq fallback
│   ├── local_ai_classifier.py       # Offline mmBERT inference
│   └── phishing_rules.py            # Display name spoofing & lookalike domains
├── ml/                              # Data, training, evaluation and promotion
├── threat_intel/
│   ├── virustotal_checker.py        # VirusTotal v3 API integration
│   ├── alienvault_checker.py        # AlienVault OTX API integration
│   ├── ip_reputation.py             # AbuseIPDB + Spamhaus DNSBL checks
│   └── passive_dns.py               # SecurityTrails passive DNS lookups
├── scoring/
│   └── risk_scoring.py              # Weighted risk scoring engine
├── report/
│   └── report_generator.py          # Markdown report builder
├── requirements.txt
├── requirements-dev.txt
├── requirements-ml-runtime.txt
├── requirements-ml.txt
├── Dockerfile
├── .env.example
├── .gitignore
└── README.md
```

## Features

| # | Feature | Module |
|---|---------|--------|
| 1 | Receive `.eml` files via Telegram | `bot/telegram_handler.py` |
| 2 | Parse email headers & body | `email_analysis/email_parser.py` |
| 3 | SPF / DKIM / DMARC analysis | `email_analysis/header_analyzer.py` |
| 4 | SMTP relay chain forensics & IP geolocation | `email_analysis/header_forensics.py` |
| 5 | Extract all URLs from email body | `email_analysis/url_extractor.py` |
| 6 | Detect & expand shortened URLs | `email_analysis/url_extractor.py` |
| 7 | Extract attachments + SHA-256 hashes | `email_analysis/attachment_analyzer.py` |
| 8 | Brand impersonation & suspicious keywords | `email_analysis/heuristic_analyzer.py` |
| 9 | Unicode / Cyrillic homograph detection | `email_analysis/homograph_analyzer.py` |
| 10 | QR code scanning in image attachments | `email_analysis/qr_code_analyzer.py` |
| 11 | Display name spoofing detection | `email_analysis/phishing_rules.py` |
| 12 | Lookalike domain detection (Levenshtein) | `email_analysis/phishing_rules.py` |
| 13 | Local bilingual AI classification with bounded Groq fallback | `email_analysis/ai_classifier.py` |
| 14 | VirusTotal threat intelligence | `threat_intel/virustotal_checker.py` |
| 15 | AlienVault OTX threat intelligence | `threat_intel/alienvault_checker.py` |
| 16 | IP reputation (AbuseIPDB + Spamhaus) | `threat_intel/ip_reputation.py` |
| 17 | Passive DNS (SecurityTrails) | `threat_intel/passive_dns.py` |
| 18 | Weighted risk scoring (0-100) | `scoring/risk_scoring.py` |
| 19 | Formatted phishing report | `report/report_generator.py` |

## Quick Start

### 1. Clone & configure

```bash
git clone <your-repo-url>
cd phishing-triage-bot

# Create .env from the example
cp .env.example .env
# Edit .env and add your API keys
```

Windows PowerShell alternative:

```powershell
Copy-Item .env.example .env
```

### 2. Install dependencies

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate

pip install -r requirements.txt
# For local development/CI tooling (ruff, black, mypy, bandit, pip-audit)
pip install -r requirements-dev.txt
```

The core application and CI do not download model weights. To run the optional
local classifier on CPU:

```bash
pip install -r requirements-ml-runtime.txt
```

For NVIDIA CUDA, install the PyTorch wheel matching the host first. The verified
Windows setup for CUDA 13.0 is:

```powershell
pip install torch==2.13.0+cu130 --index-url https://download.pytorch.org/whl/cu130
pip install -r requirements-ml-runtime.txt
```

### 3. Get your API keys

| Service | Where to get the key | Required |
|---------|---------------------|----------|
| **Telegram Bot** | Chat with [@BotFather](https://t.me/BotFather) on Telegram | Yes |
| **VirusTotal** | https://www.virustotal.com/gui/my-apikey | Recommended |
| **AlienVault OTX** | https://otx.alienvault.com/accounts/signup | Recommended |
| **Groq AI** | https://console.groq.com/keys | Optional fallback for uncertain local predictions |
| **AbuseIPDB** | https://www.abuseipdb.com/account/api | Optional |
| **SecurityTrails** | https://securitytrails.com/app/signup | Optional |

> The bot runs without optional API keys — those modules will be skipped gracefully.

## Local Bilingual AI (English + Vietnamese)

Runtime classification is local-first:

1. The promoted `jhu-clsp/mmBERT-small` artifact runs from local files only.
2. High- and low-confidence probabilities return `phishing` or `legitimate`.
3. Uncertain results may use Groq when `AI_GROQ_FALLBACK=true`.
4. With `OFFLINE_MODE=true`, no AI or threat-intelligence network request is made.

Configure the artifact and routing in `.env`:

```dotenv
LOCAL_AI_ENABLED=true
LOCAL_AI_MODEL_DIR=artifacts/models/phishing-mmbert
LOCAL_AI_MAX_LENGTH=512
AI_GROQ_FALLBACK=true
```

The runtime validates checksums, label mappings, thresholds and safetensors
before loading. If the optional ML dependencies or artifact are absent, it
fails closed to the existing fallback policy instead of downloading a model.

### Reproduce training and promotion

Install the training extras after the runtime dependencies:

```bash
pip install -r requirements-ml.txt
```

Prepare the revision-pinned public datasets, build a bounded/cached Vietnamese
slice with the local Apache-2.0 MarianMT translator, train the baseline, then
fine-tune mmBERT. One-epoch passes keep export memory bounded on a verified
4 GB NVIDIA GPU:

```bash
python -m ml.prepare_data --source public --raw-dir data/raw --output-dir data/processed/phishing --seed 42
python -m ml.augment_vietnamese_local --input data/processed/phishing/train.jsonl --output data/processed/phishing/train.vi.jsonl --cache-dir artifacts/augmentation-cache-local --split train --batch-size 8 --max-records 500 --max-source-chars 2000 --seed 42
python -m ml.augment_vietnamese_local --input data/processed/phishing/validation.jsonl --output data/processed/phishing/validation.vi.jsonl --cache-dir artifacts/augmentation-cache-local --split validation --batch-size 8 --max-records 200 --max-source-chars 2000 --seed 42
python -m ml.augment_vietnamese_local --input data/processed/phishing/test.jsonl --output data/processed/phishing/test.vi.jsonl --cache-dir artifacts/augmentation-cache-local --split test --batch-size 8 --max-records 200 --max-source-chars 2000 --seed 42
python -m ml.train_baseline --data-dir data/processed/phishing --output-dir artifacts/baseline-full --seed 42
python -m ml.train_mmbert --data-dir data/processed/phishing --train-augmentation data/processed/phishing/train.vi.jsonl --output-dir artifacts/mmbert-epoch1 --epochs 1 --seed 42
python -m ml.promote manifest --candidate artifacts/mmbert-epoch1
python -m ml.train_mmbert --data-dir data/processed/phishing --train-augmentation data/processed/phishing/train.vi.jsonl --train-augmentation data/processed/phishing/train.vi.jsonl --train-augmentation data/processed/phishing/train.vi.jsonl --train-augmentation data/processed/phishing/train.vi.jsonl --initial-model-dir artifacts/mmbert-epoch1 --output-dir artifacts/mmbert-weights --epochs 1 --learning-rate 3e-6 --seed 42
python -m ml.promote manifest --candidate artifacts/mmbert-weights
python -m ml.train_mmbert --data-dir data/processed/phishing --validation-augmentation data/processed/phishing/validation.vi.jsonl --test-augmentation data/processed/phishing/test.vi.jsonl --initial-model-dir artifacts/mmbert-weights --output-dir artifacts/mmbert-candidate --evaluate-only --min-recall 0.95 --min-vietnamese-recall 0.90 --max-vietnamese-fpr 0.20 --seed 42
python -m ml.promote manifest --candidate artifacts/mmbert-candidate
python -m ml.promote promote --candidate artifacts/mmbert-candidate --target artifacts/models/phishing-mmbert --baseline-metrics artifacts/baseline-full/metrics.json
```

The translator is downloaded once at its pinned revision, then generation is
local, content-addressed and safe to resume. URLs, domains, currency amounts and
attachment names are preserved rather than translated. Invalid cache entries
are quarantined and regenerated. Training verifies the prepared-dataset
checksums and group isolation, then exports a merged provenance manifest with
every augmentation checksum, generation manifest and oversampling
multiplicity. Warm starts must match the pinned model ID and revision recorded
by the source artifact. Train and test synthetic records are generated from
separate source splits. The Groq
augmenter remains available as an optional alternative, but may consume API
daily-token quota.

Promotion is atomic and is rejected unless English phishing recall is at least
0.90, English false-positive rate is at most 0.05, English macro-F1 matches or
exceeds the baseline, synthetic Vietnamese phishing recall is at least 0.85,
and synthetic Vietnamese false-positive rate is at most 0.20. The verified
promoted run scored English macro-F1 `0.9812` (recall `0.9761`, FPR `0.0141`)
and synthetic Vietnamese macro-F1 `0.8789` (recall `0.94`, FPR `0.1818`) on
1,506 English and 199 held-out Vietnamese records. Synthetic Vietnamese
metrics are a rollout gate, not a substitute for monitoring labeled production
email.

### 4. Run the bot

```bash
python main.py
```

### 5. Use it

1. Open Telegram and start a chat with your bot.
2. Send `/start` to confirm it's alive.
3. Upload a `.eml` file.
4. Wait for the phishing triage report.

## Running with Docker

`pyzbar` requires the native `zbar` library. The provided Dockerfile installs `libzbar0`, so the container runs out-of-the-box.

```bash
docker build -t phishing-triage-bot .
docker run --env-file .env phishing-triage-bot
```

Run API mode:

```bash
docker run --env-file .env -p 8000:8000 phishing-triage-bot python main.py --api
```

## API Authentication (API_KEY Required)

By default, API endpoints (except `/health`) require `API_KEY`. If `API_KEY` is missing in production mode, the API returns:

```json
{
        "success": false,
        "error": {
                "code": "service_unavailable",
                "message": "API is disabled. Please configure API_KEY in environment variables."
        }
}
```

Set the key:

```bash
export API_KEY=your_key
```

Call the API with the header:

```bash
curl -X POST http://localhost:8000/analyze_email \
        -H "content-type: application/json" \
        -H "x-api-key: your_key" \
        -d '{"email_raw":"From: a@b.com\nTo: c@d.com\nSubject: test\n\nhello"}'
```

Development mode behavior:

- `ENV=dev` and missing `API_KEY` → requests are allowed (local testing only).
- `ENV=prod` (default) and missing `API_KEY` → API is disabled for protected endpoints.

## API Notes

- Every API response includes `request_id` for traceability.
- Every API response also includes an `X-Request-ID` header.
- API errors use a consistent JSON envelope: `success`, `request_id`, and `error`.
- Basic in-memory rate limiting is enabled and configurable via env vars.

## CI / Security Checks

- CI runs Bandit and is configured to fail only on high-severity issues.

## Data Handling

- Uploaded `.eml` files are written under `UPLOAD_DIR` (default: `uploads/`) during processing.
- API and Telegram temporary `.eml` files are deleted in a best-effort cleanup step after analysis.

## Limits

- Maximum upload size is controlled by `MAX_UPLOAD_SIZE_BYTES` (default: `10485760`, i.e., 10 MB).

## Runtime Tuning

- `OFFLINE_MODE=true` skips external network lookups (VT/OTX/WHOIS/DNS/redirects/Groq) for local demos and deterministic tests. The promoted local classifier still runs offline.
- `LOCAL_AI_MAX_LENGTH` controls runtime token truncation (default: `512`, matching training and threshold calibration).
- `THREAT_INTEL_CACHE_TTL_SECONDS` controls the in-memory cache TTL for external lookups (default: `900`).
- `THREAT_INTEL_MAX_WORKERS` controls parallel lookup fan-out for independent threat-intel checks (default: `8`).

## Detection Logic Notes

- Domains are canonicalized with Public Suffix List support (`tldextract`) before brand, lookalike, ESP, and sender-alignment comparisons.
- URLs are normalized and checked for obfuscation patterns such as userinfo hosts (`brand.com@evil.test`), punycode, IP hosts, encoded delimiters, and credential-style paths.
- Threat-intel wrappers distinguish `clean`, `suspicious`, `malicious`, `not_found`, `not_checked`, and `unavailable` states.
- The scoring engine includes cross-signal correlation rules, for example auth anomalies plus brand impersonation plus credential collection.

## Troubleshooting

- Missing `API_KEY`: protected API endpoints return disabled/unauthorized errors; set `API_KEY` (or `API_PROTECTION_ENABLED=false` for local-only testing).
- Missing `TELEGRAM_TOKEN`: bot startup fails fast; set `TELEGRAM_TOKEN` (or `TELEGRAM_BOT_TOKEN`) or disable with `TELEGRAM_ENABLED=false`.
- Docker QR dependency: if QR scanning fails, ensure `libzbar0` is present (included in the provided Dockerfile).

## How the Analysis Pipeline Works

1. **Parse** – The `.eml` file is parsed using Python's built-in `email` library. Subject, sender, recipient, date, body (text + HTML), and raw headers are extracted.

2. **Authenticate** – The `Received-SPF` and `Authentication-Results` headers are inspected to determine pass/fail status for SPF, DKIM, and DMARC.

3. **Header Forensics** – The SMTP relay chain is reconstructed from `Received` headers. The origin IP is geolocated and checked for hosting/proxy indicators.

4. **Extract URLs** – All URLs are extracted from both the plain-text and HTML bodies. Known URL-shortener domains (bit.ly, t.co, etc.) are detected and expanded.

5. **Extract Attachments** – MIME attachments are saved to disk and their SHA-256 hashes are computed.

6. **QR Code Scanning** – Image attachments are scanned for embedded QR codes. Any URLs found are fed into the analysis pipeline.

7. **Heuristic Analysis** – Domains are checked for brand impersonation, suspicious keywords, high entropy, homograph attacks, domain age, and redirect chains.

8. **Display Name Spoofing** – The sender display name is checked for protected brand names that don't match the sender domain.

9. **Lookalike Domain Detection** – URL domains are compared against protected brands using Levenshtein edit distance (≤ 2 triggers detection).

10. **Threat Intel** – URLs, URL domains, and attachment hashes are checked against VirusTotal and AlienVault OTX. IPs are checked against AbuseIPDB and Spamhaus. SecurityTrails provides passive DNS data.

11. **AI Classification** – The local bilingual mmBERT classifier runs first. Only uncertain or unavailable local results may use the optional Groq fallback.

12. **Risk Scoring** – A weighted score (0-100) is calculated from all indicators and mapped to a verdict: **LOW**, **MEDIUM**, **HIGH**, or **CRITICAL**.

13. **Report** – A Markdown-formatted report is generated with all findings and sent back to the Telegram chat.

## Risk Scoring Breakdown

| Indicator | Points |
|-----------|--------|
| SPF fail/softfail/none | +15 |
| DKIM fail/none | +15 |
| DMARC fail/none | +20 |
| Malicious URL (per URL) | +20 |
| Suspicious URL (per URL) | +10 |
| Shortened URL (per URL) | +5 |
| Malicious attachment hash | +25 |
| AlienVault OTX pulse hit | +10 |
| Brand impersonation in URL | +25 |
| Suspicious keyword in domain | +15 |
| Display name spoofing | +20 |
| Lookalike domain (Levenshtein) | +20 |
| QR code with URL | +15 |
| Blacklisted IP (AbuseIPDB/Spamhaus) | +20 |
| AI verdict: phishing | +25 |
| AI verdict: suspicious | +10 |
| SMTP relay anomalies | +10–15 |

Score is capped at 100. Thresholds are configurable via environment variables.

## Security Disclaimer

This project is for educational and defensive security workflows (SOC triage, awareness, and testing). It is not guaranteed to detect all phishing campaigns and must not be used as the sole control for production security decisions.

Always:

- Validate high-risk findings with human review.
- Follow your organization’s legal/compliance policies.
- Use isolated test data where possible.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
