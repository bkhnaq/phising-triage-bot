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
│   ├── ai_classifier.py             # AI phishing classifier (Gemini)
│   └── phishing_rules.py            # Display name spoofing & lookalike domains
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
| 13 | AI phishing classification (Gemini) | `email_analysis/ai_classifier.py` |
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

### 3. Get your API keys

| Service | Where to get the key | Required |
|---------|---------------------|----------|
| **Telegram Bot** | Chat with [@BotFather](https://t.me/BotFather) on Telegram | Yes |
| **VirusTotal** | https://www.virustotal.com/gui/my-apikey | Recommended |
| **AlienVault OTX** | https://otx.alienvault.com/accounts/signup | Recommended |
| **Groq AI** | https://console.groq.com/keys | Optional |
| **AbuseIPDB** | https://www.abuseipdb.com/account/api | Optional |
| **SecurityTrails** | https://securitytrails.com/app/signup | Optional |

> The bot runs without optional API keys — those modules will be skipped gracefully.

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

10. **Threat Intel** – Each URL domain and attachment hash is checked against VirusTotal and AlienVault OTX. IPs are checked against AbuseIPDB and Spamhaus. SecurityTrails provides passive DNS data.

11. **AI Classification** – The email is sent to Google Gemini for an independent phishing/suspicious/legitimate verdict.

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
