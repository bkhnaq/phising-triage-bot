"""
Telegram Bot Handler
--------------------
Receives .eml file uploads from SOC analysts, triggers the analysis pipeline,
and sends the resulting phishing report back to the chat.

Uses python-telegram-bot (async, v20+).

Usage:
    from bot.telegram_handler import start_bot
    start_bot()
"""

import logging
import os
import tempfile

from telegram import Update
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

from config.settings import ALLOWED_CHAT_IDS, TELEGRAM_BOT_TOKEN, UPLOAD_DIR

logger = logging.getLogger(__name__)

# Maximum Telegram message length
_MAX_MSG_LEN = 4096


# ── Command handlers ─────────────────────────────────────────

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /start – greet the analyst."""
    if update.message is None:
        return
    await update.message.reply_text(
        "👋 Phishing Triage Bot ready!\n"
        "Send me an .eml file and I'll analyze it for phishing indicators."
    )


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /help – show usage instructions."""
    if update.message is None:
        return
    await update.message.reply_text(
        "📖 *How to use this bot*\n\n"
        "1. Forward or upload a suspicious email saved as an `.eml` file.\n"
        "2. The bot will parse headers, extract URLs & attachments, "
        "query threat-intel APIs, and compute a risk score.\n"
        "3. A full phishing triage report will be sent back to this chat.\n\n"
        "Commands:\n"
        "/start – Wake up the bot\n"
        "/help  – Show this message",
        parse_mode="Markdown",
    )


# ── Document handler ─────────────────────────────────────────

async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle uploaded documents – process .eml files."""
    if update.message is None or update.effective_chat is None:
        return

    # Access control
    if ALLOWED_CHAT_IDS and update.effective_chat.id not in ALLOWED_CHAT_IDS:
        await update.message.reply_text("⛔ Unauthorized chat.")
        return

    document = update.message.document
    if document is None or not document.file_name or not document.file_name.lower().endswith(".eml"):
        await update.message.reply_text(
            "⚠️ Please send a `.eml` file. Other file types are not supported."
        )
        return

    await update.message.reply_text("📨 Received! Analyzing the email…")

    # Download the file to a temp location
    tg_file = await document.get_file()
    local_path = os.path.join(UPLOAD_DIR, document.file_name)
    await tg_file.download_to_drive(local_path)

    try:
        report_text = _run_analysis(local_path)
    except Exception:
        logger.exception("Analysis failed for %s", local_path)
        await update.message.reply_text("❌ Analysis failed. Check bot logs for details.")
        return

    # Send report (split if longer than Telegram's limit)
    for chunk in _split_message(report_text):
        await update.message.reply_text(chunk)


# ── Analysis pipeline ────────────────────────────────────────

def _run_analysis(eml_path: str) -> str:
    """
    Run the full analysis pipeline on an .eml file and return the report text.

    This function imports and calls all analysis modules so that the bot module
    stays thin and the heavy logic lives in dedicated packages.
    """
    from email_analysis.email_parser import parse_eml_file
    from email_analysis.header_analyzer import analyze_headers
    from email_analysis.header_forensics import run_header_forensics
    from email_analysis.url_extractor import extract_urls
    from email_analysis.attachment_analyzer import extract_attachments
    from threat_intel.virustotal_checker import check_url as vt_check_url
    from threat_intel.virustotal_checker import check_file_hash as vt_check_hash
    from threat_intel.alienvault_checker import check_domain as otx_check_domain
    from threat_intel.alienvault_checker import check_file_hash as otx_check_hash
    from threat_intel.ip_reputation import check_ip_reputation
    from threat_intel.passive_dns import check_passive_dns
    from email_analysis.qr_code_analyzer import scan_attachments_for_qr, extract_qr_urls
    from email_analysis.heuristic_analyzer import run_heuristics
    from email_analysis.ai_classifier import classify_email
    from scoring.risk_scoring import calculate_risk
    from report.report_generator import generate_report

    # 1. Parse the email
    email_data = parse_eml_file(eml_path)

    # 2. Analyze authentication headers
    auth_results = analyze_headers(email_data["headers"])

    # 2b. SMTP relay chain forensics (origin IP, geolocation, relay path)
    header_forensics = run_header_forensics(email_data)

    # 3. Extract URLs
    urls = extract_urls(email_data["body_text"], email_data["body_html"])

    # 4. Extract attachments
    attachments = extract_attachments(email_data["raw_message"], save_dir=UPLOAD_DIR)

    # 5. Query VirusTotal for URLs
    vt_url_reports: list[dict] = []
    for u in urls:
        target = u.get("expanded_url", u["url"])
        report = vt_check_url(target)
        report["url"] = u["url"]
        report["is_shortened"] = u.get("is_shortened", False)
        vt_url_reports.append(report)

    # 6. Query VirusTotal for attachment hashes
    vt_hash_reports = [vt_check_hash(a["sha256"]) for a in attachments]

    # 7. Query AlienVault OTX for domains and hashes
    otx_reports: list[dict] = []
    seen_domains: set[str] = set()
    for u in urls:
        domain = u.get("domain", "")
        if domain and domain not in seen_domains:
            seen_domains.add(domain)
            otx_reports.append(otx_check_domain(domain))
    for a in attachments:
        otx_reports.append(otx_check_hash(a["sha256"]))

    # 8. Scan attachments for QR codes
    qr_findings = scan_attachments_for_qr(attachments)
    qr_urls = extract_qr_urls(qr_findings)

    # 8b. Run QR-extracted URLs through VT + OTX
    for qu in qr_urls:
        target = qu["url"]
        report = vt_check_url(target)
        report["url"] = target
        report["is_shortened"] = False
        vt_url_reports.append(report)

        domain = qu.get("domain", "")
        if domain and domain not in seen_domains:
            seen_domains.add(domain)
            otx_reports.append(otx_check_domain(domain))

    # 9. Combine body URLs + QR URLs for heuristic analysis
    all_urls = urls + qr_urls
    heuristics = run_heuristics(all_urls)

    # 10. IP reputation (AbuseIPDB + Spamhaus)
    all_domains = list(seen_domains)
    ip_reputation = check_ip_reputation(all_domains)

    # 11. Passive DNS (SecurityTrails)
    passive_dns = check_passive_dns(ip_reputation)

    # 11b. Display name spoofing & lookalike domain detection
    from email_analysis.phishing_rules import detect_display_name_spoofing, detect_lookalike_domains
    display_name_spoofing = detect_display_name_spoofing(email_data.get("from", ""))
    lookalike_domains = detect_lookalike_domains(all_urls)

    # 12. AI phishing classifier (augmented with rule-based findings)
    rule_findings = _build_rule_findings(auth_results, heuristics, header_forensics)
    ai_verdict = classify_email(email_data, all_urls, rule_findings)

    # 13. Calculate risk score
    risk = calculate_risk(
        auth_results, vt_url_reports, vt_hash_reports, otx_reports,
        heuristics, qr_findings, ip_reputation, passive_dns, ai_verdict,
        header_forensics=header_forensics,
        display_name_spoofing=display_name_spoofing,
        lookalike_domains=lookalike_domains,
    )

    # 14. Generate report
    return generate_report(
        email_data, auth_results, urls, attachments,
        risk, vt_url_reports, vt_hash_reports, otx_reports,
        heuristics, qr_findings, ip_reputation, passive_dns, ai_verdict,
        header_forensics=header_forensics,
        display_name_spoofing=display_name_spoofing,
        lookalike_domains=lookalike_domains,
    )


# ── Helpers ──────────────────────────────────────────────────

def _split_message(text: str, max_len: int = _MAX_MSG_LEN) -> list[str]:
    """Split a long message into chunks that fit Telegram's limit."""
    if len(text) <= max_len:
        return [text]
    chunks: list[str] = []
    while text:
        chunks.append(text[:max_len])
        text = text[max_len:]
    return chunks


def _build_rule_findings(
    auth_results: dict,
    heuristics: dict | None,
    header_forensics: dict | None = None,
) -> list[str]:
    """Build concise rule-based findings for AI classifier context."""
    findings: list[str] = []

    # Auth status findings
    for check in ("spf", "dkim", "dmarc"):
        result = auth_results.get(check, {}).get("result", "none")
        if result in ("fail", "softfail", "none"):
            findings.append(f"{check.upper()} {result}")

    # Header forensics findings (SPF/DKIM/DMARC-level header anomalies)
    for h in auth_results.get("forensics", {}).get("findings", []):
        summary = h.get("summary", "Header anomaly")
        findings.append(summary)

    # SMTP relay chain forensics warnings (network-level)
    if header_forensics:
        for w in header_forensics.get("warnings", []):
            # Skip pure geo-informational warnings — they add noise without signal
            if not w.startswith("Origin IP geolocation:"):
                findings.append(w)

    if heuristics:
        for f in heuristics.get("homograph_brands", [])[:3]:
            findings.append(
                f"Homograph brand: {f['brand']} in {f['original_domain']}"
            )
        for f in heuristics.get("suspicious_keywords", [])[:3]:
            findings.append(f"Suspicious keyword: {f['keyword']}")
        for f in heuristics.get("brand_impersonation", [])[:3]:
            findings.append(f"Brand impersonation: {f['brand']} in {f['domain']}")

    # Deduplicate while preserving order
    deduped: list[str] = []
    seen: set[str] = set()
    for item in findings:
        if item not in seen:
            seen.add(item)
            deduped.append(item)
    return deduped[:15]


# ── Bot entry point ──────────────────────────────────────────

def start_bot() -> None:
    """Build and run the Telegram bot (blocking)."""
    if not TELEGRAM_BOT_TOKEN:
        raise RuntimeError(
            "TELEGRAM_BOT_TOKEN is not set. "
            "Add it to your .env file or environment variables."
        )

    app = ApplicationBuilder().token(TELEGRAM_BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_document))

    logger.info("Phishing Triage Bot is polling…")
    # Pass stop_signals=None to avoid platform.system() WMI error on Windows + Python 3.13
    app.run_polling(stop_signals=None)
