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

    Uses the modular PhishingPipeline orchestrator.
    """
    from email_analysis.pipeline import PhishingPipeline

    pipeline = PhishingPipeline()
    result = pipeline.analyze_file(eml_path)
    return result["report"]


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
