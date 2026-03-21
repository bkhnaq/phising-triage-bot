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
import re
import unicodedata
import uuid
from pathlib import Path

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
    if (
        document is None
        or not document.file_name
        or not document.file_name.lower().endswith(".eml")
    ):
        await update.message.reply_text(
            "⚠️ Please send a `.eml` file. Other file types are not supported."
        )
        return

    await update.message.reply_text("📨 Received! Analyzing the email…")

    # Download the file to a temp location
    tg_file = await document.get_file()
    analysis_id = uuid.uuid4().hex[:8]
    local_path = _safe_upload_path(document.file_name, prefix=f"tg_{analysis_id}")
    await tg_file.download_to_drive(str(local_path))

    try:
        logger.info(
            "Starting Telegram analysis id=%s chat_id=%s file=%s",
            analysis_id,
            update.effective_chat.id,
            local_path.name,
        )
        report_text = _run_analysis(str(local_path))
    except Exception:
        logger.exception("Analysis failed id=%s for %s", analysis_id, local_path)
        await update.message.reply_text(
            "❌ Analysis failed. Check bot logs for details."
        )
        return
    finally:
        try:
            local_path.unlink(missing_ok=True)
        except OSError:
            logger.debug("Could not clean up temporary upload: %s", local_path)

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
    """Split long text at logical boundaries while respecting Telegram limits."""
    if len(text) <= max_len:
        return [text]

    paragraph_break = "\n\n"
    paragraphs = text.split(paragraph_break)
    chunks: list[str] = []
    current = ""

    for paragraph in paragraphs:
        block = paragraph if not current else f"{paragraph_break}{paragraph}"
        if len(current) + len(block) <= max_len:
            current += block
            continue

        if current:
            chunks.extend(_split_large_block(current, max_len))
            current = ""

        if len(paragraph) <= max_len:
            current = paragraph
        else:
            chunks.extend(_split_large_block(paragraph, max_len))

    if current:
        chunks.extend(_split_large_block(current, max_len))

    return _balance_markdown_fences(chunks)


def _split_large_block(text: str, max_len: int) -> list[str]:
    """Split a large block by line boundaries first, then by spaces."""
    if len(text) <= max_len:
        return [text]

    chunks: list[str] = []
    lines = text.split("\n")
    current = ""

    for line in lines:
        candidate = line if not current else f"{current}\n{line}"
        if len(candidate) <= max_len:
            current = candidate
            continue

        if current:
            chunks.append(current)
            current = ""

        if len(line) <= max_len:
            current = line
            continue

        words = line.split(" ")
        word_chunk = ""
        for word in words:
            candidate_word = word if not word_chunk else f"{word_chunk} {word}"
            if len(candidate_word) <= max_len:
                word_chunk = candidate_word
            else:
                if word_chunk:
                    chunks.append(word_chunk)
                if len(word) > max_len:
                    chunks.extend(
                        word[i : i + max_len] for i in range(0, len(word), max_len)
                    )
                    word_chunk = ""
                else:
                    word_chunk = word

        if word_chunk:
            current = word_chunk

    if current:
        chunks.append(current)

    return chunks


def _balance_markdown_fences(chunks: list[str]) -> list[str]:
    """Avoid splitting a message with unbalanced fenced code blocks."""
    if not chunks:
        return []

    balanced: list[str] = []
    fence_open = False
    for chunk in chunks:
        candidate = chunk
        if fence_open:
            candidate = f"```\n{candidate}"

        fence_count = len(re.findall(r"```", candidate))
        if fence_count % 2 == 1:
            candidate = f"{candidate}\n```"
            fence_open = True
        else:
            fence_open = False

        balanced.append(candidate)

    return balanced


def _sanitize_filename(filename: str | None) -> str:
    normalized = unicodedata.normalize("NFKC", filename or "email.eml")
    name_only = Path(normalized).name
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", name_only)
    return safe[:100] or "email.eml"


def _safe_upload_path(filename: str | None, prefix: str) -> Path:
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    base_dir = Path(UPLOAD_DIR).resolve()
    safe_name = _sanitize_filename(filename)
    destination = (base_dir / f"{prefix}_{safe_name}").resolve()
    if destination.parent != base_dir:
        raise ValueError("Unsafe upload path detected")
    return destination


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
