"""
Configuration settings for the Phishing Triage Bot.

Loads API keys and settings from environment variables.
Uses python-dotenv to read from a .env file during local development.
"""

import os
from dotenv import load_dotenv

# Load environment variables from .env file (if it exists)
load_dotenv()


# ── Telegram Bot ─────────────────────────────────────────────
_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"0", "false", "no", "off"})


def _get_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise ValueError(f"{name} must be a boolean (true/false)")


def _get_int(
    name: str,
    default: int,
    *,
    minimum: int,
    maximum: int | None = None,
) -> int:
    raw = os.getenv(name)
    try:
        value = int(raw) if raw is not None else default
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if value < minimum or (maximum is not None and value > maximum):
        upper = f" and {maximum}" if maximum is not None else ""
        raise ValueError(f"{name} must be between {minimum}{upper}")
    return value


TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", os.getenv("TELEGRAM_BOT_TOKEN", ""))
TELEGRAM_BOT_TOKEN = TELEGRAM_TOKEN  # Backward-compatible alias
TELEGRAM_ENABLED = _get_bool("TELEGRAM_ENABLED", True)

# Restrict the bot to specific chat IDs (comma-separated in .env)
# Leave empty to allow all chats (not recommended for production)
_allowed = os.getenv("ALLOWED_CHAT_IDS", "")
ALLOWED_CHAT_IDS: list[int] = (
    [int(cid.strip()) for cid in _allowed.split(",") if cid.strip()] if _allowed else []
)

# ── AI Classifier ────────────────────────────────────────────
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
LOCAL_AI_ENABLED = _get_bool("LOCAL_AI_ENABLED", True)
LOCAL_AI_MODEL_DIR = os.getenv(
    "LOCAL_AI_MODEL_DIR", "artifacts/models/phishing-mmbert-v2"
)
LOCAL_AI_MAX_LENGTH = _get_int("LOCAL_AI_MAX_LENGTH", 256, minimum=1)
AI_GROQ_FALLBACK = _get_bool("AI_GROQ_FALLBACK", False)

# ── REST API (FastAPI) ───────────────────────────────────────
API_HOST = os.getenv("API_HOST", "127.0.0.1")
API_PORT = _get_int("API_PORT", 8000, minimum=1, maximum=65535)
API_KEY = os.getenv("API_KEY", "")
ENV = os.getenv("ENV", "prod").strip().lower()
if ENV not in {"dev", "prod"}:
    raise ValueError("ENV must be either dev or prod")
API_PROTECTION_ENABLED = _get_bool("API_PROTECTION_ENABLED", True)
RATE_LIMIT_MAX_REQUESTS = _get_int("RATE_LIMIT_MAX_REQUESTS", 60, minimum=1)
RATE_LIMIT_WINDOW_SECONDS = _get_int("RATE_LIMIT_WINDOW_SECONDS", 60, minimum=1)
RATE_LIMIT_MAX_CLIENTS = _get_int(
    "RATE_LIMIT_MAX_CLIENTS", 10_000, minimum=1, maximum=100_000
)
MAX_UPLOAD_SIZE_BYTES = _get_int("MAX_UPLOAD_SIZE_BYTES", 10 * 1024 * 1024, minimum=1)
OFFLINE_MODE = _get_bool("OFFLINE_MODE", False)
LAB_MODE = _get_bool("LAB_MODE", False)
MAX_RAW_EMAIL_CHARS = _get_int("MAX_RAW_EMAIL_CHARS", 10 * 1024 * 1024, minimum=1)
MAX_URLS_PER_EMAIL = _get_int("MAX_URLS_PER_EMAIL", 50, minimum=1, maximum=500)
MAX_ATTACHMENTS_PER_EMAIL = _get_int(
    "MAX_ATTACHMENTS_PER_EMAIL", 25, minimum=1, maximum=100
)
# ── File Storage ─────────────────────────────────────────────
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Each completed analysis is appended for Wazuh collection. Empty disables the sink.
EVENTS_JSONL_PATH = os.getenv(
    "EVENTS_JSONL_PATH",
    "logs/events.jsonl" if os.name == "nt" else "/var/log/phishing-bot/events.jsonl",
)

# ── Logging ──────────────────────────────────────────────────
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").strip().upper()
if LOG_LEVEL not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
    raise ValueError("LOG_LEVEL must be a valid logging level")


def validate_startup_settings(*, run_api: bool) -> None:
    """Fail fast for required startup settings in the selected runtime mode."""
    if run_api:
        if API_PROTECTION_ENABLED and ENV != "dev" and not API_KEY:
            raise RuntimeError(
                "Missing required environment variable: API_KEY. "
                "Set API_KEY or disable API protection with API_PROTECTION_ENABLED=false."
            )
        return

    if TELEGRAM_ENABLED and not TELEGRAM_TOKEN:
        raise RuntimeError(
            "Missing required environment variable: TELEGRAM_TOKEN. "
            "Set TELEGRAM_TOKEN (or TELEGRAM_BOT_TOKEN) or disable Telegram with TELEGRAM_ENABLED=false."
        )
