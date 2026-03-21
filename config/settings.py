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
def _get_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", os.getenv("TELEGRAM_BOT_TOKEN", ""))
TELEGRAM_BOT_TOKEN = TELEGRAM_TOKEN  # Backward-compatible alias
TELEGRAM_ENABLED = _get_bool("TELEGRAM_ENABLED", True)

# Restrict the bot to specific chat IDs (comma-separated in .env)
# Leave empty to allow all chats (not recommended for production)
_allowed = os.getenv("ALLOWED_CHAT_IDS", "")
ALLOWED_CHAT_IDS: list[int] = (
    [int(cid.strip()) for cid in _allowed.split(",") if cid.strip()] if _allowed else []
)

# ── Threat Intelligence APIs ─────────────────────────────────
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
ALIENVAULT_OTX_API_KEY = os.getenv("ALIENVAULT_OTX_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
SECURITYTRAILS_API_KEY = os.getenv("SECURITYTRAILS_API_KEY", "")

# ── AI Classifier ────────────────────────────────────────────
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

# ── Risk Scoring Thresholds ──────────────────────────────────
RISK_HIGH_THRESHOLD = int(os.getenv("RISK_HIGH_THRESHOLD", "70"))
RISK_MEDIUM_THRESHOLD = int(os.getenv("RISK_MEDIUM_THRESHOLD", "40"))

# ── REST API (FastAPI) ───────────────────────────────────────
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "8000"))
API_KEY = os.getenv("API_KEY", "")
ENV = os.getenv("ENV", "prod").strip().lower()
API_PROTECTION_ENABLED = _get_bool("API_PROTECTION_ENABLED", True)
RATE_LIMIT_MAX_REQUESTS = int(os.getenv("RATE_LIMIT_MAX_REQUESTS", "60"))
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
MAX_UPLOAD_SIZE_BYTES = int(os.getenv("MAX_UPLOAD_SIZE_BYTES", str(10 * 1024 * 1024)))

# ── File Storage ─────────────────────────────────────────────
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ── Logging ──────────────────────────────────────────────────
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")


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
