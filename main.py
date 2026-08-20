"""Application entry point for the bot, API, healthcheck, and local CLI."""

import logging
import re
import sys

from config.settings import LOG_LEVEL

_TELEGRAM_TOKEN_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_-])(?:bot)?\d{5,12}:[A-Za-z0-9_-]{20,}" r"(?![A-Za-z0-9_-])"
)


class _RedactingFormatter(logging.Formatter):
    """Remove Telegram bot tokens from messages and formatted tracebacks."""

    def format(self, record: logging.LogRecord) -> str:
        rendered = super().format(record)
        return _TELEGRAM_TOKEN_PATTERN.sub("[REDACTED_TELEGRAM_TOKEN]", rendered)


def _configure_utf8_streams() -> None:
    """Prefer UTF-8 for bilingual reports and logs on Windows consoles."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="backslashreplace")


def _setup_logging() -> None:
    """Configure structured logging for the entire application."""
    _configure_utf8_streams()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        _RedactingFormatter(
            fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
        handlers=[handler],
    )
    # HTTPX logs Telegram Bot API URLs, which contain the bot token in the path.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


def main() -> None:
    """Configure logging and delegate mode selection to the CLI adapter."""
    _setup_logging()
    from cli import run_cli

    raise SystemExit(run_cli())


if __name__ == "__main__":
    main()
