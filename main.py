"""
Automated Phishing Triage Bot – Entry Point
============================================
Starts the Telegram bot and configures logging.

Run with:
    python main.py
"""

import logging
import sys

from config.settings import LOG_LEVEL


def _setup_logging() -> None:
    """Configure structured logging for the entire application."""
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[logging.StreamHandler(sys.stdout)],
    )


def main() -> None:
    _setup_logging()

    logger = logging.getLogger(__name__)
    logger.info("Starting Phishing Triage Bot…")

    from bot.telegram_handler import start_bot

    try:
        start_bot()
    except RuntimeError as exc:
        logger.error("Failed to start: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
