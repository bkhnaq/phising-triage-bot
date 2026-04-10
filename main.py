"""
Automated Phishing Triage Bot – Entry Point
============================================
Starts the Telegram bot or the FastAPI REST API.

Run with:
    python main.py            # start Telegram bot (default)
    python main.py --api      # start REST API server
"""

import logging
import sys
import importlib

from config.settings import LOG_LEVEL, validate_startup_settings


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
    run_api = "--api" in sys.argv
    try:
        validate_startup_settings(run_api=run_api)
    except RuntimeError as exc:
        logger.error("Startup validation failed: %s", exc)
        sys.exit(1)

    if run_api:
        logger.info("Starting Phishing Triage API server…")
        from config.settings import API_HOST, API_PORT

        uvicorn = importlib.import_module("uvicorn")

        uvicorn.run("api.routes:app", host=API_HOST, port=API_PORT)
    else:
        logger.info("Starting Phishing Triage Bot…")

        from bot.telegram_handler import start_bot

        try:
            start_bot()
        except RuntimeError as exc:
            logger.error("Failed to start: %s", exc)
            sys.exit(1)


if __name__ == "__main__":
    main()
