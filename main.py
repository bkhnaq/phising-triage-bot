"""Application entry point for the bot, API, healthcheck, and local CLI."""

import logging
import sys

from config.settings import LOG_LEVEL


def _configure_utf8_streams() -> None:
    """Prefer UTF-8 for bilingual reports and logs on Windows consoles."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="backslashreplace")


def _setup_logging() -> None:
    """Configure structured logging for the entire application."""
    _configure_utf8_streams()
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[logging.StreamHandler(sys.stdout)],
    )


def main() -> None:
    """Configure logging and delegate mode selection to the CLI adapter."""
    _setup_logging()
    from cli import run_cli

    raise SystemExit(run_cli())


if __name__ == "__main__":
    main()
