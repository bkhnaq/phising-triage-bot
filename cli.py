"""Command-line entry points for local SOC phishing triage."""

from __future__ import annotations

import argparse
import importlib
import logging
from collections.abc import Sequence
from pathlib import Path
import sys


def build_parser() -> argparse.ArgumentParser:
    """Build the command parser shared by the local, bot, and API modes."""
    parser = argparse.ArgumentParser(description="SOC phishing email triage")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--api", action="store_true", help="start the REST API")
    mode.add_argument(
        "--healthcheck", action="store_true", help="run a local health check"
    )
    mode.add_argument(
        "--analyze", type=Path, metavar="EMAIL.eml", help="analyze an .eml file"
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="disable network enrichment for local analysis",
    )
    parser.add_argument(
        "--output",
        type=Path,
        metavar="REPORT.md",
        help="write an analysis report to this UTF-8 file",
    )
    return parser


def _usage_error(message: str) -> int:
    print(f"Usage error: {message}", file=sys.stderr)
    return 2


def _analyze_file(path: Path, *, offline: bool, output: Path | None) -> int:
    try:
        resolved_path = path.expanduser().resolve(strict=True)
    except OSError:
        return _usage_error(f"email file was not found: {path}")
    if not resolved_path.is_file():
        return _usage_error(f"email path is not a file: {path}")
    if resolved_path.suffix.lower() != ".eml":
        return _usage_error("--analyze accepts only .eml files")

    if offline:
        from config import settings

        settings.OFFLINE_MODE = True

    try:
        from email_analysis.pipeline import PhishingPipeline

        result = PhishingPipeline().analyze_file(str(resolved_path))
        report = result["report"]
        if not isinstance(report, str):
            raise RuntimeError("analysis did not produce a text report")
        if output is not None:
            destination = output.expanduser().resolve()
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(report, encoding="utf-8")
        else:
            print(report)
    except (KeyError, OSError, RuntimeError, ValueError):
        logging.getLogger(__name__).exception("Local analysis failed")
        print("Analysis failed; inspect application logs for details.", file=sys.stderr)
        return 1
    return 0


def _healthcheck() -> int:
    """Run a container-safe healthcheck without requiring external services."""
    from config.settings import UPLOAD_DIR

    upload_dir = Path(UPLOAD_DIR)
    upload_dir.mkdir(parents=True, exist_ok=True)
    probe = upload_dir / ".healthcheck"
    try:
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
    except OSError as exc:
        logging.getLogger(__name__).error("Healthcheck failed: %s", exc)
        return 1

    importlib.import_module("email_analysis.pipeline")
    return 0


def _start_api() -> int:
    from config.settings import API_HOST, API_PORT, validate_startup_settings

    try:
        validate_startup_settings(run_api=True)
    except RuntimeError as exc:
        logging.getLogger(__name__).error("Startup validation failed: %s", exc)
        return 1
    logging.getLogger(__name__).info("Starting Phishing Triage API server…")
    importlib.import_module("uvicorn").run(
        "api.routes:app", host=API_HOST, port=API_PORT
    )
    return 0


def _start_bot() -> int:
    from config.settings import validate_startup_settings

    try:
        validate_startup_settings(run_api=False)
    except RuntimeError as exc:
        logging.getLogger(__name__).error("Startup validation failed: %s", exc)
        return 1
    logging.getLogger(__name__).info("Starting Phishing Triage Bot…")
    try:
        from bot.telegram_handler import start_bot

        start_bot()
    except RuntimeError as exc:
        logging.getLogger(__name__).error("Failed to start: %s", exc)
        return 1
    return 0


def run_cli(argv: Sequence[str] | None = None) -> int:
    """Run the selected application mode and return a process-style exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.analyze is not None:
        return _analyze_file(args.analyze, offline=args.offline, output=args.output)
    if args.offline or args.output is not None:
        return _usage_error("--offline and --output require --analyze")
    if args.healthcheck:
        return _healthcheck()
    if args.api:
        return _start_api()
    return _start_bot()
