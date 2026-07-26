"""Create bounded, cached Vietnamese variants through Groq augmentation."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import requests

from ml.contracts import EmailRecord
from ml.text import content_sha256, normalize_text

_GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
_DEFAULT_MODEL = "llama-3.3-70b-versatile"
_DEFAULT_PROMPT_VERSION = "vi-email-v1"
_URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_CURRENCY_PATTERN = re.compile(
    r"(?:[$€£₫]\s?\d[\d,.]*|\b\d[\d,.]*\s?(?:USD|VND|EUR|GBP)\b)",
    re.IGNORECASE,
)
_ATTACHMENT_PATTERN = re.compile(r"\[attachment:\s*[^\]]+\]", re.IGNORECASE)
_DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b",
    re.IGNORECASE,
)
_REQUIRED_ITEM_KEYS = frozenset({"source_id", "subject", "sender", "body", "label"})

RequestBatch = Callable[[list[EmailRecord]], object]

_SYSTEM_PROMPT = """You translate and culturally adapt labeled security emails
from English to natural Vietnamese for defensive phishing detection research.
Return JSON only. Never alter the classification label, sender, URL, domain,
currency amount, attachment name, credential request, financial request,
security intent, item count, or item order."""


@dataclass(frozen=True, slots=True)
class AugmentationStats:
    input_records: int
    generated_records: int
    cache_hits: int
    requests: int
    failures: int


def augmentation_cache_key(record: EmailRecord, model: str, prompt_version: str) -> str:
    canonical = json.dumps(
        {
            "content_sha256": record.content_sha256,
            "id": record.id,
            "model": model,
            "prompt_version": prompt_version,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _urls(text: str) -> list[str]:
    return sorted(match.rstrip(".,;:!?)]}") for match in _URL_PATTERN.findall(text))


def _protected_tokens(text: str) -> list[str]:
    values = _CURRENCY_PATTERN.findall(text)
    values.extend(_ATTACHMENT_PATTERN.findall(text))
    return sorted(values)


def _domains(text: str) -> list[str]:
    without_urls = _URL_PATTERN.sub(" ", text)
    without_attachments = _ATTACHMENT_PATTERN.sub(" ", without_urls)
    return sorted(
        value.lower() for value in _DOMAIN_PATTERN.findall(without_attachments)
    )


def _strict_items(payload: object) -> list[Mapping[str, object]]:
    if not isinstance(payload, Mapping) or set(payload) != {"items"}:
        raise ValueError("response must be an object containing only items")
    raw_items = payload.get("items")
    if not isinstance(raw_items, list):
        raise ValueError("response items must be a list")
    items: list[Mapping[str, object]] = []
    for index, item in enumerate(raw_items):
        if not isinstance(item, Mapping) or set(item) != _REQUIRED_ITEM_KEYS:
            raise ValueError(
                f"response item {index} must contain exactly "
                f"{sorted(_REQUIRED_ITEM_KEYS)}"
            )
        items.append(item)
    return items


def parse_augmentation_response(
    payload: object, expected: Sequence[EmailRecord]
) -> list[EmailRecord]:
    """Validate one strict batch response and construct synthetic records."""
    items = _strict_items(payload)
    expected_by_id = {record.id: record for record in expected}
    item_ids = [str(item.get("source_id") or "") for item in items]
    if (
        len(item_ids) != len(set(item_ids))
        or set(item_ids) != set(expected_by_id)
        or len(items) != len(expected)
    ):
        raise ValueError("response source IDs do not exactly match request source IDs")

    generated: list[EmailRecord] = []
    for item in items:
        original = expected_by_id[str(item["source_id"])]
        label = item.get("label")
        sender = item.get("sender")
        if label != original.label:
            raise ValueError(f"label changed for {original.id}")
        if sender != original.sender:
            raise ValueError(f"sender changed for {original.id}")

        subject = normalize_text(item.get("subject"))
        body = normalize_text(item.get("body"))
        if not body:
            raise ValueError(f"body must be non-empty for {original.id}")
        if original.subject and not subject:
            raise ValueError(f"subject must be non-empty for {original.id}")

        original_text = f"{original.subject}\n{original.body}"
        translated_text = f"{subject}\n{body}"
        if _urls(translated_text) != _urls(original_text):
            raise ValueError(f"URL set changed for {original.id}")
        if _domains(translated_text) != _domains(original_text):
            raise ValueError(f"domain set changed for {original.id}")
        if _protected_tokens(translated_text) != _protected_tokens(original_text):
            raise ValueError(f"protected token changed for {original.id}")

        generated.append(
            EmailRecord(
                id=f"{original.id}:vi",
                source=f"{original.source}:groq-vi",
                source_split=original.source_split,
                source_id=f"{original.source_id}:vi",
                language="vi",
                subject=subject,
                sender=original.sender,
                body=body,
                label=original.label,
                content_sha256=content_sha256(subject, original.sender, body),
                group_id=original.group_id,
                synthetic=True,
            )
        )
    generated_by_id = {record.id.removesuffix(":vi"): record for record in generated}
    return [generated_by_id[record.id] for record in expected]


def _cache_path(
    cache_dir: Path, record: EmailRecord, model: str, prompt_version: str
) -> Path:
    return cache_dir / f"{augmentation_cache_key(record, model, prompt_version)}.json"


def _load_cache(
    path: Path, original: EmailRecord, model: str, prompt_version: str
) -> EmailRecord | None:
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if (
            not isinstance(payload, Mapping)
            or payload.get("model") != model
            or payload.get("prompt_version") != prompt_version
            or payload.get("source_content_sha256") != original.content_sha256
            or not isinstance(payload.get("record"), Mapping)
        ):
            return None
        record = EmailRecord.from_mapping(payload["record"])
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return None
    if (
        record.group_id != original.group_id
        or record.source_split != original.source_split
        or record.label != original.label
        or record.language != "vi"
        or not record.synthetic
    ):
        return None
    return record


def _save_cache(
    path: Path,
    record: EmailRecord,
    original: EmailRecord,
    model: str,
    prompt_version: str,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "model": model,
        "prompt_version": prompt_version,
        "source_content_sha256": original.content_sha256,
        "record": record.to_dict(),
    }
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def augment_records(
    records: Sequence[EmailRecord],
    *,
    cache_dir: Path,
    model: str,
    prompt_version: str,
    request_batch: RequestBatch,
    batch_size: int = 4,
    max_requests: int = 25,
) -> tuple[list[EmailRecord], list[dict[str, str]], AugmentationStats]:
    """Augment records with cache-first processing and a strict request budget."""
    if batch_size <= 0:
        raise ValueError("batch_size must be positive")
    if max_requests < 0:
        raise ValueError("max_requests cannot be negative")

    generated_by_id: dict[str, EmailRecord] = {}
    failures: list[dict[str, str]] = []
    misses: list[EmailRecord] = []
    cache_hits = 0
    requests_made = 0

    for record in records:
        cached = _load_cache(
            _cache_path(cache_dir, record, model, prompt_version),
            record,
            model,
            prompt_version,
        )
        if cached is None:
            misses.append(record)
        else:
            generated_by_id[record.id] = cached
            cache_hits += 1

    for offset in range(0, len(misses), batch_size):
        batch = misses[offset : offset + batch_size]
        if requests_made >= max_requests:
            failures.extend(
                {"id": record.id, "reason": "request_budget_exhausted"}
                for record in batch
            )
            continue
        requests_made += 1
        try:
            payload = request_batch(batch)
            generated = parse_augmentation_response(payload, batch)
        except (
            OSError,
            RuntimeError,
            TypeError,
            ValueError,
            requests.RequestException,
        ) as exc:
            reason = f"request_failed:{type(exc).__name__}"
            failures.extend({"id": record.id, "reason": reason} for record in batch)
            continue

        for original, synthetic in zip(batch, generated, strict=True):
            generated_by_id[original.id] = synthetic
            _save_cache(
                _cache_path(cache_dir, original, model, prompt_version),
                synthetic,
                original,
                model,
                prompt_version,
            )

    ordered = [
        generated_by_id[record.id] for record in records if record.id in generated_by_id
    ]
    stats = AugmentationStats(
        input_records=len(records),
        generated_records=len(ordered),
        cache_hits=cache_hits,
        requests=requests_made,
        failures=len(failures),
    )
    return ordered, failures, stats


def _request_payload(records: Sequence[EmailRecord]) -> str:
    items = [
        {
            "source_id": record.id,
            "subject": record.subject,
            "sender": record.sender,
            "body": record.body,
            "label": record.label,
        }
        for record in records
    ]
    return (
        "Translate each item to Vietnamese. Preserve every protected value and "
        "return exactly this schema: "
        '{"items":[{"source_id":"...","subject":"...","sender":"...",'
        '"body":"...","label":"phishing|legitimate"}]}.\n'
        f"Input:\n{json.dumps({'items': items}, ensure_ascii=False)}"
    )


def _retry_delay(exc: Exception, attempt: int) -> float:
    fallback = float(2**attempt)
    response = getattr(exc, "response", None)
    if response is None or getattr(response, "status_code", None) != 429:
        return fallback
    headers = getattr(response, "headers", {})
    value = headers.get("retry-after") or headers.get("x-ratelimit-reset-tokens")
    if not isinstance(value, str):
        return fallback
    try:
        requested = float(value.removesuffix("s"))
    except ValueError:
        return fallback
    return min(60.0, max(fallback, requested))


def _completion_token_budget(records: Sequence[EmailRecord]) -> int:
    source_chars = sum(len(record.subject) + len(record.body) for record in records)
    return min(4_000, max(512, math.ceil(source_chars / 2) + 256))


class _GroqBatchClient:
    def __init__(
        self,
        api_key: str,
        model: str,
        timeout: float = 30.0,
        minimum_interval_seconds: float = 0.0,
    ) -> None:
        if minimum_interval_seconds < 0:
            raise ValueError("minimum_interval_seconds cannot be negative")
        self._api_key = api_key
        self._model = model
        self._timeout = timeout
        self._minimum_interval_seconds = minimum_interval_seconds
        self._calls = 0

    def __call__(self, records: list[EmailRecord]) -> object:
        if self._calls:
            time.sleep(self._minimum_interval_seconds)
        self._calls += 1
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                response = requests.post(
                    _GROQ_URL,
                    headers={
                        "Authorization": f"Bearer {self._api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self._model,
                        "messages": [
                            {"role": "system", "content": _SYSTEM_PROMPT},
                            {
                                "role": "user",
                                "content": _request_payload(records),
                            },
                        ],
                        "temperature": 0.0,
                        "response_format": {"type": "json_object"},
                        "max_tokens": _completion_token_budget(records),
                    },
                    timeout=self._timeout,
                )
                response.raise_for_status()
                data = response.json()
                content = data["choices"][0]["message"]["content"]
                return json.loads(content)
            except (
                IndexError,
                KeyError,
                TypeError,
                ValueError,
                json.JSONDecodeError,
                requests.RequestException,
            ) as exc:
                last_error = exc
                if attempt < 2:
                    time.sleep(_retry_delay(exc, attempt))
        raise RuntimeError("Groq augmentation failed after 3 attempts") from last_error


def _read_records(path: Path, split: str) -> list[EmailRecord]:
    records: list[EmailRecord] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
                if not isinstance(value, Mapping):
                    raise ValueError("row must be an object")
                record = EmailRecord.from_mapping(value)
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                raise ValueError(f"{path}:{line_number}: invalid record") from exc
            if record.source_split == split and not record.synthetic:
                records.append(record)
    return records


def _bounded_records(
    records: Sequence[EmailRecord], max_records: int, seed: int
) -> list[EmailRecord]:
    if max_records <= 0:
        return []
    import random

    # This is deterministic dataset sampling, not security randomness.
    rng = random.Random(seed)  # nosec B311
    by_label = {
        label: [record for record in records if record.label == label]
        for label in ("legitimate", "phishing")
    }
    for values in by_label.values():
        rng.shuffle(values)
    selected: list[EmailRecord] = []
    while len(selected) < max_records and any(by_label.values()):
        for label in ("legitimate", "phishing"):
            if by_label[label] and len(selected) < max_records:
                selected.append(by_label[label].pop())
    return selected


def _write_jsonl(path: Path, rows: Sequence[Mapping[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(
                json.dumps(
                    row, ensure_ascii=False, sort_keys=True, separators=(",", ":")
                )
                + "\n"
            )
    temporary.replace(path)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create cached Vietnamese variants with bounded Groq requests."
    )
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument("--split", choices=("train", "test"), default="train")
    parser.add_argument("--model", default=_DEFAULT_MODEL)
    parser.add_argument("--prompt-version", default=_DEFAULT_PROMPT_VERSION)
    parser.add_argument("--batch-size", type=int, default=4)
    parser.add_argument("--request-interval", type=float, default=12.0)
    parser.add_argument("--max-records", type=int, default=100)
    parser.add_argument("--max-requests", type=int, default=25)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--smoke", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    api_key = os.getenv("GROQ_API_KEY", "")
    if not api_key:
        raise SystemExit("GROQ_API_KEY is required for uncached augmentation")
    max_records = min(args.max_records, 2) if args.smoke else args.max_records
    max_requests = min(args.max_requests, 1) if args.smoke else args.max_requests
    records = _bounded_records(
        _read_records(args.input, args.split), max_records, args.seed
    )
    generated, failures, stats = augment_records(
        records,
        cache_dir=args.cache_dir,
        model=args.model,
        prompt_version=args.prompt_version,
        request_batch=_GroqBatchClient(
            api_key,
            args.model,
            minimum_interval_seconds=args.request_interval,
        ),
        batch_size=args.batch_size,
        max_requests=max_requests,
    )
    _write_jsonl(args.output, [record.to_dict() for record in generated])
    _write_jsonl(
        args.output.with_suffix(args.output.suffix + ".rejected.jsonl"), failures
    )
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "model": args.model,
        "prompt_version": args.prompt_version,
        "split": args.split,
        "seed": args.seed,
        "max_records": max_records,
        "max_requests": max_requests,
        "batch_size": args.batch_size,
        "stats": asdict(stats),
    }
    manifest_path = args.output.with_suffix(args.output.suffix + ".manifest.json")
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(asdict(stats), sort_keys=True))
    return 0 if not failures else 2


if __name__ == "__main__":
    raise SystemExit(main())
