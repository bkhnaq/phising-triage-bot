"""Create cached Vietnamese variants with a revision-pinned local translator."""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Callable, Sequence
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any

from ml.augment_vietnamese import (
    AugmentationStats,
    _ATTACHMENT_PATTERN,
    _CURRENCY_PATTERN,
    _DOMAIN_PATTERN,
    _URL_PATTERN,
    _bounded_records,
    _cache_path,
    _load_cache,
    _read_records,
    _save_cache,
    _write_jsonl,
    parse_augmentation_response,
)
from ml.contracts import EmailRecord

_MODEL_ID = "Helsinki-NLP/opus-mt-en-vi"
_MODEL_REVISION = "989c9fb9ec63987901022baf0182dcec3e149be6"
_PROMPT_VERSION = "local-opus-preserve-v1"
_LICENSE = "Apache-2.0"
_MAX_TRANSLATABLE_CHARS = 700

TranslateBatch = Callable[[list[str]], list[str]]


def _security_spans(text: str) -> list[tuple[int, int]]:
    candidates = [
        match.span()
        for pattern in (
            _URL_PATTERN,
            _ATTACHMENT_PATTERN,
            _CURRENCY_PATTERN,
            _DOMAIN_PATTERN,
        )
        for match in pattern.finditer(text)
    ]
    candidates.sort(key=lambda span: (span[0], -(span[1] - span[0])))
    selected: list[tuple[int, int]] = []
    cursor = 0
    for start, end in candidates:
        if start >= cursor:
            selected.append((start, end))
            cursor = end
    return selected


def _bounded_text_chunks(text: str) -> list[str]:
    chunks: list[str] = []
    remaining = text
    while len(remaining) > _MAX_TRANSLATABLE_CHARS:
        boundary = remaining.rfind(" ", 0, _MAX_TRANSLATABLE_CHARS + 1)
        if boundary < _MAX_TRANSLATABLE_CHARS // 2:
            boundary = _MAX_TRANSLATABLE_CHARS
        chunks.append(remaining[:boundary])
        remaining = remaining[boundary:]
    if remaining:
        chunks.append(remaining)
    return chunks


def _neutralize_generated_domains(value: str) -> str:
    return _DOMAIN_PATTERN.sub(
        lambda match: match.group(0).replace(".", ". ", 1),
        value,
    )


def translate_preserving_security_tokens(
    text: str,
    translate_batch: TranslateBatch,
) -> str:
    """Translate natural-language spans while copying security tokens verbatim."""
    pieces: list[tuple[bool, str]] = []
    cursor = 0
    for start, end in _security_spans(text):
        if start > cursor:
            pieces.extend(
                (False, chunk) for chunk in _bounded_text_chunks(text[cursor:start])
            )
        pieces.append((True, text[start:end]))
        cursor = end
    if cursor < len(text):
        pieces.extend((False, chunk) for chunk in _bounded_text_chunks(text[cursor:]))

    model_inputs: list[str] = []
    input_indexes: list[int] = []
    boundaries: dict[int, tuple[str, str]] = {}
    replacements = [value for _, value in pieces]
    for index, (protected, value) in enumerate(pieces):
        alphanumeric = [
            offset for offset, character in enumerate(value) if character.isalnum()
        ]
        if not alphanumeric:
            continue
        first = alphanumeric[0]
        last = alphanumeric[-1] + 1
        core = value[first:last]
        if not protected and core and re.search(r"[A-Za-z]", core):
            model_inputs.append(core)
            input_indexes.append(index)
            boundaries[index] = (value[:first], value[last:])
    if model_inputs:
        translated = translate_batch(model_inputs)
        if len(translated) != len(model_inputs):
            raise ValueError("translator output count does not match input")
        for index, value in zip(input_indexes, translated, strict=True):
            leading, trailing = boundaries[index]
            safe_value = _neutralize_generated_domains(value.strip())
            replacements[index] = f"{leading}{safe_value}{trailing}"
    return "".join(replacements)


def build_local_variant(
    original: EmailRecord,
    translate_batch: TranslateBatch,
    *,
    model_id: str,
) -> EmailRecord:
    """Translate one record and validate it through the shared strict contract."""
    if not model_id.strip():
        raise ValueError("model_id must be non-empty")
    subject = translate_preserving_security_tokens(original.subject, translate_batch)
    body = translate_preserving_security_tokens(original.body, translate_batch)
    payload = {
        "items": [
            {
                "source_id": original.id,
                "subject": subject,
                "sender": original.sender,
                "body": body,
                "label": original.label,
            }
        ]
    }
    generated = parse_augmentation_response(payload, [original])[0]
    return replace(generated, source=f"{original.source}:local-vi")


class _MarianTranslator:
    def __init__(
        self,
        model_id: str,
        revision: str,
        batch_size: int,
    ) -> None:
        if batch_size <= 0:
            raise ValueError("batch_size must be positive")
        try:
            import torch
            from transformers import (
                AutoModelForSeq2SeqLM,
                AutoTokenizer,
            )
        except ImportError as exc:
            raise RuntimeError(
                "local translation requires requirements-ml.txt"
            ) from exc
        self._torch = torch
        self._batch_size = batch_size
        self._device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self._tokenizer = AutoTokenizer.from_pretrained(
            model_id,
            revision=revision,
            trust_remote_code=False,
        )
        self._model = AutoModelForSeq2SeqLM.from_pretrained(
            model_id,
            revision=revision,
            trust_remote_code=False,
            use_safetensors=False,
        )
        self._model.to(self._device)
        self._model.eval()

    def __call__(self, values: list[str]) -> list[str]:
        outputs: list[str] = []
        for offset in range(0, len(values), self._batch_size):
            batch = values[offset : offset + self._batch_size]
            encoded = self._tokenizer(
                batch,
                padding=True,
                truncation=True,
                max_length=512,
                return_tensors="pt",
            )
            encoded = {key: tensor.to(self._device) for key, tensor in encoded.items()}
            with self._torch.inference_mode():
                generated = self._model.generate(
                    **encoded,
                    max_new_tokens=512,
                    num_beams=4,
                )
            outputs.extend(
                self._tokenizer.batch_decode(
                    generated,
                    skip_special_tokens=True,
                )
            )
        return outputs


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create cached Vietnamese variants with local MarianMT."
    )
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cache-dir", type=Path, required=True)
    parser.add_argument(
        "--split",
        choices=("train", "validation", "test"),
        default="train",
    )
    parser.add_argument("--model", default=_MODEL_ID)
    parser.add_argument("--revision", default=_MODEL_REVISION)
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--max-records", type=int, default=50)
    parser.add_argument("--max-source-chars", type=int, default=2_000)
    parser.add_argument("--seed", type=int, default=42)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    records = _bounded_records(
        _read_records(args.input, args.split),
        args.max_records,
        args.seed,
        max_source_chars=args.max_source_chars,
    )
    translator = _MarianTranslator(
        args.model,
        args.revision,
        args.batch_size,
    )
    cache_model = f"{args.model}@{args.revision}"
    generated: list[EmailRecord] = []
    failures: list[dict[str, str]] = []
    cache_hits = 0
    for original in records:
        path = _cache_path(
            args.cache_dir,
            original,
            cache_model,
            _PROMPT_VERSION,
        )
        cached = _load_cache(
            path,
            original,
            cache_model,
            _PROMPT_VERSION,
        )
        if cached is not None:
            generated.append(cached)
            cache_hits += 1
            continue
        try:
            synthetic = build_local_variant(
                original,
                translator,
                model_id=args.model,
            )
        except (ArithmeticError, OSError, RuntimeError, TypeError, ValueError) as exc:
            failures.append(
                {
                    "id": original.id,
                    "reason": f"translation_failed:{type(exc).__name__}",
                }
            )
            continue
        generated.append(synthetic)
        _save_cache(
            path,
            synthetic,
            original,
            cache_model,
            _PROMPT_VERSION,
        )

    _write_jsonl(args.output, [record.to_dict() for record in generated])
    _write_jsonl(
        args.output.with_suffix(args.output.suffix + ".rejected.jsonl"),
        failures,
    )
    stats = AugmentationStats(
        input_records=len(records),
        generated_records=len(generated),
        cache_hits=cache_hits,
        requests=0,
        failures=len(failures),
    )
    manifest: dict[str, Any] = {
        "schema_version": 1,
        "mode": "local",
        "model": args.model,
        "revision": args.revision,
        "license": _LICENSE,
        "prompt_version": _PROMPT_VERSION,
        "split": args.split,
        "seed": args.seed,
        "max_records": args.max_records,
        "max_source_chars": args.max_source_chars,
        "stats": asdict(stats),
    }
    args.output.with_suffix(args.output.suffix + ".manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(asdict(stats), sort_keys=True))
    return 0 if not failures else 2


if __name__ == "__main__":
    raise SystemExit(main())
