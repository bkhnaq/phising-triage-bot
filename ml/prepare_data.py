"""Prepare provenance-tracked phishing datasets without executing remote code."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import time
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path

import requests

from ml.contracts import EmailRecord
from ml.text import content_sha256, normalize_text

_DIFRAUD_REPO = "difraud/difraud"
_DIFRAUD_REVISION = "aaaf94b336c563a14806bb4f3f58727bed9ed8d4"
_TEDDYHA_REPO = "Teddyha/phishing_benign_email_dataset"
_TEDDYHA_REVISION = "ce65d43bf5866122c6e574dc9e10044cbbcb22d1"
_TEDDYHA_FILE = "phishing and benign email dataset.jsonl"
_HF_RESOLVE = "https://huggingface.co/datasets/{repo}/resolve/{revision}/{path}"
_SPLITS = ("train", "validation", "test")


def _source_id(row: Mapping[str, object]) -> str:
    value = row.get("_source_id") or row.get("id")
    if value is None or not str(value).strip():
        raise ValueError("source row requires id or _source_id")
    return normalize_text(value)


def _mapped_label(value: object, mapping: Mapping[object, str]) -> str:
    if isinstance(value, bool) or value not in mapping:
        raise ValueError(f"unsupported label: {value!r}")
    return mapping[value]


def normalize_source_row(
    row: Mapping[str, object], adapter: str, split: str
) -> EmailRecord:
    """Map one supported upstream row into the stable normalized contract."""
    if split not in _SPLITS:
        raise ValueError(f"unsupported source_split: {split!r}")

    source_id = _source_id(row)
    if adapter == "difraud":
        source = "difraud"
        subject = ""
        sender = ""
        body = normalize_text(row.get("text"))
        label = _mapped_label(row.get("label"), {0: "legitimate", 1: "phishing"})
        language = "en"
    elif adapter == "teddyha":
        if split != "train":
            raise ValueError("Teddyha supplemental dataset is training-only")
        source = _TEDDYHA_REPO
        subject = normalize_text(row.get("subject"))
        sender = normalize_text(row.get("spoofed_sender"))
        body = normalize_text(row.get("body"))
        label = _mapped_label(
            row.get("label"), {"benign": "legitimate", "phishing": "phishing"}
        )
        language = "en"
    elif adapter == "fixture":
        source = "fixture"
        subject = normalize_text(row.get("subject"))
        sender = normalize_text(row.get("sender"))
        body = normalize_text(row.get("body"))
        label = _mapped_label(
            row.get("label"),
            {
                "benign": "legitimate",
                "legitimate": "legitimate",
                "phishing": "phishing",
            },
        )
        language = normalize_text(row.get("language") or "en")
    else:
        raise ValueError(f"unsupported adapter: {adapter!r}")

    if not body:
        raise ValueError("body must be non-empty")
    record_id = f"{source}:{split}:{source_id}"
    return EmailRecord(
        id=record_id,
        source=source,
        source_split=split,
        source_id=source_id,
        language=language,
        subject=subject,
        sender=sender,
        body=body,
        label=label,
        content_sha256=content_sha256(subject, sender, body),
        group_id=record_id,
        synthetic=False,
    )


def validate_group_splits(records: Iterable[EmailRecord]) -> None:
    """Reject leakage when an original and its variants cross data splits."""
    groups: dict[str, str] = {}
    for record in records:
        previous = groups.setdefault(record.group_id, record.source_split)
        if previous != record.source_split:
            raise ValueError(
                f"group_id {record.group_id!r} crosses splits "
                f"{previous!r} and {record.source_split!r}"
            )


def deduplicate_records(
    records: Iterable[EmailRecord],
) -> tuple[list[EmailRecord], list[dict[str, str]]]:
    """Keep the first exact normalized-content occurrence."""
    seen: dict[str, str] = {}
    kept: list[EmailRecord] = []
    rejected: list[dict[str, str]] = []
    for record in records:
        duplicate_of = seen.get(record.content_sha256)
        if duplicate_of is not None:
            rejected.append(
                {
                    "id": record.id,
                    "reason": "duplicate_content",
                    "duplicate_of": duplicate_of,
                }
            )
            continue
        seen[record.content_sha256] = record.id
        kept.append(record)
    return kept, rejected


def _read_jsonl(
    path: Path,
) -> tuple[list[tuple[int, dict[str, object]]], list[dict[str, str]]]:
    rows: list[tuple[int, dict[str, object]]] = []
    rejected: list[dict[str, str]] = []
    with path.open("r", encoding="utf-8-sig") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                rejected.append(
                    {
                        "line": str(line_number),
                        "reason": "invalid_json",
                    }
                )
                continue
            if not isinstance(value, dict):
                rejected.append(
                    {
                        "line": str(line_number),
                        "reason": "row_must_be_object",
                    }
                )
                continue
            rows.append((line_number, value))
    return rows, rejected


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_jsonl(path: Path, rows: Iterable[Mapping[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(
                json.dumps(
                    row, ensure_ascii=False, sort_keys=True, separators=(",", ":")
                )
            )
            handle.write("\n")
    temporary.replace(path)


def _write_json(path: Path, value: Mapping[str, object]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _distribution(records: Sequence[EmailRecord], attribute: str) -> dict[str, int]:
    return dict(
        sorted(Counter(str(getattr(record, attribute)) for record in records).items())
    )


def _smoke_sample(
    records: Sequence[EmailRecord], seed: int, per_label: int = 8
) -> list[EmailRecord]:
    selected: list[EmailRecord] = []
    rng = random.Random(seed)
    for split_index, split in enumerate(_SPLITS):
        for label_index, label in enumerate(("legitimate", "phishing")):
            candidates = [
                record
                for record in records
                if record.source_split == split and record.label == label
            ]
            random.Random(rng.random() + split_index + label_index).shuffle(candidates)
            selected.extend(candidates[:per_label])
    return selected


def _build_manifest(
    records: Sequence[EmailRecord],
    rejected: Sequence[Mapping[str, object]],
    output_dir: Path,
    sources: Sequence[Mapping[str, object]],
    seed: int,
    smoke: bool,
) -> dict[str, object]:
    split_counts = Counter(record.source_split for record in records)
    checksums = {
        f"{split}.jsonl": _file_sha256(output_dir / f"{split}.jsonl")
        for split in _SPLITS
    }
    checksums["rejected.jsonl"] = _file_sha256(output_dir / "rejected.jsonl")
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "seed": seed,
        "smoke": smoke,
        "sources": list(sources),
        "counts": {
            "total": len(records),
            "rejected": len(rejected),
            **{split: split_counts.get(split, 0) for split in _SPLITS},
        },
        "label_distribution": _distribution(records, "label"),
        "language_distribution": _distribution(records, "language"),
        "checksums": checksums,
    }


def _prepare(
    records: Sequence[EmailRecord],
    rejected: list[dict[str, str]],
    output_dir: Path,
    sources: Sequence[Mapping[str, object]],
    seed: int,
    smoke: bool,
) -> dict[str, object]:
    validate_group_splits(records)
    kept, duplicate_rejections = deduplicate_records(records)
    rejected.extend(duplicate_rejections)
    if smoke:
        kept = _smoke_sample(kept, seed)
    kept.sort(key=lambda record: record.id)

    output_dir.mkdir(parents=True, exist_ok=True)
    for split in _SPLITS:
        _write_jsonl(
            output_dir / f"{split}.jsonl",
            (record.to_dict() for record in kept if record.source_split == split),
        )
    _write_jsonl(output_dir / "rejected.jsonl", rejected)
    manifest = _build_manifest(
        kept, rejected, output_dir, sources=sources, seed=seed, smoke=smoke
    )
    _write_json(output_dir / "dataset-manifest.json", manifest)
    return manifest


def prepare_fixture(
    fixture: Path, output_dir: Path, *, seed: int = 42, smoke: bool = False
) -> dict[str, object]:
    """Prepare a local JSONL fixture through the production normalization path."""
    records: list[EmailRecord] = []
    rows, rejected = _read_jsonl(fixture)
    for line_number, row in rows:
        split = normalize_text(row.get("source_split"))
        try:
            records.append(normalize_source_row(row, "fixture", split))
        except ValueError as exc:
            rejected.append(
                {
                    "id": str(row.get("id") or line_number),
                    "reason": normalize_text(exc),
                }
            )
    sources = [
        {
            "name": "fixture",
            "revision": _file_sha256(fixture),
            "license": "MIT",
            "path": str(fixture),
        }
    ]
    return _prepare(records, rejected, output_dir, sources, seed, smoke)


def _download_file(
    repo: str, revision: str, remote_path: str, destination: Path
) -> None:
    if destination.is_file():
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    url = _HF_RESOLVE.format(repo=repo, revision=revision, path=remote_path)
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            response = requests.get(url, timeout=(10, 60))
            response.raise_for_status()
            temporary = destination.with_suffix(destination.suffix + ".tmp")
            temporary.write_bytes(response.content)
            temporary.replace(destination)
            return
        except requests.RequestException as exc:
            last_error = exc
            if attempt < 2:
                time.sleep(2**attempt)
    raise RuntimeError(
        f"failed to download {repo}/{remote_path} after 3 attempts"
    ) from last_error


def prepare_public(
    raw_dir: Path,
    output_dir: Path,
    *,
    difraud_revision: str = _DIFRAUD_REVISION,
    teddyha_revision: str = _TEDDYHA_REVISION,
    seed: int = 42,
    smoke: bool = False,
) -> dict[str, object]:
    """Download pinned source files and prepare the public training corpus."""
    records: list[EmailRecord] = []
    rejected: list[dict[str, str]] = []

    for split in _SPLITS:
        remote_path = f"phishing/{split}.jsonl"
        local_path = raw_dir / "difraud" / difraud_revision / remote_path
        _download_file(_DIFRAUD_REPO, difraud_revision, remote_path, local_path)
        rows, malformed = _read_jsonl(local_path)
        rejected.extend(
            {
                **item,
                "id": f"difraud:{split}:line-{item['line']}",
            }
            for item in malformed
        )
        for line_number, row in rows:
            row["_source_id"] = str(line_number)
            try:
                records.append(normalize_source_row(row, "difraud", split))
            except ValueError as exc:
                rejected.append(
                    {
                        "id": f"difraud:{split}:{line_number}",
                        "reason": normalize_text(exc),
                    }
                )

    teddyha_path = raw_dir / "teddyha" / teddyha_revision / _TEDDYHA_FILE
    _download_file(_TEDDYHA_REPO, teddyha_revision, _TEDDYHA_FILE, teddyha_path)
    teddyha_rows, malformed = _read_jsonl(teddyha_path)
    rejected.extend(
        {
            **item,
            "id": f"teddyha:train:line-{item['line']}",
        }
        for item in malformed
    )
    for line_number, row in teddyha_rows:
        row.setdefault("_source_id", str(line_number))
        try:
            records.append(normalize_source_row(row, "teddyha", "train"))
        except ValueError as exc:
            rejected.append(
                {
                    "id": f"teddyha:train:{row.get('id') or line_number}",
                    "reason": normalize_text(exc),
                }
            )

    sources = [
        {
            "name": _DIFRAUD_REPO,
            "subset": "phishing",
            "revision": difraud_revision,
            "license": "MIT",
            "official_splits": True,
        },
        {
            "name": _TEDDYHA_REPO,
            "revision": teddyha_revision,
            "license": "MIT",
            "official_splits": False,
            "usage": "train-only supplemental",
        },
    ]
    return _prepare(records, rejected, output_dir, sources, seed, smoke)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prepare normalized phishing-email datasets."
    )
    parser.add_argument("--source", choices=("fixture", "public"), default="public")
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--raw-dir", type=Path, default=Path("data/raw"))
    parser.add_argument(
        "--output-dir", type=Path, default=Path("data/processed/phishing")
    )
    parser.add_argument("--difraud-revision", default=_DIFRAUD_REVISION)
    parser.add_argument("--teddyha-revision", default=_TEDDYHA_REVISION)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--smoke", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.source == "fixture":
        if args.fixture is None:
            raise SystemExit("--fixture is required when --source=fixture")
        manifest = prepare_fixture(
            args.fixture, args.output_dir, seed=args.seed, smoke=args.smoke
        )
    else:
        manifest = prepare_public(
            args.raw_dir,
            args.output_dir,
            difraud_revision=args.difraud_revision,
            teddyha_revision=args.teddyha_revision,
            seed=args.seed,
            smoke=args.smoke,
        )
    print(json.dumps(manifest["counts"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
