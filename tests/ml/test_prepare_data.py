from __future__ import annotations

import json
from pathlib import Path

import pytest

from ml.contracts import EmailRecord
from ml.prepare_data import (
    deduplicate_records,
    normalize_source_row,
    prepare_fixture,
    validate_group_splits,
)
from ml.text import content_sha256


def _record(
    record_id: str,
    split: str,
    *,
    group_id: str | None = None,
    body: str = "same body",
) -> EmailRecord:
    return EmailRecord(
        id=record_id,
        source="fixture",
        source_split=split,
        source_id=record_id,
        language="en",
        subject="same subject",
        sender="sender@example.test",
        body=body,
        label="legitimate",
        content_sha256=content_sha256("same subject", "sender@example.test", body),
        group_id=group_id or record_id,
        synthetic=False,
    )


def test_difraud_adapter_preserves_official_split_and_binary_label() -> None:
    record = normalize_source_row(
        {"_source_id": "17", "text": "Reset your password now", "label": 1},
        adapter="difraud",
        split="validation",
    )

    assert record.id == "difraud:validation:17"
    assert record.source_split == "validation"
    assert record.label == "phishing"
    assert record.body == "Reset your password now"
    assert record.group_id == record.id


def test_teddyha_adapter_is_training_only() -> None:
    row = {
        "id": "legit-001",
        "subject": "Team meeting",
        "body": "Agenda attached.",
        "spoofed_sender": "team@example.test",
        "label": "benign",
    }

    record = normalize_source_row(row, adapter="teddyha", split="train")

    assert record.label == "legitimate"
    assert record.sender == "team@example.test"
    with pytest.raises(ValueError, match="training-only"):
        normalize_source_row(row, adapter="teddyha", split="test")


def test_unknown_source_label_is_quarantinable_validation_error() -> None:
    with pytest.raises(ValueError, match="label"):
        normalize_source_row(
            {
                "id": "x",
                "subject": "Hello",
                "body": "World",
                "sender": "a@example.test",
                "label": "spam",
            },
            adapter="fixture",
            split="train",
        )


def test_exact_duplicates_keep_first_record_and_report_later_record() -> None:
    kept, rejected = deduplicate_records([_record("a", "train"), _record("b", "train")])

    assert [item.id for item in kept] == ["a"]
    assert rejected == [{"id": "b", "reason": "duplicate_content", "duplicate_of": "a"}]


def test_group_cannot_cross_splits() -> None:
    with pytest.raises(ValueError, match="group_id 'shared'"):
        validate_group_splits(
            [
                _record("a", "train", group_id="shared", body="one"),
                _record("b", "test", group_id="shared", body="two"),
            ]
        )


def test_fixture_preparation_writes_deterministic_splits_and_manifest(
    tmp_path: Path,
) -> None:
    fixture = Path(__file__).parents[1] / "fixtures" / "ml" / "tiny_emails.jsonl"
    first_output = tmp_path / "first"
    second_output = tmp_path / "second"

    first = prepare_fixture(fixture, first_output, seed=42, smoke=True)
    second = prepare_fixture(fixture, second_output, seed=42, smoke=True)

    for split in ("train", "validation", "test"):
        first_bytes = (first_output / f"{split}.jsonl").read_bytes()
        second_bytes = (second_output / f"{split}.jsonl").read_bytes()
        assert first_bytes == second_bytes
        records = [
            json.loads(line)
            for line in first_bytes.decode("utf-8").splitlines()
            if line
        ]
        assert {item["source_split"] for item in records} == {split}
        assert {item["label"] for item in records} == {
            "legitimate",
            "phishing",
        }

    assert first["counts"] == second["counts"]
    assert first["checksums"] == second["checksums"]
    assert first["sources"][0]["license"] == "MIT"
    assert (first_output / "dataset-manifest.json").is_file()
    assert (first_output / "rejected.jsonl").is_file()


def test_malformed_jsonl_row_is_quarantined_without_losing_valid_rows(
    tmp_path: Path,
) -> None:
    fixture = tmp_path / "input.jsonl"
    fixture.write_text(
        '{"id":"ok","source_split":"train","subject":"Hello",'
        '"sender":"a@example.test","body":"Valid body","label":"legitimate"}\n'
        '{"id":"broken",\n',
        encoding="utf-8",
    )

    manifest = prepare_fixture(fixture, tmp_path / "output")

    assert manifest["counts"] == {
        "total": 1,
        "rejected": 1,
        "train": 1,
        "validation": 0,
        "test": 0,
    }
    rejected = (tmp_path / "output" / "rejected.jsonl").read_text(encoding="utf-8")
    assert '"reason":"invalid_json"' in rejected
    assert '"line":"2"' in rejected
