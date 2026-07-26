from __future__ import annotations

import pytest

from ml.contracts import DecisionThresholds, EmailRecord


def _valid_record() -> dict[str, object]:
    return {
        "id": "fixture:train:1",
        "source": "fixture",
        "source_split": "train",
        "source_id": "1",
        "language": "en",
        "subject": "Quarterly update",
        "sender": "finance@example.test",
        "body": "The report is attached.",
        "label": "legitimate",
        "content_sha256": "a" * 64,
        "group_id": "fixture:1",
        "synthetic": False,
    }


def test_threshold_boundaries_map_to_three_runtime_verdicts() -> None:
    thresholds = DecisionThresholds(low=0.2, high=0.8)

    assert thresholds.verdict(0.199) == "legitimate"
    assert thresholds.verdict(0.2) == "suspicious"
    assert thresholds.verdict(0.799) == "suspicious"
    assert thresholds.verdict(0.8) == "phishing"


@pytest.mark.parametrize(
    ("low", "high"),
    [(-0.1, 0.8), (0.8, 0.8), (0.9, 0.8), (0.2, 1.1)],
)
def test_invalid_threshold_order_is_rejected(low: float, high: float) -> None:
    with pytest.raises(ValueError, match="0 <= low < high <= 1"):
        DecisionThresholds(low=low, high=high)


def test_threshold_mapping_clamps_out_of_range_probabilities() -> None:
    thresholds = DecisionThresholds(low=0.2, high=0.8)

    assert thresholds.verdict(-2.0) == "legitimate"
    assert thresholds.verdict(4.0) == "phishing"


def test_email_record_round_trips_the_normalized_contract() -> None:
    raw = _valid_record()

    record = EmailRecord.from_mapping(raw)

    assert record.to_dict() == raw


def test_email_record_rejects_unknown_label() -> None:
    raw = _valid_record()
    raw["label"] = "spam"

    with pytest.raises(ValueError, match="label"):
        EmailRecord.from_mapping(raw)


def test_email_record_rejects_unknown_split() -> None:
    raw = _valid_record()
    raw["source_split"] = "holdout"

    with pytest.raises(ValueError, match="source_split"):
        EmailRecord.from_mapping(raw)


def test_email_record_rejects_malformed_sha256() -> None:
    raw = _valid_record()
    raw["content_sha256"] = "not-a-sha"

    with pytest.raises(ValueError, match="content_sha256"):
        EmailRecord.from_mapping(raw)


def test_email_record_requires_boolean_synthetic_flag() -> None:
    raw = _valid_record()
    raw["synthetic"] = "false"

    with pytest.raises(ValueError, match="synthetic"):
        EmailRecord.from_mapping(raw)
