from __future__ import annotations

from pathlib import Path

import pytest

from ml.augment_vietnamese import (
    AugmentationStats,
    augment_records,
    augmentation_cache_key,
    parse_augmentation_response,
)
from ml.contracts import EmailRecord
from ml.text import content_sha256


def _record(
    record_id: str = "source:train:1",
    *,
    label: str = "phishing",
    body: str = (
        "Pay $10,000 at https://evil.test/login " "and open [attachment: invoice.pdf]."
    ),
) -> EmailRecord:
    return EmailRecord(
        id=record_id,
        source="source",
        source_split="train",
        source_id=record_id.rsplit(":", 1)[-1],
        language="en",
        subject="Urgent account action",
        sender="billing@evil.test",
        body=body,
        label=label,
        content_sha256=content_sha256(
            "Urgent account action", "billing@evil.test", body
        ),
        group_id=record_id,
        synthetic=False,
    )


def _valid_payload(record: EmailRecord) -> dict[str, object]:
    return {
        "items": [
            {
                "source_id": record.id,
                "subject": "Hành động khẩn cấp cho tài khoản",
                "sender": record.sender,
                "body": (
                    "Thanh toán $10,000 tại https://evil.test/login "
                    "và mở [attachment: invoice.pdf]."
                ),
                "label": record.label,
            }
        ]
    }


def test_cache_key_is_stable_and_bound_to_prompt_and_model() -> None:
    record = _record()

    first = augmentation_cache_key(record, "model-a", "v1")

    assert first == augmentation_cache_key(record, "model-a", "v1")
    assert first != augmentation_cache_key(record, "model-b", "v1")
    assert first != augmentation_cache_key(record, "model-a", "v2")
    assert len(first) == 64


def test_strict_response_builds_vietnamese_variant_in_same_group() -> None:
    original = _record()

    generated = parse_augmentation_response(_valid_payload(original), [original])

    assert len(generated) == 1
    assert generated[0].language == "vi"
    assert generated[0].synthetic is True
    assert generated[0].source_split == "train"
    assert generated[0].group_id == original.group_id
    assert generated[0].label == "phishing"
    assert generated[0].id == f"{original.id}:vi"


def test_response_allows_empty_subject_when_source_has_no_subject() -> None:
    original = _record()
    original = EmailRecord(
        **{
            **original.to_dict(),
            "subject": "",
            "content_sha256": content_sha256("", original.sender, original.body),
        }
    )
    payload = _valid_payload(original)
    items = payload["items"]
    assert isinstance(items, list)
    items[0]["subject"] = ""

    generated = parse_augmentation_response(payload, [original])

    assert generated[0].subject == ""
    assert generated[0].body.startswith("Thanh toán")


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("label", "legitimate", "label"),
        ("sender", "other@example.test", "sender"),
        (
            "body",
            "Thanh toán $10,000 tại https://safe.test/login "
            "và mở [attachment: invoice.pdf].",
            "URL",
        ),
        (
            "body",
            "Thanh toán $20 tại https://evil.test/login "
            "và mở [attachment: invoice.pdf].",
            "protected token",
        ),
        (
            "body",
            "Thanh toán $10,000 tại https://evil.test/login.",
            "protected token",
        ),
        (
            "body",
            "Thanh toán $10,000 tại https://evil.test/login qua portal.safe.test "
            "và mở [attachment: invoice.pdf].",
            "domain",
        ),
    ],
)
def test_response_cannot_change_security_critical_fields(
    field: str, value: str, error: str
) -> None:
    original = _record()
    payload = _valid_payload(original)
    items = payload["items"]
    assert isinstance(items, list)
    items[0][field] = value

    with pytest.raises(ValueError, match=error):
        parse_augmentation_response(payload, [original])


def test_response_requires_exactly_one_item_per_source_record() -> None:
    original = _record()

    with pytest.raises(ValueError, match="source IDs"):
        parse_augmentation_response({"items": []}, [original])


def test_content_addressed_cache_avoids_second_network_call(
    tmp_path: Path,
) -> None:
    original = _record()

    def first_request(records: list[EmailRecord]) -> object:
        assert records == [original]
        return _valid_payload(original)

    first, first_failures, first_stats = augment_records(
        [original],
        cache_dir=tmp_path,
        model="model-a",
        prompt_version="v1",
        request_batch=first_request,
        batch_size=4,
        max_requests=1,
    )

    def forbidden_request(_records: list[EmailRecord]) -> object:
        raise AssertionError("a cache hit must not call the network")

    second, second_failures, second_stats = augment_records(
        [original],
        cache_dir=tmp_path,
        model="model-a",
        prompt_version="v1",
        request_batch=forbidden_request,
        batch_size=4,
        max_requests=1,
    )

    assert first == second
    assert first_failures == second_failures == []
    assert first_stats == AugmentationStats(
        input_records=1,
        generated_records=1,
        cache_hits=0,
        requests=1,
        failures=0,
    )
    assert second_stats.cache_hits == 1
    assert second_stats.requests == 0


def test_request_budget_quarantines_unprocessed_records(tmp_path: Path) -> None:
    records = [_record("source:train:1"), _record("source:train:2")]

    def request_batch(batch: list[EmailRecord]) -> object:
        return _valid_payload(batch[0])

    generated, failures, stats = augment_records(
        records,
        cache_dir=tmp_path,
        model="model-a",
        prompt_version="v1",
        request_batch=request_batch,
        batch_size=1,
        max_requests=1,
    )

    assert [item.id for item in generated] == ["source:train:1:vi"]
    assert failures == [{"id": "source:train:2", "reason": "request_budget_exhausted"}]
    assert stats.requests == 1
    assert stats.failures == 1


def test_network_failure_is_quarantined_without_exposing_exception_text(
    tmp_path: Path,
) -> None:
    original = _record()

    def failed_request(_records: list[EmailRecord]) -> object:
        raise RuntimeError("secret-bearing upstream response")

    generated, failures, stats = augment_records(
        [original],
        cache_dir=tmp_path,
        model="model-a",
        prompt_version="v1",
        request_batch=failed_request,
        max_requests=1,
    )

    assert generated == []
    assert failures == [{"id": original.id, "reason": "request_failed:RuntimeError"}]
    assert "secret-bearing" not in str(failures)
    assert stats.failures == 1
