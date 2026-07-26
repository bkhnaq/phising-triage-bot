from ml.augment_vietnamese import _domains, _protected_tokens, _urls
from ml.augment_vietnamese_local import (
    _parser,
    build_local_variant,
    translate_preserving_security_tokens,
)
from ml.contracts import EmailRecord
from ml.text import content_sha256


def _record() -> EmailRecord:
    body = (
        "Pay $10,000 at https://evil.test/login, contact admin@evil.test, "
        "and open [attachment: invoice.pdf]."
    )
    return EmailRecord(
        id="source:test:1",
        source="source",
        source_split="test",
        source_id="1",
        language="en",
        subject="Urgent account verification",
        sender="billing@evil.test",
        body=body,
        label="phishing",
        content_sha256=content_sha256(
            "Urgent account verification", "billing@evil.test", body
        ),
        group_id="source:test:1",
        synthetic=False,
    )


def test_translation_never_sends_security_tokens_through_model() -> None:
    original = _record().body
    translated_inputs: list[str] = []

    def translate(parts: list[str]) -> list[str]:
        translated_inputs.extend(parts)
        return [f"VI({part})" for part in parts]

    translated = translate_preserving_security_tokens(original, translate)

    assert _urls(translated) == _urls(original)
    assert _domains(translated) == _domains(original)
    assert _protected_tokens(translated) == _protected_tokens(original)
    model_input = " ".join(translated_inputs)
    assert "https://evil.test/login" not in model_input
    assert "$10,000" not in model_input
    assert "[attachment: invoice.pdf]" not in model_input


def test_local_variant_preserves_contract_and_records_provenance() -> None:
    original = _record()

    def translate(parts: list[str]) -> list[str]:
        return [f"Bản dịch {part}" for part in parts]

    generated = build_local_variant(
        original,
        translate,
        model_id="Helsinki-NLP/opus-mt-en-vi",
    )

    assert generated.id == f"{original.id}:vi"
    assert generated.source == "source:local-vi"
    assert generated.source_split == "test"
    assert generated.group_id == original.group_id
    assert generated.language == "vi"
    assert generated.label == original.label
    assert generated.sender == original.sender
    assert generated.synthetic is True


def test_model_generated_domain_like_text_is_neutralized() -> None:
    original = _record()

    def translate(parts: list[str]) -> list[str]:
        return [f"Bản dịch 202.ainsa {part}" for part in parts]

    generated = build_local_variant(
        original,
        translate,
        model_id="Helsinki-NLP/opus-mt-en-vi",
    )

    assert _domains(f"{generated.subject}\n{generated.body}") == _domains(
        f"{original.subject}\n{original.body}"
    )


def test_local_augmenter_accepts_validation_split(tmp_path) -> None:
    args = _parser().parse_args(
        [
            "--input",
            str(tmp_path / "input.jsonl"),
            "--output",
            str(tmp_path / "output.jsonl"),
            "--cache-dir",
            str(tmp_path / "cache"),
            "--split",
            "validation",
        ]
    )

    assert args.split == "validation"
