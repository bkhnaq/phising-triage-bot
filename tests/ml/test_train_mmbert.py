from __future__ import annotations

import json
import math
from dataclasses import replace
from pathlib import Path

import pytest

import ml.train_mmbert as train_module
from ml.train_mmbert import (
    bound_tokenizer_inputs,
    build_training_arguments,
    compute_class_weights,
    freeze_token_embeddings,
    load_training_corpus,
    model_load_options,
    model_weight_dtype_name,
    probability_rows,
    schedule_warmup,
    train_mmbert,
    training_config,
)
from ml.contracts import ArtifactFile, ArtifactManifest, EmailRecord
from ml.prepare_data import prepare_fixture
from ml.text import content_sha256
from ml.train_baseline import load_split


def test_class_weights_upweight_minority_class() -> None:
    legitimate, phishing = compute_class_weights([0, 0, 0, 1])

    assert legitimate == pytest.approx(2 / 3)
    assert phishing == pytest.approx(2.0)
    assert phishing > legitimate


@pytest.mark.parametrize("labels", [[], [0, 0], [1, 1], [0, 2]])
def test_class_weights_require_both_binary_classes(labels: list[int]) -> None:
    with pytest.raises(ValueError, match="both binary classes"):
        compute_class_weights(labels)


def test_smoke_training_configuration_is_gpu_safe_and_bounded(
    tmp_path: Path,
) -> None:
    config = training_config(output_dir=tmp_path, smoke=True, seed=42)

    assert config.model_id == "jhu-clsp/mmBERT-small"
    assert config.model_revision == "abc32620dd4f6ab06f5fbe905dc25f310618e09f"
    assert config.max_length == 512
    assert config.per_device_train_batch_size == 1
    assert config.gradient_accumulation_steps == 16
    assert config.max_steps == 2
    assert config.num_train_epochs == 1.0
    assert config.freeze_token_embeddings is True
    assert config.seed == 42


def test_full_training_configuration_keeps_checkpoints_outside_candidate(
    tmp_path: Path,
) -> None:
    output_dir = tmp_path / "candidate"

    config = training_config(output_dir=output_dir, smoke=False, seed=7)

    assert config.checkpoint_dir == tmp_path / "candidate-checkpoints"
    assert config.max_steps == -1
    assert config.num_train_epochs == 4.0
    assert config.checkpoint_dir != config.output_dir


@pytest.mark.parametrize(
    ("smoke", "train_examples", "expected_steps"),
    [(True, 32, 1), (False, 1_600, 40)],
)
def test_warmup_is_an_explicit_ten_percent_of_optimizer_steps(
    tmp_path: Path,
    smoke: bool,
    train_examples: int,
    expected_steps: int,
) -> None:
    config = training_config(tmp_path / "candidate", smoke=smoke, seed=42)

    scheduled = schedule_warmup(config, train_examples)

    assert scheduled.warmup_steps == expected_steps


def test_training_arguments_match_installed_cpu_transformers_api(
    tmp_path: Path,
) -> None:
    pytest.importorskip("transformers")
    config = training_config(tmp_path / "candidate", smoke=True, seed=42)

    arguments = build_training_arguments(
        config, cuda_available=False, bf16_available=False
    )

    assert arguments.output_dir == str(config.checkpoint_dir)
    assert arguments.eval_strategy.value == "no"
    assert arguments.save_strategy.value == "no"
    assert arguments.fp16 is False
    assert arguments.bf16 is False
    assert arguments.optim.value == "adafactor"
    assert arguments.save_only_model is True
    assert arguments.gradient_checkpointing is False
    assert arguments.max_steps == 2
    assert arguments.warmup_steps == 0


def test_single_epoch_full_run_evaluates_without_resident_checkpoint_save(
    tmp_path: Path,
) -> None:
    pytest.importorskip("transformers")
    config = replace(
        training_config(tmp_path / "candidate", smoke=False, seed=42),
        num_train_epochs=1.0,
    )

    arguments = build_training_arguments(
        config,
        cuda_available=False,
        bf16_available=False,
    )

    assert arguments.eval_strategy.value == "epoch"
    assert arguments.save_strategy.value == "no"
    assert arguments.load_best_model_at_end is False


def test_base_model_loading_is_revision_pinned_without_remote_code(
    tmp_path: Path,
) -> None:
    config = training_config(tmp_path / "candidate", smoke=True, seed=42)

    options = model_load_options(config)

    assert options == {
        "revision": "abc32620dd4f6ab06f5fbe905dc25f310618e09f",
        "trust_remote_code": False,
        "use_safetensors": False,
    }


def test_warm_start_loading_requires_validated_local_safetensors(
    tmp_path: Path,
) -> None:
    initial_model_dir = tmp_path / "previous-candidate"
    config = training_config(
        tmp_path / "candidate",
        smoke=False,
        seed=42,
        initial_model_dir=initial_model_dir,
        learning_rate=1e-5,
    )

    options = model_load_options(config)

    assert config.initial_model_dir == initial_model_dir
    assert config.learning_rate == 1e-5
    assert options == {
        "revision": "abc32620dd4f6ab06f5fbe905dc25f310618e09f",
        "trust_remote_code": False,
        "use_safetensors": True,
        "local_files_only": True,
    }


@pytest.mark.parametrize("learning_rate", [0.0, -1e-5, math.inf, math.nan])
def test_training_configuration_rejects_invalid_learning_rate(
    tmp_path: Path,
    learning_rate: float,
) -> None:
    with pytest.raises(ValueError, match="learning_rate"):
        training_config(
            tmp_path / "candidate",
            smoke=False,
            seed=42,
            learning_rate=learning_rate,
        )


def test_evaluate_only_requires_a_validated_initial_artifact(
    tmp_path: Path,
) -> None:
    config = training_config(
        tmp_path / "candidate",
        smoke=False,
        seed=42,
    )

    with pytest.raises(ValueError, match="initial_model_dir"):
        train_mmbert(
            config,
            tmp_path / "data",
            evaluate_only=True,
        )


@pytest.mark.parametrize(
    ("model_id", "model_revision"),
    [
        ("different/model", "abc32620dd4f6ab06f5fbe905dc25f310618e09f"),
        ("jhu-clsp/mmBERT-small", "different-revision"),
    ],
)
def test_warm_start_requires_exact_configured_model_identity(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    model_id: str,
    model_revision: str,
) -> None:
    initial_model_dir = tmp_path / "initial"
    config = training_config(
        tmp_path / "candidate",
        smoke=False,
        seed=42,
        initial_model_dir=initial_model_dir,
    )
    manifest = ArtifactManifest(
        schema_version=2,
        model_id=model_id,
        model_revision=model_revision,
        files={"model.safetensors": ArtifactFile("a" * 64, 1)},
    )
    monkeypatch.setattr(
        train_module,
        "validate_artifact",
        lambda _directory: manifest,
    )

    with pytest.raises(ValueError, match="identity"):
        train_mmbert(config, tmp_path / "data", evaluate_only=True)


@pytest.mark.parametrize(
    ("cuda_available", "bf16_available", "expected"),
    [
        (True, True, "bfloat16"),
        (True, False, None),
        (False, False, None),
    ],
)
def test_native_bf16_weights_are_used_only_on_supported_gpu(
    cuda_available: bool,
    bf16_available: bool,
    expected: str | None,
) -> None:
    assert model_weight_dtype_name(cuda_available, bf16_available) == expected


def test_token_embedding_freeze_only_disables_embedding_parameters() -> None:
    embedding_parameter = _FakeParameter()
    encoder_parameter = _FakeParameter()
    model = _FakeModel(embedding_parameter, encoder_parameter)

    frozen = freeze_token_embeddings(model)

    assert frozen == 1
    assert embedding_parameter.requires_grad is False
    assert encoder_parameter.requires_grad is True


def test_tokenizer_inputs_are_balanced_and_bounded_before_encoding() -> None:
    text = "HEAD" + ("x" * 8_000) + "TAIL"

    bounded = bound_tokenizer_inputs([text], max_length=512)

    assert len(bounded[0]) == 2_048
    assert bounded[0].startswith("HEAD")
    assert bounded[0].endswith("TAIL")
    assert "[...]" in bounded[0]


def test_probability_rows_preserve_record_metadata() -> None:
    rows = probability_rows(
        [
            {
                "id": "one",
                "source_split": "test",
                "language": "vi",
                "synthetic": True,
                "label": "phishing",
            }
        ],
        [0.875],
    )

    assert rows == [
        {
            "id": "one",
            "source_split": "test",
            "language": "vi",
            "synthetic": True,
            "label": "phishing",
            "phishing_probability": 0.875,
        }
    ]


def test_probability_rows_reject_length_mismatch() -> None:
    with pytest.raises(ValueError, match="same length"):
        probability_rows([], [0.5])


def _prepared_data(tmp_path: Path) -> Path:
    data_dir = tmp_path / "data"
    fixture = Path(__file__).parents[1] / "fixtures" / "ml" / "tiny_emails.jsonl"
    prepare_fixture(fixture, data_dir)
    return data_dir


def _write_augmentation(
    path: Path,
    original: EmailRecord,
    split: str,
    *,
    group_id: str | None = None,
) -> EmailRecord:
    body = f"Báº£n dá»‹ch {original.body}"
    record = EmailRecord(
        id=f"{original.id}:{split}:vi",
        source=f"{original.source}:local-vi",
        source_split=split,
        source_id=f"{original.source_id}:{split}:vi",
        language="vi",
        subject=f"Báº£n dá»‹ch {original.subject}",
        sender=original.sender,
        body=body,
        label=original.label,
        content_sha256=content_sha256(
            f"Báº£n dá»‹ch {original.subject}",
            original.sender,
            body,
        ),
        group_id=group_id or f"{original.group_id}:{split}:vi",
        synthetic=True,
    )
    path.write_text(
        json.dumps(record.to_dict(), ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    path.with_suffix(path.suffix + ".manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "mode": "local",
                "model": "translator",
                "revision": "pinned-revision",
                "split": split,
            }
        ),
        encoding="utf-8",
    )
    return record


def test_training_rejects_base_dataset_checksum_mismatch(tmp_path: Path) -> None:
    data_dir = _prepared_data(tmp_path)
    train_path = data_dir / "train.jsonl"
    train_path.write_text(
        train_path.read_text(encoding="utf-8") + " \n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="checksum mismatch.*train.jsonl"):
        load_training_corpus(data_dir, (), (), ())


def test_training_rejects_augmentation_group_leakage(tmp_path: Path) -> None:
    data_dir = _prepared_data(tmp_path)
    original = load_split(data_dir / "train.jsonl", "train")[2][0]
    augmentation = tmp_path / "validation.vi.jsonl"
    _write_augmentation(
        augmentation,
        original,
        "validation",
        group_id=original.group_id,
    )

    with pytest.raises(ValueError, match="crosses splits"):
        load_training_corpus(data_dir, (), (augmentation,), ())


def test_merged_manifest_binds_augmentation_and_multiplicity(
    tmp_path: Path,
) -> None:
    data_dir = _prepared_data(tmp_path)
    original = load_split(data_dir / "train.jsonl", "train")[2][0]
    augmentation = tmp_path / "train.vi.jsonl"
    _write_augmentation(augmentation, original, "train")
    base_train_count = len(load_split(data_dir / "train.jsonl", "train")[2])

    train, _validation, _test, manifest = load_training_corpus(
        data_dir,
        (augmentation, augmentation),
        (),
        (),
    )

    entries = manifest["augmentations"]
    assert isinstance(entries, list)
    assert len(entries) == 1
    assert entries[0]["split"] == "train"
    assert entries[0]["multiplicity"] == 2
    assert len(entries[0]["sha256"]) == 64
    assert entries[0]["generation_manifest"]["revision"] == "pinned-revision"
    assert manifest["splits"]["train"]["sample_count"] == base_train_count + 2
    assert len(train[2]) == base_train_count + 2
    assert "base/train.jsonl" in manifest["checksums"]
    assert any(key.startswith("augmentation/train/") for key in manifest["checksums"])


class _FakeParameter:
    def __init__(self) -> None:
        self.requires_grad = True


class _FakeEmbeddings:
    def __init__(self, parameter: _FakeParameter) -> None:
        self._parameter = parameter

    def parameters(self) -> list[_FakeParameter]:
        return [self._parameter]


class _FakeModel:
    def __init__(
        self,
        embedding_parameter: _FakeParameter,
        encoder_parameter: _FakeParameter,
    ) -> None:
        self._embeddings = _FakeEmbeddings(embedding_parameter)
        self.encoder_parameter = encoder_parameter

    def get_input_embeddings(self) -> _FakeEmbeddings:
        return self._embeddings
