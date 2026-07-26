from __future__ import annotations

from pathlib import Path

import pytest

from ml.train_mmbert import (
    bound_tokenizer_inputs,
    build_training_arguments,
    compute_class_weights,
    freeze_token_embeddings,
    model_load_options,
    model_weight_dtype_name,
    probability_rows,
    schedule_warmup,
    training_config,
)


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


def test_training_arguments_match_installed_transformers_api(
    tmp_path: Path,
) -> None:
    pytest.importorskip("transformers")
    config = training_config(tmp_path / "candidate", smoke=True, seed=42)

    arguments = build_training_arguments(
        config, cuda_available=True, bf16_available=True
    )

    assert arguments.output_dir == str(config.checkpoint_dir)
    assert arguments.eval_strategy.value == "no"
    assert arguments.save_strategy.value == "no"
    assert arguments.fp16 is False
    assert arguments.bf16 is True
    assert arguments.optim.value == "adafactor"
    assert arguments.save_only_model is True
    assert arguments.gradient_checkpointing is True
    assert arguments.max_steps == 2
    assert arguments.warmup_steps == 0


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
