"""Fine-tune mmBERT for calibrated bilingual phishing classification."""

from __future__ import annotations

import argparse
import gc
import json
import math
import shutil
import time
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any

from ml.calibrate import select_thresholds
from ml.contracts import DecisionThresholds, EmailRecord
from ml.evaluate import compute_metrics, evaluate_slices
from ml.train_baseline import load_split

_MODEL_ID = "jhu-clsp/mmBERT-small"
_MODEL_REVISION = "abc32620dd4f6ab06f5fbe905dc25f310618e09f"


@dataclass(frozen=True, slots=True)
class TrainingConfig:
    output_dir: Path
    checkpoint_dir: Path
    model_id: str
    model_revision: str
    max_length: int
    per_device_train_batch_size: int
    per_device_eval_batch_size: int
    gradient_accumulation_steps: int
    learning_rate: float
    weight_decay: float
    warmup_steps: int
    num_train_epochs: float
    max_steps: int
    seed: int
    smoke: bool


def training_config(
    output_dir: Path,
    smoke: bool,
    seed: int,
    *,
    checkpoint_dir: Path | None = None,
    model_id: str = _MODEL_ID,
    model_revision: str = _MODEL_REVISION,
    max_length: int = 512,
) -> TrainingConfig:
    if max_length <= 0:
        raise ValueError("max_length must be positive")
    return TrainingConfig(
        output_dir=output_dir,
        checkpoint_dir=checkpoint_dir
        or output_dir.parent / f"{output_dir.name}-checkpoints",
        model_id=model_id,
        model_revision=model_revision,
        max_length=max_length,
        per_device_train_batch_size=1,
        per_device_eval_batch_size=2,
        gradient_accumulation_steps=16,
        learning_rate=2e-5,
        weight_decay=0.01,
        warmup_steps=0,
        num_train_epochs=1.0 if smoke else 4.0,
        max_steps=2 if smoke else -1,
        seed=seed,
        smoke=smoke,
    )


def schedule_warmup(
    config: TrainingConfig,
    train_examples: int,
) -> TrainingConfig:
    """Resolve a stable 10% warmup schedule without deprecated ratios."""
    if train_examples <= 0:
        raise ValueError("train_examples must be positive")
    if config.max_steps > 0:
        optimizer_steps = config.max_steps
    else:
        steps_per_epoch = math.ceil(
            train_examples
            / (config.per_device_train_batch_size * config.gradient_accumulation_steps)
        )
        optimizer_steps = math.ceil(steps_per_epoch * config.num_train_epochs)
    return replace(
        config,
        warmup_steps=max(1, round(optimizer_steps * 0.1)),
    )


def model_load_options(config: TrainingConfig) -> dict[str, object]:
    """Return the auditable, non-executable remote base-model load policy."""
    return {
        "revision": config.model_revision,
        "trust_remote_code": False,
        "use_safetensors": False,
    }


def compute_class_weights(labels: Sequence[int]) -> tuple[float, float]:
    counts = Counter(int(label) for label in labels)
    if set(counts) != {0, 1}:
        raise ValueError("class weights require both binary classes")
    total = len(labels)
    return (
        total / (2 * counts[0]),
        total / (2 * counts[1]),
    )


def probability_rows(
    records: Sequence[Mapping[str, object]],
    probabilities: Sequence[float],
) -> list[dict[str, object]]:
    if len(records) != len(probabilities):
        raise ValueError("records and probabilities must have the same length")
    rows: list[dict[str, object]] = []
    for record, probability in zip(records, probabilities, strict=True):
        rows.append(
            {
                "id": record["id"],
                "source_split": record["source_split"],
                "language": record["language"],
                "synthetic": record["synthetic"],
                "label": record["label"],
                "phishing_probability": float(probability),
            }
        )
    return rows


def _probabilities_from_logits(logits: Any) -> list[float]:
    import numpy as np

    array = np.asarray(logits, dtype=np.float64)
    if array.ndim != 2 or array.shape[1] not in {1, 2}:
        raise ValueError("model predictions must contain one or two logits")
    if array.shape[1] == 1:
        values = 1.0 / (1.0 + np.exp(-array[:, 0]))
    else:
        shifted = array - np.max(array, axis=1, keepdims=True)
        exponentials = np.exp(shifted)
        values = exponentials[:, 1] / np.sum(exponentials, axis=1)
    return [max(0.0, min(1.0, float(value))) for value in values]


def _load_corpus(
    data_dir: Path,
    train_augmentations: Sequence[Path],
    test_augmentations: Sequence[Path],
) -> tuple[
    tuple[list[str], list[int], list[EmailRecord]],
    tuple[list[str], list[int], list[EmailRecord]],
    tuple[list[str], list[int], list[EmailRecord]],
]:
    train = load_split(data_dir / "train.jsonl", "train")
    validation = load_split(data_dir / "validation.jsonl", "validation")
    test = load_split(data_dir / "test.jsonl", "test")
    for path in train_augmentations:
        extra = load_split(path, "train")
        train[0].extend(extra[0])
        train[1].extend(extra[1])
        train[2].extend(extra[2])
    for path in test_augmentations:
        extra = load_split(path, "test")
        test[0].extend(extra[0])
        test[1].extend(extra[1])
        test[2].extend(extra[2])
    return train, validation, test


def _balanced_smoke(
    texts: Sequence[str],
    labels: Sequence[int],
    records: Sequence[EmailRecord],
    per_class: int = 4,
) -> tuple[list[str], list[int], list[EmailRecord]]:
    selected: list[int] = []
    for label in (0, 1):
        selected.extend(index for index, value in enumerate(labels) if value == label)
        selected = selected[: per_class * (label + 1)]
    selected = sorted(set(selected))
    return (
        [texts[index] for index in selected],
        [labels[index] for index in selected],
        [records[index] for index in selected],
    )


class _EncodedDataset:
    def __init__(
        self,
        texts: Sequence[str],
        labels: Sequence[int],
        tokenizer: Any,
        max_length: int,
    ) -> None:
        import torch

        encodings = tokenizer(
            list(texts),
            truncation=True,
            max_length=max_length,
            padding=False,
        )
        self._items: list[dict[str, Any]] = []
        for index, label in enumerate(labels):
            item = {
                name: torch.tensor(values[index], dtype=torch.long)
                for name, values in encodings.items()
            }
            item["labels"] = torch.tensor(label, dtype=torch.long)
            self._items.append(item)

    def __len__(self) -> int:
        return len(self._items)

    def __getitem__(self, index: int) -> dict[str, Any]:
        return self._items[index]


def _trainer_class(
    trainer_base: type[Any], class_weights: tuple[float, float]
) -> type[Any]:
    import torch

    class WeightedTrainer(trainer_base):
        def compute_loss(
            self,
            model: Any,
            inputs: dict[str, Any],
            return_outputs: bool = False,
            num_items_in_batch: Any = None,
        ) -> Any:
            del num_items_in_batch
            model_inputs = dict(inputs)
            labels = model_inputs.pop("labels")
            outputs = model(**model_inputs)
            weights = torch.tensor(
                class_weights,
                dtype=outputs.logits.dtype,
                device=outputs.logits.device,
            )
            loss = torch.nn.functional.cross_entropy(
                outputs.logits, labels, weight=weights
            )
            return (loss, outputs) if return_outputs else loss

    return WeightedTrainer


def _metric_float(metrics: Mapping[str, object], key: str) -> float:
    value = metrics.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"metric {key!r} must be numeric")
    return float(value)


def _metric_callback(prediction: Any) -> dict[str, float]:
    probabilities = _probabilities_from_logits(prediction.predictions)
    labels = [int(value) for value in prediction.label_ids]
    metrics = compute_metrics(
        labels,
        probabilities,
        DecisionThresholds(low=0.25, high=0.5),
    )
    return {
        "macro_f1": _metric_float(metrics, "macro_f1"),
        "phishing_recall": _metric_float(metrics, "phishing_recall"),
        "false_positive_rate": _metric_float(metrics, "false_positive_rate"),
    }


def build_training_arguments(
    config: TrainingConfig,
    *,
    cuda_available: bool,
    bf16_available: bool,
) -> Any:
    """Build version-checked Transformers arguments outside model loading."""
    from transformers import TrainingArguments

    strategy = "no" if config.smoke else "epoch"
    return TrainingArguments(
        output_dir=str(config.checkpoint_dir),
        per_device_train_batch_size=config.per_device_train_batch_size,
        per_device_eval_batch_size=config.per_device_eval_batch_size,
        gradient_accumulation_steps=config.gradient_accumulation_steps,
        learning_rate=config.learning_rate,
        weight_decay=config.weight_decay,
        warmup_steps=config.warmup_steps,
        num_train_epochs=config.num_train_epochs,
        max_steps=config.max_steps,
        eval_strategy=strategy,
        save_strategy=strategy,
        eval_steps=None,
        save_steps=500,
        logging_steps=1 if config.smoke else 50,
        load_best_model_at_end=not config.smoke,
        metric_for_best_model="eval_macro_f1",
        greater_is_better=True,
        save_total_limit=2,
        fp16=cuda_available and not bf16_available,
        bf16=cuda_available and bf16_available,
        gradient_checkpointing=True,
        eval_accumulation_steps=4,
        dataloader_num_workers=0,
        dataloader_pin_memory=cuda_available,
        report_to=[],
        seed=config.seed,
        data_seed=config.seed,
        optim="adafactor",
        save_only_model=config.smoke,
    )


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


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


def train_mmbert(
    config: TrainingConfig,
    data_dir: Path,
    *,
    train_augmentations: Sequence[Path] = (),
    test_augmentations: Sequence[Path] = (),
    resume_from_checkpoint: Path | None = None,
    max_fpr: float = 0.05,
) -> dict[str, object]:
    """Fine-tune, calibrate, evaluate, and export a clean candidate artifact."""
    try:
        import torch
        import transformers
        from transformers import (
            AutoConfig,
            AutoModelForSequenceClassification,
            AutoTokenizer,
            DataCollatorWithPadding,
            EarlyStoppingCallback,
            Trainer,
        )
    except ImportError as exc:
        raise RuntimeError(
            "PyTorch, Transformers, and Accelerate are required; "
            "install requirements-ml.txt"
        ) from exc

    train, validation, test = _load_corpus(
        data_dir, train_augmentations, test_augmentations
    )
    if config.smoke:
        train = _balanced_smoke(*train)
        validation = _balanced_smoke(*validation, per_class=2)
        test = _balanced_smoke(*test, per_class=2)
    if set(train[1]) != {0, 1} or set(validation[1]) != {0, 1}:
        raise ValueError("train and validation data must contain both classes")
    config = schedule_warmup(config, len(train[1]))

    transformers.set_seed(config.seed)
    if torch.cuda.is_available():
        torch.cuda.reset_peak_memory_stats()
    tokenizer = AutoTokenizer.from_pretrained(
        config.model_id,
        revision=config.model_revision,
        trust_remote_code=False,
    )
    model_config = AutoConfig.from_pretrained(
        config.model_id,
        revision=config.model_revision,
        num_labels=2,
        id2label={0: "legitimate", 1: "phishing"},
        label2id={"legitimate": 0, "phishing": 1},
        trust_remote_code=False,
    )
    model = AutoModelForSequenceClassification.from_pretrained(
        config.model_id,
        config=model_config,
        revision=config.model_revision,
        trust_remote_code=False,
        use_safetensors=False,
    )
    model.gradient_checkpointing_enable(
        gradient_checkpointing_kwargs={"use_reentrant": False}
    )

    train_dataset = _EncodedDataset(train[0], train[1], tokenizer, config.max_length)
    validation_dataset = _EncodedDataset(
        validation[0], validation[1], tokenizer, config.max_length
    )
    test_dataset = _EncodedDataset(test[0], test[1], tokenizer, config.max_length)
    training_arguments = build_training_arguments(
        config,
        cuda_available=torch.cuda.is_available(),
        bf16_available=(torch.cuda.is_available() and torch.cuda.is_bf16_supported()),
    )
    weighted_trainer = _trainer_class(Trainer, compute_class_weights(train[1]))
    trainer = weighted_trainer(
        model=model,
        args=training_arguments,
        train_dataset=train_dataset,
        eval_dataset=validation_dataset,
        data_collator=DataCollatorWithPadding(
            tokenizer=tokenizer,
            pad_to_multiple_of=8 if torch.cuda.is_available() else None,
        ),
        compute_metrics=_metric_callback,
        callbacks=(
            [] if config.smoke else [EarlyStoppingCallback(early_stopping_patience=2)]
        ),
        processing_class=tokenizer,
    )

    started = time.perf_counter()
    train_result = trainer.train(
        resume_from_checkpoint=(
            str(resume_from_checkpoint) if resume_from_checkpoint else None
        )
    )
    training_seconds = time.perf_counter() - started
    validation_output = trainer.predict(validation_dataset)
    test_output = trainer.predict(test_dataset)
    validation_probabilities = _probabilities_from_logits(validation_output.predictions)
    test_probabilities = _probabilities_from_logits(test_output.predictions)
    thresholds = select_thresholds(
        validation[1], validation_probabilities, max_fpr=max_fpr
    )
    validation_rows = probability_rows(
        [record.to_dict() for record in validation[2]],
        validation_probabilities,
    )
    test_rows = probability_rows(
        [record.to_dict() for record in test[2]], test_probabilities
    )
    metrics = {
        "schema_version": 1,
        "model": config.model_id,
        "validation": compute_metrics(
            validation[1], validation_probabilities, thresholds
        ),
        "test": evaluate_slices(test_rows, thresholds),
        "latency": {
            "training_seconds": training_seconds,
            "validation_seconds": float(
                validation_output.metrics.get("test_runtime", 0.0)
            ),
            "test_seconds": float(test_output.metrics.get("test_runtime", 0.0)),
        },
    }

    trainer.optimizer = None
    trainer.lr_scheduler = None
    gc.collect()
    if torch.cuda.is_available():
        torch.cuda.empty_cache()
    config.output_dir.mkdir(parents=True, exist_ok=True)
    trainer.save_model(str(config.output_dir))
    tokenizer.save_pretrained(str(config.output_dir))
    dataset_manifest = data_dir / "dataset-manifest.json"
    if not dataset_manifest.is_file():
        raise ValueError(f"dataset manifest not found: {dataset_manifest}")
    shutil.copyfile(dataset_manifest, config.output_dir / "dataset-manifest.json")
    _write_json(
        config.output_dir / "thresholds.json",
        {
            **thresholds.to_dict(),
            "calibration": {
                "max_fpr": max_fpr,
                "validation_sample_count": len(validation[1]),
            },
        },
    )
    _write_json(config.output_dir / "metrics.json", metrics)
    _write_jsonl(
        config.output_dir / "validation-predictions.jsonl",
        validation_rows,
    )
    _write_jsonl(config.output_dir / "test-predictions.jsonl", test_rows)
    peak_memory = (
        int(torch.cuda.max_memory_allocated()) if torch.cuda.is_available() else None
    )
    _write_json(
        config.output_dir / "training-metadata.json",
        {
            "config": {
                **asdict(config),
                "output_dir": str(config.output_dir),
                "checkpoint_dir": str(config.checkpoint_dir),
            },
            "train_metrics": train_result.metrics,
            "peak_cuda_memory_bytes": peak_memory,
            "torch_version": torch.__version__,
            "transformers_version": transformers.__version__,
        },
    )
    return metrics


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fine-tune mmBERT for bilingual phishing classification."
    )
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--checkpoint-dir", type=Path)
    parser.add_argument("--train-augmentation", type=Path, action="append", default=[])
    parser.add_argument("--test-augmentation", type=Path, action="append", default=[])
    parser.add_argument("--resume-from-checkpoint", type=Path)
    parser.add_argument("--model-id", default=_MODEL_ID)
    parser.add_argument("--model-revision", default=_MODEL_REVISION)
    parser.add_argument("--max-length", type=int, default=512)
    parser.add_argument("--epochs", type=float)
    parser.add_argument("--max-fpr", type=float, default=0.05)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--smoke", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    config = training_config(
        args.output_dir,
        args.smoke,
        args.seed,
        checkpoint_dir=args.checkpoint_dir,
        model_id=args.model_id,
        model_revision=args.model_revision,
        max_length=args.max_length,
    )
    if args.epochs is not None:
        if args.epochs <= 0 or not math.isfinite(args.epochs):
            raise SystemExit("--epochs must be a positive finite number")
        config = replace(config, num_train_epochs=args.epochs)
    metrics = train_mmbert(
        config,
        args.data_dir,
        train_augmentations=args.train_augmentation,
        test_augmentations=args.test_augmentation,
        resume_from_checkpoint=args.resume_from_checkpoint,
        max_fpr=args.max_fpr,
    )
    validation = metrics.get("validation")
    macro_f1 = validation.get("macro_f1") if isinstance(validation, Mapping) else None
    print(
        json.dumps(
            {
                "output_dir": str(args.output_dir),
                "validation_macro_f1": macro_f1,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
