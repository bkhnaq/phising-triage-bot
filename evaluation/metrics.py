"""Metric and report helpers for phishing-triage regression evaluation."""

from __future__ import annotations

from collections import Counter, defaultdict
from statistics import mean

SEVERITY_ORDER = {"LOW": 0, "MODERATE": 1, "ELEVATED": 2, "HIGH": 3, "CRITICAL": 4}
POSITIVE_VERDICTS = frozenset({"SUSPICIOUS", "PHISHING", "BEC", "MALWARE"})


def safe_div(numerator: int | float, denominator: int | float) -> float:
    return round(float(numerator) / float(denominator), 4) if denominator else 0.0


def binary_metrics(samples: list[dict]) -> dict:
    labeled = [item for item in samples if item["label"] in {"phishing", "benign"}]
    tp = sum(
        item["label"] == "phishing" and item["predicted_positive"] for item in labeled
    )
    tn = sum(
        item["label"] == "benign" and not item["predicted_positive"] for item in labeled
    )
    fp = sum(
        item["label"] == "benign" and item["predicted_positive"] for item in labeled
    )
    fn = sum(
        item["label"] == "phishing" and not item["predicted_positive"]
        for item in labeled
    )
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    return {
        "evaluated": len(labeled),
        "excluded_ambiguous": len(samples) - len(labeled),
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": safe_div(2 * precision * recall, precision + recall),
        "accuracy": safe_div(tp + tn, len(labeled)),
        "false_positive_rate": safe_div(fp, fp + tn),
        "false_negative_rate": safe_div(fn, fn + tp),
    }


def class_metrics(samples: list[dict]) -> dict[str, dict]:
    classes = sorted(
        {item["attack_class"] for item in samples}
        | {item["predicted_class"] for item in samples}
    )
    metrics: dict[str, dict] = {}
    for class_name in classes:
        tp = sum(
            item["attack_class"] == class_name and item["predicted_class"] == class_name
            for item in samples
        )
        fp = sum(
            item["attack_class"] != class_name and item["predicted_class"] == class_name
            for item in samples
        )
        fn = sum(
            item["attack_class"] == class_name and item["predicted_class"] != class_name
            for item in samples
        )
        support = sum(item["attack_class"] == class_name for item in samples)
        precision = safe_div(tp, tp + fp)
        recall = safe_div(tp, tp + fn)
        metrics[class_name] = {
            "precision": precision,
            "recall": recall,
            "f1": safe_div(2 * precision * recall, precision + recall),
            "support": support,
            "tp": tp,
            "fp": fp,
            "fn": fn,
        }
    return metrics


def detector_metrics(samples: list[dict]) -> dict[str, dict]:
    counts: dict[str, Counter] = defaultdict(Counter)
    for item in samples:
        observed = set(item["observed_findings"])
        for detector in item["expected_findings"]:
            counts[detector]["tp" if detector in observed else "fn"] += 1
        for detector in item["forbidden_findings"]:
            counts[detector]["fp" if detector in observed else "tn"] += 1

    output: dict[str, dict] = {}
    for detector, values in sorted(counts.items()):
        tp, tn, fp, fn = (values[key] for key in ("tp", "tn", "fp", "fn"))
        precision = safe_div(tp, tp + fp)
        recall = safe_div(tp, tp + fn)
        output[detector] = {
            "tp": tp,
            "tn": tn,
            "fp": fp,
            "fn": fn,
            "precision": precision,
            "recall": recall,
            "f1": safe_div(2 * precision * recall, precision + recall),
            "annotated_support": tp + tn + fp + fn,
        }
    return output


def severity_metrics(samples: list[dict]) -> dict:
    within = sum(item["severity_within_expected_range"] for item in samples)
    errors = [item["severity_distance"] for item in samples]
    confusion: dict[str, Counter] = defaultdict(Counter)
    for item in samples:
        expected_band = (
            f"{item['expected_min_severity']}..{item['expected_max_severity']}"
        )
        confusion[expected_band][item["severity"]] += 1
    return {
        "within_expected_range": within,
        "outside_expected_range": len(samples) - within,
        "range_accuracy": safe_div(within, len(samples)),
        "mean_ordinal_distance": round(mean(errors), 3) if errors else 0.0,
        "confusion": {key: dict(value) for key, value in sorted(confusion.items())},
    }


def confidence_buckets(samples: list[dict]) -> dict[str, dict]:
    buckets = {
        "0.00-0.49": (0.0, 0.5),
        "0.50-0.69": (0.5, 0.7),
        "0.70-0.84": (0.7, 0.85),
        "0.85-1.00": (0.85, 1.01),
    }
    output: dict[str, dict] = {}
    for name, (low, high) in buckets.items():
        members = [item for item in samples if low <= item["confidence"] < high]
        correct = [item for item in members if item["binary_correct"] is True]
        output[name] = {
            "count": len(members),
            "labeled_count": sum(
                item["binary_correct"] is not None for item in members
            ),
            "accuracy": safe_div(
                len(correct),
                sum(item["binary_correct"] is not None for item in members),
            ),
            "mean_score": (
                round(mean(item["score"] for item in members), 2) if members else 0.0
            ),
        }
    return output


def score_distribution(samples: list[dict]) -> dict:
    bins = {
        "0-24": (0, 25),
        "25-49": (25, 50),
        "50-69": (50, 70),
        "70-84": (70, 85),
        "85-100": (85, 101),
    }
    by_label: dict[str, dict] = {}
    for label in ("benign", "phishing", "ambiguous"):
        values = [item["score"] for item in samples if item["label"] == label]
        by_label[label] = {
            "count": len(values),
            "minimum": min(values) if values else None,
            "maximum": max(values) if values else None,
            "mean": round(mean(values), 2) if values else None,
            "bins": {
                name: sum(low <= value < high for value in values)
                for name, (low, high) in bins.items()
            },
        }
    return by_label


def severity_distance(actual: str, expected_min: str, expected_max: str) -> int:
    actual_value = SEVERITY_ORDER[actual]
    lower = SEVERITY_ORDER[expected_min]
    upper = SEVERITY_ORDER[expected_max]
    if lower <= actual_value <= upper:
        return 0
    return lower - actual_value if actual_value < lower else actual_value - upper


def render_markdown(evaluation: dict) -> str:
    binary = evaluation["metrics"]["binary"]
    severity = evaluation["metrics"]["severity"]
    lines = [
        "# Offline Phishing Triage Evaluation",
        "",
        f"Dataset: **{evaluation['dataset']['total']}** samples "
        f"({evaluation['dataset']['phishing']} phishing, "
        f"{evaluation['dataset']['benign']} benign, "
        f"{evaluation['dataset']['ambiguous']} ambiguous).",
        "",
        "## Binary metrics",
        "",
        "| TP | TN | FP | FN | Precision | Recall | F1 | Accuracy | FPR | FNR |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        f"| {binary['tp']} | {binary['tn']} | {binary['fp']} | {binary['fn']} | "
        f"{binary['precision']:.3f} | {binary['recall']:.3f} | {binary['f1']:.3f} | "
        f"{binary['accuracy']:.3f} | {binary['false_positive_rate']:.3f} | "
        f"{binary['false_negative_rate']:.3f} |",
        "",
        "Ambiguous samples are excluded from binary metrics and retained in all "
        "sample-level, severity, finding, confidence, and invariant checks.",
        "",
        "## Per-class metrics",
        "",
        "| Class | Support | Precision | Recall | F1 |",
        "|---|---:|---:|---:|---:|",
    ]
    for name, values in evaluation["metrics"]["per_class"].items():
        lines.append(
            f"| {name} | {values['support']} | {values['precision']:.3f} | "
            f"{values['recall']:.3f} | {values['f1']:.3f} |"
        )
    lines.extend(
        [
            "",
            "## Severity",
            "",
            f"Within expected range: **{severity['within_expected_range']}/"
            f"{evaluation['dataset']['total']}** ({severity['range_accuracy']:.3f}); "
            f"mean ordinal distance: **{severity['mean_ordinal_distance']:.3f}**.",
            "",
            "## Finding-level detector metrics",
            "",
            "| Finding | TP | TN | FP | FN | Precision | Recall | F1 |",
            "|---|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for name, values in evaluation["metrics"]["detectors"].items():
        lines.append(
            f"| {name} | {values['tp']} | {values['tn']} | {values['fp']} | "
            f"{values['fn']} | {values['precision']:.3f} | {values['recall']:.3f} | "
            f"{values['f1']:.3f} |"
        )
    lines.extend(
        [
            "",
            "## Confidence buckets",
            "",
            "| Confidence | Samples | Binary-labeled | Accuracy | Mean score |",
            "|---|---:|---:|---:|---:|",
        ]
    )
    for name, values in evaluation["metrics"]["confidence_buckets"].items():
        lines.append(
            f"| {name} | {values['count']} | {values['labeled_count']} | "
            f"{values['accuracy']:.3f} | {values['mean_score']:.2f} |"
        )
    lines.extend(
        [
            "",
            "## Score distribution",
            "",
            "| Label | Count | Min | Mean | Max | 0-24 | 25-49 | 50-69 | 70-84 | 85-100 |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for label, values in evaluation["metrics"]["score_distribution"].items():
        bins = values["bins"]
        lines.append(
            f"| {label} | {values['count']} | {values['minimum']} | "
            f"{values['mean']} | {values['maximum']} | {bins['0-24']} | "
            f"{bins['25-49']} | {bins['50-69']} | {bins['70-84']} | "
            f"{bins['85-100']} |"
        )
    lines.extend(["", "## False positives and false negatives", ""])
    errors = evaluation["errors"]
    if not errors["false_positives"] and not errors["false_negatives"]:
        lines.append("No binary false positives or false negatives.")
    for title, key in (
        ("False positives", "false_positives"),
        ("False negatives", "false_negatives"),
    ):
        if not errors[key]:
            continue
        lines.extend([f"### {title}", ""])
        for item in errors[key]:
            causes = "; ".join(item["top_causes"]) or "No score-bearing cause"
            lines.append(
                f"- `{item['sample_id']}`: {item['verdict']} / {item['severity']} / "
                f"score {item['score']} — {causes}"
            )
        lines.append("")
    lines.extend(["", "## Critical regressions and quality gates", ""])
    if evaluation["quality_gate"]["failures"]:
        for failure in evaluation["quality_gate"]["failures"]:
            lines.append(f"- FAIL: {failure}")
    else:
        lines.append("All critical regression checks and metric thresholds passed.")
    baseline = evaluation.get("baseline_comparison", {})
    lines.extend(["", "## Baseline comparison", ""])
    if baseline.get("available"):
        deltas = baseline.get("metric_deltas", {})
        lines.append(
            "Metric deltas: "
            + ", ".join(f"{name}={float(value):+.4f}" for name, value in deltas.items())
            + "."
        )
        lines.append(
            f"Per-sample prediction changes: {len(baseline.get('sample_changes', []))}."
        )
    else:
        lines.append("No baseline was available for this run.")
    lines.extend(["", "## Per-sample results", ""])
    lines.append(
        "| Sample | Truth | Predicted | Severity | Score | Confidence | Status |"
    )
    lines.append("|---|---|---|---|---:|---:|---|")
    for item in evaluation["samples"]:
        status = "PASS" if not item["errors"] else "FAIL: " + "; ".join(item["errors"])
        lines.append(
            f"| `{item['sample_id']}` | {item['label']} / {item['attack_class']} | "
            f"{item['verdict']} / {item['predicted_class']} | {item['severity']} | "
            f"{item['score']} | {item['confidence']:.2f} | {status} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation limitations",
            "",
            "- This is a safe synthetic regression corpus, not an estimate of prevalence in production mail.",
            "- Finding-level TN/FP values only use explicitly annotated forbidden findings; unannotated detector/sample pairs are not assumed negative.",
            "- Pipeline confidence is verdict confidence, not a calibrated phishing probability; buckets report correctness by confidence band.",
            "- Threat-intelligence, QR, DNS, WHOIS, landing-page and AI responses are deterministic fixtures and never contact live services.",
            "",
        ]
    )
    return "\n".join(lines)
