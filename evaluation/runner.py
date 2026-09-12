"""Run the production phishing pipeline over the deterministic regression corpus."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from email_analysis.pipeline import PhishingPipeline
from evaluation.email_factory import build_email
from evaluation.fixtures import deterministic_fixtures
from evaluation.metrics import (
    POSITIVE_VERDICTS,
    SEVERITY_ORDER,
    binary_metrics,
    class_metrics,
    confidence_buckets,
    detector_metrics,
    render_markdown,
    score_distribution,
    severity_distance,
    severity_metrics,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATASET = Path(__file__).with_name("dataset.json")
DEFAULT_BASELINE = Path(__file__).with_name("baseline.json")
QUALITY_TARGETS = {
    "precision": 0.90,
    "recall": 0.90,
    "f1": 0.90,
    "false_positive_rate_max": 0.10,
}


def load_dataset(path: Path = DEFAULT_DATASET) -> dict:
    dataset = json.loads(path.read_text(encoding="utf-8"))
    samples = dataset.get("samples")
    if not isinstance(samples, list) or len(samples) < 20:
        raise ValueError("Evaluation dataset must contain at least 20 samples")
    required = {
        "sample_id",
        "description",
        "label",
        "attack_class",
        "expected_classification",
        "expected_min_severity",
        "expected_max_severity",
        "expected_findings",
        "forbidden_findings",
        "environment",
        "notes",
    }
    seen: set[str] = set()
    for sample in samples:
        missing = required - set(sample)
        if missing:
            raise ValueError(
                f"Sample {sample.get('sample_id', '?')} missing: {sorted(missing)}"
            )
        sample_id = str(sample["sample_id"])
        if sample_id in seen:
            raise ValueError(f"Duplicate sample_id: {sample_id}")
        seen.add(sample_id)
        if sample["label"] not in {"phishing", "benign", "ambiguous"}:
            raise ValueError(f"Invalid label for {sample_id}: {sample['label']}")
        for key in ("expected_min_severity", "expected_max_severity"):
            if sample[key] not in SEVERITY_ORDER:
                raise ValueError(f"Invalid {key} for {sample_id}: {sample[key]}")
    return dataset


def evaluate_dataset(
    dataset_path: Path = DEFAULT_DATASET,
    *,
    baseline_path: Path | None = DEFAULT_BASELINE,
    report_verbosity: str = "NORMAL",
) -> dict:
    dataset = load_dataset(dataset_path)
    evaluated: list[dict] = []
    with tempfile.TemporaryDirectory(prefix="phishing-evaluation-") as upload_dir:
        for sample in dataset["samples"]:
            raw_email = build_email(sample, repository_root=ROOT)
            with deterministic_fixtures(sample):
                result = PhishingPipeline(
                    upload_dir=upload_dir,
                    events_jsonl_path="",
                    analysis_id=f"eval-{sample['sample_id'][:24]}",
                    lab_mode=sample["environment"] == "LAB",
                    report_verbosity=report_verbosity,
                ).analyze_raw(raw_email)
            evaluated.append(_evaluate_sample(sample, result))

    metrics = {
        "binary": binary_metrics(evaluated),
        "per_class": class_metrics(evaluated),
        "severity": severity_metrics(evaluated),
        "detectors": detector_metrics(evaluated),
        "confidence_buckets": confidence_buckets(evaluated),
        "score_distribution": score_distribution(evaluated),
    }
    counts = Counter(item["label"] for item in evaluated)
    output: dict[str, Any] = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "offline_deterministic",
        "dataset": {
            "path": str(
                dataset_path.relative_to(ROOT)
                if dataset_path.is_relative_to(ROOT)
                else dataset_path
            ),
            "schema_version": dataset.get("schema_version", 1),
            "total": len(evaluated),
            "phishing": counts["phishing"],
            "benign": counts["benign"],
            "ambiguous": counts["ambiguous"],
            "attack_classes": dict(Counter(item["attack_class"] for item in evaluated)),
        },
        "quality_targets": QUALITY_TARGETS,
        "metrics": metrics,
        "errors": {
            "false_positives": [
                _error_detail(item)
                for item in evaluated
                if item["label"] == "benign" and item["predicted_positive"]
            ],
            "false_negatives": [
                _error_detail(item)
                for item in evaluated
                if item["label"] == "phishing" and not item["predicted_positive"]
            ],
            "sample_expectation_failures": [
                {"sample_id": item["sample_id"], "errors": item["errors"]}
                for item in evaluated
                if item["errors"]
            ],
        },
        "samples": evaluated,
    }
    output["baseline_comparison"] = _compare_baseline(output, baseline_path)
    output["quality_gate"] = _quality_gate(output)
    return output


def _evaluate_sample(sample: dict, result: dict) -> dict:
    risk = result["risk"]
    verdict = str(risk["verdict"]).upper()
    severity = str(risk["risk_severity"]).upper()
    findings = _observed_findings(result)
    predicted_positive = verdict in POSITIVE_VERDICTS
    expected_min = str(sample["expected_min_severity"])
    expected_max = str(sample["expected_max_severity"])
    distance = severity_distance(severity, expected_min, expected_max)
    predicted_class = _predicted_class(result, predicted_positive)
    invariant_errors = _invariant_errors(sample, result, findings)
    expectation_errors: list[str] = []
    if verdict not in set(sample["expected_classification"]):
        expectation_errors.append(
            f"verdict {verdict} not in expected {sample['expected_classification']}"
        )
    if distance:
        expectation_errors.append(
            f"severity {severity} outside {expected_min}..{expected_max}"
        )
    missing_findings = sorted(set(sample["expected_findings"]) - findings)
    forbidden_findings = sorted(set(sample["forbidden_findings"]) & findings)
    if missing_findings:
        expectation_errors.append("missing findings: " + ", ".join(missing_findings))
    if forbidden_findings:
        expectation_errors.append(
            "forbidden findings: " + ", ".join(forbidden_findings)
        )
    if result["analysis_environment"]["type"] != sample["environment"]:
        expectation_errors.append(
            "environment "
            f"{result['analysis_environment']['type']} != expected {sample['environment']}"
        )
    binary_correct: bool | None = None
    if sample["label"] == "phishing":
        binary_correct = predicted_positive
    elif sample["label"] == "benign":
        binary_correct = not predicted_positive

    gate = risk["score_reconciliation"]["critical_evidence_gate"]
    return {
        "sample_id": sample["sample_id"],
        "description": sample["description"],
        "notes": sample["notes"],
        "label": sample["label"],
        "requires_external_enrichment": bool(sample.get("requires_external_enrichment")),
        "attack_class": sample["attack_class"],
        "predicted_class": predicted_class,
        "expected_classification": sample["expected_classification"],
        "verdict": verdict,
        "predicted_positive": predicted_positive,
        "binary_correct": binary_correct,
        "expected_min_severity": expected_min,
        "expected_max_severity": expected_max,
        "severity": severity,
        "severity_within_expected_range": distance == 0,
        "severity_distance": distance,
        "score": int(risk["score"]),
        "confidence": float(risk["confidence"]),
        "data_completeness": int(risk["data_completeness"]),
        "environment": result["analysis_environment"]["type"],
        "critical_gate": gate,
        "category_scores": risk["category_scores"],
        "top_causes": _top_causes(risk),
        "expected_findings": list(sample["expected_findings"]),
        "forbidden_findings": list(sample["forbidden_findings"]),
        "observed_findings": sorted(findings),
        "missing_findings": missing_findings,
        "unexpected_forbidden_findings": forbidden_findings,
        "invariant_errors": invariant_errors,
        "expectation_errors": expectation_errors,
        "errors": invariant_errors + expectation_errors,
    }


def _observed_findings(result: dict) -> set[str]:
    findings: set[str] = set()
    auth = result["auth_results"]
    for check in ("spf", "dkim", "dmarc"):
        state = str(auth.get(check, {}).get("result", "unknown")).lower()
        findings.add(f"{check}_{state}")
    if any(
        str(auth.get(check, {}).get("result", "unknown")).lower() == "unknown"
        for check in ("spf", "dkim", "dmarc")
    ):
        findings.add("missing_authentication")
    for item in auth.get("forensics", {}).get("findings", []):
        item_type = str(item.get("type", ""))
        if item_type:
            findings.add(item_type)
        if item_type == "message_id_mismatch" and int(item.get("risk_score", 0)) == 0:
            findings.add("message_id_informational")
        if item_type == "missing_received_headers":
            findings.add("missing_received")
    for item in result.get("evidence_bundle", {}).get("evidence", []):
        indicator = str(item.get("indicator", ""))
        if indicator:
            findings.add(indicator)
        findings.update(str(tag) for tag in item.get("tags", []))
    for item in result["risk"].get("final_findings", []):
        findings.add(str(item.get("type", "")))
    if any(
        int(item.get("risk_score", 0)) > 0
        for item in result.get("url_intelligence", {}).get("deceptive_links", [])
    ):
        findings.add("deceptive_href")
    if result.get("url_intelligence", {}).get("shortener_findings"):
        findings.add("url_shortener")
    if result.get("credential_harvesting", {}).get("detected"):
        findings.update({"credential_collection", "credential_lure"})
    categories = set(result.get("language_analysis", {}).get("categories", {}))
    if categories & {
        "credential_harvesting",
        "account_verification",
        "password_expiration",
    }:
        findings.add("credential_lure")
    if "financial" in categories:
        findings.add("financial_pressure")
    if "urgency" in categories:
        findings.add("urgency")
    if result.get("attachment_risks"):
        findings.add("attachment_suspicious")
    if any(item.get("url") for item in result.get("qr_findings", [])):
        findings.add("qr_url")
    if not result.get("urls"):
        findings.add("no_url_analyzed")
    if not result.get("attachments"):
        findings.add("no_attachment_analyzed")
    ai = result.get("ai_verdict", {})
    if ai.get("verdict") == "phishing":
        findings.add("ai_phishing")
    elif ai.get("verdict") == "suspicious":
        findings.add("ai_suspicious")
    findings.add("external_enrichment_pending")
    randomness = result.get("domain_intelligence", {}).get("randomness_results", [])
    if any(int(item.get("risk_score", 0)) > 0 for item in randomness):
        findings.add("domain_randomness")
    environment = result["analysis_environment"]["type"].lower()
    findings.add(f"{environment}_environment")
    gate = result["risk"]["score_reconciliation"]["critical_evidence_gate"]
    findings.add(f"critical_gate_{str(gate['status']).lower()}")
    return {item for item in findings if item}


def _predicted_class(result: dict, predicted_positive: bool) -> str:
    verdict = str(result["risk"]["verdict"]).upper()
    if result.get("attachment_risks") and predicted_positive:
        return "malware_delivery"
    if result.get("qr_findings") and predicted_positive:
        return "qr_phishing"
    categories = set(result.get("language_analysis", {}).get("categories", {}))
    subject = str(result.get("email_data", {}).get("subject", "")).lower()
    if any(item.get("type") == "reply_to_payment_fraud" for item in result["risk"].get("final_findings", [])):
        return (
            "invoice_payment"
            if any(token in subject for token in ("invoice", "billing", "payment"))
            else "bec"
        )
    if "financial" in categories and predicted_positive:
        return "invoice_payment"
    if (
        categories
        & {"credential_harvesting", "account_verification", "password_expiration"}
        and predicted_positive
    ):
        return "credential_phishing"
    if verdict == "PHISHING":
        return "credential_phishing"
    if verdict == "SUSPICIOUS":
        return "suspicious"
    if predicted_positive:
        return "phishing"
    return "benign" if verdict in {"BENIGN", "LIKELY_BENIGN"} else "unknown"


def _invariant_errors(sample: dict, result: dict, findings: set[str]) -> list[str]:
    risk = result["risk"]
    reconciliation = risk["score_reconciliation"]
    errors: list[str] = []
    category_sum = sum(
        int(value)
        for category, value in risk["category_scores"].items()
        if category != "data completeness"
    )
    expected_pre_calibration = max(0, min(100, category_sum))
    if int(reconciliation["pre_calibration_score"]) != expected_pre_calibration:
        errors.append(
            f"arithmetic mismatch: categories={category_sum}, pre_calibration={reconciliation['pre_calibration_score']}"
        )
    if int(risk["score"]) != int(reconciliation["base_score"]):
        errors.append(
            "arithmetic mismatch: risk score differs from reconciled base score"
        )
    gate = reconciliation["critical_evidence_gate"]
    if (
        int(reconciliation["pre_calibration_score"]) < int(gate["critical_threshold"])
        and gate["status"] != "NOT_REQUIRED"
    ):
        errors.append("critical gate applied below Critical threshold")
    for observable in result.get("observables", []):
        value = str(observable.get("value", "")).lower()
        if str(observable.get("environment", "")).upper() == "TEST" and observable.get("exportable"):
            errors.append(f"special-use observable is exportable: {value}")
    if sample["sample_id"] == "benign_ai_false_positive" and risk["risk_severity"] in {
        "HIGH",
        "CRITICAL",
    }:
        errors.append("AI-only evidence produced HIGH/CRITICAL severity")
    if (
        "deceptive_href" in sample["expected_findings"]
        and "deceptive_href" not in findings
    ):
        errors.append("deceptive hyperlink detector stopped firing")
    return errors


def _top_causes(risk: dict, limit: int = 4) -> list[str]:
    causes: list[tuple[int, str]] = []
    for category, details in risk.get("category_details", {}).items():
        for item in details.get("items", []):
            contribution = int(item.get("contribution", 0))
            if contribution > 0:
                causes.append(
                    (
                        contribution,
                        f"{category}: {item.get('label', item.get('id', 'signal'))} (+{contribution})",
                    )
                )
    if not causes:
        for category, score in risk.get("category_scores", {}).items():
            if int(score) > 0:
                causes.append((int(score), f"{category} (+{score})"))
    return [label for _score, label in sorted(causes, reverse=True)[:limit]]


def _error_detail(item: dict) -> dict:
    return {
        "sample_id": item["sample_id"],
        "description": item["description"],
        "verdict": item["verdict"],
        "severity": item["severity"],
        "score": item["score"],
        "confidence": item["confidence"],
        "top_causes": item["top_causes"],
        "observed_findings": item["observed_findings"],
    }


def _quality_gate(evaluation: dict) -> dict:
    binary = evaluation["metrics"]["binary"]
    failures: list[str] = []
    if binary["precision"] < QUALITY_TARGETS["precision"]:
        failures.append(
            f"precision {binary['precision']:.3f} < {QUALITY_TARGETS['precision']:.2f}"
        )
    if binary["recall"] < QUALITY_TARGETS["recall"]:
        failures.append(
            f"recall {binary['recall']:.3f} < {QUALITY_TARGETS['recall']:.2f}"
        )
    if binary["f1"] < QUALITY_TARGETS["f1"]:
        failures.append(f"F1 {binary['f1']:.3f} < {QUALITY_TARGETS['f1']:.2f}")
    if binary["false_positive_rate"] > QUALITY_TARGETS["false_positive_rate_max"]:
        failures.append(
            f"FPR {binary['false_positive_rate']:.3f} > {QUALITY_TARGETS['false_positive_rate_max']:.2f}"
        )
    for item in evaluation["samples"]:
        if item["label"] == "phishing" and not item["predicted_positive"] and not item.get("requires_external_enrichment"):
            failures.append(
                f"known phishing became non-positive: {item['sample_id']} ({item['verdict']})"
            )
        if item["label"] == "benign" and item["severity"] in {"HIGH", "CRITICAL"}:
            failures.append(
                f"benign sample reached {item['severity']}: {item['sample_id']}"
            )
        failures.extend(
            f"{item['sample_id']}: {error}" for error in item["invariant_errors"]
        )
        failures.extend(
            f"{item['sample_id']}: {error}" for error in item["expectation_errors"]
        )
    baseline = evaluation.get("baseline_comparison", {})
    if baseline.get("available"):
        deltas = baseline.get("metric_deltas", {})
        for metric in ("precision", "recall", "f1", "accuracy"):
            if float(deltas.get(metric, 0.0)) < 0:
                failures.append(
                    f"baseline regression: {metric} changed by {deltas[metric]:.4f}"
                )
        for metric in ("false_positive_rate", "false_negative_rate"):
            if float(deltas.get(metric, 0.0)) > 0:
                failures.append(
                    f"baseline regression: {metric} changed by +{deltas[metric]:.4f}"
                )
    return {"passed": not failures, "failures": list(dict.fromkeys(failures))}


def _baseline_payload(evaluation: dict) -> dict:
    return {
        "schema_version": 1,
        "dataset": evaluation["dataset"],
        "quality_targets": evaluation["quality_targets"],
        "metrics": evaluation["metrics"],
        "samples": {
            item["sample_id"]: {
                "verdict": item["verdict"],
                "severity": item["severity"],
                "score": item["score"],
                "predicted_class": item["predicted_class"],
                "observed_findings": item["observed_findings"],
            }
            for item in evaluation["samples"]
        },
    }


def _compare_baseline(evaluation: dict, baseline_path: Path | None) -> dict:
    if baseline_path is None or not baseline_path.exists():
        return {
            "available": False,
            "path": str(baseline_path) if baseline_path else None,
            "metric_deltas": {},
            "sample_changes": [],
        }
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    if baseline.get("dataset", {}).get("schema_version") != evaluation["dataset"]["schema_version"]:
        return {"available": False, "path": str(baseline_path), "reason": "Baseline belongs to the previous enriched scoring contract", "metric_deltas": {}, "sample_changes": []}
    current_binary = evaluation["metrics"]["binary"]
    old_binary = baseline.get("metrics", {}).get("binary", {})
    metric_deltas = {
        key: round(float(current_binary.get(key, 0)) - float(old_binary.get(key, 0)), 4)
        for key in (
            "precision",
            "recall",
            "f1",
            "accuracy",
            "false_positive_rate",
            "false_negative_rate",
        )
    }
    old_samples = baseline.get("samples", {})
    changes = []
    for item in evaluation["samples"]:
        old = old_samples.get(item["sample_id"])
        current = {
            key: item[key]
            for key in ("verdict", "severity", "score", "predicted_class")
        }
        if old and any(old.get(key) != value for key, value in current.items()):
            changes.append(
                {
                    "sample_id": item["sample_id"],
                    "before": {key: old.get(key) for key in current},
                    "after": current,
                }
            )
    return {
        "available": True,
        "path": str(baseline_path),
        "metric_deltas": metric_deltas,
        "sample_changes": changes,
    }


def write_outputs(
    evaluation: dict,
    *,
    output_json: Path | None,
    output_report: Path | None,
    write_baseline: Path | None,
) -> None:
    if output_json:
        output_json.parent.mkdir(parents=True, exist_ok=True)
        output_json.write_text(
            json.dumps(evaluation, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    if output_report:
        output_report.parent.mkdir(parents=True, exist_ok=True)
        output_report.write_text(render_markdown(evaluation), encoding="utf-8")
    if write_baseline:
        write_baseline.parent.mkdir(parents=True, exist_ok=True)
        write_baseline.write_text(
            json.dumps(_baseline_payload(evaluation), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument(
        "--output-json", type=Path, default=Path("artifacts/evaluation/results.json")
    )
    parser.add_argument(
        "--output-report", type=Path, default=Path("artifacts/evaluation/report.md")
    )
    parser.add_argument("--write-baseline", type=Path)
    parser.add_argument(
        "--report-verbosity", choices=("NORMAL", "DEBUG"), default="NORMAL"
    )
    parser.add_argument("--quality-gate", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    evaluation = evaluate_dataset(
        args.dataset,
        baseline_path=args.baseline,
        report_verbosity=args.report_verbosity,
    )
    write_outputs(
        evaluation,
        output_json=args.output_json,
        output_report=args.output_report,
        write_baseline=args.write_baseline,
    )
    binary = evaluation["metrics"]["binary"]
    print(
        "evaluation: "
        f"samples={evaluation['dataset']['total']} precision={binary['precision']:.3f} "
        f"recall={binary['recall']:.3f} f1={binary['f1']:.3f} "
        f"fpr={binary['false_positive_rate']:.3f} gate={'PASS' if evaluation['quality_gate']['passed'] else 'FAIL'}"
    )
    if args.quality_gate and not evaluation["quality_gate"]["passed"]:
        for failure in evaluation["quality_gate"]["failures"]:
            print(f"quality-gate: {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
