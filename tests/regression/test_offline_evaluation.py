from __future__ import annotations

from functools import lru_cache

import pytest

from evaluation.runner import evaluate_dataset, load_dataset

pytestmark = pytest.mark.regression


@lru_cache(maxsize=1)
def _evaluation() -> dict:
    return evaluate_dataset(baseline_path=None)


def test_corpus_is_large_balanced_and_schema_valid() -> None:
    samples = load_dataset()["samples"]

    assert len(samples) >= 30
    assert sum(item["label"] == "phishing" for item in samples) >= 12
    assert sum(item["label"] == "benign" for item in samples) >= 12
    assert sum(item["label"] == "ambiguous" for item in samples) >= 3
    assert len({item["sample_id"] for item in samples}) == len(samples)


def test_quality_targets_and_all_sample_expectations_pass() -> None:
    evaluation = _evaluation()

    assert evaluation["quality_gate"]["passed"], evaluation["quality_gate"]["failures"]
    assert evaluation["errors"]["sample_expectation_failures"] == []
    binary = evaluation["metrics"]["binary"]
    assert binary["precision"] >= 0.90
    assert binary["recall"] >= 0.90
    assert binary["f1"] >= 0.90
    assert binary["false_positive_rate"] <= 0.10


def test_critical_regression_contracts_hold() -> None:
    evaluation = _evaluation()
    samples = {item["sample_id"]: item for item in evaluation["samples"]}

    assert all(
        item["predicted_positive"]
        for item in samples.values()
        if item["label"] == "phishing" and not item.get("requires_external_enrichment")
    )
    assert all(
        item["severity"] not in {"HIGH", "CRITICAL"}
        for item in samples.values()
        if item["label"] == "benign"
    )
    assert all(
        "deceptive_href" in item["observed_findings"]
        for item in samples.values()
        if "deceptive_href" in item["expected_findings"]
    )
    assert all(not item["invariant_errors"] for item in samples.values())
    assert samples["benign_ai_false_positive"]["severity"] == "LOW"


def test_compromised_legitimate_domain_remains_an_explicit_recall_miss() -> None:
    result = _evaluation()
    missed = next(item for item in result["samples"] if item["sample_id"] == "phish_compromised_legit_domain")
    assert missed["label"] == "phishing"
    assert missed["requires_external_enrichment"] is True
    assert missed["predicted_positive"] is False
    assert result["metrics"]["binary"]["recall"] < 1.0
