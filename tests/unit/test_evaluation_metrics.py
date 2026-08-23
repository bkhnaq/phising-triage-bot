from __future__ import annotations

import pytest

from evaluation.metrics import binary_metrics, severity_distance
from scoring.risk_scoring import calculate_risk

pytestmark = pytest.mark.unit


def test_binary_metrics_include_confusion_and_rates() -> None:
    samples = [
        {"label": "phishing", "predicted_positive": True},
        {"label": "phishing", "predicted_positive": False},
        {"label": "benign", "predicted_positive": True},
        {"label": "benign", "predicted_positive": False},
        {"label": "ambiguous", "predicted_positive": True},
    ]

    metrics = binary_metrics(samples)

    assert metrics["tp"] == metrics["tn"] == 1
    assert metrics["fp"] == metrics["fn"] == 1
    assert metrics["precision"] == metrics["recall"] == metrics["f1"] == 0.5
    assert metrics["false_positive_rate"] == 0.5
    assert metrics["false_negative_rate"] == 0.5
    assert metrics["excluded_ambiguous"] == 1


def test_severity_distance_uses_expected_range() -> None:
    assert severity_distance("ELEVATED", "MODERATE", "HIGH") == 0
    assert severity_distance("LOW", "ELEVATED", "CRITICAL") == 2
    assert severity_distance("CRITICAL", "LOW", "HIGH") == 1


def test_spf_forwarding_failure_with_surviving_dkim_dmarc_is_not_positive() -> None:
    result = calculate_risk(
        {
            "spf": {"result": "fail"},
            "dkim": {"result": "pass"},
            "dmarc": {"result": "pass"},
        },
        [],
        [],
        [],
    )

    assert result["score"] == 12
    assert result["verdict"] == "LIKELY_BENIGN"
    assert result["risk_severity"] == "LOW"


def test_total_auth_failure_remains_suspicious() -> None:
    result = calculate_risk(
        {
            "spf": {"result": "fail"},
            "dkim": {"result": "fail"},
            "dmarc": {"result": "fail"},
        },
        [],
        [],
        [],
    )

    assert result["verdict"] == "SUSPICIOUS"
    assert result["score"] >= 25
