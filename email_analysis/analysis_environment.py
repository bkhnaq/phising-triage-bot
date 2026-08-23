"""Central analysis-environment classification for reports and automation."""

from __future__ import annotations

VALID_ENVIRONMENTS = frozenset({"PRODUCTION", "TEST", "LAB", "MIXED", "UNKNOWN"})


def classify_analysis_environment(
    observables: list[dict], *, lab_mode: bool = False
) -> dict:
    """Classify global context without overriding per-observable export safety."""
    has_test = any(
        str(item.get("environment", "")).lower() == "test" for item in observables
    )
    has_production = any(
        str(item.get("environment", "")).lower() == "production" for item in observables
    )

    if has_test and has_production:
        environment_type = "MIXED"
    elif has_test:
        environment_type = "LAB" if lab_mode else "TEST"
    elif has_production:
        environment_type = "PRODUCTION"
    elif lab_mode:
        environment_type = "LAB"
    else:
        environment_type = "UNKNOWN"

    reasons: list[str] = []
    if lab_mode:
        reasons.append("Analysis was explicitly run in lab mode")
    test_reasons = {
        str(item.get("export_reason", "")).strip()
        for item in observables
        if str(item.get("environment", "")).lower() == "test"
        and item.get("export_reason")
    }
    reasons.extend(sorted(test_reasons))
    if has_test and has_production:
        reasons.append("Both production and reserved test observables were detected")
    elif has_production:
        reasons.append("Production-routable observables were detected")
    if not reasons:
        reasons.append("No environment-bearing observables were available")

    return {
        "type": environment_type,
        "production_usable": environment_type == "PRODUCTION",
        "per_observable_export_required": environment_type == "MIXED",
        "contains_test_observables": has_test,
        "contains_production_observables": has_production,
        "reasons": reasons,
    }


def normalize_analysis_environment(value: dict | None) -> dict:
    """Validate renderer input without re-detecting infrastructure."""
    supplied = value or {}
    environment_type = str(supplied.get("type", "UNKNOWN")).upper()
    if environment_type not in VALID_ENVIRONMENTS:
        environment_type = "UNKNOWN"
    return {
        "type": environment_type,
        "production_usable": bool(supplied.get("production_usable", False)),
        "per_observable_export_required": bool(
            supplied.get("per_observable_export_required", False)
        ),
        "contains_test_observables": bool(
            supplied.get("contains_test_observables", False)
        ),
        "contains_production_observables": bool(
            supplied.get("contains_production_observables", False)
        ),
        "reasons": [str(item) for item in supplied.get("reasons", [])],
    }
