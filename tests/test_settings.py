import importlib

import pytest

from config import settings


def test_get_bool_rejects_typo(monkeypatch) -> None:
    monkeypatch.setenv("FEATURE_FLAG", "treu")
    with pytest.raises(ValueError, match="FEATURE_FLAG must be a boolean"):
        settings._get_bool("FEATURE_FLAG", False)


def test_get_int_enforces_closed_range(monkeypatch) -> None:
    monkeypatch.setenv("PORT", "70000")
    with pytest.raises(ValueError, match="PORT must be between 1 and 65535"):
        settings._get_int("PORT", 8000, minimum=1, maximum=65535)


@pytest.mark.parametrize(
    ("name", "value", "maximum"),
    [
        ("SAFE_HTTP_MAX_BYTES", "80001", 80_000),
        ("SAFE_HTTP_TIMEOUT_SECONDS", "7", 6),
        ("SAFE_HTTP_MAX_REDIRECTS", "11", 10),
    ],
)
def test_safe_http_settings_reject_values_above_hard_ceilings(
    monkeypatch,
    name: str,
    value: str,
    maximum: int,
) -> None:
    monkeypatch.setenv(name, value)
    with pytest.raises(
        ValueError,
        match=rf"{name} must be between \d+ and {maximum}",
    ):
        importlib.reload(settings)
