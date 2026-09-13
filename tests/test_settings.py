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
