"""Library's own settings keep the verifier's limits and Library's names."""

from __future__ import annotations

import os

import pytest
from pydantic import ValidationError

from library.config import Settings


@pytest.fixture(autouse=True)
def no_library_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in tuple(os.environ):
        if name.startswith("LIBRARY_"):
            monkeypatch.delenv(name)


def test_defaults_are_librarys_own() -> None:
    settings = Settings(_env_file=None)
    assert settings.app_id == "library"
    assert settings.database_url == "postgresql://localhost/library"
    assert settings.public_origin == "https://library.aweb.ai"


def test_the_environment_prefix_is_library(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PUBLIC_ORIGIN", "https://unprefixed.test")
    monkeypatch.setenv("LIBRARY_PUBLIC_ORIGIN", "https://library.example.test")
    assert Settings(_env_file=None).public_origin == "https://library.example.test"


@pytest.mark.parametrize(
    ("setting", "limit"), [("auth_cache_ttl_seconds", 60), ("timestamp_skew_seconds", 300)]
)
def test_a_setting_past_its_limit_stops_the_service_from_starting(
    monkeypatch: pytest.MonkeyPatch, setting: str, limit: int
) -> None:
    assert getattr(Settings(_env_file=None), setting) == limit
    with pytest.raises(ValidationError, match=f"less than or equal to {limit}"):
        Settings(_env_file=None, **{setting: limit + 1})

    # As a deployment sets it: through the environment.
    monkeypatch.setenv(f"LIBRARY_{setting.upper()}", str(limit))
    assert getattr(Settings(_env_file=None), setting) == limit
    monkeypatch.setenv(f"LIBRARY_{setting.upper()}", str(limit + 1))
    with pytest.raises(ValidationError, match=f"less than or equal to {limit}"):
        Settings(_env_file=None)
