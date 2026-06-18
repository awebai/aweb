from __future__ import annotations

import pytest
from pydantic import ValidationError

from library.config import Settings


def test_defaults_use_library_naming() -> None:
    settings = Settings()
    assert settings.app_id == "library"
    assert "library" in settings.database_url
    assert settings.public_origin.startswith("http")


def test_env_prefix_is_library(monkeypatch) -> None:
    monkeypatch.setenv("LIBRARY_PUBLIC_ORIGIN", "https://library.example.test")
    monkeypatch.setenv("LIBRARY_APP_EMIT_KID", "library:emit-1")
    settings = Settings()
    assert settings.public_origin == "https://library.example.test"
    assert settings.app_emit_kid == "library:emit-1"


def test_db_pool_validation_rejects_max_below_min() -> None:
    with pytest.raises(ValidationError):
        Settings(db_pool_min_connections=5, db_pool_max_connections=2)


def test_emit_is_disabled_by_default() -> None:
    settings = Settings()
    assert settings.app_events_origin is None
    assert settings.app_emit_kid is None
    assert settings.app_emit_key_seed_hex is None
