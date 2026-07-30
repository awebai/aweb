from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from folio.config import Settings
from folio.db import FolioDatabase


def test_default_db_pool_is_modest_for_neon_pooler() -> None:
    settings = Settings()

    assert settings.db_pool_min_connections == 1
    assert settings.db_pool_max_connections == 5
    assert settings.db_statement_cache_size == 0


def test_db_pool_is_configurable_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FOLIO_DB_POOL_MIN_CONNECTIONS", "2")
    monkeypatch.setenv("FOLIO_DB_POOL_MAX_CONNECTIONS", "4")
    monkeypatch.setenv("FOLIO_DB_STATEMENT_CACHE_SIZE", "0")

    settings = Settings()

    assert settings.db_pool_min_connections == 2
    assert settings.db_pool_max_connections == 4
    assert settings.db_statement_cache_size == 0


def test_db_pool_rejects_max_below_min() -> None:
    with pytest.raises(ValidationError, match="db_pool_max_connections"):
        Settings(db_pool_min_connections=5, db_pool_max_connections=4)


def test_database_manager_uses_configured_pool(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    class FakeDatabaseManager:
        def __init__(self, config: object) -> None:
            captured["config"] = config

    monkeypatch.setattr("folio.db.AsyncDatabaseManager", FakeDatabaseManager)

    database = FolioDatabase(
        Settings(
            database_url="postgresql://example.invalid/folio",
            db_pool_min_connections=2,
            db_pool_max_connections=3,
            db_statement_cache_size=0,
        )
    )

    assert isinstance(database.db, FakeDatabaseManager)
    config: Any = captured["config"]
    assert config.min_connections == 2
    assert config.max_connections == 3
    assert config.statement_cache_size == 0
