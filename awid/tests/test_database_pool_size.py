"""awid-service's ordinary database pool size, apart from transaction-pooler mode."""

from __future__ import annotations

import pytest
from pgdbm import AsyncDatabaseManager, DatabaseConfig

from awid_service.config import Settings, get_settings
from awid_service.db import database_config_from_settings

POOL_ENV = (
    "AWID_DATABASE_MIN_CONNECTIONS",
    "AWID_DATABASE_MAX_CONNECTIONS",
    "AWID_DATABASE_USES_TRANSACTION_POOLER",
    "AWID_DATABASE_POOLER_MAX_CONNECTIONS",
    "AWID_DATABASE_STATEMENT_CACHE_SIZE",
    "AWID_DATABASE_REQUIRE_SESSION_SETTINGS",
)


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("AWID_DATABASE_URL", "postgresql://awid@localhost/awid")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    for name in POOL_ENV:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


def test_unset_sizes_keep_pgdbm_defaults(env):
    config = database_config_from_settings(get_settings())
    defaults = DatabaseConfig(connection_string="postgresql://unused/x")
    assert (config.min_connections, config.max_connections) == (
        defaults.min_connections,
        defaults.max_connections,
    )


def test_sizes_apply_without_pooler_mode_effects(env):
    env.setenv("AWID_DATABASE_MIN_CONNECTIONS", "1")
    env.setenv("AWID_DATABASE_MAX_CONNECTIONS", "5")
    sized = database_config_from_settings(get_settings())
    assert (sized.min_connections, sized.max_connections) == (1, 5)
    # Only the sizes change: the statement cache and search path stay as
    # they are without pooler mode.
    for name in ("AWID_DATABASE_MIN_CONNECTIONS", "AWID_DATABASE_MAX_CONNECTIONS"):
        env.delenv(name)
    unsized = database_config_from_settings(get_settings())
    assert sized.statement_cache_size == unsized.statement_cache_size
    assert sized.shared_pool_search_path == unsized.shared_pool_search_path


def test_one_size_alone_applies(env):
    env.setenv("AWID_DATABASE_MAX_CONNECTIONS", "15")
    config = database_config_from_settings(get_settings())
    assert config.max_connections == 15
    defaults = DatabaseConfig(connection_string="postgresql://unused/x")
    assert config.min_connections == defaults.min_connections


def test_pooler_mode_still_bounds_a_larger_size(env):
    env.setenv("AWID_DATABASE_USES_TRANSACTION_POOLER", "true")
    env.setenv("AWID_DATABASE_POOLER_MAX_CONNECTIONS", "4")
    env.setenv("AWID_DATABASE_MIN_CONNECTIONS", "3")
    env.setenv("AWID_DATABASE_MAX_CONNECTIONS", "9")
    config = database_config_from_settings(get_settings())
    assert (config.min_connections, config.max_connections) == (3, 4)
    assert config.statement_cache_size == 0


@pytest.mark.parametrize(
    "minimum,maximum,message",
    [
        ("-1", None, "AWID_DATABASE_MIN_CONNECTIONS must be at least 0"),
        (None, "0", "AWID_DATABASE_MAX_CONNECTIONS must be at least 1"),
        (
            "6",
            "5",
            "AWID_DATABASE_MIN_CONNECTIONS (6) exceeds AWID_DATABASE_MAX_CONNECTIONS (5)",
        ),
        ("x", None, "AWID_DATABASE_MIN_CONNECTIONS must be an integer"),
    ],
)
def test_invalid_sizes_refuse_to_start(env, minimum, maximum, message):
    if minimum is not None:
        env.setenv("AWID_DATABASE_MIN_CONNECTIONS", minimum)
    if maximum is not None:
        env.setenv("AWID_DATABASE_MAX_CONNECTIONS", maximum)
    with pytest.raises(
        ValueError, match=message.replace("(", r"\(").replace(")", r"\)")
    ):
        get_settings()


def test_settings_keep_their_existing_positions():
    settings = Settings(
        "0.0.0.0",
        8010,
        "info",
        False,
        "postgresql://awid@localhost/awid",
        "redis://localhost:6379/0",
        "awid",
        "redis",
        None,
        True,
        7,
        0,
        True,
        12.5,
    )
    assert settings.database_uses_transaction_pooler is True
    assert settings.database_pooler_max_connections == 7
    assert settings.database_statement_cache_size == 0
    assert settings.database_require_session_settings is True
    assert settings.database_session_check_timeout_seconds == 12.5
    assert (settings.database_min_connections, settings.database_max_connections) == (
        None,
        None,
    )


@pytest.mark.asyncio
async def test_the_pool_opens_with_the_configured_sizes(env, test_db_factory):
    db = await test_db_factory.create_db(suffix="awid_pool_size")
    env.setenv("AWID_DATABASE_URL", db.config.get_dsn())
    env.setenv("AWID_DATABASE_MIN_CONNECTIONS", "1")
    env.setenv("AWID_DATABASE_MAX_CONNECTIONS", "5")
    manager = AsyncDatabaseManager(database_config_from_settings(get_settings()))
    await manager.connect()
    try:
        stats = await manager.get_pool_stats()
        assert (stats["min_size"], stats["max_size"]) == (1, 5), stats
    finally:
        await manager.disconnect()
