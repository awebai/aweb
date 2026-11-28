from __future__ import annotations

import os
from dataclasses import dataclass

from pgdbm import DatabaseConfig

from awid.ratelimit import normalize_service_token


def _env_bool(name: str, *, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    host: str
    port: int
    log_level: str
    reload: bool
    database_url: str
    redis_url: str
    db_schema: str
    rate_limit_backend: str
    service_token: str | None
    # Behind a transaction pooler (PgBouncer, Neon's -pooler endpoints) asyncpg's
    # statement cache must be off and the pool bounded.
    database_uses_transaction_pooler: bool = False
    database_pooler_max_connections: int = 10
    database_statement_cache_size: int | None = None
    # Refuse to start unless every connection carries the search_path pin and the
    # pgdbm timeouts. A pooler that drops startup parameters needs them as role
    # defaults (ALTER ROLE ... SET ...).
    database_require_session_settings: bool = False
    database_session_check_timeout_seconds: float = 30.0
    # The pool's ordinary bounds; None keeps pgdbm's defaults. Independent of
    # transaction-pooler mode, which still caps the pool at its own bound.
    database_min_connections: int | None = None
    database_max_connections: int | None = None


def get_settings() -> Settings:
    database_url = os.getenv("AWID_DATABASE_URL") or os.getenv("DATABASE_URL")
    if not database_url:
        raise ValueError(
            "DATABASE_URL or AWID_DATABASE_URL environment variable is required. "
            "Example: postgresql://user:pass@localhost:5432/awid"
        )

    redis_url = (
        os.getenv("AWID_REDIS_URL")
        or os.getenv("REDIS_URL")
        or "redis://localhost:6379/0"
    )
    schema = (os.getenv("AWID_DB_SCHEMA") or "awid").strip() or "awid"
    rate_limit_backend = (
        os.getenv("AWID_RATE_LIMIT_BACKEND") or "redis"
    ).strip().lower() or "redis"

    pooler_max_raw = os.getenv("AWID_DATABASE_POOLER_MAX_CONNECTIONS", "10")
    pooler_max_connections = int(pooler_max_raw)
    if pooler_max_connections < 1:
        raise ValueError(
            f"AWID_DATABASE_POOLER_MAX_CONNECTIONS must be at least 1, got {pooler_max_connections}"
        )
    min_connections = _env_int_at_least("AWID_DATABASE_MIN_CONNECTIONS", 0)
    max_connections = _env_int_at_least("AWID_DATABASE_MAX_CONNECTIONS", 1)
    uses_transaction_pooler = _env_bool("AWID_DATABASE_USES_TRANSACTION_POOLER")
    if not uses_transaction_pooler:
        # The transaction pooler clamps the pair itself; without it, a side
        # left unset takes pgdbm's default and the pair must still be ordered.
        _require_ordered_pool_sizes(min_connections, max_connections)
    session_check_timeout = float(
        os.getenv("AWID_DATABASE_SESSION_CHECK_TIMEOUT_SECONDS", "30")
    )
    if session_check_timeout <= 0:
        raise ValueError(
            f"AWID_DATABASE_SESSION_CHECK_TIMEOUT_SECONDS must be positive, got {session_check_timeout}"
        )
    statement_cache_raw = (
        os.getenv("AWID_DATABASE_STATEMENT_CACHE_SIZE") or ""
    ).strip()
    statement_cache_size = int(statement_cache_raw) if statement_cache_raw else None

    port_raw = os.getenv("AWID_PORT", "8010")
    port = int(port_raw)
    if not 1 <= port <= 65535:
        raise ValueError(f"AWID_PORT must be between 1 and 65535, got {port}")

    return Settings(
        host=os.getenv("AWID_HOST", "0.0.0.0"),
        port=port,
        log_level=os.getenv("AWID_LOG_LEVEL", "info"),
        reload=_env_bool("AWID_RELOAD"),
        database_url=database_url,
        redis_url=redis_url,
        db_schema=schema,
        rate_limit_backend=rate_limit_backend,
        service_token=normalize_service_token(os.getenv("AWID_SERVICE_TOKEN")),
        database_uses_transaction_pooler=uses_transaction_pooler,
        database_pooler_max_connections=pooler_max_connections,
        database_statement_cache_size=statement_cache_size,
        database_min_connections=min_connections,
        database_max_connections=max_connections,
        database_require_session_settings=_env_bool(
            "AWID_DATABASE_REQUIRE_SESSION_SETTINGS"
        ),
        database_session_check_timeout_seconds=session_check_timeout,
    )


def _env_int_at_least(name: str, minimum: int) -> int | None:
    """An optional integer setting; unset or blank is None."""
    raw = (os.getenv(name) or "").strip()
    if not raw:
        return None
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from None
    if value < minimum:
        raise ValueError(f"{name} must be at least {minimum}, got {value}")
    return value


def _require_ordered_pool_sizes(
    min_connections: int | None, max_connections: int | None
) -> None:
    """Refuse a pool whose minimum exceeds its maximum, naming the setting."""
    defaults = DatabaseConfig.model_fields
    if min_connections is not None and max_connections is not None:
        if min_connections > max_connections:
            raise ValueError(
                f"AWID_DATABASE_MIN_CONNECTIONS ({min_connections}) exceeds "
                f"AWID_DATABASE_MAX_CONNECTIONS ({max_connections})"
            )
    elif max_connections is not None:
        default_min = defaults["min_connections"].default
        if max_connections < default_min:
            raise ValueError(
                f"AWID_DATABASE_MAX_CONNECTIONS ({max_connections}) is below the "
                f"default minimum of {default_min}; set AWID_DATABASE_MIN_CONNECTIONS too"
            )
    elif min_connections is not None:
        default_max = defaults["max_connections"].default
        if min_connections > default_max:
            raise ValueError(
                f"AWID_DATABASE_MIN_CONNECTIONS ({min_connections}) exceeds the "
                f"default maximum of {default_max}; set AWID_DATABASE_MAX_CONNECTIONS too"
            )
