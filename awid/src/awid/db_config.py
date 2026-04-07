from __future__ import annotations

from pgdbm import DatabaseConfig

DEFAULT_TRANSACTION_POOLER_MIN_CONNECTIONS = 1
DEFAULT_TRANSACTION_POOLER_MAX_CONNECTIONS = 5


def build_database_config(
    *,
    connection_string: str,
    schema: str | None = None,
    min_connections: int | None = None,
    max_connections: int | None = None,
    server_settings: dict[str, str] | None = None,
    statement_cache_size: int | None = None,
    uses_transaction_pooler: bool = False,
) -> DatabaseConfig:
    kwargs: dict[str, object] = {
        "connection_string": connection_string,
    }

    if uses_transaction_pooler:
        effective_max = DEFAULT_TRANSACTION_POOLER_MAX_CONNECTIONS
        if max_connections is not None:
            effective_max = min(max_connections, DEFAULT_TRANSACTION_POOLER_MAX_CONNECTIONS)
        effective_min = DEFAULT_TRANSACTION_POOLER_MIN_CONNECTIONS
        if min_connections is not None:
            effective_min = min(min_connections, effective_max)
        min_connections = effective_min
        max_connections = effective_max

    if schema is not None:
        kwargs["schema"] = schema
    if server_settings is not None:
        kwargs["server_settings"] = server_settings
    if min_connections is not None:
        kwargs["min_connections"] = min_connections
    if max_connections is not None:
        kwargs["max_connections"] = max_connections
    if statement_cache_size is not None:
        kwargs["statement_cache_size"] = statement_cache_size
    elif uses_transaction_pooler:
        kwargs["statement_cache_size"] = 0

    return DatabaseConfig(**kwargs)
