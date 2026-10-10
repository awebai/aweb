from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Optional

from pgdbm import AsyncDatabaseManager, DatabaseConfig
from pgdbm.migrations import AsyncMigrationManager

from awid.db_config import build_database_config

from .config import get_settings

# The pgdbm protections that travel as startup parameters besides the search_path
# pin, which pgdbm verifies itself.
REQUIRED_SESSION_SETTINGS = (
    "statement_timeout",
    "lock_timeout",
    "idle_in_transaction_session_timeout",
    "jit",
)


class DatabaseSessionSettingsError(RuntimeError):
    """The database connection does not carry the session settings awid requires."""


def database_config_from_settings(settings: Any) -> DatabaseConfig:
    require = bool(getattr(settings, "database_require_session_settings", False))
    return build_database_config(
        connection_string=settings.database_url,
        statement_cache_size=getattr(settings, "database_statement_cache_size", None),
        uses_transaction_pooler=bool(getattr(settings, "database_uses_transaction_pooler", False)),
        pooler_max_connections=int(getattr(settings, "database_pooler_max_connections", 10)),
        shared_pool_search_path="pg_catalog" if require else None,
    )


MIN_SESSION_SETTING_SAMPLES = 20
DEFAULT_SESSION_CHECK_TIMEOUT_SECONDS = 30.0


def _search_path_entries(value: str | None) -> list[str]:
    return [entry.strip() for entry in (value or "").split(",") if entry.strip()]


async def _sample_session_settings(conn: Any, names: list[str], barrier: asyncio.Barrier) -> dict[str, Any]:
    # One transaction pins one server connection behind a transaction pooler, so
    # the role, backend and settings read here all describe the same connection.
    # The barrier keeps every transaction of the round open at once, so each
    # sample holds a different server connection.
    try:
        async with conn.transaction():
            identity = await conn.fetchrow("SELECT current_user AS role, pg_backend_pid() AS backend")
            rows = await conn.fetch(
                "SELECT name, setting FROM pg_catalog.pg_settings WHERE name = ANY($1::text[])",
                names,
            )
            await barrier.wait()
    except BaseException:
        # Release the other samples of this round instead of leaving them waiting.
        await barrier.abort()
        raise
    return {
        "role": identity["role"],
        "backend": identity["backend"],
        "settings": {row["name"]: row["setting"] for row in rows},
    }


async def verify_session_settings(
    pool: Any,
    config: DatabaseConfig,
    *,
    timeout_seconds: float = DEFAULT_SESSION_CHECK_TIMEOUT_SECONDS,
) -> None:
    """Fail closed unless the pool's server connections carry the settings awid requests.

    pgdbm sends them as startup parameters, which a transaction pooler may drop
    without error; role or database defaults survive the pooler. Behind a
    transaction pooler each transaction may run on a different server
    connection, so this samples many concurrently held connections, at least
    MIN_SESSION_SETTING_SAMPLES in rounds as wide as the pool. The whole check is
    bounded by timeout_seconds, and a sample that fails ends its round at once.
    """
    requested = config.get_server_settings()
    required = {name: requested[name] for name in REQUIRED_SESSION_SETTINGS if name in requested}
    if config.shared_pool_search_path is not None:
        required["search_path"] = config.shared_pool_search_path
    names = sorted(required)

    width = max(1, pool.get_max_size())
    rounds = max(2, -(-MIN_SESSION_SETTING_SAMPLES // width))
    samples: list[dict[str, Any]] = []

    async def sample_rounds() -> None:
        for _ in range(rounds):
            connections: list[Any] = []
            try:
                for _ in range(width):
                    connections.append(await pool.acquire())
                barrier = asyncio.Barrier(width)
                results = await asyncio.gather(
                    *(_sample_session_settings(conn, names, barrier) for conn in connections),
                    return_exceptions=True,
                )
            finally:
                for conn in connections:
                    await pool.release(conn)
            errors = [result for result in results if isinstance(result, BaseException)]
            if errors:
                # The barrier aborts on the first failure, so later ones are BrokenBarrierError.
                cause = next((e for e in errors if not isinstance(e, asyncio.BrokenBarrierError)), errors[0])
                raise cause
            samples.extend(results)

    try:
        async with asyncio.timeout(timeout_seconds):
            await sample_rounds()
    except TimeoutError as exc:
        raise DatabaseSessionSettingsError(
            f"Could not verify database session settings: timed out after {timeout_seconds:g}s "
            f"holding {width} concurrent server connections; the pooler may serve fewer "
            "server connections than the pool size."
        ) from exc
    except DatabaseSessionSettingsError:
        raise
    except Exception as exc:
        raise DatabaseSessionSettingsError(
            f"Could not verify database session settings: {type(exc).__name__}: {exc}"
        ) from exc

    def matches(name: str, effective: str | None) -> bool:
        if name == "search_path":
            return _search_path_entries(effective) == _search_path_entries(required[name])
        return effective == required[name]

    failing = [
        sample
        for sample in samples
        if any(not matches(name, sample["settings"].get(name)) for name in names)
    ]
    if not failing:
        return

    role = failing[0]["role"]
    wrong: dict[str, set[str | None]] = {}
    for sample in failing:
        for name in names:
            effective = sample["settings"].get(name)
            if not matches(name, effective):
                wrong.setdefault(name, set()).add(effective)
    backends = sorted({sample["backend"] for sample in failing})
    lines = [
        f"  {name}: requested {required[name]!r}, connections have {sorted(map(str, values))}"
        for name, values in sorted(wrong.items())
    ]
    fixes = [f"  ALTER ROLE \"{role}\" SET {name} = '{required[name]}';" for name in sorted(wrong)]
    raise DatabaseSessionSettingsError(
        f"Database session settings missing on {len(failing)} of {len(samples)} sampled server "
        f"connections (backends {backends}); a connection pooler probably dropped the startup "
        "parameters:\n"
        + "\n".join(lines)
        + "\nSet them as role defaults, which every new server connection applies:\n"
        + "\n".join(fixes)
        + "\nThen refresh the pooler's server connections and confirm with "
        "SELECT name, setting, source FROM pg_settings."
    )


class AwidDatabaseInfra:
    """Thin pgdbm wrapper that exposes the manager contract expected by `aweb` routes."""

    def __init__(self, *, schema: str = "awid") -> None:
        self.schema = schema
        self._shared_pool: Optional[Any] = None
        self._manager: Optional[AsyncDatabaseManager] = None
        self._initialized = False
        self._init_lock = asyncio.Lock()
        self._owns_pool = True

    async def initialize(
        self,
        *,
        shared_pool: Optional[Any] = None,
        run_migrations: bool = True,
    ) -> None:
        if self._initialized:
            return

        async with self._init_lock:
            if self._initialized:
                return

            if shared_pool is None:
                settings = get_settings()
                config = database_config_from_settings(settings)
                shared_pool = await AsyncDatabaseManager.create_shared_pool(config)
                if getattr(settings, "database_require_session_settings", False):
                    try:
                        await verify_session_settings(
                            shared_pool,
                            config,
                            timeout_seconds=float(
                                getattr(
                                    settings,
                                    "database_session_check_timeout_seconds",
                                    DEFAULT_SESSION_CHECK_TIMEOUT_SECONDS,
                                )
                            ),
                        )
                    except BaseException:
                        await shared_pool.close()
                        raise
                self._owns_pool = True
            else:
                self._owns_pool = False

            self._shared_pool = shared_pool
            self._manager = AsyncDatabaseManager(pool=shared_pool, schema=self.schema)

            quoted_schema = self.schema.replace('"', '""')
            await self._manager.execute(f'CREATE SCHEMA IF NOT EXISTS "{quoted_schema}"')

            if run_migrations:
                import awid_service

                awid_path = Path(awid_service.__file__).resolve().parent
                migrations = AsyncMigrationManager(
                    self._manager,
                    migrations_path=str(awid_path / "migrations"),
                    module_name="awid-service",
                    migrations_table="schema_migrations",
                )
                await migrations.apply_pending_migrations()

            self._initialized = True

    async def close(self) -> None:
        if self._shared_pool is not None and self._owns_pool:
            await self._shared_pool.close()

        self._shared_pool = None
        self._manager = None
        self._initialized = False
        self._owns_pool = True

    @property
    def is_initialized(self) -> bool:
        return self._initialized

    def get_manager(self, name: str = "aweb") -> AsyncDatabaseManager:
        if not self._initialized or self._manager is None:
            raise RuntimeError("AwidDatabaseInfra is not initialized")
        # The imported aweb routes and helpers are not consistent about the manager
        # name they request. This wrapper owns only one schema-bound manager, so
        # any requested name must resolve to that same manager.
        return self._manager
