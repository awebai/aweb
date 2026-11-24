"""Ordered native migrations shared by standalone and embedding hosts.

Hosts supply the initialized native database manager and own its schema/pool.
Their own migration chains stay outside this inventory. Readiness reads the
same module identities, filenames and checksums that application uses.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from pgdbm import AsyncDatabaseManager, AsyncMigrationManager

from aweb_naapp_contracts.hooks.owner_act_nonces import MIGRATIONS_MODULE, MIGRATIONS_PATH

logger = logging.getLogger(__name__)

__all__ = [
    "AppliedNativeMigrations",
    "MigrationModule",
    "NativeMigration",
    "NativeMigrationError",
    "PendingNativeMigrations",
    "apply_native_migrations",
    "native_migration_modules",
    "pending_native_migrations",
]


@dataclass(frozen=True)
class MigrationModule:
    module_name: str
    migrations_path: Path


@dataclass(frozen=True)
class NativeMigration:
    module_name: str
    filename: str


@dataclass(frozen=True)
class AppliedNativeMigrations:
    applied: tuple[NativeMigration, ...]


@dataclass(frozen=True)
class PendingNativeMigrations:
    pending: tuple[NativeMigration, ...]

    @property
    def ready(self) -> bool:
        """Whether every module in the native migration inventory is applied."""
        return not self.pending

    @property
    def message(self) -> str:
        """Describe the migration readiness result with an actionable missing-module list."""
        if self.ready:
            return "Native migrations are current."
        names = ", ".join(f"{item.module_name}/{item.filename}" for item in self.pending)
        return f"Pending native migrations: {names}. Run apply_native_migrations(db) before serving traffic."


class NativeMigrationError(RuntimeError):
    """A native apply/check failed; the underlying error is logged and chained."""

    def __init__(self, *, operation: str, module_name: str) -> None:
        self.operation = operation
        self.module_name = module_name
        super().__init__(
            f"Could not {operation} native migrations for {module_name}. "
            "Check the database connection and packaged migration files, then retry before serving traffic."
        )


def native_migration_modules() -> tuple[MigrationModule, ...]:
    """Native core, then the hooks kit's nonce module, in application order."""
    return (
        MigrationModule("aweb-aweb", Path(__file__).resolve().parent / "aweb"),
        MigrationModule(MIGRATIONS_MODULE, MIGRATIONS_PATH),
    )


def _manager(db: AsyncDatabaseManager, module: MigrationModule) -> AsyncMigrationManager:
    # pgdbm treats a missing directory as an empty migration chain. A missing
    # native package must instead prevent both startup and false readiness.
    if not module.migrations_path.is_dir() or not any(module.migrations_path.glob("*.sql")):
        raise FileNotFoundError(f"Native migration files unavailable for {module.module_name}")
    return AsyncMigrationManager(
        db, migrations_path=str(module.migrations_path), module_name=module.module_name,
    )


async def apply_native_migrations(db: AsyncDatabaseManager) -> AppliedNativeMigrations:
    """Apply every native module; propagate a typed failure before readiness.

    Module identities and pgdbm's receipt/checksum/advisory-lock behavior are
    unchanged. A failure can leave earlier migrations committed; retry applies
    only those still pending. This operation does not own the host's pool.
    """
    applied: list[NativeMigration] = []
    for module in native_migration_modules():
        try:
            result = await _manager(db, module).apply_pending_migrations()
        except Exception as exc:
            logger.exception("Native migration apply failed for %s", module.module_name)
            raise NativeMigrationError(operation="apply", module_name=module.module_name) from exc
        applied.extend(NativeMigration(module.module_name, item["filename"]) for item in result["applied"])
    return AppliedNativeMigrations(tuple(applied))


async def pending_native_migrations(db: AsyncDatabaseManager) -> PendingNativeMigrations:
    """Read pending filenames/checksums without creating a migration ledger.

    A fresh schema with no ledger has every native migration pending. An
    unreadable ledger or modified applied file raises NativeMigrationError;
    neither is represented as a successful readiness result.
    """
    pending: list[NativeMigration] = []
    for module in native_migration_modules():
        try:
            manager = _manager(db, module)
            ledger = f"{db.schema}.schema_migrations" if db.schema else "schema_migrations"
            exists = await db.fetch_value("SELECT to_regclass($1)", ledger)
            migrations = (
                await manager.get_pending_migrations() if exists is not None
                else await manager.find_migration_files()
            )
        except Exception as exc:
            logger.exception("Native migration check failed for %s", module.module_name)
            raise NativeMigrationError(operation="check", module_name=module.module_name) from exc
        pending.extend(NativeMigration(module.module_name, item.filename) for item in migrations)
    return PendingNativeMigrations(tuple(pending))
