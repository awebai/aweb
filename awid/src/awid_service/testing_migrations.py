"""Historical test data upgraded by the registry's published migration chain.

These fixtures describe persisted history, never present-day authorization.
Use only before starting a registry on an empty isolated test schema. This
module does not create an app, pool, transport, DNS override or bypass route.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from uuid import UUID

from pgdbm import AsyncDatabaseManager
from pgdbm.migrations import AsyncMigrationManager, Migration


class LegacyNamespacePreparationError(RuntimeError):
    """The isolated schema cannot reproduce the requested historical origin."""


class HistoricalNamespaceVerification(StrEnum):
    """Persisted namespace status written by the pre-010 registration route."""

    VERIFIED = "verified"


@dataclass(frozen=True, kw_only=True)
class HistoricalNamespace:
    """A verified namespace persisted before migration 010, without ancestry.

    The caller retains its controller's key separately for subsequent real
    requests. Supplying these old stored facts proves no current authority.
    """

    namespace_id: UUID
    domain: str
    controller_did: str
    registered_at: datetime
    default_delivery_origin: str | None = None

    def __post_init__(self) -> None:
        if self.registered_at.utcoffset() is None:
            raise ValueError("Supply a timezone-aware historical timestamp.")


@dataclass(frozen=True, kw_only=True)
class AppliedRegistryMigration:
    filename: str
    checksum: str


@dataclass(frozen=True, kw_only=True)
class LegacyNamespaceUpgradeReceipt:
    """Observed migration checkpoints, not a certificate or authority proof."""

    namespace_columns_before_010: tuple[str, ...]
    epoch_rows_after_010: int
    unwitnessed_domains_after_011: tuple[str, ...]
    applied_migrations: tuple[AppliedRegistryMigration, ...]


def _check_historical_namespaces(namespaces: tuple[HistoricalNamespace, ...]) -> None:
    if not namespaces:
        raise ValueError("Supply at least one historical namespace to upgrade.")
    if len({record.domain for record in namespaces}) != len(namespaces):
        raise ValueError("Supply each historical namespace domain only once.")
    if len({record.namespace_id for record in namespaces}) != len(namespaces):
        raise ValueError("Supply a distinct UUID for each historical namespace.")


async def _require_empty_schema(db: AsyncDatabaseManager) -> None:
    if not db.schema or await db.fetch_value(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema=$1)",
        db.schema,
    ):
        raise LegacyNamespacePreparationError(
            "Legacy namespace preparation requires an empty schema. "
            "Use a new isolated test database; do not clear an existing registry."
        )


def _legacy_migration_prefix(migrations: list[Migration]) -> tuple[Migration, ...]:
    """Require the published historical boundary before changing the schema."""
    if (
        len(migrations) < 11
        or tuple(item.version for item in migrations[:11])
        != tuple(f"{number:03d}" for number in range(1, 12))
        or migrations[9].filename != "010_id_certificates.sql"
        or migrations[10].filename != "011_namespace_delegation.sql"
    ):
        raise LegacyNamespacePreparationError(
            "The published namespace migration boundary is unavailable. "
            "Restore the registry's complete immutable 001 through 011 migration files."
        )
    return tuple(migrations[:11])


async def _write_pre010_namespaces(
    db: AsyncDatabaseManager, *, namespaces: tuple[HistoricalNamespace, ...]
) -> None:
    # Exact persisted columns/values from dns_namespaces.register_namespace at
    # 24c923fa9e9b6bae750da647952ec57cf52df794, before 010 existed. No epoch or
    # parent witness was stored by that writer; neither is inferred here.
    async with db.transaction() as tx:
        for record in namespaces:
            await tx.execute(
                """
                INSERT INTO {{tables.dns_namespaces}}
                    (namespace_id, domain, controller_did, verification_status,
                     default_delivery_origin, last_verified_at, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                """,
                record.namespace_id,
                record.domain,
                record.controller_did,
                HistoricalNamespaceVerification.VERIFIED.value,
                record.default_delivery_origin,
                record.registered_at,
                record.registered_at,
            )


async def prepare_legacy_namespace_upgrade(
    db: AsyncDatabaseManager, *, namespaces: tuple[HistoricalNamespace, ...]
) -> LegacyNamespaceUpgradeReceipt:
    """Populate pre-010 history and upgrade it before the test app starts.

    docs/awid-sot.md:1487-1523 requires the real ordered files/checksum ledger;
    docs/id-certificates.md#key-rotation-and-re-sign states:
    "No pre-upgrade namespace history is guessed."
    The existing registry fixture owns the database and serving lifecycle.
    Failure leaves that disposable schema for diagnosis; nothing is cleared.
    """
    _check_historical_namespaces(namespaces)
    await _require_empty_schema(db)
    manager = AsyncMigrationManager(
        db,
        migrations_path=str(Path(__file__).parent / "migrations"),
        module_name="awid-service",
        migrations_table="schema_migrations",
    )
    prefix = _legacy_migration_prefix(await manager.find_migration_files())
    await manager.ensure_migrations_table()
    for migration in prefix[:9]:
        await manager.apply_migration(migration)
    await _write_pre010_namespaces(db, namespaces=namespaces)
    columns = await db.fetch_all(
        """SELECT column_name FROM information_schema.columns
           WHERE table_schema=$1 AND table_name='dns_namespaces'
           ORDER BY ordinal_position""",
        db.schema,
    )
    await manager.apply_migration(prefix[9])
    epoch_count = await db.fetch_value(
        "SELECT count(*) FROM {{tables.id_namespace_epochs}}"
    )
    if epoch_count != 0:
        raise LegacyNamespacePreparationError(
            "Migration 010 manufactured historical namespace epochs. "
            "Inspect the disposable fixture; do not use it as migration-origin evidence."
        )
    await manager.apply_migration(prefix[10])
    parents = await db.fetch_all(
        """SELECT domain, parent_domain, parent_controller_key
           FROM {{tables.dns_namespaces}} ORDER BY domain"""
    )
    if any(
        row["parent_domain"] is not None or row["parent_controller_key"] is not None
        for row in parents
    ):
        raise LegacyNamespacePreparationError(
            "Migration 011 manufactured historical parent witnesses. "
            "Inspect the disposable fixture; do not use it as migration-origin evidence."
        )
    # Verify prefix checksums and apply every remaining published file using
    # the same startup runner. No migration source or ledger row is fabricated.
    await manager.apply_pending_migrations()
    applied = await manager.get_applied_migrations()
    return LegacyNamespaceUpgradeReceipt(
        namespace_columns_before_010=tuple(row["column_name"] for row in columns),
        epoch_rows_after_010=epoch_count,
        unwitnessed_domains_after_011=tuple(row["domain"] for row in parents),
        applied_migrations=tuple(
            AppliedRegistryMigration(filename=item.filename, checksum=item.checksum)
            for item in applied.values()
        ),
    )
