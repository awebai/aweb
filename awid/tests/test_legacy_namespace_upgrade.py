"""Real published migrations must not manufacture legacy namespace authority."""

from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

import awid_service
import pytest
from awid.did import did_from_public_key, generate_keypair
from awid_service.testing_migrations import (
    HistoricalNamespace,
    LegacyNamespacePreparationError,
    prepare_legacy_namespace_upgrade,
)
from pgdbm.migrations import AsyncMigrationManager


def historical_namespaces():
    registered_at = datetime(2026, 9, 1, tzinfo=timezone.utc)
    records = []
    for number, domain in enumerate(("example.test", "child.example.test"), 1):
        _signer, public_key = generate_keypair()
        records.append(
            HistoricalNamespace(
                namespace_id=UUID(int=number),
                domain=domain,
                controller_did=did_from_public_key(public_key),
                registered_at=registered_at,
                default_delivery_origin="https://delivery.example.test",
            )
        )
    return tuple(records)


def published_migration_manager(db):
    return AsyncMigrationManager(
        db,
        migrations_path=str(Path(awid_service.__file__).parent / "migrations"),
        module_name="awid-service",
        migrations_table="schema_migrations",
    )


@pytest.mark.asyncio
async def test_pre010_rows_pass_real_migrations_without_guessed_epochs_or_parents(
    test_db_factory,
):
    db = await test_db_factory.create_db(suffix="legacy_namespace", schema="awid")
    namespaces = historical_namespaces()

    receipt = await prepare_legacy_namespace_upgrade(db, namespaces=namespaces)

    assert "parent_domain" not in receipt.namespace_columns_before_010
    assert "parent_controller_key" not in receipt.namespace_columns_before_010
    assert receipt.epoch_rows_after_010 == 0
    assert receipt.unwitnessed_domains_after_011 == tuple(
        sorted(record.domain for record in namespaces)
    )
    assert (
        await db.fetch_value("SELECT count(*) FROM {{tables.id_namespace_epochs}}") == 0
    )
    rows = await db.fetch_all("SELECT * FROM {{tables.dns_namespaces}} ORDER BY domain")
    assert len(rows) == len(namespaces)
    for row, record in zip(
        rows, sorted(namespaces, key=lambda item: item.domain), strict=True
    ):
        assert row["namespace_id"] == record.namespace_id
        assert row["domain"] == record.domain
        assert row["controller_did"] == record.controller_did
        assert row["verification_status"] == "verified"
        assert row["created_at"] == row["last_verified_at"] == record.registered_at
        assert row["default_delivery_origin"] == record.default_delivery_origin
        assert row["deleted_at"] is None
        assert row["parent_domain"] is row["parent_controller_key"] is None

    manager = published_migration_manager(db)
    published = await manager.find_migration_files()
    applied = await manager.get_applied_migrations()
    assert [(item.filename, item.checksum) for item in receipt.applied_migrations] == [
        (item.filename, item.checksum) for item in published
    ]
    assert set(applied) == {item.filename for item in published}
    for migration in published:
        assert applied[migration.filename].checksum == migration.checksum
        assert applied[migration.filename].module_name == "awid-service"
    assert (await manager.apply_pending_migrations())["status"] == "up_to_date"


@pytest.mark.asyncio
async def test_preparation_refuses_an_existing_schema_without_changing_its_rows(
    test_db_factory,
):
    db = await test_db_factory.create_db(suffix="legacy_existing", schema="awid")
    namespaces = historical_namespaces()
    await prepare_legacy_namespace_upgrade(db, namespaces=namespaces)
    tables = ("schema_migrations", "dns_namespaces", "id_namespace_epochs")
    before = {
        table: await db.fetch_all(f"SELECT * FROM {{{{tables.{table}}}}} ORDER BY 1")
        for table in tables
    }

    with pytest.raises(LegacyNamespacePreparationError) as refusal:
        await prepare_legacy_namespace_upgrade(db, namespaces=namespaces)

    assert str(refusal.value) == (
        "Legacy namespace preparation requires an empty schema. "
        "Use a new isolated test database; do not clear an existing registry."
    )
    for table in tables:
        assert (
            await db.fetch_all(f"SELECT * FROM {{{{tables.{table}}}}} ORDER BY 1")
            == before[table]
        )


def test_historical_namespace_requires_an_explicit_timezone():
    with pytest.raises(
        ValueError, match="Supply a timezone-aware historical timestamp"
    ):
        HistoricalNamespace(
            namespace_id=UUID(int=1),
            domain="example.test",
            controller_did=historical_namespaces()[0].controller_did,
            registered_at=datetime(2026, 9, 1),
        )
