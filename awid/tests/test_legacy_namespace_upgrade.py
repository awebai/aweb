"""Real published migrations must not manufacture legacy namespace authority."""

import hashlib
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

import awid_service
import pytest
from awid.did import did_from_public_key, generate_keypair
from awid_service.testing_migrations import (
    HistoricalNamespace,
    LegacyNamespacePreparationError,
    _check_historical_namespaces,
    _legacy_migration_prefix,
    prepare_legacy_namespace_upgrade,
)
from pgdbm.migrations import AsyncMigrationManager, Migration


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
    with pytest.raises(ValueError) as refusal:
        HistoricalNamespace(
            namespace_id=UUID(int=1),
            domain="example.test",
            controller_did=historical_namespaces()[0].controller_did,
            registered_at=datetime(2026, 9, 1),
        )
    assert str(refusal.value) == "Supply a timezone-aware historical timestamp."


def invalid_histories():
    first, second = historical_namespaces()
    return [
        pytest.param(
            (),
            "Supply at least one historical namespace to upgrade.",
            id="empty",
        ),
        pytest.param(
            (first, replace(second, domain=first.domain)),
            "Supply each historical namespace domain only once.",
            id="duplicate-domain",
        ),
        pytest.param(
            (first, replace(second, namespace_id=first.namespace_id)),
            "Supply a distinct UUID for each historical namespace.",
            id="duplicate-uuid",
        ),
    ]


@pytest.mark.parametrize(("records", "message"), invalid_histories())
def test_historical_input_refusals_give_exact_actionable_advice(records, message):
    with pytest.raises(ValueError) as refusal:
        _check_historical_namespaces(records)
    assert str(refusal.value) == message


def test_distinct_historical_namespaces_with_aware_timestamps_are_accepted():
    records = historical_namespaces()
    assert len({record.namespace_id for record in records}) == 2
    assert len({record.domain for record in records}) == 2
    assert all(record.registered_at.utcoffset() is not None for record in records)
    _check_historical_namespaces(records)


def published_migrations():
    return [
        Migration(
            filename=path.name,
            checksum=hashlib.sha256(path.read_bytes()).hexdigest(),
            content=path.read_text(),
        )
        for path in sorted(
            (Path(awid_service.__file__).parent / "migrations").glob("*.sql")
        )
    ]


@pytest.mark.parametrize(
    "malform",
    [
        pytest.param(lambda files: files[:10], id="missing-boundary"),
        pytest.param(lambda files: [files[1], files[0], *files[2:]], id="wrong-order"),
        pytest.param(
            lambda files: [
                *files[:9],
                files[9].model_copy(update={"filename": "010_wrong_boundary.sql"}),
                *files[10:],
            ],
            id="wrong-010-file",
        ),
        pytest.param(
            lambda files: [
                *files[:10],
                files[10].model_copy(update={"filename": "011_wrong_boundary.sql"}),
                *files[11:],
            ],
            id="wrong-011-file",
        ),
    ],
)
def test_malformed_migration_prefix_gives_exact_restore_instruction(malform):
    with pytest.raises(LegacyNamespacePreparationError) as refusal:
        _legacy_migration_prefix(malform(published_migrations()))
    assert str(refusal.value) == (
        "The published namespace migration boundary is unavailable. "
        "Restore the registry's complete immutable 001 through 011 migration files."
    )


def test_published_migration_prefix_preserves_its_actual_files():
    files = published_migrations()
    assert _legacy_migration_prefix(files) == tuple(files[:11])
