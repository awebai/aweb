from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import asyncpg
import pytest
from pgdbm.errors import QueryError


_MIGRATIONS_DIR = Path(__file__).resolve().parents[1] / "src" / "awid_service" / "migrations"


@pytest.mark.asyncio
async def test_dns_namespaces_scope_id_has_no_foreign_key(awid_db_infra):
    db = awid_db_infra.get_manager("aweb")
    row = await db.fetch_one(
        """
        SELECT COUNT(*)::int AS count
        FROM pg_constraint c
        JOIN pg_class t
          ON t.oid = c.conrelid
        JOIN pg_namespace n
          ON n.oid = t.relnamespace
        JOIN pg_attribute a
          ON a.attrelid = t.oid
         AND a.attnum = ANY(c.conkey)
        WHERE n.nspname = current_schema()
          AND t.relname = 'dns_namespaces'
          AND a.attname = 'scope_id'
          AND c.contype = 'f'
        """
    )

    assert row is not None
    assert row["count"] == 0


@pytest.mark.asyncio
async def test_route_level_delivery_origin_schema(awid_db_infra):
    db = awid_db_infra.get_manager("aweb")
    rows = await db.fetch_all(
        """
        SELECT 'dns_namespaces' AS table_name, attname AS column_name
        FROM pg_attribute
        WHERE attrelid = '{{tables.dns_namespaces}}'::regclass
          AND attname = 'default_delivery_origin'
          AND NOT attisdropped
        UNION ALL
        SELECT 'did_aw_mappings' AS table_name, attname AS column_name
        FROM pg_attribute
        WHERE attrelid = '{{tables.did_aw_mappings}}'::regclass
          AND attname = 'delivery_origin'
          AND NOT attisdropped
        ORDER BY table_name, column_name
        """
    )

    assert [(row["table_name"], row["column_name"]) for row in rows] == [
        ("dns_namespaces", "default_delivery_origin"),
    ]


@pytest.mark.asyncio
async def test_did_aw_mappings_has_no_address_fields(awid_db_infra):
    db = awid_db_infra.get_manager("aweb")
    rows = await db.fetch_all(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'did_aw_mappings'
          AND column_name = ANY($1::text[])
        """,
        ["server_url", "address", "handle"],
    )

    assert [row["column_name"] for row in rows] == []


@pytest.mark.asyncio
async def test_public_addresses_resolve_key_by_fk_only(awid_db_infra):
    db = awid_db_infra.get_manager("aweb")
    rows = await db.fetch_all(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'public_addresses'
          AND column_name = ANY($1::text[])
        ORDER BY column_name
        """,
        ["current_did_key", "reachability", "visible_to_team_id"],
    )
    assert [row["column_name"] for row in rows] == []

    now = datetime.now(timezone.utc)
    namespace_id = uuid4()
    await db.execute(
        """
        INSERT INTO {{tables.dns_namespaces}}
            (namespace_id, domain, verification_status, created_at)
        VALUES ($1, $2, 'verified', $3)
        """,
        namespace_id,
        "fk-address.example",
        now,
    )
    with pytest.raises(QueryError) as excinfo:
        await db.execute(
            """
            INSERT INTO {{tables.public_addresses}}
                (address_id, namespace_id, name, did_aw, created_at)
            VALUES ($1, $2, $3, $4, $5)
            """,
            uuid4(),
            namespace_id,
            "missing",
            "did:aw:missing",
            now,
        )
    assert isinstance(excinfo.value.__cause__, asyncpg.ForeignKeyViolationError)


def _drop_address_reachability_migration_sql(table_name: str) -> str:
    return (_MIGRATIONS_DIR / "003_drop_address_reachability.sql").read_text().replace(
        "{{tables.public_addresses}}",
        "{{tables." + table_name + "}}",
    )


async def _create_pre_003_public_addresses_table(db, table_name: str) -> None:
    # The probe rides the manager's {{tables.}} templating so it lands in the
    # manager's schema: under the pinned search_path an unqualified CREATE
    # resolves into pg_catalog and is denied.
    await db.execute(
        "CREATE TABLE {{tables." + table_name + """}} (
            address_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            reachability TEXT NOT NULL DEFAULT 'nobody',
            visible_to_team_id TEXT,
            deleted_at TIMESTAMPTZ
        )
        """
    )


async def _legacy_columns(db, table_name: str) -> list[str]:
    rows = await db.fetch_all(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = $3
          AND table_name = $1
          AND column_name = ANY($2::text[])
        ORDER BY column_name
        """,
        table_name,
        ["reachability", "visible_to_team_id"],
        db.schema or "public",
    )
    return [row["column_name"] for row in rows]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("reachability", "visible_to_team_id"),
    [
        ("nobody", None),
        ("team_members_only", "backend:example.com"),
    ],
)
async def test_drop_address_reachability_migration_blocks_active_non_neutral_rows(
    awid_db_infra,
    reachability: str,
    visible_to_team_id: str | None,
):
    db = awid_db_infra.get_manager("aweb")
    table_name = f"migration_public_addresses_{uuid4().hex}"
    try:
        await _create_pre_003_public_addresses_table(db, table_name)
        await db.execute(
            "INSERT INTO {{tables." + table_name + """}} (reachability, visible_to_team_id, deleted_at)
            VALUES ($1, $2, NULL)
            """,
            reachability,
            visible_to_team_id,
        )

        with pytest.raises(QueryError) as excinfo:
            await db.execute(_drop_address_reachability_migration_sql(table_name))

        assert "Refusing to drop legacy address reachability columns" in str(excinfo.value)
        assert await _legacy_columns(db, table_name) == ["reachability", "visible_to_team_id"]
    finally:
        await db.execute("DROP TABLE IF EXISTS {{tables." + table_name + "}}")


@pytest.mark.asyncio
async def test_drop_address_reachability_migration_allows_deleted_non_neutral_rows(awid_db_infra):
    db = awid_db_infra.get_manager("aweb")
    table_name = f"migration_public_addresses_{uuid4().hex}"
    try:
        await _create_pre_003_public_addresses_table(db, table_name)
        await db.execute(
            "INSERT INTO {{tables." + table_name + """}} (reachability, visible_to_team_id, deleted_at)
            VALUES ('team_members_only', 'backend:example.com', NOW())
            """
        )

        await db.execute(_drop_address_reachability_migration_sql(table_name))

        assert await _legacy_columns(db, table_name) == []
    finally:
        await db.execute("DROP TABLE IF EXISTS {{tables." + table_name + "}}")


@pytest.mark.asyncio
async def test_drop_address_reachability_migration_allows_active_neutral_rows(awid_db_infra):
    db = awid_db_infra.get_manager("aweb")
    table_name = f"migration_public_addresses_{uuid4().hex}"
    try:
        await _create_pre_003_public_addresses_table(db, table_name)
        await db.execute(
            "INSERT INTO {{tables." + table_name + """}} (reachability, visible_to_team_id, deleted_at)
            VALUES ('public', NULL, NULL)
            """
        )

        await db.execute(_drop_address_reachability_migration_sql(table_name))

        assert await _legacy_columns(db, table_name) == []
    finally:
        await db.execute("DROP TABLE IF EXISTS {{tables." + table_name + "}}")
