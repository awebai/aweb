from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import asyncpg
import pytest
from pgdbm.errors import QueryError


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
          AND column_name = 'current_did_key'
        """
    )
    assert rows == []

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
                (address_id, namespace_id, name, did_aw, reachability, created_at)
            VALUES ($1, $2, $3, $4, 'public', $5)
            """,
            uuid4(),
            namespace_id,
            "missing",
            "did:aw:missing",
            now,
        )
    assert isinstance(excinfo.value.__cause__, asyncpg.ForeignKeyViolationError)
