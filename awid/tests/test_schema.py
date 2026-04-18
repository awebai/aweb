from __future__ import annotations

import pytest


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
