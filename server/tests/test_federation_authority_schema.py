from __future__ import annotations

import json
from pathlib import Path

import pytest


_ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.asyncio
async def test_authority_schema_keys_checkpoint_by_did_and_cohort_by_address(
    aweb_cloud_db,
) -> None:
    db = aweb_cloud_db.aweb_db
    checkpoint_pk = await db.fetch_all(
        """
        SELECT a.attname
        FROM pg_index i
        JOIN pg_class c ON c.oid = i.indrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = ANY(i.indkey)
        WHERE n.nspname = 'aweb' AND c.relname = 'federation_did_checkpoints'
          AND i.indisprimary
        ORDER BY array_position(i.indkey, a.attnum)
        """
    )
    cohort_pk = await db.fetch_all(
        """
        SELECT a.attname
        FROM pg_index i
        JOIN pg_class c ON c.oid = i.indrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = ANY(i.indkey)
        WHERE n.nspname = 'aweb' AND c.relname = 'federation_address_authority_cohorts'
          AND i.indisprimary
        ORDER BY array_position(i.indkey, a.attnum)
        """
    )
    assert [row["attname"] for row in checkpoint_pk] == ["did_aw"]
    assert [row["attname"] for row in cohort_pk] == ["canonical_address"]
    checkpoint_columns = await db.fetch_all(
        """
        SELECT column_name FROM information_schema.columns
        WHERE table_schema = 'aweb' AND table_name = 'federation_did_checkpoints'
        """
    )
    assert "registry_origin" not in {row["column_name"] for row in checkpoint_columns}


@pytest.mark.asyncio
async def test_cohort_schema_contains_every_immutable_vector_field(
    aweb_cloud_db,
) -> None:
    vector = json.loads(
        (_ROOT / "docs" / "vectors" / "federation-authority-state-v1.json").read_text()
    )
    rows = await aweb_cloud_db.aweb_db.fetch_all(
        """
        SELECT column_name FROM information_schema.columns
        WHERE table_schema = 'aweb'
          AND table_name = 'federation_address_authority_cohorts'
        """
    )
    columns = {row["column_name"] for row in rows}
    assert set(vector["cohort_required_fields"]) <= columns


@pytest.mark.asyncio
async def test_fence_counter_is_restrict_referenced_and_not_expiry_state(
    aweb_cloud_db,
) -> None:
    row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT confdeltype
        FROM pg_constraint con
        JOIN pg_class child ON child.oid = con.conrelid
        JOIN pg_class parent ON parent.oid = con.confrelid
        JOIN pg_namespace n ON n.oid = child.relnamespace
        WHERE n.nspname = 'aweb'
          AND child.relname = 'federation_authority_leases'
          AND parent.relname = 'federation_authority_fences'
          AND con.contype = 'f'
        """
    )
    assert row["confdeltype"] == b"r"
    columns = await aweb_cloud_db.aweb_db.fetch_all(
        """
        SELECT column_name FROM information_schema.columns
        WHERE table_schema = 'aweb' AND table_name = 'federation_authority_fences'
        """
    )
    assert "expires_at" not in {item["column_name"] for item in columns}
