from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from pgdbm import AsyncDatabaseManager
from pgdbm.migrations import AsyncMigrationManager

import aweb
from awid_service.migrate import migrate_from_aweb


@pytest.mark.asyncio
async def test_migrate_from_aweb_backfills_controller_did_from_replacements(
    monkeypatch,
    shared_test_pool,
):
    source = AsyncDatabaseManager(pool=shared_test_pool, schema="aweb")
    await source.execute('CREATE SCHEMA IF NOT EXISTS "aweb"')
    aweb_path = __import__("pathlib").Path(aweb.__file__).resolve().parent
    migrations = AsyncMigrationManager(
        source,
        migrations_path=str(aweb_path / "migrations" / "aweb"),
        module_name="awid-migrate-source",
        migrations_table="schema_migrations",
    )
    await migrations.apply_pending_migrations()
    await source.execute(
        'ALTER TABLE "aweb".dns_namespaces DROP CONSTRAINT chk_dns_namespaces_type_fields'
    )

    now = datetime.now(timezone.utc)
    project_id = uuid4()
    old_agent_id = uuid4()
    new_agent_id = uuid4()
    namespace_id = uuid4()
    announcement_id = uuid4()
    address_id = uuid4()

    await source.execute(
        """
        INSERT INTO {{tables.projects}} (project_id, slug, name, created_at)
        VALUES ($1, $2, $3, $4)
        """,
        project_id,
        "proj",
        "proj",
        now,
    )
    await source.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, project_id, alias, human_name, agent_type, access_mode, lifetime, status, created_at)
        VALUES ($1, $2, $3, '', 'agent', 'open', 'persistent', 'active', $4),
               ($5, $2, $6, '', 'agent', 'open', 'persistent', 'active', $4)
        """,
        old_agent_id,
        project_id,
        "old",
        now,
        new_agent_id,
        "new",
    )
    await source.execute(
        """
        INSERT INTO {{tables.did_aw_mappings}}
            (did_aw, current_did_key, server_url, address, handle, created_at, updated_at)
        VALUES ($1, $2, $3, $4, $5, $6, $6)
        """,
        "did:aw:migrated",
        "did:key:zmigrated",
        "https://server.example",
        "example.com/support",
        "support",
        now,
    )
    await source.execute(
        """
        INSERT INTO {{tables.dns_namespaces}}
            (namespace_id, domain, controller_did, verification_status, last_verified_at, created_at, namespace_type)
        VALUES ($1, $2, NULL, 'verified', $3, $3, 'dns_verified')
        """,
        namespace_id,
        "example.com",
        now,
    )
    await source.execute(
        """
        INSERT INTO {{tables.public_addresses}}
            (address_id, namespace_id, name, did_aw, current_did_key, reachability, created_at)
        VALUES ($1, $2, $3, $4, $5, 'public', $6)
        """,
        address_id,
        namespace_id,
        "support",
        "did:aw:migrated",
        "did:key:zmigrated",
        now,
    )
    await source.execute(
        """
        INSERT INTO {{tables.replacement_announcements}}
            (announcement_id, project_id, old_agent_id, new_agent_id, namespace_id, address_name,
             old_did, new_did, controller_did, replacement_timestamp, controller_signature, authorized_by, created_at)
        VALUES ($1, $2, $3, $4, $5, $6,
                $7, $8, $9, $10, $11, $12, $13)
        """,
        announcement_id,
        project_id,
        old_agent_id,
        new_agent_id,
        namespace_id,
        "support",
        "did:aw:old",
        "did:aw:new",
        "did:key:zcontroller",
        "2026-04-03T00:00:00Z",
        "sig",
        "did:key:zcontroller",
        now,
    )

    monkeypatch.setenv("AWID_DATABASE_URL", source.config.get_dsn())

    result = await migrate_from_aweb(source_schema="aweb", target_schema="awid")
    assert result.namespaces == 1
    assert result.addresses == 1
    assert result.replacements == 1

    target = AsyncDatabaseManager(pool=shared_test_pool, schema="awid")
    row = await target.fetch_one(
        """
        SELECT controller_did
        FROM {{tables.dns_namespaces}}
        WHERE domain = $1
        """,
        "example.com",
    )
    assert row is not None
    assert row["controller_did"] == "did:key:zcontroller"
