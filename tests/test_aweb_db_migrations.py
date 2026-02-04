import uuid
from pathlib import Path

import pytest
from pgdbm.migrations import AsyncMigrationManager


@pytest.mark.asyncio
async def test_aweb_migrations_apply(test_db_with_schema):
    """Apply aweb migrations into an isolated test schema and verify core tables work."""
    root = Path(__file__).resolve().parents[1]
    migrations_path = root / "src" / "aweb" / "migrations" / "aweb"

    manager = AsyncMigrationManager(
        test_db_with_schema,
        migrations_path=str(migrations_path),
        module_name="aweb-aweb",
    )
    await manager.apply_pending_migrations()

    cols = await test_db_with_schema.fetch_all(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = $1 AND table_name = $2
        """,
        test_db_with_schema.schema,
        "projects",
    )
    col_names = {c["column_name"] for c in cols}
    assert "tenant_id" in col_names

    cols = await test_db_with_schema.fetch_all(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = $1 AND table_name = $2
        """,
        test_db_with_schema.schema,
        "api_keys",
    )
    col_names = {c["column_name"] for c in cols}
    assert "user_id" in col_names
    assert "agent_id" in col_names

    await test_db_with_schema.execute(
        "INSERT INTO {{tables.projects}} (slug, name) VALUES ($1, $2)",
        "test-project",
        "Test Project",
    )

    project = await test_db_with_schema.fetch_one(
        "SELECT project_id, slug, name FROM {{tables.projects}} WHERE slug = $1",
        "test-project",
    )
    assert project is not None

    await test_db_with_schema.execute(
        "INSERT INTO {{tables.agents}} (project_id, alias, human_name, agent_type) VALUES ($1, $2, $3, $4)",
        project["project_id"],
        "agent-1",
        "Agent One",
        "agent",
    )

    agent = await test_db_with_schema.fetch_one(
        "SELECT agent_id, project_id, alias FROM {{tables.agents}} WHERE project_id = $1 AND alias = $2",
        project["project_id"],
        "agent-1",
    )
    assert agent is not None

    await test_db_with_schema.execute(
        "INSERT INTO {{tables.api_keys}} (project_id, key_prefix, key_hash, is_active) VALUES ($1, $2, $3, $4)",
        project["project_id"],
        "aw_sk_deadbeef",
        "sha256-hash-placeholder",
        True,
    )

    key = await test_db_with_schema.fetch_one(
        "SELECT key_prefix, is_active FROM {{tables.api_keys}} WHERE project_id = $1 AND key_prefix = $2",
        project["project_id"],
        "aw_sk_deadbeef",
    )
    assert key is not None
    assert key["is_active"] is True

    with pytest.raises(Exception):
        await test_db_with_schema.execute(
            "INSERT INTO {{tables.projects}} (slug, name) VALUES ($1, $2)",
            "test-project",
            "Duplicate",
        )

    tenant_id = uuid.uuid4()
    await test_db_with_schema.execute(
        "INSERT INTO {{tables.projects}} (tenant_id, slug, name) VALUES ($1, $2, $3)",
        tenant_id,
        "test-project",
        "Hosted Project",
    )

    with pytest.raises(Exception):
        await test_db_with_schema.execute(
            "INSERT INTO {{tables.projects}} (tenant_id, slug, name) VALUES ($1, $2, $3)",
            tenant_id,
            "test-project",
            "Hosted Project Duplicate",
        )
