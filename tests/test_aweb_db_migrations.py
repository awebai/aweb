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

    # --- Migration 013: agent identity columns ---
    agent_cols = await test_db_with_schema.fetch_all(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = $1 AND table_name = $2
        """,
        test_db_with_schema.schema,
        "agents",
    )
    agent_col_names = {c["column_name"] for c in agent_cols}
    for col in (
        "did",
        "public_key",
        "custody",
        "signing_key_enc",
        "lifetime",
        "status",
        "successor_agent_id",
    ):
        assert col in agent_col_names, f"agents table missing column: {col}"

    # Verify defaults: agent created above should have lifetime='persistent', status='active'
    agent_with_identity = await test_db_with_schema.fetch_one(
        "SELECT lifetime, status, did, custody FROM {{tables.agents}} WHERE agent_id = $1",
        agent["agent_id"],
    )
    assert agent_with_identity["lifetime"] == "persistent"
    assert agent_with_identity["status"] == "active"
    assert agent_with_identity["did"] is None
    assert agent_with_identity["custody"] is None

    # --- Migration 014: message identity columns ---
    msg_cols = await test_db_with_schema.fetch_all(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = $1 AND table_name = $2
        """,
        test_db_with_schema.schema,
        "messages",
    )
    msg_col_names = {c["column_name"] for c in msg_cols}
    for col in ("from_did", "to_did", "signature", "signing_key_id"):
        assert col in msg_col_names, f"messages table missing column: {col}"

    # --- Migration 015: chat_message identity columns ---
    chat_cols = await test_db_with_schema.fetch_all(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = $1 AND table_name = $2
        """,
        test_db_with_schema.schema,
        "chat_messages",
    )
    chat_col_names = {c["column_name"] for c in chat_cols}
    for col in ("from_did", "to_did", "signature", "signing_key_id"):
        assert col in chat_col_names, f"chat_messages table missing column: {col}"

    # --- Migration 016: agent_log table ---
    log_cols = await test_db_with_schema.fetch_all(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = $1 AND table_name = $2
        """,
        test_db_with_schema.schema,
        "agent_log",
    )
    log_col_names = {c["column_name"] for c in log_cols}
    for col in (
        "log_id",
        "agent_id",
        "project_id",
        "operation",
        "old_did",
        "new_did",
        "signed_by",
        "entry_signature",
        "metadata",
        "created_at",
    ):
        assert col in log_col_names, f"agent_log table missing column: {col}"

    # Verify agent_log works with an insert
    await test_db_with_schema.execute(
        "INSERT INTO {{tables.agent_log}} (agent_id, project_id, operation, new_did) VALUES ($1, $2, $3, $4)",
        agent["agent_id"],
        project["project_id"],
        "create",
        "did:key:zTest",
    )
    log_entry = await test_db_with_schema.fetch_one(
        "SELECT operation, new_did FROM {{tables.agent_log}} WHERE agent_id = $1",
        agent["agent_id"],
    )
    assert log_entry is not None
    assert log_entry["operation"] == "create"
    assert log_entry["new_did"] == "did:key:zTest"
