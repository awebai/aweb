"""Tests for soft_delete_agent — workspace cleanup (aweb-9h3)."""

from __future__ import annotations

import uuid

import pytest

from aweb.auth import hash_api_key
from aweb.bootstrap import soft_delete_agent
from aweb.db import DatabaseInfra


async def _setup_agent(aweb_db) -> dict:
    """Create a project + agent + API key directly in the DB."""
    namespace_id = uuid.uuid4()
    project_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    slug = f"test/softdel-{uuid.uuid4().hex[:6]}"

    await aweb_db.execute(
        "INSERT INTO {{tables.namespaces}} (namespace_id, slug) VALUES ($1, $2)",
        namespace_id,
        slug,
    )
    await aweb_db.execute(
        "INSERT INTO {{tables.projects}} (project_id, slug, name, namespace_id) VALUES ($1, $2, $3, $4)",
        project_id,
        slug,
        "Soft Delete Test",
        namespace_id,
    )
    await aweb_db.execute(
        """INSERT INTO {{tables.agents}}
           (agent_id, project_id, alias, human_name, agent_type, lifetime, namespace_id)
           VALUES ($1, $2, $3, $4, $5, $6, $7)""",
        agent_id,
        project_id,
        "cleanup-agent",
        "Cleanup Agent",
        "agent",
        "persistent",
        namespace_id,
    )
    key = f"aw_sk_{uuid.uuid4().hex}"
    await aweb_db.execute(
        """INSERT INTO {{tables.api_keys}}
           (project_id, agent_id, key_prefix, key_hash, is_active)
           VALUES ($1, $2, $3, $4, true)""",
        project_id,
        agent_id,
        key[:12],
        hash_api_key(key),
    )
    return {
        "project_id": str(project_id),
        "agent_id": str(agent_id),
        "slug": slug,
        "api_key": key,
    }


@pytest.mark.asyncio
async def test_soft_delete_sets_deleted_at_and_status(aweb_db_infra):
    """soft_delete_agent sets deleted_at and status='deregistered'."""
    aweb_db_infra: DatabaseInfra
    aweb_db = aweb_db_infra.get_manager("aweb")
    env = await _setup_agent(aweb_db)

    await soft_delete_agent(
        aweb_db_infra,
        agent_id=env["agent_id"],
        project_id=env["project_id"],
    )

    row = await aweb_db.fetch_one(
        "SELECT status, deleted_at FROM {{tables.agents}} WHERE agent_id = $1",
        uuid.UUID(env["agent_id"]),
    )
    assert row is not None
    assert row["status"] == "deregistered"
    assert row["deleted_at"] is not None


@pytest.mark.asyncio
async def test_soft_delete_writes_agent_log(aweb_db_infra):
    """soft_delete_agent writes a workspace_cleanup entry to agent_log."""
    aweb_db_infra: DatabaseInfra
    aweb_db = aweb_db_infra.get_manager("aweb")
    env = await _setup_agent(aweb_db)

    await soft_delete_agent(
        aweb_db_infra,
        agent_id=env["agent_id"],
        project_id=env["project_id"],
    )

    log = await aweb_db.fetch_one(
        """SELECT operation, old_did
           FROM {{tables.agent_log}}
           WHERE agent_id = $1
           ORDER BY created_at DESC LIMIT 1""",
        uuid.UUID(env["agent_id"]),
    )
    assert log is not None
    assert log["operation"] == "workspace_cleanup"
    # Agent created without DID, so old_did should be None.
    assert log["old_did"] is None


@pytest.mark.asyncio
async def test_soft_delete_frees_alias(aweb_db_infra):
    """After soft_delete, the alias is available for reuse."""
    aweb_db_infra: DatabaseInfra
    aweb_db = aweb_db_infra.get_manager("aweb")
    env = await _setup_agent(aweb_db)

    await soft_delete_agent(
        aweb_db_infra,
        agent_id=env["agent_id"],
        project_id=env["project_id"],
    )

    # The alias should not appear in active agents
    active = await aweb_db.fetch_one(
        """SELECT agent_id FROM {{tables.agents}}
           WHERE project_id = $1 AND alias = $2 AND deleted_at IS NULL""",
        uuid.UUID(env["project_id"]),
        "cleanup-agent",
    )
    assert active is None


@pytest.mark.asyncio
async def test_soft_delete_works_for_persistent_agents(aweb_db_infra):
    """soft_delete_agent works for persistent agents (unlike deregister which rejects them)."""
    aweb_db_infra: DatabaseInfra
    aweb_db = aweb_db_infra.get_manager("aweb")
    env = await _setup_agent(aweb_db)

    # Verify the agent is persistent
    row = await aweb_db.fetch_one(
        "SELECT lifetime FROM {{tables.agents}} WHERE agent_id = $1",
        uuid.UUID(env["agent_id"]),
    )
    assert row["lifetime"] == "persistent"

    # soft_delete should NOT raise, unlike deregister which would 400
    await soft_delete_agent(
        aweb_db_infra,
        agent_id=env["agent_id"],
        project_id=env["project_id"],
    )

    row = await aweb_db.fetch_one(
        "SELECT deleted_at FROM {{tables.agents}} WHERE agent_id = $1",
        uuid.UUID(env["agent_id"]),
    )
    assert row["deleted_at"] is not None


@pytest.mark.asyncio
async def test_soft_delete_idempotent(aweb_db_infra):
    """Calling soft_delete_agent twice doesn't raise."""
    aweb_db_infra: DatabaseInfra
    aweb_db = aweb_db_infra.get_manager("aweb")
    env = await _setup_agent(aweb_db)

    await soft_delete_agent(
        aweb_db_infra,
        agent_id=env["agent_id"],
        project_id=env["project_id"],
    )
    # Second call should not raise
    await soft_delete_agent(
        aweb_db_infra,
        agent_id=env["agent_id"],
        project_id=env["project_id"],
    )


@pytest.mark.asyncio
async def test_soft_delete_deactivates_api_keys(aweb_db_infra):
    """soft_delete_agent deactivates the agent's API keys."""
    aweb_db_infra: DatabaseInfra
    aweb_db = aweb_db_infra.get_manager("aweb")
    env = await _setup_agent(aweb_db)

    await soft_delete_agent(
        aweb_db_infra,
        agent_id=env["agent_id"],
        project_id=env["project_id"],
    )

    key_row = await aweb_db.fetch_one(
        "SELECT is_active FROM {{tables.api_keys}} WHERE agent_id = $1",
        uuid.UUID(env["agent_id"]),
    )
    assert key_row is not None
    assert key_row["is_active"] is False


@pytest.mark.asyncio
async def test_soft_delete_wrong_project_is_noop(aweb_db_infra):
    """soft_delete_agent with wrong project_id leaves agent untouched."""
    aweb_db_infra: DatabaseInfra
    aweb_db = aweb_db_infra.get_manager("aweb")
    env = await _setup_agent(aweb_db)

    # Use a random project_id that doesn't match
    await soft_delete_agent(
        aweb_db_infra,
        agent_id=env["agent_id"],
        project_id=str(uuid.uuid4()),
    )

    row = await aweb_db.fetch_one(
        "SELECT deleted_at, status FROM {{tables.agents}} WHERE agent_id = $1",
        uuid.UUID(env["agent_id"]),
    )
    assert row["deleted_at"] is None
    assert row["status"] != "deregistered"
