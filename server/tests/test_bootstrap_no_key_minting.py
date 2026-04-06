"""Verify bootstrap_identity and bootstrap_scope_agent with mint_api_key=False."""
from __future__ import annotations

import pytest; pytest.skip("Tests reference removed schema (projects/api_keys/bootstrap) — to be deleted in aaez.5", allow_module_level=True)

import uuid

import pytest

from aweb.bootstrap import bootstrap_identity
from aweb.scope_agents import bootstrap_scope_agent


class _DbInfra:
    is_initialized = True

    def __init__(self, aweb_db, server_db):
        self._aweb_db = aweb_db
        self._server_db = server_db

    def get_manager(self, name: str = "aweb"):
        if name == "aweb":
            return self._aweb_db
        if name == "server":
            return self._server_db
        raise KeyError(name)


@pytest.mark.asyncio
async def test_bootstrap_identity_without_key_minting(aweb_cloud_db):
    """bootstrap_identity(mint_api_key=False) must not create api_keys rows."""
    db_infra = _DbInfra(aweb_cloud_db.aweb_db, aweb_cloud_db.oss_db)
    aweb_db = aweb_cloud_db.aweb_db
    slug = f"nokey-{uuid.uuid4().hex[:8]}"

    result = await bootstrap_identity(
        db_infra,
        project_slug=slug,
        alias="cowork-test",
        human_name="Test User",
        agent_type="human",
        lifetime="persistent",
        mint_api_key=False,
    )

    assert result.agent_id
    assert result.alias == "cowork-test"
    assert result.api_key is None

    # The invariant: zero api_keys rows for this agent
    key_count = await aweb_db.fetch_value(
        """
        SELECT COUNT(*)
        FROM {{tables.api_keys}}
        WHERE agent_id = $1
        """,
        uuid.UUID(result.agent_id),
    )
    assert key_count == 0


@pytest.mark.asyncio
async def test_bootstrap_identity_without_key_minting_is_idempotent(aweb_cloud_db):
    """Repeated calls with mint_api_key=False must not accumulate api_keys rows."""
    db_infra = _DbInfra(aweb_cloud_db.aweb_db, aweb_cloud_db.oss_db)
    aweb_db = aweb_cloud_db.aweb_db
    slug = f"nokey-idem-{uuid.uuid4().hex[:8]}"

    # Call three times — simulates repeated auth-bridge ensure calls
    for _ in range(3):
        result = await bootstrap_identity(
            db_infra,
            project_slug=slug,
            alias="cowork-idem",
            human_name="Test User",
            agent_type="human",
            lifetime="persistent",
            mint_api_key=False,
        )

    assert result.agent_id
    assert result.api_key is None

    key_count = await aweb_db.fetch_value(
        """
        SELECT COUNT(*)
        FROM {{tables.api_keys}}
        WHERE agent_id = $1
        """,
        uuid.UUID(result.agent_id),
    )
    assert key_count == 0


@pytest.mark.asyncio
async def test_bootstrap_scope_agent_without_key_minting(aweb_cloud_db):
    """bootstrap_scope_agent(mint_api_key=False) threads through correctly."""
    aweb_db = aweb_cloud_db.aweb_db
    slug = f"scope-nokey-{uuid.uuid4().hex[:8]}"

    # Create a project first
    project = await aweb_db.fetch_one(
        """
        INSERT INTO {{tables.projects}} (slug, name)
        VALUES ($1, $2)
        RETURNING project_id
        """,
        slug,
        slug,
    )
    project_id = str(project["project_id"])

    result = await bootstrap_scope_agent(
        aweb_db=aweb_db,
        scope_id=project_id,
        payload={
            "alias": "cowork-scope",
            "human_name": "Test User",
            "agent_type": "human",
            "lifetime": "persistent",
        },
        mint_api_key=False,
    )

    assert result["agent_id"]
    assert "api_key" not in result or result.get("api_key") is None

    key_count = await aweb_db.fetch_value(
        """
        SELECT COUNT(*)
        FROM {{tables.api_keys}}
        WHERE agent_id = $1
        """,
        uuid.UUID(result["agent_id"]),
    )
    assert key_count == 0
