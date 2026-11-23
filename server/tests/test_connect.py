"""Tests for POST /v1/connect — agent auto-provisioning via team certificate."""

from __future__ import annotations

import uuid

import pytest

from nacl.signing import SigningKey

from awid.did import did_from_public_key


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_keypair():
    sk = SigningKey.generate()
    pk = bytes(sk.verify_key)
    did_key = did_from_public_key(pk)
    return bytes(sk), pk, did_key


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestConnect:
    @pytest.mark.asyncio
    async def test_auto_provisions_team_and_agent(self, aweb_cloud_db):
        from aweb.routes.connect import connect_agent

        db = aweb_cloud_db.aweb_db

        team_sk, _, team_did_key = _make_keypair()
        agent_sk, _, agent_did_key = _make_keypair()

        cert_info = {
            "team_id": "backend:acme.com",
            "alias": "alice",
            "did_key": agent_did_key,
            "identity_scope": "global",
            "certificate_id": "cert-001",
        }

        result = await connect_agent(
            db=db,
            cert_info=cert_info,
            team_did_key=team_did_key,
            hostname="Mac.local",
            workspace_path="/Users/alice/project",
            repo_origin="https://github.com/acme/backend.git",
            role="developer",
            human_name="Alice",
            agent_type="agent",
        )

        assert result["team_id"] == "backend:acme.com"
        assert result["alias"] == "alice"
        assert result["role"] == "developer"
        assert result["agent_id"] is not None
        assert result["workspace_id"] is not None

        # Verify team row was created
        team = await db.fetch_one(
            "SELECT * FROM {{tables.teams}} WHERE team_id = $1",
            "backend:acme.com",
        )
        assert team is not None
        assert team["team_did_key"] == team_did_key
        assert team["namespace"] == "acme.com"
        assert team["team_name"] == "backend"

        # Verify agent row was created
        agent = await db.fetch_one(
            "SELECT * FROM {{tables.agents}} WHERE agent_id = $1",
            uuid.UUID(result["agent_id"]),
        )
        assert agent is not None
        assert agent["alias"] == "alice"
        assert agent["did_key"] == agent_did_key
        assert agent["identity_scope"] == "global"

    @pytest.mark.asyncio
    async def test_idempotent_reconnect(self, aweb_cloud_db):
        from aweb.routes.connect import connect_agent

        db = aweb_cloud_db.aweb_db

        team_sk, _, team_did_key = _make_keypair()
        _, _, agent_did_key = _make_keypair()

        cert_info = {
            "team_id": "backend:acme.com",
            "alias": "alice",
            "did_key": agent_did_key,
            "identity_scope": "global",
            "certificate_id": "cert-001",
        }

        kwargs = dict(
            db=db,
            cert_info=cert_info,
            team_did_key=team_did_key,
            hostname="Mac.local",
            workspace_path="/Users/alice/project",
            repo_origin="",
            role="developer",
            human_name="",
            agent_type="agent",
        )

        result1 = await connect_agent(**kwargs)
        result2 = await connect_agent(**kwargs)

        assert result1["agent_id"] == result2["agent_id"]
        assert result1["team_id"] == result2["team_id"]
        assert result1["workspace_id"] == result2["workspace_id"]

    @pytest.mark.asyncio
    async def test_team_id_parsed_correctly(self, aweb_cloud_db):
        from aweb.routes.connect import connect_agent

        db = aweb_cloud_db.aweb_db

        team_sk, _, team_did_key = _make_keypair()
        _, _, agent_did_key = _make_keypair()

        cert_info = {
            "team_id": "frontend:example.org",
            "alias": "bob",
            "did_key": agent_did_key,
            "identity_scope": "local",
            "certificate_id": "cert-002",
        }

        await connect_agent(
            db=db,
            cert_info=cert_info,
            team_did_key=team_did_key,
            hostname="",
            workspace_path="",
            repo_origin="",
            role="",
            human_name="",
            agent_type="agent",
        )

        team = await db.fetch_one(
            "SELECT * FROM {{tables.teams}} WHERE team_id = $1",
            "frontend:example.org",
        )
        assert team["namespace"] == "example.org"
        assert team["team_name"] == "frontend"

    @pytest.mark.asyncio
    async def test_ephemeral_cert_leaves_did_aw_and_address_null(self, aweb_cloud_db):
        from aweb.routes.connect import connect_agent

        db = aweb_cloud_db.aweb_db

        _, _, team_did_key = _make_keypair()
        _, _, agent_did_key = _make_keypair()

        cert_info = {
            "team_id": "backend:acme.com",
            "alias": "alice",
            "did_key": agent_did_key,
            "identity_scope": "local",
            "certificate_id": "cert-ephemeral-001",
            "member_did_aw": "",
            "member_address": "",
        }

        result = await connect_agent(
            db=db,
            cert_info=cert_info,
            team_did_key=team_did_key,
            hostname="",
            workspace_path="",
            repo_origin="",
            role="",
            human_name="",
            agent_type="agent",
        )

        agent = await db.fetch_one(
            "SELECT did_aw, address FROM {{tables.agents}} WHERE agent_id = $1",
            uuid.UUID(result["agent_id"]),
        )
        assert agent["did_aw"] is None
        assert agent["address"] is None

    @pytest.mark.asyncio
    async def test_workspace_created_with_repo(self, aweb_cloud_db):
        from aweb.routes.connect import connect_agent

        db = aweb_cloud_db.aweb_db

        _, _, team_did_key = _make_keypair()
        _, _, agent_did_key = _make_keypair()

        cert_info = {
            "team_id": "backend:acme.com",
            "alias": "alice",
            "did_key": agent_did_key,
            "identity_scope": "global",
            "certificate_id": "cert-001",
        }

        result = await connect_agent(
            db=db,
            cert_info=cert_info,
            team_did_key=team_did_key,
            hostname="Mac.local",
            workspace_path="/Users/alice/project",
            repo_origin="https://github.com/acme/backend.git",
            role="developer",
            human_name="Alice",
            agent_type="agent",
        )

        workspace = await db.fetch_one(
            "SELECT * FROM {{tables.workspaces}} WHERE workspace_id = $1",
            uuid.UUID(result["workspace_id"]),
        )
        assert workspace is not None
        assert workspace["hostname"] == "Mac.local"
        assert workspace["workspace_path"] == "/Users/alice/project"
        assert workspace["alias"] == "alice"


@pytest.mark.asyncio
async def test_planned_connect_uses_exact_ids_and_rejects_changed_replay_atomically(aweb_cloud_db):
    """Retained creation IDs constrain allocation and never replace existing rows."""
    from aweb.routes.connect import PlannedIdentityConflict, PlannedIdentityIds, connect_agent

    db = aweb_cloud_db.aweb_db
    _, _, team_key = _make_keypair()
    _, _, member_key = _make_keypair()
    planned = PlannedIdentityIds(agent_id=uuid.uuid4(), workspace_id=uuid.uuid4())
    arguments = dict(
        db=db, cert_info={"team_id": "planned:example.com", "did_key": member_key,
                          "alias": "planned", "identity_scope": "local"},
        team_did_key=team_key, hostname="original", workspace_path="", repo_origin="",
        role="", human_name="", agent_type="agent",
    )
    result = await connect_agent(**arguments, planned_ids=planned)
    assert result["agent_id"] == str(planned.agent_id)
    assert result["workspace_id"] == str(planned.workspace_id)
    assert await connect_agent(**arguments, planned_ids=planned) == result
    assert await connect_agent(**arguments) == result
    before_agents = await db.fetch_all("SELECT * FROM {{tables.agents}} ORDER BY agent_id")
    before_workspaces = await db.fetch_all("SELECT * FROM {{tables.workspaces}} ORDER BY workspace_id")
    for changed in (
        PlannedIdentityIds(agent_id=uuid.uuid4(), workspace_id=planned.workspace_id),
        PlannedIdentityIds(agent_id=planned.agent_id, workspace_id=uuid.uuid4()),
    ):
        with pytest.raises(PlannedIdentityConflict) as refused:
            await connect_agent(**{**arguments, "hostname": "must roll back", "human_name": "must roll back"},
                                planned_ids=changed)
        assert refused.value.status_code == 409
        assert refused.value.detail == {
            "code": "planned_identity_conflict",
            "message": "Reload the retained creation request and use its exact agent and workspace IDs.",
        }
        assert await db.fetch_all("SELECT * FROM {{tables.agents}} ORDER BY agent_id") == before_agents
        assert await db.fetch_all("SELECT * FROM {{tables.workspaces}} ORDER BY workspace_id") == before_workspaces


@pytest.mark.asyncio
@pytest.mark.parametrize("collision", ["agent", "workspace"])
async def test_planned_connect_refuses_cross_identity_uuid_collision(aweb_cloud_db, collision):
    """A retained UUID cannot take another member's resources, even in another team."""
    from aweb.routes.connect import PlannedIdentityConflict, PlannedIdentityIds, connect_agent

    db = aweb_cloud_db.aweb_db
    _, _, team_key = _make_keypair()
    _, _, first_key = _make_keypair()
    _, _, second_key = _make_keypair()
    arguments = dict(db=db, team_did_key=team_key, hostname="", workspace_path="", repo_origin="",
                     role="", human_name="", agent_type="agent")
    first = await connect_agent(**arguments, cert_info={"team_id": "first:example.com", "alias": "first", "did_key": first_key})
    planned = PlannedIdentityIds(
        agent_id=uuid.UUID(first["agent_id"]) if collision == "agent" else uuid.uuid4(),
        workspace_id=uuid.UUID(first["workspace_id"]) if collision == "workspace" else uuid.uuid4(),
    )
    before_agents = await db.fetch_all("SELECT * FROM {{tables.agents}} ORDER BY agent_id")
    before_workspaces = await db.fetch_all("SELECT * FROM {{tables.workspaces}} ORDER BY workspace_id")
    with pytest.raises(PlannedIdentityConflict):
        await connect_agent(**arguments, planned_ids=planned,
                            cert_info={"team_id": "second:example.com", "alias": "second", "did_key": second_key})
    assert await db.fetch_all("SELECT * FROM {{tables.agents}} ORDER BY agent_id") == before_agents
    assert await db.fetch_all("SELECT * FROM {{tables.workspaces}} ORDER BY workspace_id") == before_workspaces
    assert not await db.fetch_value("SELECT EXISTS(SELECT 1 FROM {{tables.teams}} WHERE team_id='second:example.com')")
