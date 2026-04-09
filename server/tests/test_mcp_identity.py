import json
from uuid import uuid4

import pytest

from aweb.mcp.auth import AuthContext
from aweb.mcp.tools import identity as identity_tools


class DBInfra:
    def __init__(self, aweb_db):
        self._aweb_db = aweb_db

    def get_manager(self, name: str):
        if name != "aweb":
            raise KeyError(name)
        return self._aweb_db


@pytest.mark.asyncio
async def test_whoami_requires_auth_context(aweb_cloud_db):
    with pytest.raises(RuntimeError, match="No MCP auth context"):
        await identity_tools.whoami(DBInfra(aweb_cloud_db.aweb_db))


@pytest.mark.asyncio
async def test_whoami_returns_agent_identity_with_stable_fields(aweb_cloud_db, monkeypatch):
    team_address = "acme.com/backend-stable"
    did_key = "did:key:z6MkStable"
    agent_id = uuid4()

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_address, namespace, team_name, team_did_key)
        VALUES ($1, $2, $3, $4)
        """,
        team_address,
        "acme.com",
        "backend-stable",
        "did:key:z6MkTeam",
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_address, did_key, did_aw, address, alias, lifetime, status)
        VALUES ($1, $2, $3, $4, $5, $6, 'persistent', 'active')
        """,
        agent_id,
        team_address,
        did_key,
        "did:aw:alice",
        "acme.com/alice",
        "alice",
    )

    monkeypatch.setattr(
        identity_tools,
        "get_auth",
        lambda: AuthContext(
            team_address=team_address,
            agent_id=str(agent_id),
            alias="alice",
            did_key=did_key,
        ),
    )

    data = json.loads(await identity_tools.whoami(DBInfra(aweb_cloud_db.aweb_db)))

    assert data == {
        "team_address": team_address,
        "agent_id": str(agent_id),
        "alias": "alice",
        "did_key": did_key,
        "did_aw": "did:aw:alice",
        "address": "acme.com/alice",
    }


@pytest.mark.asyncio
async def test_whoami_returns_empty_stable_fields_for_ephemeral_agent(aweb_cloud_db, monkeypatch):
    team_address = "acme.com/backend-ephemeral"
    did_key = "did:key:z6MkEphemeral"
    agent_id = uuid4()

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_address, namespace, team_name, team_did_key)
        VALUES ($1, $2, $3, $4)
        """,
        team_address,
        "acme.com",
        "backend-ephemeral",
        "did:key:z6MkTeam",
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}}
            (agent_id, team_address, did_key, alias, lifetime, status)
        VALUES ($1, $2, $3, $4, 'ephemeral', 'active')
        """,
        agent_id,
        team_address,
        did_key,
        "eve",
    )

    monkeypatch.setattr(
        identity_tools,
        "get_auth",
        lambda: AuthContext(
            team_address=team_address,
            agent_id=str(agent_id),
            alias="eve",
            did_key=did_key,
        ),
    )

    data = json.loads(await identity_tools.whoami(DBInfra(aweb_cloud_db.aweb_db)))

    assert data == {
        "team_address": team_address,
        "agent_id": str(agent_id),
        "alias": "eve",
        "did_key": did_key,
        "did_aw": "",
        "address": "",
    }
