from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from aweb.coordination.routes import workspaces as workspace_routes
from aweb.mcp.tools import agents as mcp_agents
from aweb.routes import agents as agent_routes


class _FakeAwebDB:
    def __init__(self, alias: str = "ivy"):
        self.alias = alias

    async def fetch_one(self, _query: str, *_args):
        return {"alias": self.alias}

    async def execute(self, _query: str, *_args):
        return None


class _FakeDbInfra:
    def __init__(self, alias: str = "ivy"):
        self._db = _FakeAwebDB(alias=alias)

    def get_manager(self, _name: str = "aweb"):
        return self._db


@pytest.mark.asyncio
async def test_mcp_heartbeat_passes_team_address(monkeypatch):
    seen: dict[str, str] = {}

    monkeypatch.setattr(
        mcp_agents,
        "get_auth",
        lambda: SimpleNamespace(agent_id="agent-1", team_address="acme.com/default"),
    )

    async def _capture_presence(_redis, **kwargs):
        seen.update(kwargs)
        return "2026-04-07T00:00:00Z"

    monkeypatch.setattr(mcp_agents, "update_agent_presence", _capture_presence)

    payload = json.loads(await mcp_agents.heartbeat(db_infra=_FakeDbInfra(), redis=object()))

    assert payload["agent_id"] == "agent-1"
    assert seen["team_address"] == "acme.com/default"
    assert seen["alias"] == "ivy"


@pytest.mark.asyncio
async def test_route_heartbeat_passes_team_address(monkeypatch):
    seen: dict[str, str] = {}

    async def _capture_presence(_redis, **kwargs):
        seen.update(kwargs)
        return "2026-04-07T00:00:00Z"

    monkeypatch.setattr(agent_routes, "update_agent_presence", _capture_presence)

    identity = SimpleNamespace(
        team_address="acme.com/default",
        agent_id="agent-1",
        alias="ivy",
    )

    response = await agent_routes.heartbeat(
        request=None,
        db=_FakeDbInfra(),
        redis=object(),
        identity=identity,
    )

    assert response.agent_id == "agent-1"
    assert seen["team_address"] == "acme.com/default"
    assert seen["alias"] == "ivy"


@pytest.mark.asyncio
async def test_list_online_workspaces_filters_by_team_address(monkeypatch):
    async def _identity(_request, _db_infra):
        return SimpleNamespace(team_address="acme.com/default")

    async def _presences(_redis):
        return [
            {
                "workspace_id": "ws-1",
                "alias": "ivy",
                "team_address": "acme.com/default",
                "last_seen": "2026-04-07T00:00:00Z",
            },
            {
                "workspace_id": "ws-2",
                "alias": "other",
                "team_address": "other.com/default",
                "last_seen": "2026-04-07T00:00:01Z",
            },
        ]

    monkeypatch.setattr(workspace_routes, "get_team_identity", _identity)
    monkeypatch.setattr(workspace_routes, "list_agent_presences", _presences)

    response = await workspace_routes.list_online_workspaces(
        request=None,
        human_name=None,
        redis=object(),
        db_infra=object(),
    )

    assert [workspace.alias for workspace in response.workspaces] == ["ivy"]
    assert response.workspaces[0].team_address == "acme.com/default"
