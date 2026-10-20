"""Real aweb/AWID/PostgreSQL/Redis heartbeat and roster integration."""

import pytest

from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401
from test_messages_http import _signed_team_headers


@pytest.mark.asyncio
async def test_heartbeat_makes_distinct_workspace_active_in_rosters(privacy_app):
    env = privacy_app
    actor = env.actors["alice"]
    assert actor.id != actor.workspace

    def headers():
        return _signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate)

    heartbeat = await env.client.post("/v1/agents/heartbeat", headers=headers())
    assert heartbeat.status_code == 200, heartbeat.text
    roster = await env.client.get("/v1/workspaces?include_presence=true", headers=headers())
    assert roster.status_code == 200, roster.text
    listed = await env.client.get("/v1/agents", headers=headers())
    assert listed.status_code == 200, listed.text

    assert await env.redis.exists(f"presence:{actor.workspace}")
    assert not await env.redis.exists(f"presence:{actor.id}")
    workspace = next(w for w in roster.json()["workspaces"] if w["workspace_id"] == str(actor.workspace))
    assert workspace["agent_id"] == str(actor.id)
    assert (workspace["alias"], workspace["status"]) == ("alice", "active")
    agent = next(a for a in listed.json()["agents"] if a["alias"] == "alice")
    assert (agent["status"], agent["online"]) == ("active", True)
