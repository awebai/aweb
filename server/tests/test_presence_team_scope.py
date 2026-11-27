"""Team presence through real certificate/proxy HTTP, MCP, DB and Redis."""

import json
from uuid import uuid4

import pytest

from aweb.internal_auth import (
    ProxyHeaderTrust,
    ProxyVerificationConfig,
    build_internal_auth_header_value,
)
from test_coordination_state_http import call_mcp, request_as
from test_coordination_state_http import coordination_mcp
from test_dashboard_privacy import TEAM
from test_dashboard_privacy import privacy_app
from test_workspace_liveness_http import (
    _connect_registered_member,
    _send_member_request,
)

__all__ = ["coordination_mcp", "privacy_app"]

PROXY_SECRET = "r15-disposable-proxy-test-secret"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("privacy_app", "transport"),
    [
        pytest.param(
            ProxyVerificationConfig(trust=ProxyHeaderTrust.DISABLED),
            "certificate",
            id="certificate",
        ),
        pytest.param(
            ProxyVerificationConfig(
                trust=ProxyHeaderTrust.SHARED_SECRET, shared_secret=PROXY_SECRET
            ),
            "proxy",
            id="proxy",
        ),
    ],
    indirect=["privacy_app"],
)
async def test_mcp_heartbeat_and_agent_list_use_the_workspace_and_team(
    coordination_mcp, transport
):
    env = coordination_mcp
    alice = env.actors["alice"]
    if transport == "certificate":
        result = await call_mcp(env, name="heartbeat")
    else:
        user_id = str(uuid4())
        response = await env.client.post(
            "/coordination-mcp/",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "heartbeat", "arguments": {}},
            },
            headers={
                "X-Team-ID": TEAM,
                "X-User-ID": user_id,
                "X-AWEB-Actor-ID": str(alice.id),
                "X-AWEB-Auth": build_internal_auth_header_value(
                    secret=PROXY_SECRET,
                    team_id=TEAM,
                    principal_type="u",
                    principal_id=user_id,
                    actor_id=str(alice.id),
                ),
                "Accept": "application/json, text/event-stream",
            },
        )
        assert response.status_code == 200, response.text
        payload = response.json()["result"]
        assert not payload.get("isError"), payload
        result = json.loads(payload["content"][0]["text"])
    assert result["agent_id"] == str(alice.id)
    presence = await env.redis.hgetall(f"presence:{alice.workspace}")
    assert presence["team_id"] == TEAM
    assert presence["alias"] == "alice"
    assert presence["workspace_id"] == str(alice.workspace)
    agents = await call_mcp(env, name="list_agents")
    assert (
        next(agent for agent in agents["agents"] if agent["alias"] == "alice")["online"]
        is True
    )


@pytest.mark.asyncio
async def test_route_heartbeat_and_online_list_keep_the_team_boundary(privacy_app):
    env = privacy_app
    for alias in ("bob", "carol"):
        seeded = await request_as(
            env, alias=alias, method="POST", path="/v1/agents/heartbeat"
        )
        assert seeded.status_code == 200, seeded.text
    response = await request_as(
        env, alias="alice", method="POST", path="/v1/agents/heartbeat"
    )
    assert response.status_code == 200, response.text
    presence = await env.redis.hgetall(f"presence:{env.actors['alice'].workspace}")
    assert presence["team_id"] == TEAM
    assert presence["alias"] == "alice"
    # An unrelated team's real row and presence must not join this team's view.
    foreign_team = "foreign:example.test"
    expected_aliases = set(env.actors)
    await env.app.state.awid_registry_client.register_team(
        domain="example.test",
        name="foreign",
        display_name="Foreign",
        team_did_key=env.team_did,
        visibility="public",
        namespace_controller_signing_key=env.namespace_sk,
    )
    await _connect_registered_member(env, alias="outsider", team_id=foreign_team)
    foreign_heartbeat = await _send_member_request(
        env,
        alias="outsider",
        method="POST",
        path="/v1/agents/heartbeat",
        team_id=foreign_team,
    )
    assert foreign_heartbeat.status_code == 200, foreign_heartbeat.text
    online = await request_as(
        env, alias="alice", method="GET", path="/v1/workspaces/online"
    )
    assert online.status_code == 200, online.text
    assert {row["alias"] for row in online.json()["workspaces"]} == expected_aliases
    assert {row["team_id"] for row in online.json()["workspaces"]} == {TEAM}
