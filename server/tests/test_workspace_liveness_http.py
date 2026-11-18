"""Live-workspace deletion protection through real aweb, AWID, PostgreSQL and Redis."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
from uuid import UUID

import pytest

from aweb.lifecycle import (
    LifecycleActor,
    LifecycleCascadeRequest,
    apply_lifecycle_cascade,
)
from aweb.mcp.server import create_mcp_app
from aweb.presence import clear_workspace_presence
from test_dashboard_privacy import TEAM, privacy_app  # noqa: F401
from test_identity_grants import _grant_headers, _session_keypair
from test_messages_http import _signed_team_headers


async def _request(env, alias, method, path, body=None):
    actor = env.actors[alias]
    content = json.dumps(body).encode() if body is not None else b""
    headers = _signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate, content)
    return await env.client.request(
        method,
        path,
        content=content,
        headers={**headers, "Content-Type": "application/json"},
    )


async def _mcp_heartbeat(env):
    origin = str(env.client.base_url).rstrip("/")
    mcp = create_mcp_app(
        db_infra=env.infra,
        redis=env.redis,
        registry_client=env.app.state.awid_registry_client,
        public_origin=origin,
    )
    env.app.mount("/liveness-mcp", mcp)
    await mcp.startup()
    try:
        actor = env.actors["alice"]
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "heartbeat", "arguments": {}},
            }
        ).encode()
        headers = _signed_team_headers(actor.sk, actor.did, TEAM, actor.certificate, body)
        response = await env.client.post(
            "/liveness-mcp/",
            content=body,
            headers={
                **headers,
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
        )
        assert response.status_code == 200, response.text
        result = response.json()["result"]
        assert not result.get("isError"), result
        assert "error" not in json.loads(result["content"][0]["text"]), result
    finally:
        await mcp.shutdown()


async def _grant_heartbeat(env, path):
    session_key, session_did = _session_keypair()
    minted = await _request(
        env,
        "alice",
        "POST",
        "/v1/identity-grants",
        {
            "grant_did_key": session_did,
            "scopes": ["presence.write"],
            "ttl_seconds": 600,
        },
    )
    assert minted.status_code == 200, minted.text
    grant = minted.json()
    payload = {"workspace_id": str(env.actors["alice"].workspace), "alias": "alice"}
    body = json.dumps(payload).encode() if path == "/v1/workspaces/heartbeat" else b""
    headers = _grant_headers(
        signing_key=session_key,
        did_key=session_did,
        grant_id=grant["grant_id"],
        method="POST",
        path=path,
        body=body,
        aud=str(env.client.base_url).rstrip("/"),
    )
    response = await env.client.post(path, content=body, headers=headers)
    assert response.status_code == 200, response.text
    return UUID(grant["grant_id"])


async def _stale_workspace(env):
    await env.db.execute(
        "UPDATE {{tables.workspaces}} SET last_seen_at = NOW() - INTERVAL '2 hours' "
        "WHERE workspace_id = $1",
        env.actors["alice"].workspace,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("activity", ["connect", "mcp", "grant_agent", "grant_workspace"])
async def test_live_activity_protects_workspace_from_teammate_delete(privacy_app, activity):
    env = privacy_app
    actor = env.actors["alice"]
    if activity == "connect":
        # First connect, not the reconnect UPDATE that already records last_seen.
        await env.db.execute(
            "DELETE FROM {{tables.workspaces}} WHERE workspace_id=$1", actor.workspace
        )
        connected = await _request(
            env,
            "alice",
            "POST",
            "/v1/connect",
            {
                "hostname": "liveness-test",
                "workspace_path": "/tmp/liveness-test",
                "repo_origin": "",
            },
        )
        assert connected.status_code == 200, connected.text
        actor.workspace = UUID(connected.json()["workspace_id"])
    else:
        await _stale_workspace(env)
        if activity == "mcp":
            await _mcp_heartbeat(env)
        else:
            path = (
                "/v1/agents/heartbeat" if activity == "grant_agent" else "/v1/workspaces/heartbeat"
            )
            await _grant_heartbeat(env, path)
            # A grant heartbeat must not rewrite shared root presence.
            assert not await env.redis.exists(f"presence:{actor.workspace}")
            seen = await env.db.fetch_value(
                "SELECT last_seen_at FROM {{tables.workspaces}} WHERE workspace_id=$1",
                actor.workspace,
            )
            assert seen < datetime.now(timezone.utc) - timedelta(hours=1)

    try:
        request = LifecycleCascadeRequest(
            operation="delete_local_workspace",
            actor=LifecycleActor(str(env.actors["bob"].id), "agent", "team_identity"),
            team_id=TEAM,
            target_agent_id=str(actor.id),
            target_workspace_ids=(str(actor.workspace),),
            require_identity_scope="local",
            mark_local_agent_deleted=True,
            stale_before=datetime.now(timezone.utc) - timedelta(minutes=30),
        )
        # Both planner and mutator must enforce the rule, even if a host calls
        # the public owner without the HTTP route's pre-check.
        planned = await apply_lifecycle_cascade(env.db, env.redis, replace(request, dry_run=True))
        assert [error.code for error in planned.errors] == ["local_workspace_still_active"]
        applied = await apply_lifecycle_cascade(env.db, env.redis, request)
        assert [error.code for error in applied.errors] == ["local_workspace_still_active"]
        response = await _request(env, "bob", "DELETE", f"/v1/workspaces/{actor.workspace}")
        assert response.status_code == 409, response.text
        assert response.json()["detail"]["code"] == "local_workspace_still_active"
        assert await env.db.fetch_value(
            "SELECT deleted_at IS NULL FROM {{tables.agents}} WHERE agent_id=$1",
            actor.id,
        )
        roster = await _request(env, "bob", "GET", "/v1/agents")
        assert roster.status_code == 200, roster.text
        assert next(a for a in roster.json()["agents"] if a["alias"] == "alice")["online"]
    finally:
        await clear_workspace_presence(env.redis, [str(actor.workspace)])


@pytest.mark.asyncio
@pytest.mark.parametrize("grant_state", ["revoked", "expired", "stale"])
async def test_invalid_grant_liveness_does_not_prevent_stale_workspace_cleanup(
    privacy_app, grant_state
):
    env = privacy_app
    actor = env.actors["alice"]
    await _stale_workspace(env)
    grant_id = await _grant_heartbeat(env, "/v1/agents/heartbeat")
    if grant_state == "revoked":
        response = await _request(env, "alice", "POST", f"/v1/identity-grants/{grant_id}/revoke")
        assert response.status_code == 200, response.text
    elif grant_state == "expired":
        await env.db.execute(
            "UPDATE {{tables.identity_session_grants}} SET expires_at=NOW()-INTERVAL '1 second' WHERE grant_id=$1",
            grant_id,
        )
    else:
        await env.db.execute(
            "UPDATE {{tables.identity_grant_liveness}} SET last_seen_at=NOW()-INTERVAL '2 hours' WHERE grant_id=$1",
            grant_id,
        )
    response = await _request(env, "bob", "DELETE", f"/v1/workspaces/{actor.workspace}")
    assert response.status_code == 200, response.text
    assert response.json()["identity_deleted"] is True


@pytest.mark.asyncio
async def test_live_owner_can_still_delete_own_workspace(privacy_app):
    env = privacy_app
    actor = env.actors["alice"]
    await _mcp_heartbeat(env)
    response = await _request(env, "alice", "DELETE", f"/v1/workspaces/{actor.workspace}")
    assert response.status_code == 200, response.text
    assert response.json()["identity_deleted"] is True
