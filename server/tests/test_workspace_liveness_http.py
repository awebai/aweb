"""Live-workspace deletion protection through real aweb, AWID, PostgreSQL and Redis."""

import asyncio
import json
import socket
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from awid.registry import RegistryClient
from awid.team_ids import parse_team_id
from fastapi import HTTPException
from aweb.config import get_presence_ttl_seconds
from aweb.coordination.routes import workspaces as workspace_routes
from aweb.lifecycle import (
    AgentDisposition,
    LifecycleActor,
    LifecycleCascadeRequest,
    apply_lifecycle_cascade,
)
from aweb.mcp.server import create_mcp_app
from aweb.presence import clear_workspace_presence
from aweb.routes.connect import WorkspaceContact, connect_agent
from aweb.workspace_activity import workspace_stale_cutoff
from test_dashboard_privacy import TEAM
from test_dashboard_privacy import privacy_app
from test_identity_grants import _grant_headers, _session_keypair
from test_messages_http import (
    _encode_certificate,
    _make_certificate,
    _make_keypair,
    _signed_team_headers,
)

__all__ = ["privacy_app"]


class Activity(StrEnum):
    FIRST_CONNECT = "connect"
    MCP_HEARTBEAT = "mcp"
    GRANT_AGENT_HEARTBEAT = "grant_agent"
    GRANT_WORKSPACE_HEARTBEAT = "grant_workspace"


class GrantHeartbeatRoute(StrEnum):
    AGENT = "/v1/agents/heartbeat"
    WORKSPACE = "/v1/workspaces/heartbeat"


class InvalidGrantActivity(StrEnum):
    REVOKED = "revoked"
    EXPIRED = "expired"
    STALE = "stale"


async def _send_member_request(
    env, *, alias: str, method: str, path: str, body: dict | None = None,
    team_id: str = TEAM,
):
    actor = env.actors[alias]
    content = json.dumps(body).encode() if body is not None else b""
    headers = _signed_team_headers(actor.sk, actor.did, team_id, actor.certificate, content)
    return await env.client.request(
        method,
        path,
        content=content,
        headers={**headers, "Content-Type": "application/json"},
    )


async def _connect_registered_member(
    env, *, alias: str, team_id: str = TEAM, scope: str = "local", reserve: bool = False,
):
    registry = env.app.state.awid_registry_client
    namespace, team_name = parse_team_id(team_id)
    sk, _, did = _make_keypair()
    did_aw = (await registry.register_did(did, sk)).did_aw if scope == "global" else None
    certificate_id = f"workspace-test-{uuid4()}"
    certificate_fields = {} if did_aw is None else {"member_did_aw": did_aw}
    claims = _make_certificate(
        env.team_sk, env.team_did, did, team_id=team_id, alias=alias,
        identity_scope=scope, certificate_id=certificate_id, **certificate_fields,
    )
    certificate = _encode_certificate(claims)
    await registry.register_team_certificate(
        namespace, team_name,
        team_controller_signing_key=env.team_sk, certificate_id=certificate_id,
        member_did_key=did, member_did_aw=did_aw, member_address=None,
        alias=alias, identity_scope=scope, certificate=certificate,
    )
    profile = {
        "hostname": "workspace-test", "workspace_path": f"/tmp/workspace-test/{alias}",
        "repo_origin": "",
    }
    if reserve:
        connected = await connect_agent(
            db=env.db,
            cert_info={**claims, "did_key": did},
            team_did_key=env.team_did,
            contact=WorkspaceContact.NONE,
            role="", human_name="", agent_type="agent",
            **profile,
        )
    else:
        body = json.dumps(profile).encode()
        response = await env.client.post(
            "/v1/connect",
            content=body,
            headers={
                **_signed_team_headers(sk, did, team_id, certificate, body),
                "Content-Type": "application/json",
            },
        )
        assert response.status_code == 200, response.text
        connected = response.json()
    member = SimpleNamespace(
        alias=alias, sk=sk, did=did, certificate=certificate,
        id=UUID(connected["agent_id"]), workspace=UUID(connected["workspace_id"]),
    )
    env.actors[alias] = member
    return member


async def _send_mcp_heartbeat(env):
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


async def _send_grant_heartbeat(
    env, *, path: GrantHeartbeatRoute, ttl_seconds: int = 600
) -> UUID:
    session_key, session_did = _session_keypair()
    minted = await _send_member_request(
        env,
        alias="alice",
        method="POST",
        path="/v1/identity-grants",
        body={
            "grant_did_key": session_did,
            "scopes": ["presence.write"],
            "ttl_seconds": ttl_seconds,
        },
    )
    assert minted.status_code == 200, minted.text
    grant = minted.json()
    payload = {"workspace_id": str(env.actors["alice"].workspace), "alias": "alice"}
    body = json.dumps(payload).encode() if path == GrantHeartbeatRoute.WORKSPACE else b""
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


async def _root_last_seen(env):
    return await env.db.fetch_value(
        "SELECT last_seen_at FROM {{tables.workspaces}} WHERE workspace_id=$1",
        env.actors["alice"].workspace,
    )


def _set_workspace_route_time(monkeypatch, now):
    class WorkspaceRouteClock(datetime):
        @classmethod
        def now(cls, tz):
            return now.astimezone(tz)

    monkeypatch.setattr(workspace_routes, "datetime", WorkspaceRouteClock)


@pytest.mark.asyncio
async def test_reserved_workspace_ages_for_peer_cleanup_and_planning_without_appearing_online(
    privacy_app, monkeypatch,
):
    env = privacy_app
    monkeypatch.setenv("AWEB_PRESENCE_TTL_SECONDS", "1800")
    actor = await _connect_registered_member(env, alias="reserved-peer", reserve=True)
    row = await env.db.fetch_one(
        "SELECT created_at, last_seen_at FROM {{tables.workspaces}} WHERE workspace_id=$1",
        actor.workspace,
    )
    assert row["last_seen_at"] is None
    roster = await _send_member_request(env, alias="bob", method="GET", path="/v1/agents")
    assert roster.status_code == 200, roster.text
    visible = next(agent for agent in roster.json()["agents"] if agent["alias"] == actor.alias)
    assert visible["online"] is False and visible["last_seen"] is None

    workspace_path = f"/v1/workspaces/{actor.workspace}"
    fresh_cutoff = workspace_stale_cutoff(now=datetime.now(UTC))
    plan = LifecycleCascadeRequest(
        operation="delete_local_workspace",
        actor=LifecycleActor(
            actor_id=str(env.actors["bob"].id), actor_type="agent", authority="team_identity"
        ),
        team_id=TEAM,
        target_agent_id=str(actor.id),
        target_workspace_ids=(str(actor.workspace),),
        require_identity_scope="local",
        agent_disposition=AgentDisposition.DELETED,
        stale_before=fresh_cutoff,
        dry_run=True,
    )
    registry = env.app.state.awid_registry_client
    fresh = await _send_member_request(env, alias="bob", method="DELETE", path=workspace_path)
    assert fresh.status_code == 409, fresh.text
    assert fresh.json()["detail"]["code"] == "local_workspace_still_active"
    planned = await apply_lifecycle_cascade(env.db, env.redis, plan, registry_client=registry)
    assert [error.code for error in planned.errors] == ["local_workspace_still_active"]

    later = row["created_at"] + timedelta(minutes=30, seconds=1)
    _set_workspace_route_time(monkeypatch, later)
    planned = await apply_lifecycle_cascade(
        env.db, env.redis, replace(plan, stale_before=workspace_stale_cutoff(now=later)),
        registry_client=registry,
    )
    assert planned.dry_run and planned.errors == ()
    aged = await _send_member_request(env, alias="bob", method="DELETE", path=workspace_path)
    assert aged.status_code == 200, aged.text
    assert aged.json()["identity_deleted"] is True


@pytest.mark.asyncio
async def test_owner_can_delete_fresh_reserved_workspace(privacy_app):
    env = privacy_app
    actor = await _connect_registered_member(env, alias="reserved-self", reserve=True)
    assert await env.db.fetch_value(
        "SELECT last_seen_at FROM {{tables.workspaces}} WHERE workspace_id=$1", actor.workspace,
    ) is None
    response = await _send_member_request(
        env, alias=actor.alias, method="DELETE", path=f"/v1/workspaces/{actor.workspace}",
    )
    assert response.status_code == 200, response.text
    assert response.json()["identity_deleted"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize("activity", list(Activity))
async def test_live_activity_protects_workspace_from_teammate_delete(
    privacy_app, activity: Activity
):
    env = privacy_app
    alias = "alice"
    if activity == Activity.FIRST_CONNECT:
        alias = "first-connect"
        actor = await _connect_registered_member(env, alias=alias)
    else:
        actor = env.actors[alias]
        assert await _root_last_seen(env) is None
        if activity == Activity.MCP_HEARTBEAT:
            await _send_mcp_heartbeat(env)
        else:
            path = (
                GrantHeartbeatRoute.AGENT
                if activity == Activity.GRANT_AGENT_HEARTBEAT
                else GrantHeartbeatRoute.WORKSPACE
            )
            await _send_grant_heartbeat(env, path=path)
            # A grant heartbeat must not rewrite shared root presence.
            assert not await env.redis.exists(f"presence:{actor.workspace}")
            assert await _root_last_seen(env) is None

    try:
        request = LifecycleCascadeRequest(
            operation="delete_local_workspace",
            actor=LifecycleActor(
                actor_id=str(env.actors["bob"].id), actor_type="agent", authority="team_identity"
            ),
            team_id=TEAM,
            target_agent_id=str(actor.id),
            target_workspace_ids=(str(actor.workspace),),
            require_identity_scope="local",
            mark_local_agent_deleted=True,
            stale_before=datetime.now(UTC) - timedelta(minutes=30),
        )
        # Both planner and mutator must enforce the rule, even if a host calls
        # the public owner without the HTTP route's pre-check.
        planned = await apply_lifecycle_cascade(
            env.db,
            env.redis,
            replace(request, dry_run=True),
            registry_client=env.app.state.awid_registry_client,
        )
        assert [error.code for error in planned.errors] == ["local_workspace_still_active"]
        applied = await apply_lifecycle_cascade(
            env.db, env.redis, request, registry_client=env.app.state.awid_registry_client
        )
        assert [error.code for error in applied.errors] == ["local_workspace_still_active"]
        response = await _send_member_request(
            env, alias="bob", method="DELETE", path=f"/v1/workspaces/{actor.workspace}"
        )
        assert response.status_code == 409, response.text
        assert response.json()["detail"]["code"] == "local_workspace_still_active"
        assert await env.db.fetch_value(
            "SELECT deleted_at IS NULL FROM {{tables.agents}} WHERE agent_id=$1",
            actor.id,
        )
        roster = await _send_member_request(env, alias="bob", method="GET", path="/v1/agents")
        assert roster.status_code == 200, roster.text
        assert next(a for a in roster.json()["agents"] if a["alias"] == alias)["online"]
    finally:
        await clear_workspace_presence(env.redis, [str(actor.workspace)])


@pytest.mark.asyncio
@pytest.mark.parametrize("grant_state", list(InvalidGrantActivity))
async def test_invalid_grant_liveness_does_not_prevent_stale_workspace_cleanup(
    privacy_app, monkeypatch, grant_state: InvalidGrantActivity
):
    env = privacy_app
    actor = env.actors["alice"]
    assert await _root_last_seen(env) is None
    if grant_state == InvalidGrantActivity.STALE:
        monkeypatch.setenv("AWEB_PRESENCE_TTL_SECONDS", "10")
    grant_id = await _send_grant_heartbeat(
        env, path=GrantHeartbeatRoute.AGENT,
        ttl_seconds=60 if grant_state == InvalidGrantActivity.EXPIRED else 600,
    )
    created_at = await env.db.fetch_value(
        "SELECT created_at FROM {{tables.workspaces}} WHERE workspace_id=$1", actor.workspace,
    )
    last_seen = await env.db.fetch_value(
        "SELECT last_seen_at FROM {{tables.identity_grant_liveness}} WHERE grant_id=$1", grant_id,
    )
    # The cutoff puts the reservation behind the window but the grant
    # heartbeat ahead of it. Only invalid grant evidence permits cleanup.
    cutoff = created_at + (last_seen - created_at) / 2
    assert created_at < cutoff < last_seen
    if grant_state == InvalidGrantActivity.REVOKED:
        response = await _send_member_request(
            env, alias="alice", method="POST", path=f"/v1/identity-grants/{grant_id}/revoke"
        )
        assert response.status_code == 200, response.text
    elif grant_state == InvalidGrantActivity.EXPIRED:
        expired_at = await env.db.fetch_value(
            "SELECT expires_at FROM {{tables.identity_session_grants}} WHERE grant_id=$1",
            grant_id,
        )
    else:
        expired_at = last_seen + timedelta(seconds=10)
    if grant_state != InvalidGrantActivity.REVOKED:
        # The actual HTTP-minted grant or its configured activity window expires.
        await asyncio.sleep(max(0, (expired_at - datetime.now(UTC)).total_seconds()) + 0.05)
    _set_workspace_route_time(monkeypatch, cutoff + timedelta(seconds=get_presence_ttl_seconds()))
    response = await _send_member_request(
        env, alias="bob", method="DELETE", path=f"/v1/workspaces/{actor.workspace}"
    )
    assert response.status_code == 200, response.text
    assert response.json()["identity_deleted"] is True


@pytest.mark.asyncio
async def test_live_owner_can_still_delete_own_workspace(privacy_app):
    env = privacy_app
    actor = env.actors["alice"]
    await _send_mcp_heartbeat(env)
    response = await _send_member_request(
        env, alias="alice", method="DELETE", path=f"/v1/workspaces/{actor.workspace}"
    )
    assert response.status_code == 200, response.text
    assert response.json()["identity_deleted"] is True


@pytest.mark.asyncio
async def test_unknown_registry_liveness_cannot_authorize_stale_workspace_deletion(privacy_app):
    """A real registry connection failure is uncertainty, not proof of inactivity."""
    env = privacy_app
    actor = env.actors["alice"]
    assert await _root_last_seen(env) is None
    grant_id = await _send_grant_heartbeat(env, path=GrantHeartbeatRoute.AGENT)
    request = LifecycleCascadeRequest(
        operation="delete_local_workspace",
        actor=LifecycleActor(
            actor_id=str(env.actors["bob"].id), actor_type="agent", authority="team_identity"
        ),
        team_id=TEAM,
        target_agent_id=str(actor.id),
        target_workspace_ids=(str(actor.workspace),),
        require_identity_scope="local",
        stale_before=datetime.now(UTC) - timedelta(minutes=30),
        agent_disposition=AgentDisposition.DELETED,
    )
    available = await apply_lifecycle_cascade(
        env.db,
        env.redis,
        request,
        registry_client=env.app.state.awid_registry_client,
    )
    assert [error.code for error in available.errors] == ["local_workspace_still_active"]
    before = await env.db.fetch_value(
        "SELECT count(*) FROM {{tables.lifecycle_side_effect_outbox}} WHERE team_id=$1", TEAM
    )
    # Keep the port reserved but do not listen: the real SDK must observe refusal.
    with socket.socket() as unavailable_endpoint:
        unavailable_endpoint.bind(("127.0.0.1", 0))
        port = unavailable_endpoint.getsockname()[1]
        registry = RegistryClient(registry_url=f"http://127.0.0.1:{port}", timeout_seconds=1)
        try:
            with pytest.raises(HTTPException) as failure:
                await apply_lifecycle_cascade(env.db, env.redis, request, registry_client=registry)
            assert failure.value.status_code == 503
        finally:
            await registry.aclose()
    assert (
        await env.db.fetch_value(
            "SELECT deleted_at FROM {{tables.workspaces}} WHERE workspace_id=$1", actor.workspace
        )
        is None
    )
    assert (
        await env.db.fetch_value(
            "SELECT deleted_at FROM {{tables.agents}} WHERE agent_id=$1", actor.id
        )
        is None
    )
    assert (
        await env.db.fetch_value(
            "SELECT count(*) FROM {{tables.identity_grant_liveness}} WHERE grant_id=$1", grant_id
        )
        == 1
    )
    assert (
        await env.db.fetch_value(
            "SELECT count(*) FROM {{tables.lifecycle_side_effect_outbox}} WHERE team_id=$1", TEAM
        )
        == before
    )
