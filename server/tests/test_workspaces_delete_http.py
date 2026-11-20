"""Workspace consumers use actual registry admission, native HTTP and Redis."""

import asyncio
import json
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from urllib.parse import quote, urlsplit, urlunsplit
from uuid import UUID, uuid4

import httpx
import pytest
import pytest_asyncio
from redis.asyncio import Redis

from aweb.api import create_app
from aweb.events import team_events_channel_name
from aweb.lifecycle import replay_lifecycle_side_effects
from aweb.outbox_recovery import stop_outbox_recovery
from aweb.presence import clear_workspace_presence
from messaging_actor_support import (
    admit_messaging_actor,
    register_messaging_team,
    messaging_actor_headers,
)
from test_agents_suggest_alias_http import request_as, _global_actor
from test_dashboard_privacy import TEAM, privacy_stack
from test_team_room import admit_room_member


@pytest_asyncio.fixture
async def workspace_stack(shared_test_pool, monkeypatch):
    async with privacy_stack(shared_test_pool, monkeypatch) as env:
        for alias in ("alice", "bob"):
            await admit_room_member(env, alias=alias)
        # The original fixtures contain exactly the two selected live members.
        await env.db.execute(
            "UPDATE {{tables.workspaces}} SET deleted_at=NOW() WHERE team_id=$1 AND alias='carol'",
            TEAM,
        )
        await env.db.execute(
            "UPDATE {{tables.agents}} SET deleted_at=NOW() WHERE team_id=$1 AND alias='carol'",
            TEAM,
        )
        yield env


async def _new_member(env, alias):
    member = await admit_messaging_actor(env, alias=alias, team_id=TEAM, local=True)
    workspace = await env.db.fetch_value(
        "SELECT workspace_id FROM {{tables.workspaces}} WHERE agent_id=$1 AND deleted_at IS NULL ORDER BY created_at DESC LIMIT 1",
        UUID(member.agent_id),
    )
    actor = SimpleNamespace(
        sk=member.signing_key,
        did=member.did_key,
        certificate=member.certificate,
        id=UUID(member.agent_id),
        workspace=workspace,
    )
    env.actors[alias] = actor
    return actor


async def _stale(env, actor, *, days=0):
    seen = datetime.now(timezone.utc) - (
        timedelta(days=days) if days else timedelta(hours=2)
    )
    await env.db.execute(
        "UPDATE {{tables.workspaces}} SET last_seen_at=$1 WHERE workspace_id=$2",
        seen,
        actor.workspace,
    )
    await clear_workspace_presence(env.redis, [str(actor.workspace), str(actor.id)])
    return seen


async def _claims(env, alias, count):
    refs = []
    for index in range(count):
        made = await request_as(
            env,
            alias=alias,
            method="POST",
            path="/v1/tasks",
            payload={"title": f"Workspace claim {index}"},
        )
        assert made.status_code == 200, made.text
        ref = made.json()["task_ref"]
        claimed = await request_as(
            env,
            alias=alias,
            method="PATCH",
            path=f"/v1/tasks/{ref}",
            payload={"status": "in_progress"},
        )
        assert claimed.status_code == 200, claimed.text
        refs.append(ref)
    return refs


async def _rows(env, actor):
    workspace = await env.db.fetch_one(
        "SELECT * FROM {{tables.workspaces}} WHERE workspace_id=$1", actor.workspace
    )
    agent = await env.db.fetch_one(
        "SELECT * FROM {{tables.agents}} WHERE agent_id=$1", actor.id
    )
    return workspace, agent


async def _delete(env, caller, workspace):
    return await request_as(
        env, alias=caller, method="DELETE", path=f"/v1/workspaces/{workspace}"
    )


async def _hide_initial(env):
    await env.db.execute(
        "UPDATE {{tables.workspaces}} SET deleted_at=NOW() WHERE team_id=$1", TEAM
    )
    await env.db.execute(
        "UPDATE {{tables.agents}} SET deleted_at=NOW() WHERE team_id=$1", TEAM
    )
    await clear_workspace_presence(
        env.redis, [str(actor.workspace) for actor in env.actors.values()]
    )


@pytest.mark.asyncio
async def test_team_roster_prioritizes_live_presence_and_reports_truncation(
    workspace_stack,
):
    env = workspace_stack
    await _hide_initial(env)
    active_aliases = {f"live-{i}" for i in range(5)}
    for alias in sorted(active_aliases):
        actor = await _new_member(env, alias)
        heartbeat = await request_as(
            env,
            alias=alias,
            method="POST",
            path="/v1/workspaces/heartbeat",
            payload={"workspace_id": str(actor.workspace), "alias": alias},
        )
        assert heartbeat.status_code == 200, heartbeat.text
    for index in range(10):
        alias = f"stale-{index}"
        actor = await _new_member(env, alias)
        await _claims(env, alias, 1)
        seen = await _stale(env, actor, days=60)
        await env.db.execute(
            "UPDATE {{tables.task_claims}} SET claimed_at=$1 WHERE workspace_id=$2",
            seen,
            actor.workspace,
        )
    base = "/v1/workspaces/team?include_claims=true&only_with_claims=false&limit=5"
    response = await request_as(
        env,
        alias="live-0",
        method="GET",
        path=base
        + f"&include_presence=true&always_include_workspace_id={env.actors['live-0'].workspace}",
    )
    response_without_presence = await request_as(
        env, alias="live-0", method="GET", path=base + "&include_presence=false"
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["has_more"] is True
    assert {workspace["alias"] for workspace in data["workspaces"]} == active_aliases
    assert all(workspace["status"] == "active" for workspace in data["workspaces"])
    assert response_without_presence.status_code == 200, response_without_presence.text
    assert response_without_presence.json()["has_more"] is True


@pytest.mark.asyncio
async def test_team_roster_keeps_live_presence_outside_sql_candidate_window(
    workspace_stack,
):
    env = workspace_stack
    await _hide_initial(env)
    live = await _new_member(env, "live")
    await env.db.execute(
        "UPDATE {{tables.workspaces}} SET last_seen_at=NOW()-INTERVAL '60 days' WHERE workspace_id=$1",
        live.workspace,
    )
    heartbeat = await request_as(
        env, alias="live", method="POST", path="/v1/agents/heartbeat"
    )
    assert heartbeat.status_code == 200, heartbeat.text
    # Keep genuine fresh presence while the persisted SQL observation is old.
    await env.db.execute(
        "UPDATE {{tables.workspaces}} SET last_seen_at=NOW()-INTERVAL '60 days' WHERE workspace_id=$1",
        live.workspace,
    )
    for index in range(5):
        actor = await _new_member(env, f"offline-{index}")
        await _stale(env, actor)
    response = await request_as(
        env,
        alias="live",
        method="GET",
        path="/v1/workspaces/team?include_presence=true&only_with_claims=false&limit=1",
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["has_more"] is True
    assert [workspace["alias"] for workspace in data["workspaces"]] == ["live"]
    assert data["workspaces"][0]["status"] == "active"


@asynccontextmanager
async def _redis_without_delete(env):
    # Existing R14 real-service fault: one temporary ACL denies only DEL.
    username, password = f"cleanup-{uuid4().hex}", uuid4().hex
    await env.redis.execute_command(
        "ACL", "SETUSER", username, "on", f">{password}", "~*", "&*", "+@all", "-del"
    )
    try:
        parts = urlsplit(os.environ["REDIS_URL"])
        endpoint = urlunsplit(
            parts._replace(
                netloc=f"{quote(username)}:{quote(password)}@{parts.netloc.rsplit('@', 1)[-1]}"
            )
        )
        async with Redis.from_url(endpoint, decode_responses=True) as restricted:
            await restricted.ping()
            yield restricted
    finally:
        await env.redis.execute_command("ACL", "DELUSER", username)


@pytest.mark.asyncio
async def test_delete_workspace_recovers_post_commit_presence_failure(workspace_stack):
    env = workspace_stack
    bob = env.actors["bob"]
    refs = await _claims(env, "bob", 1)
    seen = await _stale(env, bob)
    # Historical pre-coordinate presence includes the old identity-keyed entry.
    for key in (str(bob.workspace), str(bob.id)):
        await env.redis.hset(
            f"presence:{key}",
            mapping={
                "workspace_id": key,
                "alias": "bob",
                "team_id": TEAM,
                "last_seen": seen.isoformat(),
            },
        )
        await env.redis.sadd("idx:all_workspaces", key)
        assert await env.redis.exists(f"presence:{key}") == 1
    await stop_outbox_recovery(env.app)
    channels = [f"events:{bob.workspace}", team_events_channel_name(TEAM)]
    async with env.redis.pubsub() as pubsub:
        await pubsub.subscribe(*channels)
        async with _redis_without_delete(env) as restricted:
            app = create_app(
                db_infra=env.infra,
                redis=restricted,
                public_origin=str(env.client.base_url).rstrip("/"),
                host_runs_outbox_recovery=True,
            )
            app.state.awid_registry_client = env.app.state.awid_registry_client
            app.state.on_mutation = env.app.state.on_mutation
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url=str(env.client.base_url),
            ) as client:
                alice = env.actors["alice"]
                from test_messages_http import _signed_team_headers

                failed = await client.delete(
                    f"/v1/workspaces/{bob.workspace}",
                    headers=_signed_team_headers(
                        alice.sk, alice.did, TEAM, alice.certificate
                    ),
                )
                assert failed.status_code == 503, failed.text
                assert failed.json()["detail"]["code"] == "post_commit_cleanup_pending"
                app.state.redis = env.redis
                response = await client.delete(
                    f"/v1/workspaces/{bob.workspace}",
                    headers=_signed_team_headers(
                        alice.sk, alice.did, TEAM, alice.certificate
                    ),
                )
                assert response.status_code == 200, response.text
                body = response.json()
                assert body["workspace_id"] == str(bob.workspace)
                assert body["alias"] == "bob"
                assert body["identity_deleted"] is True
            for operation in await env.db.fetch_all(
                "SELECT DISTINCT operation_id FROM {{tables.lifecycle_side_effect_outbox}} WHERE team_id=$1 AND delivered_at IS NULL",
                TEAM,
            ):
                replay = await replay_lifecycle_side_effects(
                    env.db, env.redis, operation_id=str(operation["operation_id"])
                )
                assert replay.pending_count == 0
        received = []
        async with asyncio.timeout(5):
            async for item in pubsub.listen():
                if item["type"] == "message":
                    event = json.loads(item["data"])
                    if event.get("type") == "task.unclaimed":
                        received.append((item["channel"], event))
                        if {channel for channel, event in received} == set(channels):
                            break
    workspace, agent = await _rows(env, bob)
    assert workspace["deleted_at"] is not None
    assert agent["deleted_at"] is not None
    assert agent["status"] == "deleted"
    assert (
        await env.db.fetch_value(
            "SELECT count(*) FROM {{tables.task_claims}} WHERE workspace_id=$1",
            bob.workspace,
        )
        == 0
    )
    assert any(
        channel == channels[0]
        and event["workspace_id"] == str(bob.workspace)
        and event["task_ref"] == refs[0]
        and event["alias"] == "bob"
        for channel, event in received
    )
    assert any(
        channel == channels[1]
        and event["team_id"] == TEAM
        and event["task_ref"] == refs[0]
        and event["alias"] == "bob"
        for channel, event in received
    )
    for key in (str(bob.workspace), str(bob.id)):
        assert await env.redis.exists(f"presence:{key}") == 0
        assert not await env.redis.sismember("idx:all_workspaces", key)


@pytest.mark.asyncio
async def test_delete_workspace_rejects_persistent_identity(workspace_stack):
    env = workspace_stack
    alice = env.actors["alice"]
    stable = await _global_actor(env, "alice", address="example.test/alice")
    await _claims(env, "alice", 1)
    response = await _delete(env, "alice", alice.workspace)
    assert response.status_code == 409, response.text
    detail = response.json()["detail"]
    assert detail["code"] == "global_identity_not_cleanup_eligible"
    assert detail["workspace_id"] == str(alice.workspace)
    assert detail["identity_id"] == str(alice.id)
    assert detail["identity_scope"] == "global"
    workspace, agent = await _rows(env, alice)
    assert workspace["deleted_at"] is None
    assert agent["deleted_at"] is None
    assert agent["status"] == "active"
    assert agent["did_key"] == alice.did
    assert agent["did_aw"] == stable
    assert agent["address"] == "example.test/alice"
    assert agent["identity_scope"] == "global"
    assert (
        await env.db.fetch_value(
            "SELECT count(*) FROM {{tables.task_claims}} WHERE workspace_id=$1",
            alice.workspace,
        )
        == 1
    )


@pytest.mark.asyncio
async def test_delete_workspace_unknown_identity_scope_fails_closed(workspace_stack):
    env = workspace_stack
    workspace_id, missing_agent_id = uuid4(), uuid4()
    # Deliberately corrupt historical storage: no member is bound to this seat.
    await env.db.execute(
        "INSERT INTO {{tables.workspaces}} (workspace_id,team_id,agent_id,alias,last_seen_at) VALUES ($1,$2,$3,'orphan',NOW()-INTERVAL '2 hours')",
        workspace_id,
        TEAM,
        missing_agent_id,
    )
    await env.db.execute(
        "INSERT INTO {{tables.task_claims}} (team_id,workspace_id,alias,task_ref) VALUES ($1,$2,'orphan','orphan-unknown')",
        TEAM,
        workspace_id,
    )
    response = await _delete(env, "alice", workspace_id)
    assert response.status_code == 409, response.text
    detail = response.json()["detail"]
    assert detail["code"] == "unknown_identity_scope_no_cleanup"
    assert detail["workspace_id"] == str(workspace_id)
    assert detail["identity_id"] == str(missing_agent_id)
    assert detail["identity_scope"] == "unknown"
    assert (
        await env.db.fetch_value(
            "SELECT deleted_at FROM {{tables.workspaces}} WHERE workspace_id=$1",
            workspace_id,
        )
        is None
    )
    assert (
        await env.db.fetch_value(
            "SELECT count(*) FROM {{tables.task_claims}} WHERE workspace_id=$1",
            workspace_id,
        )
        == 1
    )


@pytest.mark.asyncio
async def test_delete_workspace_rejects_recent_ephemeral_workspace_of_another_agent(
    workspace_stack,
):
    env = workspace_stack
    bob = env.actors["bob"]
    await env.db.execute(
        "UPDATE {{tables.workspaces}} SET last_seen_at=NOW() WHERE workspace_id=$1",
        bob.workspace,
    )
    response = await _delete(env, "alice", bob.workspace)
    assert response.status_code == 409, response.text
    assert response.json()["detail"]["code"] == "local_workspace_still_active"
    workspace, agent = await _rows(env, bob)
    assert workspace["deleted_at"] is None
    assert agent["deleted_at"] is None


@pytest.mark.asyncio
async def test_delete_workspace_allows_agent_to_delete_its_own_recent_workspace(
    workspace_stack,
):
    env = workspace_stack
    alice = env.actors["alice"]
    await env.db.execute(
        "UPDATE {{tables.workspaces}} SET last_seen_at=NOW() WHERE workspace_id=$1",
        alice.workspace,
    )
    response = await _delete(env, "alice", alice.workspace)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["workspace_id"] == str(alice.workspace)
    assert body["identity_deleted"] is True
    workspace, agent = await _rows(env, alice)
    assert workspace["deleted_at"] is not None
    assert agent["deleted_at"] is not None


@pytest.mark.asyncio
async def test_delete_workspace_rejects_cross_team_request(workspace_stack):
    env = workspace_stack
    alice = env.actors["alice"]
    neighbor = f"neighbor-{uuid4().hex}:example.test"
    await register_messaging_team(env, team_id=neighbor)
    foreign = await admit_messaging_actor(
        env, alias="eve", team_id=neighbor, local=True
    )
    response = await env.client.delete(
        f"/v1/workspaces/{alice.workspace}", headers=messaging_actor_headers(foreign)
    )
    assert response.status_code == 404, response.text
    workspace, agent = await _rows(env, alice)
    assert workspace["deleted_at"] is None
    assert agent["deleted_at"] is None


@pytest.mark.asyncio
async def test_delete_workspace_reports_the_claims_it_released(workspace_stack):
    env = workspace_stack
    alice = env.actors["alice"]
    await _claims(env, "alice", 3)
    scope_before = await env.db.fetch_value(
        "SELECT identity_scope FROM {{tables.agents}} WHERE agent_id=$1", alice.id
    )
    assert scope_before == "local"
    response = await _delete(env, "alice", alice.workspace)
    assert response.status_code == 200, response.text
    assert (
        await env.db.fetch_value(
            "SELECT count(*) FROM {{tables.task_claims}} WHERE workspace_id=$1",
            alice.workspace,
        )
        == 0
    )
    assert response.json()["claims_released"] == 3


@pytest.mark.asyncio
async def test_delete_workspace_reports_zero_claims_when_it_released_none(
    workspace_stack,
):
    env = workspace_stack
    response = await _delete(env, "alice", env.actors["alice"].workspace)
    assert response.status_code == 200, response.text
    assert response.json()["claims_released"] == 0


async def _ownership_pair(env):
    caller = await _new_member(env, "caller")
    owner = await _new_member(env, "bot")
    seen = await _stale(env, owner)
    await _stale(env, caller)
    await env.db.execute(
        "UPDATE {{tables.workspaces}} SET hostname=NULL,workspace_path='/tmp/bot-worktree',focus_task_ref=NULL WHERE workspace_id=$1",
        owner.workspace,
    )
    return caller, owner, seen


@pytest.mark.asyncio
async def test_workspace_heartbeat_refuses_another_members_workspace(
    workspace_stack, caplog
):
    env = workspace_stack
    _, owner, seen = await _ownership_pair(env)
    presence = await env.redis.hgetall(f"presence:{owner.workspace}")
    response = await request_as(
        env,
        alias="caller",
        method="POST",
        path="/v1/workspaces/heartbeat",
        payload={
            "workspace_id": str(owner.workspace),
            "alias": "bot",
            "hostname": "attacker-host",
        },
    )
    assert response.status_code == 403, response.text
    assert (
        response.json()["detail"]
        == f"Workspace {owner.workspace} belongs to another agent."
    )
    row = await env.db.fetch_one(
        "SELECT hostname,last_seen_at FROM {{tables.workspaces}} WHERE workspace_id=$1",
        owner.workspace,
    )
    assert row["hostname"] is None
    assert row["last_seen_at"] == seen
    assert await env.redis.hgetall(f"presence:{owner.workspace}") == presence
    assert [
        record.getMessage()
        for record in caplog.records
        if record.levelname == "WARNING"
    ] == ["Workspace heartbeat refused: workspace belongs to another agent"]


@pytest.mark.asyncio
async def test_workspace_heartbeat_refreshes_the_callers_own_workspace(workspace_stack):
    env = workspace_stack
    caller, _, _ = await _ownership_pair(env)
    seen = await _stale(env, caller)
    response = await request_as(
        env,
        alias="caller",
        method="POST",
        path="/v1/workspaces/heartbeat",
        payload={
            "workspace_id": str(caller.workspace),
            "alias": "caller",
            "hostname": "caller-host",
        },
    )
    assert response.status_code == 200, response.text
    row = await env.db.fetch_one(
        "SELECT hostname,last_seen_at FROM {{tables.workspaces}} WHERE workspace_id=$1",
        caller.workspace,
    )
    assert row["hostname"] == "caller-host"
    assert row["last_seen_at"] > seen
    presence = await env.redis.hgetall(f"presence:{caller.workspace}")
    assert presence["workspace_id"] == str(caller.workspace)
    assert presence["alias"] == "caller"
    assert presence["team_id"] == TEAM


@pytest.mark.asyncio
async def test_workspace_patch_refuses_another_members_workspace(
    workspace_stack, caplog
):
    env = workspace_stack
    _, owner, _ = await _ownership_pair(env)
    response = await request_as(
        env,
        alias="caller",
        method="PATCH",
        path=f"/v1/workspaces/{owner.workspace}",
        payload={
            "hostname": "attacker-host",
            "workspace_path": "/tmp/attacker-worktree",
            "focus_task_ref": "other-task",
        },
    )
    assert response.status_code == 403, response.text
    assert (
        response.json()["detail"]
        == f"Workspace {owner.workspace} belongs to another agent."
    )
    row = await env.db.fetch_one(
        "SELECT hostname,workspace_path,focus_task_ref FROM {{tables.workspaces}} WHERE workspace_id=$1",
        owner.workspace,
    )
    assert row["hostname"] is None
    assert row["workspace_path"] == "/tmp/bot-worktree"
    assert row["focus_task_ref"] is None
    assert [
        record.getMessage()
        for record in caplog.records
        if record.levelname == "WARNING"
    ] == ["Workspace update refused: workspace belongs to another agent"]


@pytest.mark.asyncio
async def test_workspace_patch_updates_the_callers_own_workspace(workspace_stack):
    env = workspace_stack
    caller, _, _ = await _ownership_pair(env)
    response = await request_as(
        env,
        alias="caller",
        method="PATCH",
        path=f"/v1/workspaces/{caller.workspace}",
        payload={"hostname": "caller-host", "focus_task_ref": "backend-y"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["updated"] is True
    row = await env.db.fetch_one(
        "SELECT hostname,focus_task_ref FROM {{tables.workspaces}} WHERE workspace_id=$1",
        caller.workspace,
    )
    assert row["hostname"] == "caller-host"
    assert row["focus_task_ref"] == "backend-y"
