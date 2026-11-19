"""Workspace deletion against the real native app, AWID, PostgreSQL and Redis."""

import asyncio
import json
import os
from contextlib import asynccontextmanager
from urllib.parse import quote, urlsplit, urlunsplit
from uuid import uuid4

import httpx
import pytest
from redis.asyncio import Redis

from aweb.api import create_app
from aweb.events import team_events_channel_name
from aweb.lifecycle import replay_lifecycle_side_effects
from aweb.outbox_recovery import stop_outbox_recovery
from aweb.presence import clear_workspace_presence
from test_dashboard_privacy import TEAM, TEAM_NAME
from test_dashboard_privacy import privacy_app as privacy_app
from test_messages_http import _encode_certificate, _make_certificate, _signed_team_headers
from test_workspace_liveness_http import _send_member_request


async def _claim_tasks(env, *, count: int) -> list[str]:
    refs = []
    for index in range(count):
        created = await _send_member_request(
            env,
            alias="alice",
            method="POST",
            path="/v1/tasks",
            body={"title": f"Workspace deletion claim {index}"},
        )
        assert created.status_code == 200, created.text
        ref = created.json()["task_ref"]
        claimed = await _send_member_request(
            env,
            alias="alice",
            method="PATCH",
            path=f"/v1/tasks/{ref}",
            body={"status": "in_progress"},
        )
        assert claimed.status_code == 200, claimed.text
        refs.append(ref)
    return refs


@pytest.mark.asyncio
@pytest.mark.parametrize("claim_count", [0, 3])
async def test_self_delete_reports_actual_released_claims_and_events(privacy_app, claim_count):
    env = privacy_app
    alice = env.actors["alice"]
    refs = await _claim_tasks(env, count=claim_count)
    channels = [f"events:{alice.workspace}", team_events_channel_name(TEAM)]
    async with env.redis.pubsub() as pubsub:
        await pubsub.subscribe(*channels)
        response = await _send_member_request(
            env,
            alias="alice",
            method="DELETE",
            path=f"/v1/workspaces/{alice.workspace}",
        )
        assert response.status_code == 200, response.text
        assert response.json()["claims_released"] == claim_count
        assert response.json()["identity_deleted"] is True
        received = []
        if refs:
            async with asyncio.timeout(3):
                async for message in pubsub.listen():
                    if message["type"] == "message":
                        event = json.loads(message["data"])
                        assert isinstance(event, dict)
                        if event.get("type") == "task.unclaimed":
                            received.append((message["channel"], event))
                            if len(received) == 2 * claim_count:
                                break
            for channel in channels:
                assert {
                    event["task_ref"] for observed, event in received if observed == channel
                } == set(refs)
                assert all(
                    event["type"] == "task.unclaimed"
                    for observed, event in received
                    if observed == channel
                )
    assert (
        await env.db.fetch_value(
            "SELECT count(*) FROM {{tables.task_claims}} WHERE workspace_id=$1", alice.workspace
        )
        == 0
    )
    assert await env.db.fetch_value(
        "SELECT deleted_at IS NOT NULL FROM {{tables.workspaces}} WHERE workspace_id=$1",
        alice.workspace,
    )
    assert await env.db.fetch_value(
        "SELECT deleted_at IS NOT NULL FROM {{tables.agents}} WHERE agent_id=$1", alice.id
    )


@pytest.mark.asyncio
async def test_peer_delete_preserves_a_global_identity_and_its_claim(privacy_app):
    env = privacy_app
    alice = env.actors["alice"]
    await _claim_tasks(env, count=1)
    registry = env.app.state.awid_registry_client
    registered = await registry.register_did(alice.did, alice.sk)
    certificate_id = f"global-{uuid4()}"
    certificate = _encode_certificate(
        _make_certificate(
            env.team_sk,
            env.team_did,
            alice.did,
            team_id=TEAM,
            alias="alice",
            identity_scope="global",
            member_did_aw=registered.did_aw,
            certificate_id=certificate_id,
        )
    )
    await registry.register_team_certificate(
        "example.test",
        TEAM_NAME,
        team_controller_signing_key=env.team_sk,
        certificate_id=certificate_id,
        member_did_key=alice.did,
        member_did_aw=registered.did_aw,
        member_address=None,
        alias="alice",
        identity_scope="global",
        certificate=certificate,
    )
    await env.db.execute(
        "UPDATE {{tables.agents}} SET identity_scope='global',did_aw=$2,did_aw_verified_key=$3,"
        "certificate_id=$4,accepted_team_did_key=$5 WHERE agent_id=$1",
        alice.id,
        registered.did_aw,
        alice.did,
        certificate_id,
        env.team_did,
    )
    response = await _send_member_request(
        env, alias="bob", method="DELETE", path=f"/v1/workspaces/{alice.workspace}"
    )
    assert response.status_code == 409, response.text
    assert response.json()["detail"]["code"] == "global_identity_not_cleanup_eligible"
    assert (
        await env.db.fetch_value(
            "SELECT deleted_at FROM {{tables.agents}} WHERE agent_id=$1", alice.id
        )
        is None
    )
    assert (
        await env.db.fetch_value(
            "SELECT deleted_at FROM {{tables.workspaces}} WHERE workspace_id=$1", alice.workspace
        )
        is None
    )
    assert (
        await env.db.fetch_value(
            "SELECT count(*) FROM {{tables.task_claims}} WHERE workspace_id=$1", alice.workspace
        )
        == 1
    )


@pytest.mark.asyncio
async def test_peer_delete_preserves_an_unbound_workspace_and_its_claim(privacy_app):
    env = privacy_app
    alice = env.actors["alice"]
    await _claim_tasks(env, count=1)
    await env.db.execute(
        "UPDATE {{tables.workspaces}} SET agent_id=NULL WHERE workspace_id=$1", alice.workspace
    )
    response = await _send_member_request(
        env, alias="bob", method="DELETE", path=f"/v1/workspaces/{alice.workspace}"
    )
    assert response.status_code == 409, response.text
    assert response.json()["detail"]["code"] == "unknown_identity_scope_no_cleanup"
    assert (
        await env.db.fetch_value(
            "SELECT deleted_at FROM {{tables.workspaces}} WHERE workspace_id=$1", alice.workspace
        )
        is None
    )
    assert (
        await env.db.fetch_value(
            "SELECT count(*) FROM {{tables.task_claims}} WHERE workspace_id=$1", alice.workspace
        )
        == 1
    )


@pytest.mark.asyncio
async def test_cross_team_workspace_delete_does_not_touch_foreign_bindings(privacy_app):
    env = privacy_app
    team = "neighbor:example.test"
    agent, workspace = uuid4(), uuid4()
    await env.db.execute(
        "INSERT INTO {{tables.teams}} (team_id,namespace,team_name,team_did_key) VALUES ($1,'example.test','neighbor',$2)",
        team,
        env.team_did,
    )
    await env.db.execute(
        "INSERT INTO {{tables.agents}} (agent_id,team_id,did_key,alias) VALUES ($1,$2,$3,'foreign')",
        agent,
        team,
        env.actors["alice"].did,
    )
    await env.db.execute(
        "INSERT INTO {{tables.workspaces}} (workspace_id,team_id,agent_id,alias) VALUES ($1,$2,$3,'foreign')",
        workspace,
        team,
        agent,
    )
    await env.db.execute(
        "INSERT INTO {{tables.task_claims}} (team_id,workspace_id,alias,task_ref) VALUES ($1,$2,'foreign','neighbor-1')",
        team,
        workspace,
    )
    response = await _send_member_request(
        env, alias="bob", method="DELETE", path=f"/v1/workspaces/{workspace}"
    )
    assert response.status_code == 404, response.text
    assert (
        await env.db.fetch_value(
            "SELECT deleted_at FROM {{tables.workspaces}} WHERE workspace_id=$1", workspace
        )
        is None
    )
    assert (
        await env.db.fetch_value(
            "SELECT deleted_at FROM {{tables.agents}} WHERE agent_id=$1", agent
        )
        is None
    )
    assert (
        await env.db.fetch_value(
            "SELECT count(*) FROM {{tables.task_claims}} WHERE workspace_id=$1", workspace
        )
        == 1
    )


@asynccontextmanager
async def _redis_without_delete(env):
    """A real, temporary Redis ACL user denies only destructive key deletion."""
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
async def test_post_commit_redis_permission_failure_is_retried_against_real_service(privacy_app):
    env = privacy_app
    alice, bob = env.actors["alice"], env.actors["bob"]
    await _claim_tasks(env, count=1)
    await env.db.execute(
        "UPDATE {{tables.workspaces}} SET last_seen_at=NOW()-INTERVAL '2 hours' WHERE workspace_id=$1",
        alice.workspace,
    )
    await clear_workspace_presence(env.redis, [str(alice.workspace)])
    # This host owns replay explicitly; the test drives it after the outage.
    await stop_outbox_recovery(env.app)
    async with _redis_without_delete(env) as restricted:
        app = create_app(
            db_infra=env.infra,
            redis=restricted,
            public_origin=str(env.client.base_url).rstrip("/"),
            host_runs_outbox_recovery=True,
        )
        app.state.db, app.state.redis = env.infra, restricted
        app.state.awid_registry_client = env.app.state.awid_registry_client
        app.state.on_mutation = env.app.state.on_mutation
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=str(env.client.base_url)
        ) as client:
            headers = _signed_team_headers(bob.sk, bob.did, TEAM, bob.certificate)
            failed = await client.delete(f"/v1/workspaces/{alice.workspace}", headers=headers)
            assert failed.status_code == 503, failed.text
            assert failed.json()["detail"]["code"] == "post_commit_cleanup_pending"
            operations = await env.db.fetch_all(
                "SELECT DISTINCT operation_id FROM {{tables.lifecycle_side_effect_outbox}} WHERE team_id=$1 AND delivered_at IS NULL",
                TEAM,
            )
            assert operations
            assert await env.db.fetch_value(
                "SELECT deleted_at IS NOT NULL FROM {{tables.workspaces}} WHERE workspace_id=$1",
                alice.workspace,
            )
            assert (
                await env.db.fetch_value(
                    "SELECT count(*) FROM {{tables.task_claims}} WHERE workspace_id=$1",
                    alice.workspace,
                )
                == 0
            )
            app.state.redis = env.redis
            recovered = await client.delete(
                f"/v1/workspaces/{alice.workspace}",
                headers=_signed_team_headers(bob.sk, bob.did, TEAM, bob.certificate),
            )
            assert recovered.status_code == 200, recovered.text
            assert recovered.json()["identity_deleted"] is True
        for row in operations:
            replay = await replay_lifecycle_side_effects(
                env.db, env.redis, operation_id=str(row["operation_id"])
            )
            assert replay.pending_count == 0
        assert (
            await env.db.fetch_value(
                "SELECT count(*) FROM {{tables.lifecycle_side_effect_outbox}} WHERE team_id=$1 AND delivered_at IS NULL",
                TEAM,
            )
            == 0
        )
