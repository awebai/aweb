"""Workspace deletion against the real native app, AWID, PostgreSQL and Redis."""

import asyncio
import json
import os
from contextlib import asynccontextmanager
from datetime import timedelta
from urllib.parse import quote, urlsplit, urlunsplit
from uuid import uuid4

import httpx
import pytest
from redis.asyncio import Redis

from aweb.api import create_app
from aweb.config import get_presence_ttl_seconds
from aweb.events import team_events_channel_name
from aweb.lifecycle import replay_lifecycle_side_effects
from aweb.outbox_recovery import stop_outbox_recovery
from aweb.presence import clear_workspace_presence
from test_dashboard_privacy import TEAM
from test_dashboard_privacy import privacy_app
from test_messages_http import _signed_team_headers
from test_workspace_liveness_http import (
    _connect_registered_member,
    _send_member_request,
    _set_workspace_route_time,
)

__all__ = ["privacy_app"]


async def _claim_tasks(
    env, *, count: int, alias: str = "alice", team_id: str = TEAM
) -> list[str]:
    refs = []
    for index in range(count):
        created = await _send_member_request(
            env,
            alias=alias,
            team_id=team_id,
            method="POST",
            path="/v1/tasks",
            body={"title": f"Workspace deletion claim {index}"},
        )
        assert created.status_code == 200, created.text
        ref = created.json()["task_ref"]
        claimed = await _send_member_request(
            env,
            alias=alias,
            team_id=team_id,
            method="PATCH",
            path=f"/v1/tasks/{ref}",
            body={"status": "in_progress"},
        )
        assert claimed.status_code == 200, claimed.text
        refs.append(ref)
    return refs


@pytest.mark.asyncio
@pytest.mark.parametrize("claim_count", [0, 3])
async def test_self_delete_reports_actual_released_claims_and_events(
    privacy_app, claim_count
):
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
                    event["task_ref"]
                    for observed, event in received
                    if observed == channel
                } == set(refs)
                assert all(
                    event["type"] == "task.unclaimed"
                    for observed, event in received
                    if observed == channel
                )
    assert (
        await env.db.fetch_value(
            "SELECT count(*) FROM {{tables.task_claims}} WHERE workspace_id=$1",
            alice.workspace,
        )
        == 0
    )
    assert await env.db.fetch_value(
        "SELECT deleted_at IS NOT NULL FROM {{tables.workspaces}} WHERE workspace_id=$1",
        alice.workspace,
    )
    assert await env.db.fetch_value(
        "SELECT deleted_at IS NOT NULL FROM {{tables.agents}} WHERE agent_id=$1",
        alice.id,
    )


@pytest.mark.asyncio
async def test_peer_delete_preserves_a_global_identity_and_its_claim(privacy_app):
    env = privacy_app
    alice = await _connect_registered_member(env, alias="global-member", scope="global")
    await _claim_tasks(env, count=1, alias="global-member")
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
            "SELECT deleted_at FROM {{tables.workspaces}} WHERE workspace_id=$1",
            alice.workspace,
        )
        is None
    )
    assert (
        await env.db.fetch_value(
            "SELECT count(*) FROM {{tables.task_claims}} WHERE workspace_id=$1",
            alice.workspace,
        )
        == 1
    )


@pytest.mark.asyncio
async def test_cross_team_workspace_delete_does_not_touch_foreign_bindings(privacy_app):
    env = privacy_app
    team = "neighbor:example.test"
    await env.app.state.awid_registry_client.register_team(
        domain="example.test",
        name="neighbor",
        display_name="Neighbor",
        team_did_key=env.team_did,
        visibility="public",
        namespace_controller_signing_key=env.namespace_sk,
    )
    member = await _connect_registered_member(env, alias="foreign", team_id=team)
    agent, workspace = member.id, member.workspace
    await _claim_tasks(env, count=1, alias="foreign", team_id=team)
    response = await _send_member_request(
        env, alias="bob", method="DELETE", path=f"/v1/workspaces/{workspace}"
    )
    assert response.status_code == 404, response.text
    assert (
        await env.db.fetch_value(
            "SELECT deleted_at FROM {{tables.workspaces}} WHERE workspace_id=$1",
            workspace,
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
            "SELECT count(*) FROM {{tables.task_claims}} WHERE workspace_id=$1",
            workspace,
        )
        == 1
    )


@asynccontextmanager
async def _redis_without_command(env, command: str):
    """A temporary Redis client with one forbidden command."""
    username, password = f"cleanup-{uuid4().hex}", uuid4().hex
    await env.redis.execute_command(
        "ACL",
        "SETUSER",
        username,
        "on",
        f">{password}",
        "~*",
        "&*",
        "+@all",
        f"-{command}",
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
async def test_post_commit_redis_permission_failure_is_retried_against_real_service(
    privacy_app, monkeypatch
):
    env = privacy_app
    alice, bob = env.actors["alice"], env.actors["bob"]
    await _claim_tasks(env, count=1)
    reservation = await env.db.fetch_one(
        "SELECT created_at, last_seen_at FROM {{tables.workspaces}} WHERE workspace_id=$1",
        alice.workspace,
    )
    assert reservation["last_seen_at"] is None
    _set_workspace_route_time(
        monkeypatch,
        reservation["created_at"] + timedelta(seconds=get_presence_ttl_seconds() + 1),
    )
    await clear_workspace_presence(env.redis, [str(alice.workspace)])
    # This host owns replay explicitly; the test drives it after the outage.
    await stop_outbox_recovery(env.app)
    async with _redis_without_command(env, "del") as restricted:
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
            failed = await client.delete(
                f"/v1/workspaces/{alice.workspace}", headers=headers
            )
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
