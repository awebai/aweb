"""Member cleanup rules through real aweb, AWID, PostgreSQL and Redis."""

import asyncio
import json
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from aweb.events import team_events_channel_name
from test_dashboard_privacy import TEAM
from test_dashboard_privacy import privacy_app
from test_workspace_liveness_http import _connect_registered_member, _send_member_request

__all__ = ["privacy_app"]


async def _acquire_lock(env, *, alias: str, resource_key: str, team_id: str = TEAM) -> None:
    response = await _send_member_request(
        env,
        alias=alias,
        method="POST",
        path="/v1/reservations",
        body={"resource_key": resource_key, "ttl_seconds": 600},
        team_id=team_id,
    )
    assert response.status_code == 200, response.text


async def _connect_repo_workspaces(env, *aliases: str) -> UUID:
    repo_id = None
    for alias in aliases:
        response = await _send_member_request(
            env,
            alias=alias,
            method="POST",
            path="/v1/connect",
            body={
                "hostname": "cleanup-tests",
                "workspace_path": f"/tmp/member-cleanup/{alias}",
                "repo_origin": "https://github.com/example/member-cleanup.git",
            },
        )
        assert response.status_code == 200, response.text
        workspace_repo = await env.db.fetch_value(
            "SELECT repo_id FROM {{tables.workspaces}} WHERE workspace_id=$1",
            env.actors[alias].workspace,
        )
        assert workspace_repo is not None
        if repo_id is not None:
            assert workspace_repo == repo_id
        repo_id = workspace_repo
    return repo_id


@pytest.mark.asyncio
async def test_repo_delete_applies_self_or_stale_rule_and_reports_live_peer_skipped(privacy_app, monkeypatch):
    """Antares 9a131b85: repo deletion obeys the single-workspace cleanup rule."""
    env = privacy_app
    monkeypatch.setenv("AWEB_PRESENCE_TTL_SECONDS", "10")
    repo_id = await _connect_repo_workspaces(env, "bob")
    bob_seen = await env.db.fetch_value(
        "SELECT last_seen_at FROM {{tables.workspaces}} WHERE workspace_id=$1",
        env.actors["bob"].workspace,
    )
    for alias in ("bob", "carol"):
        await _acquire_lock(env, alias=alias, resource_key=f"repo-delete/{alias}")
    task = await _send_member_request(
        env, alias="bob", method="POST", path="/v1/tasks", body={"title": "Stale member claim"}
    )
    assert task.status_code == 200, task.text
    claimed = await _send_member_request(
        env,
        alias="bob",
        method="PATCH",
        path=f"/v1/tasks/{task.json()['task_ref']}",
        body={"status": "in_progress"},
    )
    assert claimed.status_code == 200, claimed.text
    stale_at = bob_seen + timedelta(seconds=10)
    await asyncio.sleep(max(0, (stale_at - datetime.now(UTC)).total_seconds()) + 0.05)
    assert await _connect_repo_workspaces(env, "alice", "carol") == repo_id
    response = await _send_member_request(
        env, alias="alice", method="DELETE", path=f"/v1/repos/{repo_id}"
    )
    assert response.status_code == 200, response.text
    assert await env.db.fetch_value(
        "SELECT deleted_at IS NULL FROM {{tables.workspaces}} WHERE workspace_id=$1",
        env.actors["carol"].workspace,
    ), "a live teammate's workspace must survive repo cleanup"
    assert response.json()["workspaces_deleted"] == 2
    assert response.json()["repo_deleted"] is False
    assert await env.db.fetch_value(
        "SELECT deleted_at IS NULL FROM {{tables.repos}} WHERE id=$1", repo_id
    )
    assert response.json()["skipped_workspaces"] == [
        {
            "workspace_id": str(env.actors["carol"].workspace),
            "code": "local_workspace_still_active",
        }
    ]
    for alias in ("alice", "bob"):
        assert await env.db.fetch_value(
            "SELECT deleted_at IS NOT NULL FROM {{tables.agents}} WHERE agent_id=$1",
            env.actors[alias].id,
        )
    assert (
        await env.db.fetch_value(
            "SELECT count(*) FROM {{tables.task_claims}} WHERE workspace_id=$1",
            env.actors["bob"].workspace,
        )
        == 0
    )
    reservations = await env.db.fetch_all(
        "SELECT resource_key FROM {{tables.reservations}} WHERE team_id=$1", TEAM
    )
    assert [row["resource_key"] for row in reservations] == ["repo-delete/carol"]
    audit = await env.db.fetch_one(
        "SELECT actor_did_key FROM {{tables.audit_log}} WHERE team_id=$1 AND event_type='repos.delete'",
        TEAM,
    )
    assert audit is not None and audit["actor_did_key"] == env.actors["alice"].did
    assert (
        await env.db.fetch_value(
            "SELECT count(*) FROM {{tables.lifecycle_side_effect_outbox}} WHERE team_id=$1", TEAM
        )
        > 0
    )


@pytest.mark.asyncio
async def test_emergency_revoke_records_member_and_notifies_every_affected_holder(privacy_app):
    """Any member may revoke; Antares 9a131b85 requires an attributable release."""
    env = privacy_app
    for alias in ("bob", "carol"):
        await _acquire_lock(env, alias=alias, resource_key=f"emergency/{alias}")
    await _acquire_lock(env, alias="carol", resource_key="untouched/carol")
    channels = [
        team_events_channel_name(TEAM),
        f"events:{env.actors['bob'].workspace}",
        f"events:{env.actors['carol'].workspace}",
    ]
    async with env.redis.pubsub() as pubsub:
        await pubsub.subscribe(*channels)
        response = await _send_member_request(
            env,
            alias="alice",
            method="POST",
            path="/v1/reservations/revoke",
            body={"prefix": "emergency/"},
        )
        assert response.status_code == 200, response.text
        assert sorted(response.json()["revoked_keys"]) == ["emergency/bob", "emergency/carol"]
        released = [context for event, context in env.dispatched if event == "reservation.released"]
        assert {context["resource_key"] for context in released} == {
            "emergency/bob",
            "emergency/carol",
        }, "emergency override must use the same release events as ordinary release"
        received = []
        async with asyncio.timeout(3):
            async for message in pubsub.listen():
                if message["type"] == "message":
                    event = json.loads(message["data"])
                    assert event["type"] == "reservation.released"
                    received.append((message["channel"], event))
                    if len(received) == 4:
                        break
        for alias in ("bob", "carol"):
            holder_events = [
                event
                for channel, event in received
                if channel == f"events:{env.actors[alias].workspace}"
            ]
            assert len(holder_events) == 1
            assert holder_events[0]["paths"] == [f"emergency/{alias}"]
    audit = await env.db.fetch_one(
        "SELECT actor_did_key FROM {{tables.audit_log}} "
        "WHERE team_id=$1 AND event_type='reservations.revoke'",
        TEAM,
    )
    assert audit is not None and audit["actor_did_key"] == env.actors["alice"].did
    assert (
        await env.db.fetch_value(
            "SELECT count(*) FROM {{tables.reservations}} WHERE team_id=$1 AND resource_key='untouched/carol'",
            TEAM,
        )
        == 1
    )
    ordinary_release = await _send_member_request(
        env,
        alias="alice",
        method="POST",
        path="/v1/reservations/release",
        body={"resource_key": "untouched/carol"},
    )
    assert ordinary_release.status_code == 409, ordinary_release.text


@pytest.mark.asyncio
async def test_failed_emergency_revoke_audit_preserves_lock_and_emits_no_release(privacy_app):
    """The required audit and lock release commit together (docs/operator-audit.md)."""
    env = privacy_app
    await _acquire_lock(env, alias="bob", resource_key="audit-rollback/bob")
    await env.db.execute(
        "ALTER TABLE {{tables.audit_log}} ADD CONSTRAINT reject_emergency_revoke_audit "
        "CHECK (event_type <> 'reservations.revoke') NOT VALID"
    )
    try:
        response = await _send_member_request(
            env,
            alias="alice",
            method="POST",
            path="/v1/reservations/revoke",
            body={"prefix": "audit-rollback/"},
        )
        assert response.status_code == 500, response.text
        assert (
            await env.db.fetch_value(
                "SELECT count(*) FROM {{tables.reservations}} WHERE team_id=$1 AND resource_key=$2",
                TEAM,
                "audit-rollback/bob",
            )
            == 1
        )
        assert not [context for event, context in env.dispatched if event == "reservation.released"]
    finally:
        await env.db.execute(
            "ALTER TABLE {{tables.audit_log}} DROP CONSTRAINT reject_emergency_revoke_audit"
        )


@pytest.mark.asyncio
async def test_empty_prefix_emergency_revoke_keeps_another_teams_reservations(privacy_app):
    """A team's emergency override has the authenticated team's exact bound."""
    env = privacy_app
    for alias in ("bob", "carol"):
        await _acquire_lock(env, alias=alias, resource_key=f"all/{alias}")
    other_team = "cleanup-neighbor:example.test"
    await env.app.state.awid_registry_client.register_team(
        domain="example.test", name="cleanup-neighbor", display_name="Cleanup neighbor",
        team_did_key=env.team_did, visibility="public",
        namespace_controller_signing_key=env.namespace_sk,
    )
    await _connect_registered_member(env, alias="other", team_id=other_team)
    await _acquire_lock(env, alias="other", resource_key="all/other", team_id=other_team)
    response = await _send_member_request(
        env,
        alias="alice",
        method="POST",
        path="/v1/reservations/revoke",
        body={},
    )
    assert response.status_code == 200, response.text
    assert set(response.json()["revoked_keys"]) == {"all/bob", "all/carol"}
    assert (
        await env.db.fetch_value(
            "SELECT count(*) FROM {{tables.reservations}} WHERE team_id=$1", TEAM
        )
        == 0
    )
    assert (
        await env.db.fetch_value(
            "SELECT resource_key FROM {{tables.reservations}} WHERE team_id=$1", other_team
        )
        == "all/other"
    )
    events = [context for event, context in env.dispatched if event == "reservation.released"]
    assert {context["resource_key"] for context in events} == {"all/bob", "all/carol"}
    assert (
        await env.db.fetch_value(
            "SELECT actor_did_key FROM {{tables.audit_log}} WHERE team_id=$1 AND event_type='reservations.revoke'",
            TEAM,
        )
        == env.actors["alice"].did
    )
