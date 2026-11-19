from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
from uuid import UUID, uuid4

import os

import pytest
import pytest_asyncio
from redis.asyncio import Redis

from aweb.events import team_events_channel_name
from aweb.presence import get_agent_presence
from test_dashboard_privacy import TEAM
from test_dashboard_privacy import privacy_app as privacy_app
from test_workspace_liveness_http import _send_member_request

from aweb.messaging.waiting import get_waiting_agents, register_waiting

import aweb.lifecycle as lifecycle
from aweb.lifecycle import (
    LifecycleActor,
    LifecycleCascadeRequest,
    apply_lifecycle_cascade,
    plan_lifecycle_cascade,
)


async def _seed_workspace_with_claim(aweb_db, *, identity_scope: str = "local"):
    team_id = "backend:acme.com"
    agent_id = uuid4()
    workspace_id = uuid4()
    await aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, 'acme.com', 'backend', 'did:key:z6Mkteam')
        """,
        team_id,
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (agent_id, team_id, did_key, alias, identity_scope, role)
        VALUES ($1, $2, 'did:key:z6Mkalice', 'alice', $3, 'developer')
        """,
        agent_id,
        team_id,
        identity_scope,
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.workspaces}} (
            workspace_id, team_id, agent_id, alias, human_name, role,
            workspace_type, last_seen_at
        )
        VALUES ($1, $2, $3, 'alice', 'Alice', 'developer', 'manual', $4)
        """,
        workspace_id,
        team_id,
        agent_id,
        datetime.now(timezone.utc) - timedelta(hours=1),
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.task_claims}}
            (team_id, workspace_id, alias, human_name, task_ref, claimed_at)
        VALUES ($1, $2, 'alice', 'Alice', 'backend-777', NOW())
        """,
        team_id,
        workspace_id,
    )
    return team_id, agent_id, workspace_id


@pytest_asyncio.fixture
async def lifecycle_redis():
    """Use the isolated gate Redis; never flush keys owned by another test."""
    async with Redis.from_url(os.environ["REDIS_URL"], decode_responses=True) as redis:
        await redis.ping()
        yield redis


async def _seed_waiting_chat(aweb_db, *, team_id: str, agent_id):
    session_id = uuid4()
    did = "did:key:z6Mkalice"
    await aweb_db.execute(
        """
        INSERT INTO {{tables.chat_sessions}} (
            session_id, team_id, created_by, wait_seconds, wait_started_at,
            wait_started_by
        )
        VALUES ($1, $2, $3, 60, NOW(), $4)
        """,
        session_id,
        team_id,
        did,
        agent_id,
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.chat_participants}} (session_id, did, agent_id, alias)
        VALUES ($1, $2, $3, 'alice')
        """,
        session_id,
        did,
        agent_id,
    )
    return session_id, did


def _request(*, team_id: str, agent_id, workspace_id) -> LifecycleCascadeRequest:
    return LifecycleCascadeRequest(
        operation="delete_local_workspace",
        actor=LifecycleActor(
            actor_id=str(agent_id),
            actor_type="agent",
            authority="test",
        ),
        team_id=team_id,
        target_agent_id=str(agent_id),
        target_workspace_ids=(str(workspace_id),),
        workspace_scope="explicit",
        require_identity_scope="local",
        stale_before=datetime.now(timezone.utc) - timedelta(minutes=10),
        mark_local_agent_deleted=True,
    )


@dataclass(frozen=True)
class _ServiceLifecycle:
    request: LifecycleCascadeRequest
    task_ref: str
    session_id: str
    did: str
    workspace_id: UUID


@pytest_asyncio.fixture
async def service_lifecycle(privacy_app):
    """Create docs/aweb-sot.md:1256–1262 coordination through its real owners."""
    env = privacy_app
    actor = env.actors["alice"]
    task = await _send_member_request(
        env,
        alias="alice",
        method="POST",
        path="/v1/tasks",
        body={"title": "Retirement transaction control"},
    )
    assert task.status_code == 200, task.text
    task_body = task.json()
    assert isinstance(task_body, dict), task_body
    task_ref = task_body.get("task_ref")
    assert isinstance(task_ref, str), task_body
    claim = await _send_member_request(
        env,
        alias="alice",
        method="PATCH",
        path=f"/v1/tasks/{task_ref}",
        body={"status": "in_progress"},
    )
    assert claim.status_code == 200, claim.text
    heartbeat = await _send_member_request(
        env,
        alias="alice",
        method="POST",
        path="/v1/agents/heartbeat",
    )
    assert heartbeat.status_code == 200, heartbeat.text
    chat = await _send_member_request(
        env,
        alias="alice",
        method="POST",
        path="/v1/chat/sessions",
        body={"to_dids": [env.actors["bob"].did], "message": "Retirement wait", "wait_seconds": 60},
    )
    assert chat.status_code == 200, chat.text
    chat_body = chat.json()
    assert isinstance(chat_body, dict), chat_body
    session_id = chat_body.get("session_id")
    assert isinstance(session_id, str), chat_body
    await register_waiting(env.redis, session_id, actor.did)
    case = _ServiceLifecycle(
        request=LifecycleCascadeRequest(
            operation="delete_local_workspace",
            actor=LifecycleActor(actor_id=str(actor.id), actor_type="agent", authority="test"),
            team_id=TEAM,
            target_agent_id=str(actor.id),
            target_workspace_ids=(str(actor.workspace),),
            workspace_scope="explicit",
            require_identity_scope="local",
            agent_disposition=lifecycle.AgentDisposition.DELETED,
        ),
        task_ref=task_ref,
        session_id=session_id,
        did=actor.did,
        workspace_id=actor.workspace,
    )
    await _assert_service_coordination_retained(env, case=case)
    return env, case


@asynccontextmanager
async def _lifecycle_subscription(env, *, case: _ServiceLifecycle):
    channels = {f"events:{case.workspace_id}", team_events_channel_name(TEAM)}
    async with env.redis.pubsub() as pubsub:
        await pubsub.subscribe(*channels)
        # Observe this subscription's actual acknowledgement before mutating.
        acknowledged = set()
        async with asyncio.timeout(5):
            async for message in pubsub.listen():
                if message["type"] == "subscribe":
                    acknowledged.add(message["channel"])
                    if acknowledged == channels:
                        break
        yield pubsub


async def _unclaimed_events_through_barrier(env, pubsub, *, case: _ServiceLifecycle):
    """Drain both real channels through ordered markers, including the empty case."""
    channels = {f"events:{case.workspace_id}", team_events_channel_name(TEAM)}
    marker = str(uuid4())
    for channel in channels:
        await env.redis.publish(channel, json.dumps({"lifecycle_test_barrier": marker}))
    reached = set()
    events = []
    async with asyncio.timeout(5):
        async for message in pubsub.listen():
            if message["type"] != "message":
                continue
            event = json.loads(message["data"])
            assert isinstance(event, dict), event
            if event.get("lifecycle_test_barrier") == marker:
                reached.add(message["channel"])
                if reached == channels:
                    return events
            elif event.get("type") == "task.unclaimed":
                assert isinstance(event.get("task_ref"), str), event
                events.append((message["channel"], event["task_ref"]))
    raise AssertionError("Redis did not deliver both lifecycle test barriers")


async def _assert_service_coordination_retained(env, *, case: _ServiceLifecycle):
    assert await get_agent_presence(env.redis, str(case.workspace_id)) is not None
    assert await get_waiting_agents(env.redis, case.session_id, [case.did]) == [case.did]
    assert (
        await env.db.fetch_value(
            "SELECT count(*) FROM {{tables.task_claims}} WHERE workspace_id=$1 AND task_ref=$2",
            case.workspace_id,
            case.task_ref,
        )
        == 1
    )
    assert (
        await env.db.fetch_value(
            "SELECT deleted_at FROM {{tables.workspaces}} WHERE workspace_id=$1",
            case.workspace_id,
        )
        is None
    )


async def _assert_service_coordination_released(env, *, case: _ServiceLifecycle):
    assert await get_agent_presence(env.redis, str(case.workspace_id)) is None
    # A strict read distinguishes deletion from the display helper's outage omission.
    assert await env.redis.zscore(f"chat:waiting:{case.session_id}", case.did) is None
    assert (
        await env.db.fetch_value(
            "SELECT count(*) FROM {{tables.task_claims}} WHERE workspace_id=$1",
            case.workspace_id,
        )
        == 0
    )
    assert await env.db.fetch_value(
        "SELECT deleted_at IS NOT NULL FROM {{tables.workspaces}} WHERE workspace_id=$1",
        case.workspace_id,
    )
    assert await env.db.fetch_value(
        "SELECT wait_started_by IS NULL FROM {{tables.chat_sessions}} WHERE session_id=$1",
        UUID(case.session_id),
    )


async def _wait_for_committed_delivery(env, *, operation_id: str):
    async with asyncio.timeout(5):
        while True:
            state = await env.db.fetch_one(
                """SELECT count(*) AS total,
                          count(*) FILTER (WHERE delivered_at IS NULL) AS pending
                   FROM {{tables.lifecycle_side_effect_outbox}} WHERE operation_id=$1""",
                UUID(operation_id),
            )
            assert state is not None
            assert state["total"] == 4
            if state["pending"] == 0:
                return
            await asyncio.sleep(0.01)


@pytest.mark.asyncio
async def test_lifecycle_plan_reports_claims_without_mutating(service_lifecycle):
    env, case = service_lifecycle
    async with _lifecycle_subscription(env, case=case) as pubsub:
        result = await plan_lifecycle_cascade(env.db, case.request, redis=env.redis)
        assert result.dry_run is True
        assert result.errors == ()
        assert result.task_unclaim_count == 1
        assert result.chat_participant_cleanup_count == 1
        assert result.presence_cleanup_status == "planned"
        assert result.workspace_changes[0].workspace_id == str(case.workspace_id)
        assert await _unclaimed_events_through_barrier(env, pubsub, case=case) == []
    await _assert_service_coordination_retained(env, case=case)
    assert (
        await env.db.fetch_value("SELECT count(*) FROM {{tables.lifecycle_side_effect_outbox}}")
        == 0
    )


@pytest.mark.asyncio
async def test_lifecycle_outer_transaction_defers_side_effects_until_commit(service_lifecycle):
    env, case = service_lifecycle
    async with _lifecycle_subscription(env, case=case) as pubsub:
        async with env.db.transaction() as outer:
            result = await apply_lifecycle_cascade(outer, env.redis, case.request)
            assert result.errors == ()
            assert result.post_commit_status == "pending"
            assert result.outbox_operation_id is not None
            assert await _unclaimed_events_through_barrier(env, pubsub, case=case) == []
            assert await get_agent_presence(env.redis, str(case.workspace_id)) is not None
            assert await get_waiting_agents(env.redis, case.session_id, [case.did]) == [case.did]
        await _wait_for_committed_delivery(env, operation_id=result.outbox_operation_id)
        assert sorted(await _unclaimed_events_through_barrier(env, pubsub, case=case)) == sorted(
            [
                (f"events:{case.workspace_id}", case.task_ref),
                (team_events_channel_name(TEAM), case.task_ref),
            ]
        )
    await _assert_service_coordination_released(env, case=case)


@pytest.mark.asyncio
async def test_lifecycle_outer_transaction_rollback_emits_no_side_effects(service_lifecycle):
    env, case = service_lifecycle

    class RollbackControl(Exception):
        """Abort the caller's real transaction after the lifecycle savepoint."""

    async with _lifecycle_subscription(env, case=case) as pubsub:
        with pytest.raises(RollbackControl):
            async with env.db.transaction() as outer:
                result = await apply_lifecycle_cascade(outer, env.redis, case.request)
                assert result.errors == ()
                assert result.post_commit_status == "pending"
                assert result.outbox_operation_id is not None
                assert await _unclaimed_events_through_barrier(env, pubsub, case=case) == []
                raise RollbackControl
        replay = await lifecycle.replay_lifecycle_side_effects(
            env.db,
            env.redis,
            operation_id=result.outbox_operation_id,
        )
        assert replay.attempted_count == 0
        assert replay.pending_count == 0
        assert await _unclaimed_events_through_barrier(env, pubsub, case=case) == []
    await _assert_service_coordination_retained(env, case=case)
    assert (
        await env.db.fetch_value("SELECT count(*) FROM {{tables.lifecycle_side_effect_outbox}}")
        == 0
    )


@pytest.mark.asyncio
async def test_lifecycle_plain_handle_still_publishes_side_effects(service_lifecycle):
    env, case = service_lifecycle
    async with _lifecycle_subscription(env, case=case) as pubsub:
        result = await apply_lifecycle_cascade(env.db, env.redis, case.request)
        assert result.errors == ()
        assert result.post_commit_status == "completed"
        assert result.outbox_operation_id is not None
        assert sorted(await _unclaimed_events_through_barrier(env, pubsub, case=case)) == sorted(
            [
                (f"events:{case.workspace_id}", case.task_ref),
                (team_events_channel_name(TEAM), case.task_ref),
            ]
        )
    await _assert_service_coordination_released(env, case=case)


@pytest.mark.asyncio
async def test_lifecycle_committed_outbox_replays_after_process_death(
    aweb_cloud_db, monkeypatch, lifecycle_redis
):
    db = aweb_cloud_db.aweb_db
    team_id, agent_id, workspace_id = await _seed_workspace_with_claim(db)
    await _seed_waiting_chat(db, team_id=team_id, agent_id=agent_id)
    observed: list[str] = []

    monkeypatch.setattr(
        lifecycle,
        "_schedule_replay_after_outer_transaction",
        lambda *_args, **_kwargs: None,
    )

    async def _capture_workspace_event(_redis, _event):
        observed.append("workspace_event")
        return 1

    async def _capture_team_event(_redis, _event):
        observed.append("team_event")
        return 1

    async def _capture_presence(_redis, _workspace_ids):
        observed.append("presence")
        return 1

    async def _capture_waiting(_redis, _session_id, _did):
        observed.append("waiting")

    monkeypatch.setattr(lifecycle, "publish_event", _capture_workspace_event)
    monkeypatch.setattr(lifecycle, "publish_team_event", _capture_team_event)
    monkeypatch.setattr(lifecycle, "clear_workspace_presence", _capture_presence)
    monkeypatch.setattr(lifecycle, "unregister_waiting_strict", _capture_waiting)

    async with db.transaction() as outer:
        result = await apply_lifecycle_cascade(
            outer,
            lifecycle_redis,
            _request(team_id=team_id, agent_id=agent_id, workspace_id=workspace_id),
        )
        assert result.post_commit_status == "pending"

    assert observed == []
    assert (
        await db.fetch_value(
            "SELECT COUNT(*) FROM {{tables.task_claims}} WHERE workspace_id = $1",
            workspace_id,
        )
        == 0
    )
    assert (
        await db.fetch_value(
            """
        SELECT COUNT(*)
        FROM {{tables.lifecycle_side_effect_outbox}}
        WHERE delivered_at IS NULL
        """
        )
        == 4
    )

    assert result.outbox_operation_id is not None
    replay = await lifecycle.replay_lifecycle_side_effects(
        db,
        lifecycle_redis,
        operation_id=result.outbox_operation_id,
    )

    assert replay.delivered_count == 4
    assert replay.pending_count == 0
    assert set(observed) == {
        "workspace_event",
        "team_event",
        "presence",
        "waiting",
    }


@pytest.mark.asyncio
async def test_operation_replay_drains_more_than_the_global_batch_default(
    aweb_cloud_db, monkeypatch, lifecycle_redis
):
    db = aweb_cloud_db.aweb_db
    team_id, agent_id, workspace_id = await _seed_workspace_with_claim(db)
    await db.execute(
        """
        INSERT INTO {{tables.task_claims}} (
            team_id, workspace_id, alias, human_name, task_ref, claimed_at
        )
        SELECT $1, $2, 'alice', 'Alice', 'backend-' || series, NOW()
        FROM generate_series(1, 50) AS series
        """,
        team_id,
        workspace_id,
    )
    published: list[str] = []

    monkeypatch.setattr(
        lifecycle,
        "_schedule_replay_after_outer_transaction",
        lambda *_args, **_kwargs: None,
    )

    async def _capture_workspace_event(_redis, _event):
        published.append("workspace")
        return 1

    async def _capture_team_event(_redis, _event):
        published.append("team")
        return 1

    async def _capture_presence(_redis, _workspace_ids):
        return 1

    monkeypatch.setattr(lifecycle, "publish_event", _capture_workspace_event)
    monkeypatch.setattr(lifecycle, "publish_team_event", _capture_team_event)
    monkeypatch.setattr(lifecycle, "clear_workspace_presence", _capture_presence)

    async with db.transaction() as outer:
        result = await apply_lifecycle_cascade(
            outer,
            lifecycle_redis,
            _request(team_id=team_id, agent_id=agent_id, workspace_id=workspace_id),
        )

    replay = await lifecycle.replay_lifecycle_side_effects(
        db,
        lifecycle_redis,
        operation_id=result.outbox_operation_id,
    )

    assert replay.delivered_count == 103
    assert replay.pending_count == 0
    assert published.count("workspace") == 51
    assert published.count("team") == 51


@pytest.mark.asyncio
async def test_lifecycle_duplicate_replay_does_not_redeliver_completed_rows(
    aweb_cloud_db, monkeypatch, lifecycle_redis
):
    db = aweb_cloud_db.aweb_db
    team_id, agent_id, workspace_id = await _seed_workspace_with_claim(db)
    published: list[str] = []

    async def _capture_workspace_event(_redis, _event):
        published.append("workspace")
        return 1

    async def _capture_team_event(_redis, _event):
        published.append("team")
        return 1

    async def _capture_presence(_redis, _workspace_ids):
        return 1

    monkeypatch.setattr(lifecycle, "publish_event", _capture_workspace_event)
    monkeypatch.setattr(lifecycle, "publish_team_event", _capture_team_event)
    monkeypatch.setattr(lifecycle, "clear_workspace_presence", _capture_presence)

    result = await apply_lifecycle_cascade(
        db,
        lifecycle_redis,
        _request(team_id=team_id, agent_id=agent_id, workspace_id=workspace_id),
    )
    assert result.post_commit_status == "completed"
    assert published == ["workspace", "team"]

    duplicate = await lifecycle.replay_lifecycle_side_effects(db, lifecycle_redis)

    assert duplicate.attempted_count == 0
    assert duplicate.delivered_count == 0
    assert duplicate.pending_count == 0
    assert published == ["workspace", "team"]


@pytest.mark.asyncio
async def test_chat_waiting_failure_stays_pending_then_replays(
    aweb_cloud_db, monkeypatch, lifecycle_redis
):
    db = aweb_cloud_db.aweb_db
    team_id, agent_id, workspace_id = await _seed_workspace_with_claim(db)
    session_id, did = await _seed_waiting_chat(db, team_id=team_id, agent_id=agent_id)
    redis = lifecycle_redis
    await register_waiting(redis, str(session_id), did)
    assert await get_waiting_agents(redis, str(session_id), [did]) == [did]
    real_zrem = redis.zrem
    release_attempts = 0

    async def _fail_first_waiting_release(key: str, *members: str):
        nonlocal release_attempts
        release_attempts += 1
        if release_attempts == 1:
            raise ConnectionError("injected waiting-release outage")
        return await real_zrem(key, *members)

    monkeypatch.setattr(redis, "zrem", _fail_first_waiting_release)

    async def _capture_event(_redis, _event):
        return 1

    async def _capture_presence(_redis, workspace_ids):
        return len(workspace_ids)

    monkeypatch.setattr(lifecycle, "publish_event", _capture_event)
    monkeypatch.setattr(lifecycle, "publish_team_event", _capture_event)
    monkeypatch.setattr(lifecycle, "clear_workspace_presence", _capture_presence)

    result = await apply_lifecycle_cascade(
        db,
        redis,
        _request(team_id=team_id, agent_id=agent_id, workspace_id=workspace_id),
    )

    assert result.post_commit_status == "failed"
    assert result.chat_waiting_cleanup_status == "failed"
    assert (
        await db.fetch_value(
            """
        SELECT COUNT(*)
        FROM {{tables.lifecycle_side_effect_outbox}}
        WHERE operation_id = $1
          AND effect_kind = 'chat_waiting_clear'
          AND delivered_at IS NULL
        """,
            UUID(result.outbox_operation_id),
        )
        == 1
    )

    replay = await lifecycle.replay_lifecycle_side_effects(
        db,
        redis,
        operation_id=result.outbox_operation_id,
    )

    assert replay.delivered_count == 1
    assert replay.pending_count == 0
    assert release_attempts == 2
    assert await get_waiting_agents(redis, str(session_id), [did]) == []


@pytest.mark.asyncio
async def test_global_replay_advances_past_a_full_failed_batch(
    aweb_cloud_db, monkeypatch, lifecycle_redis
):
    db = aweb_cloud_db.aweb_db
    await db.execute(
        """
        INSERT INTO {{tables.lifecycle_side_effect_outbox}} (
            operation_id, effect_order, team_id, effect_kind, payload_json,
            created_at
        )
        SELECT
            gen_random_uuid(),
            0,
            'backend:acme.com',
            'workspace_task_unclaimed',
            jsonb_build_object(
                'workspace_id', gen_random_uuid()::text,
                'team_id', 'backend:acme.com',
                'task_ref', 'poison-' || series,
                'alias', 'alice',
                'timestamp', NOW()::text
            ),
            NOW() - INTERVAL '1 hour'
        FROM generate_series(1, 100) AS series
        """
    )
    await db.execute(
        """
        INSERT INTO {{tables.lifecycle_side_effect_outbox}} (
            operation_id, effect_order, team_id, effect_kind, payload_json,
            created_at
        )
        VALUES (
            gen_random_uuid(), 0, 'backend:acme.com', 'presence_clear',
            '{"workspace_ids": ["healthy-workspace"]}'::jsonb, NOW()
        )
        """
    )
    presence_clears: list[tuple[str, ...]] = []

    async def _fail_event(_redis, _event):
        raise RuntimeError("poison event")

    async def _capture_presence(_redis, workspace_ids):
        presence_clears.append(tuple(workspace_ids))
        return len(workspace_ids)

    monkeypatch.setattr(lifecycle, "publish_event", _fail_event)
    monkeypatch.setattr(lifecycle, "clear_workspace_presence", _capture_presence)

    first = await lifecycle.replay_lifecycle_side_effects(db, lifecycle_redis)
    scheduled_failure_count = await db.fetch_value(
        """
        SELECT COUNT(*)
        FROM {{tables.lifecycle_side_effect_outbox}}
        WHERE effect_kind = 'workspace_task_unclaimed'
          AND attempt_count = 1
          AND next_attempt_at > created_at
        """
    )
    second = await lifecycle.replay_lifecycle_side_effects(db, lifecycle_redis)

    assert first.attempted_count == 100
    assert scheduled_failure_count == 100
    assert first.delivered_count == 0
    assert second.attempted_count == 1
    assert second.delivered_count == 1
    assert second.pending_count == 100
    assert presence_clears == [("healthy-workspace",)]


@pytest.mark.asyncio
async def test_lifecycle_apply_reports_post_commit_event_failures(
    aweb_cloud_db, monkeypatch, lifecycle_redis
):
    team_id, agent_id, workspace_id = await _seed_workspace_with_claim(aweb_cloud_db.aweb_db)
    cleared_workspaces: list[list[str]] = []

    async def _fail_workspace_event(_redis, _event):
        raise RuntimeError("publish failed")

    async def _capture_team_event(_redis, _event):
        return 1

    async def _capture_presence(_redis, workspace_ids):
        cleared_workspaces.append(list(workspace_ids))
        return len(workspace_ids)

    monkeypatch.setattr(lifecycle, "publish_event", _fail_workspace_event)
    monkeypatch.setattr(lifecycle, "publish_team_event", _capture_team_event)
    monkeypatch.setattr(lifecycle, "clear_workspace_presence", _capture_presence)

    result = await apply_lifecycle_cascade(
        aweb_cloud_db.aweb_db,
        lifecycle_redis,
        _request(team_id=team_id, agent_id=agent_id, workspace_id=workspace_id),
    )

    assert result.errors == ()
    assert result.post_commit_status == "failed"
    assert result.task_unclaim_count == 1
    assert result.workspace_event_count == 0
    assert result.team_event_count == 1
    assert len(result.failed_event_intents) == 1
    assert result.failed_event_intents[0].event_kind == "workspace_task_unclaimed"
    assert result.presence_cleanup_status == "cleared"
    assert {str(workspace_id), str(agent_id)} in [set(ids) for ids in cleared_workspaces]

    claim_count = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.task_claims}} WHERE workspace_id = $1",
        workspace_id,
    )
    workspace_deleted_at = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT deleted_at FROM {{tables.workspaces}} WHERE workspace_id = $1",
        workspace_id,
    )
    assert claim_count == 0
    assert workspace_deleted_at is not None
    assert (
        await aweb_cloud_db.aweb_db.fetch_value(
            """
        SELECT COUNT(*)
        FROM {{tables.lifecycle_side_effect_outbox}}
        WHERE delivered_at IS NULL
        """
        )
        == 1
    )

    retried: list[str] = []

    async def _retry_workspace_event(_redis, event):
        retried.append(event.task_ref)
        return 1

    monkeypatch.setattr(lifecycle, "publish_event", _retry_workspace_event)
    replay = await lifecycle.replay_lifecycle_side_effects(
        aweb_cloud_db.aweb_db,
        lifecycle_redis,
        operation_id=result.outbox_operation_id,
    )
    duplicate = await lifecycle.replay_lifecycle_side_effects(
        aweb_cloud_db.aweb_db,
        lifecycle_redis,
        operation_id=result.outbox_operation_id,
    )

    assert replay.workspace_event_count == 1
    assert replay.pending_count == 0
    assert retried == ["backend-777"]
    assert duplicate.attempted_count == 0


@pytest.mark.asyncio
async def test_lifecycle_archive_global_agent_cleans_coordination_state(
    aweb_cloud_db, monkeypatch, lifecycle_redis
):
    team_id, agent_id, workspace_id = await _seed_workspace_with_claim(
        aweb_cloud_db.aweb_db,
        identity_scope="global",
    )
    second_workspace_id = uuid4()
    session_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        "ALTER TABLE {{tables.agents}} ADD COLUMN signing_key_enc BYTEA"
    )
    await aweb_cloud_db.aweb_db.execute(
        "UPDATE {{tables.agents}} SET signing_key_enc = $2 WHERE agent_id = $1",
        agent_id,
        b"hosted-key",
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.workspaces}} (
            workspace_id, team_id, agent_id, alias, human_name, role,
            workspace_type, last_seen_at
        )
        VALUES ($1, $2, $3, 'alice-laptop', 'Alice', 'developer', 'manual', $4)
        """,
        second_workspace_id,
        team_id,
        agent_id,
        datetime.now(timezone.utc) - timedelta(hours=2),
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.task_claims}}
            (team_id, workspace_id, alias, human_name, task_ref, claimed_at)
        VALUES ($1, $2, 'alice-laptop', 'Alice', 'backend-778', NOW())
        """,
        team_id,
        second_workspace_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.reservations}} (
            team_id, resource_key, holder_alias, holder_agent_id, expires_at
        )
        VALUES ($1, 'repo:deploy', 'alice', $2, NOW() + INTERVAL '1 hour')
        """,
        team_id,
        agent_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_sessions}} (
            session_id, team_id, created_by, wait_seconds, wait_started_at,
            wait_started_by
        )
        VALUES ($1, $2, 'did:key:z6Mkalice', 60, NOW(), $3)
        """,
        session_id,
        team_id,
        agent_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.chat_participants}} (session_id, did, agent_id, alias)
        VALUES ($1, 'did:key:z6Mkalice', $2, 'alice')
        """,
        session_id,
        agent_id,
    )
    redis = lifecycle_redis
    await register_waiting(redis, str(session_id), "did:key:z6Mkalice")

    async def _publish_noop(_redis, _event):
        return 1

    async def _clear_presence_noop(_redis, workspace_ids):
        return len(workspace_ids)

    monkeypatch.setattr(lifecycle, "publish_event", _publish_noop)
    monkeypatch.setattr(lifecycle, "publish_team_event", _publish_noop)
    monkeypatch.setattr(lifecycle, "clear_workspace_presence", _clear_presence_noop)

    result = await apply_lifecycle_cascade(
        aweb_cloud_db.aweb_db,
        redis,
        LifecycleCascadeRequest(
            operation="archive_global_agent",
            actor=LifecycleActor(
                actor_id="support-1",
                actor_type="support",
                authority="test",
            ),
            team_id=team_id,
            target_agent_id=str(agent_id),
            workspace_scope="all_for_agent",
            require_identity_scope="global",
        ),
    )

    assert result.errors == ()
    assert result.identity_archived is True
    assert result.task_unclaim_count == 2
    assert result.reservation_release_count == 1
    assert result.chat_participant_cleanup_count == 1
    assert result.chat_waiting_cleanup_status == "cleared"
    assert result.chat_waiting_session_clear_count == 1
    assert result.chat_waiting_cleared_count == 1
    assert len(result.workspace_changes) == 2
    assert "agent.archive_global" in result.completed_mutations
    assert await get_waiting_agents(redis, str(session_id), ["did:key:z6Mkalice"]) == []

    agent = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT status, deleted_at, signing_key_enc
        FROM {{tables.agents}}
        WHERE agent_id = $1
        """,
        agent_id,
    )
    claim_count = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.task_claims}} WHERE team_id = $1",
        team_id,
    )
    reservation_count = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.reservations}} WHERE holder_agent_id = $1",
        agent_id,
    )
    participant_count = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.chat_participants}} WHERE agent_id = $1 AND left_at IS NULL",
        agent_id,
    )
    wait_started_by = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT wait_started_by FROM {{tables.chat_sessions}} WHERE session_id = $1",
        session_id,
    )
    active_workspace_count = await aweb_cloud_db.aweb_db.fetch_value(
        """
        SELECT COUNT(*)
        FROM {{tables.workspaces}}
        WHERE agent_id = $1 AND deleted_at IS NULL
        """,
        agent_id,
    )

    assert agent["status"] == "archived"
    assert agent["deleted_at"] is not None
    assert agent["signing_key_enc"] == b"hosted-key"
    assert claim_count == 0
    assert reservation_count == 0
    assert participant_count == 0
    assert wait_started_by is None
    assert active_workspace_count == 0


@pytest.mark.asyncio
async def test_lifecycle_archive_global_agent_without_workspace_archives_agent(
    aweb_cloud_db,
):
    team_id = "backend:acme.com"
    agent_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, 'acme.com', 'backend', 'did:key:z6Mkteam')
        """,
        team_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (agent_id, team_id, did_key, alias, identity_scope, role)
        VALUES ($1, $2, 'did:key:z6Mkalice', 'alice', 'global', 'developer')
        """,
        agent_id,
        team_id,
    )

    result = await apply_lifecycle_cascade(
        aweb_cloud_db.aweb_db,
        None,
        LifecycleCascadeRequest(
            operation="archive_global_agent",
            actor=LifecycleActor(
                actor_id="support-1",
                actor_type="support",
                authority="test",
            ),
            team_id=team_id,
            target_agent_id=str(agent_id),
            workspace_scope="all_for_agent",
            require_identity_scope="global",
        ),
    )

    agent = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT status, deleted_at FROM {{tables.agents}} WHERE agent_id = $1",
        agent_id,
    )
    assert result.errors == ()
    assert result.workspace_changes == ()
    assert result.identity_archived is True
    assert result.post_commit_status == "skipped_no_redis"
    assert result.outbox_operation_id is not None
    assert agent["status"] == "archived"
    assert agent["deleted_at"] is not None


@pytest.mark.asyncio
async def test_lifecycle_archive_global_agent_rejects_workspace_subset(
    aweb_cloud_db,
):
    team_id, agent_id, workspace_id = await _seed_workspace_with_claim(
        aweb_cloud_db.aweb_db,
        identity_scope="global",
    )

    result = await apply_lifecycle_cascade(
        aweb_cloud_db.aweb_db,
        None,
        LifecycleCascadeRequest(
            operation="archive_global_agent",
            actor=LifecycleActor(
                actor_id="support-1",
                actor_type="support",
                authority="test",
            ),
            team_id=team_id,
            target_agent_id=str(agent_id),
            target_workspace_ids=(str(workspace_id),),
            workspace_scope="explicit",
            require_identity_scope="global",
        ),
    )

    assert [error.code for error in result.errors] == [
        "global_archive_requires_all_agent_workspaces"
    ]
    agent = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT status, deleted_at FROM {{tables.agents}} WHERE agent_id = $1",
        agent_id,
    )
    workspace_deleted_at = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT deleted_at FROM {{tables.workspaces}} WHERE workspace_id = $1",
        workspace_id,
    )
    claim_count = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.task_claims}} WHERE workspace_id = $1",
        workspace_id,
    )
    assert agent["status"] == "active"
    assert agent["deleted_at"] is None
    assert workspace_deleted_at is None
    assert claim_count == 1


@pytest.mark.asyncio
async def test_lifecycle_archive_global_agent_rejects_non_global_target(
    aweb_cloud_db,
):
    team_id, agent_id, workspace_id = await _seed_workspace_with_claim(
        aweb_cloud_db.aweb_db,
        identity_scope="local",
    )

    result = await apply_lifecycle_cascade(
        aweb_cloud_db.aweb_db,
        None,
        LifecycleCascadeRequest(
            operation="archive_global_agent",
            actor=LifecycleActor(
                actor_id="support-1",
                actor_type="support",
                authority="test",
            ),
            team_id=team_id,
            target_agent_id=str(agent_id),
            workspace_scope="all_for_agent",
            require_identity_scope="global",
        ),
    )

    assert "lifecycle_identity_scope_precondition_failed" in {error.code for error in result.errors}
    agent = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT status, deleted_at FROM {{tables.agents}} WHERE agent_id = $1",
        agent_id,
    )
    workspace_deleted_at = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT deleted_at FROM {{tables.workspaces}} WHERE workspace_id = $1",
        workspace_id,
    )
    claim_count = await aweb_cloud_db.aweb_db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.task_claims}} WHERE workspace_id = $1",
        workspace_id,
    )
    assert agent["status"] == "active"
    assert agent["deleted_at"] is None
    assert workspace_deleted_at is None
    assert claim_count == 1


@pytest.mark.asyncio
async def test_chat_waiting_cleanup_wakes_the_remaining_participants(aweb_cloud_db):
    from aweb.agent_wake import AgentWakeHub, did_wake_key

    db = aweb_cloud_db.aweb_db
    team_id, agent_id, workspace_id = await _seed_workspace_with_claim(db)
    session_id, did = await _seed_waiting_chat(db, team_id=team_id, agent_id=agent_id)
    bob_did = f"did:key:z6Mkbob{uuid4().hex}"
    await db.execute(
        "INSERT INTO {{tables.chat_participants}} (session_id, did, alias) VALUES ($1, $2, 'bob')",
        session_id,
        bob_did,
    )
    async with Redis.from_url(
        os.environ.get("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True
    ) as redis:
        await register_waiting(redis, str(session_id), did)
        hub = AgentWakeHub(redis)
        await hub.start()
        try:
            async with hub.subscribe([did_wake_key(bob_did)]) as wakes:
                result = await apply_lifecycle_cascade(
                    db,
                    redis,
                    _request(team_id=team_id, agent_id=agent_id, workspace_id=workspace_id),
                )
                assert result.chat_waiting_cleanup_status == "cleared"
                await asyncio.wait_for(wakes.wait(), 1.0)
                assert wakes.take().kinds == {"chat"}
        finally:
            await hub.close()
        assert await redis.zscore(f"chat:waiting:{session_id}", did) is None
