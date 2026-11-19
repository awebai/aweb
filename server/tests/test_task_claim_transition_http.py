"""Real writers preserve active claim ownership and committed mutation facts."""

import asyncio
import json
from contextlib import asynccontextmanager
from uuid import UUID, uuid4

import pytest
import pytest_asyncio

from aweb.embedding import OutboxRecoveryOwnership
from aweb.events import team_events_channel_name
from test_coordination_state_http import request_as
from test_dashboard_privacy import TEAM, privacy_stack


@pytest_asyncio.fixture
async def privacy_app(shared_test_pool, monkeypatch):
    async with privacy_stack(
        shared_test_pool, monkeypatch, outbox_recovery=OutboxRecoveryOwnership.HOST
    ) as env:
        yield env


@pytest.mark.asyncio
async def test_retained_deleted_claim_is_locked_but_never_reacquired(privacy_app):
    # docs/aweb-sot.md:1155–1165 and the retained-path cleanup contract.
    env = privacy_app
    created = await request_as(
        env, alias="alice", method="POST", path="/v1/tasks", payload={"title": "Retained claim"}
    )
    assert created.status_code == 200, created.text
    ref = created.json()["task_ref"]
    path = f"/v1/tasks/{ref}"
    claimed = await request_as(
        env, alias="alice", method="PATCH", path=path, payload={"status": "in_progress"}
    )
    assert claimed.status_code == 200, claimed.text
    old_workspace = env.actors["alice"].workspace
    claim_before = await env.db.fetch_one(
        "SELECT * FROM {{tables.task_claims}} WHERE team_id=$1 AND task_ref=$2", TEAM, ref
    )
    # Retained claims on deleted workspaces are supported cleanup input. This
    # changes lifecycle state, never authentication or the claim decision.
    await env.db.execute(
        "UPDATE {{tables.workspaces}} SET deleted_at=NOW() WHERE workspace_id=$1",
        old_workspace,
    )
    workspace_before = await env.db.fetch_one(
        "SELECT * FROM {{tables.workspaces}} WHERE workspace_id=$1", old_workspace
    )
    refused = await request_as(
        env, alias="alice", method="PATCH", path=path, payload={"status": "in_progress"}
    )
    assert refused.status_code == 409, refused.text
    assert "already in progress" in refused.json()["detail"]
    assert dict(
        await env.db.fetch_one(
            "SELECT * FROM {{tables.workspaces}} WHERE workspace_id=$1", old_workspace
        )
    ) == dict(workspace_before)
    assert dict(
        await env.db.fetch_one(
            "SELECT * FROM {{tables.task_claims}} WHERE team_id=$1 AND task_ref=$2", TEAM, ref
        )
    ) == dict(claim_before)

    # Explicit release still includes the retained deleted path in its lock set.
    reopened = await request_as(
        env, alias="bob", method="PATCH", path=path, payload={"status": "open"}
    )
    assert reopened.status_code == 200, reopened.text
    assert (
        await env.db.fetch_value(
            "SELECT COUNT(*) FROM {{tables.task_claims}} WHERE team_id=$1 AND task_ref=$2",
            TEAM,
            ref,
        )
        == 0
    )
    connected = await request_as(env, alias="alice", method="POST", path="/v1/connect", payload={})
    assert connected.status_code == 200, connected.text
    live_workspace = UUID(connected.json()["workspace_id"])
    assert live_workspace != old_workspace
    assert connected.json()["agent_id"] == str(env.actors["alice"].id)
    taken = await request_as(
        env, alias="alice", method="PATCH", path=path, payload={"status": "in_progress"}
    )
    assert taken.status_code == 200, taken.text
    owner = await env.db.fetch_one(
        "SELECT workspace_id, alias FROM {{tables.task_claims}} WHERE team_id=$1 AND task_ref=$2",
        TEAM,
        ref,
    )
    assert owner["workspace_id"] == live_workspace
    assert owner["alias"] == "alice"


@pytest.mark.asyncio
@pytest.mark.parametrize("later_write", ["reopen", "delete"])
async def test_later_writer_cannot_replace_or_suppress_committed_claim_event(
    privacy_app, monkeypatch, later_write
):
    # docs/aweb-sot.md:1155–1166: the hook announces the actual transaction.
    env = privacy_app
    parent = await request_as(
        env, alias="bob", method="POST", path="/v1/tasks", payload={"title": "Later parent"}
    )
    assert parent.status_code == 200, parent.text
    created = await request_as(
        env, alias="alice", method="POST", path="/v1/tasks", payload={"title": "Before claim"}
    )
    assert created.status_code == 200, created.text
    task_id, ref = created.json()["task_id"], created.json()["task_ref"]
    path = f"/v1/tasks/{ref}"
    committed, resume = asyncio.Event(), asyncio.Event()
    real_transaction = env.db.transaction
    first_transaction = True

    @asynccontextmanager
    async def pause_first_committed_transaction():
        # Scheduler instrumentation only: the original pgdbm transaction and
        # every query/result are untouched. Pause after its real COMMIT, before
        # returning to the first HTTP writer; a second signed writer then runs.
        nonlocal first_transaction
        pause = first_transaction
        first_transaction = False
        async with real_transaction() as tx:
            yield tx
        if pause:
            committed.set()
            await resume.wait()

    monkeypatch.setattr(env.db, "transaction", pause_first_committed_transaction)
    async with env.redis.pubsub() as stream:
        await stream.subscribe(team_events_channel_name(TEAM))
        subscribed = await stream.get_message(timeout=5)
        assert subscribed is not None and subscribed["type"] == "subscribe"
        first = asyncio.create_task(
            request_as(
                env,
                alias="alice",
                method="PATCH",
                path=path,
                payload={"status": "in_progress", "title": "Alice committed title"},
            )
        )
        try:
            async with asyncio.timeout(5):
                await committed.wait()
            row = await env.db.fetch_one(
                "SELECT status,assignee_alias FROM {{tables.tasks}} WHERE task_id=$1", UUID(task_id)
            )
            assert (row["status"], row["assignee_alias"]) == ("in_progress", "alice")
            assert (
                await env.db.fetch_value(
                    "SELECT alias FROM {{tables.task_claims}} WHERE team_id=$1 AND task_ref=$2",
                    TEAM,
                    ref,
                )
                == "alice"
            )
            if later_write == "reopen":
                later = await request_as(
                    env,
                    alias="bob",
                    method="PATCH",
                    path=path,
                    payload={
                        "status": "open",
                        "assignee_alias": "bob",
                        "title": "Bob later title",
                        "parent_task_id": parent.json()["task_id"],
                    },
                )
            else:
                later = await request_as(env, alias="bob", method="DELETE", path=path)
            assert later.status_code == 200, later.text
        finally:
            resume.set()
            response = await first
        assert response.status_code == (200 if later_write == "reopen" else 404), response.text
        transitions = [
            context
            for event, context in env.dispatched
            if event == "task.status_changed"
            and context.get("task_id") == task_id
            and context.get("actor_alias") == "alice"
        ]
        assert len(transitions) == 1
        transition = transitions[0]
        assert (transition["old_status"], transition["new_status"]) == ("open", "in_progress")
        assert transition["assignee_alias"] == "alice"
        assert transition["title"] == "Alice committed title"
        assert transition["parent_task_id"] is None
        assert transition["claim_preacquired"] is True
        assert transition["actor_workspace_id"] == str(env.actors["alice"].workspace)
        barrier = {"type": "test.claim.barrier", "id": uuid4().hex}
        await env.redis.publish(team_events_channel_name(TEAM), json.dumps(barrier))
        events = []
        async with asyncio.timeout(5):
            while True:
                frame = await stream.get_message(ignore_subscribe_messages=True, timeout=1)
                if frame is None:
                    continue
                event = json.loads(frame["data"])
                if event == barrier:
                    break
                events.append(event)
        claims = [event for event in events if event["type"] == "task.claimed"]
        assert len(claims) == 1
        assert (claims[0]["task_ref"], claims[0]["alias"], claims[0]["title"]) == (
            ref,
            "alice",
            "Alice committed title",
        )
