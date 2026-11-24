"""Real writers preserve active claim ownership and committed mutation facts."""

import asyncio
import json
from contextlib import asynccontextmanager
from uuid import UUID, uuid4

import pytest
import pytest_asyncio

from aweb.claims import lock_task_claim_workspaces_on
from aweb.coordination.tasks_service import update_task
from aweb.db import TransactionInfra
from aweb.embedding import OutboxRecoveryOwnership
from aweb.team_auth_deps import TeamIdentity
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
async def test_parent_closure_waits_for_child_before_locking_their_shared_workspace(
    privacy_app,
):
    env = privacy_app
    parent = await request_as(
        env, alias="alice", method="POST", path="/v1/tasks",
        payload={"title": "Parent lock order"},
    )
    assert parent.status_code == 200, parent.text
    parent_ref = parent.json()["task_ref"]
    child = await request_as(
        env, alias="alice", method="POST", path="/v1/tasks",
        payload={"title": "Child lock order", "parent_task_id": parent_ref},
    )
    assert child.status_code == 200, child.text
    child_id = UUID(child.json()["task_id"])
    child_ref = child.json()["task_ref"]
    for ref in (parent_ref, child_ref):
        claimed = await request_as(
            env, alias="alice", method="PATCH", path=f"/v1/tasks/{ref}",
            payload={"status": "in_progress"},
        )
        assert claimed.status_code == 200, claimed.text

    pending = None
    try:
        async with env.db.transaction() as child_tx:
            await child_tx.fetch_value(
                "SELECT task_id FROM {{tables.tasks}} WHERE task_id=$1 FOR UPDATE",
                child_id,
            )
            pending = asyncio.create_task(
                request_as(
                    env, alias="bob", method="PATCH", path=f"/v1/tasks/{parent_ref}",
                    payload={"status": "closed"},
                )
            )
            async with asyncio.timeout(4):
                # PostgreSQL supplies the barrier. Only continue when the
                # parent transaction actually waits on the held child row.
                while not await child_tx.fetch_value("""
                    SELECT EXISTS (
                        SELECT 1 FROM pg_stat_activity a
                        WHERE a.datname = current_database()
                          AND pg_backend_pid() = ANY(pg_blocking_pids(a.pid))
                    )
                """):
                    assert not pending.done()
                locked = await lock_task_claim_workspaces_on(
                    child_tx, team_id=TEAM, task_refs=[child_ref]
                )
                assert [row["workspace_id"] for row in locked] == [
                    env.actors["alice"].workspace
                ]
                alice = env.actors["alice"]
                updated = await update_task(
                    TransactionInfra(env.infra, child_tx),
                    actor=TeamIdentity(
                        team_id=TEAM, agent_id=str(alice.id), alias="alice",
                        did_key=alice.did, did_aw="", address="", identity_scope="local",
                        certificate_id="privacy-alice",
                    ),
                    on_mutation=None,
                    ref=child_ref,
                    title="Child write committed before closing",
                )
                assert updated["title"] == "Child write committed before closing"
        response = await pending
        assert response.status_code == 200, response.text
        assert response.json()["auto_closed"] == [{
            "task_id": str(child_id),
            "task_ref": child_ref,
            "title": "Child write committed before closing",
        }]
    finally:
        if pending is not None and not pending.done():
            pending.cancel()
            await asyncio.gather(pending, return_exceptions=True)

    assert await env.db.fetch_value(
        "SELECT status FROM {{tables.tasks}} WHERE task_id=$1", child_id
    ) == "closed"
    assert not await env.db.fetch_all(
        "SELECT task_ref FROM {{tables.task_claims}} WHERE team_id=$1 AND task_ref=ANY($2::text[])",
        TEAM,
        [parent_ref, child_ref],
    )
    assert await env.db.fetch_value(
        "SELECT focus_task_ref FROM {{tables.workspaces}} WHERE workspace_id=$1",
        env.actors["alice"].workspace,
    ) is None
    releases = {
        ctx["task_ref"]: ctx["released_claim_workspace_ids"]
        for name, ctx in env.dispatched
        if name == "task.status_changed" and ctx["new_status"] == "closed"
    }
    assert releases == {
        parent_ref: [str(env.actors["alice"].workspace)],
        child_ref: [str(env.actors["alice"].workspace)],
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("later_write", ["reopen", "delete"])
async def test_later_writer_cannot_replace_or_suppress_committed_claim_event(
    privacy_app, monkeypatch, later_write
):
    # docs/aweb-sot.md:1155–1166: the hook announces the actual transaction.
    env = privacy_app
    parent = await request_as(
        env,
        alias="bob",
        method="POST",
        path="/v1/tasks",
        payload={"title": "Later parent"},
    )
    assert parent.status_code == 200, parent.text
    created = await request_as(
        env,
        alias="alice",
        method="POST",
        path="/v1/tasks",
        payload={"title": "Before claim"},
    )
    assert created.status_code == 200, created.text
    task_id, ref = created.json()["task_id"], created.json()["task_ref"]
    path = f"/v1/tasks/{ref}"
    committed, resume = asyncio.Event(), asyncio.Event()
    real_transaction = env.db.transaction
    first_task_commit = True

    @asynccontextmanager
    async def pause_first_committed_task_transaction():
        # Scheduler instrumentation only: the original pgdbm transaction and
        # every query/result are untouched. Admission may commit earlier work;
        # pause only after the target task's real COMMIT, before returning to
        # the first HTTP writer. A second signed writer then runs.
        nonlocal first_task_commit
        async with real_transaction() as tx:
            yield tx
        if not first_task_commit:
            return
        row = await env.db.fetch_one(
            "SELECT status,assignee_alias,title FROM {{tables.tasks}} WHERE task_id=$1",
            UUID(task_id),
        )
        if row and (row["status"], row["assignee_alias"], row["title"]) == (
            "in_progress",
            "alice",
            "Alice committed title",
        ):
            first_task_commit = False
            committed.set()
            await resume.wait()

    monkeypatch.setattr(env.db, "transaction", pause_first_committed_task_transaction)
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
                "SELECT status,assignee_alias FROM {{tables.tasks}} WHERE task_id=$1",
                UUID(task_id),
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
        assert response.status_code == (200 if later_write == "reopen" else 404), (
            response.text
        )
        transitions = [
            context
            for event, context in env.dispatched
            if event == "task.status_changed"
            and context.get("task_id") == task_id
            and context.get("actor_alias") == "alice"
        ]
        assert len(transitions) == 1
        transition = transitions[0]
        assert (transition["old_status"], transition["new_status"]) == (
            "open",
            "in_progress",
        )
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
                frame = await stream.get_message(
                    ignore_subscribe_messages=True, timeout=1
                )
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
