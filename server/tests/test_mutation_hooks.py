from __future__ import annotations

from uuid import uuid4

import pytest

import aweb.lifecycle as lifecycle
import aweb.mutation_hooks as mutation_hooks
from aweb.hooks import HeldMutationEvents
import test_mcp_mutation_hook_parity as mutation_fixtures
from aweb.events import (
    ChatMessageEvent,
    MessageDeliveredEvent,
    ReservationAcquiredEvent,
    TaskClaimedEvent,
    TaskCreatedEvent,
    TaskUnclaimedEvent,
    TeamReservationAcquiredEvent,
    TeamReservationReleasedEvent,
    TeamReservationRenewedEvent,
    TeamTaskClaimedEvent,
    TeamTaskStatusChangedEvent,
    TeamTaskUnclaimedEvent,
)


mutation_server = mutation_fixtures.server
MUTATION_TEAM = mutation_fixtures.TEAM


class _DbShim:
    def __init__(self, aweb_db) -> None:
        self._db = aweb_db

    def get_manager(self, name: str = "aweb"):
        return self._db


@pytest.mark.asyncio
async def test_agent_deleted_cascade_releases_claims_events_and_presence(
    aweb_cloud_db, monkeypatch
):
    agent_id = uuid4()
    workspace_id = uuid4()
    published_workspace: list[object] = []
    published_team: list[object] = []
    cleared_workspaces: list[list[str]] = []

    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:z6Mkteam')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (agent_id, team_id, did_key, alias, identity_scope, role, inbound_mode)
        VALUES ($1, 'backend:acme.com', 'did:key:z6Mkdeleted', 'alice', 'local', 'developer', 'open')
        """,
        agent_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.workspaces}} (
            workspace_id, team_id, agent_id, alias, human_name, role, workspace_type
        )
        VALUES ($1, 'backend:acme.com', $2, 'alice', 'Alice', 'developer', 'manual')
        """,
        workspace_id,
        agent_id,
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.task_claims}}
            (team_id, workspace_id, alias, human_name, task_ref, claimed_at)
        VALUES ('backend:acme.com', $1, 'alice', 'Alice', 'backend-777', NOW())
        """,
        workspace_id,
    )

    async def _capture_workspace_event(_redis, event):
        published_workspace.append(event)
        return 1

    async def _capture_team_event(_redis, event):
        published_team.append(event)
        return 1

    async def _capture_clear_presence(_redis, workspace_ids):
        cleared_workspaces.append(list(workspace_ids))
        return len(workspace_ids)

    monkeypatch.setattr(lifecycle, "publish_event", _capture_workspace_event)
    monkeypatch.setattr(lifecycle, "publish_team_event", _capture_team_event)
    monkeypatch.setattr(lifecycle, "clear_workspace_presence", _capture_clear_presence)

    handler = mutation_hooks.create_mutation_handler(
        redis=object(), db_infra=_DbShim(aweb_cloud_db.aweb_db)
    )
    await handler("agent.deleted", {"agent_id": str(agent_id)})

    workspace_row = await aweb_cloud_db.aweb_db.fetch_one(
        """
        SELECT deleted_at FROM {{tables.workspaces}}
        WHERE workspace_id = $1
        """,
        workspace_id,
    )
    claim_count = await aweb_cloud_db.aweb_db.fetch_value(
        """
        SELECT COUNT(*) FROM {{tables.task_claims}}
        WHERE workspace_id = $1
        """,
        workspace_id,
    )

    assert workspace_row["deleted_at"] is not None
    assert claim_count == 0
    assert any(
        event.type == "task.unclaimed"
        and event.workspace_id == str(workspace_id)
        and event.task_ref == "backend-777"
        and event.alias == "alice"
        for event in published_workspace
    )
    assert any(
        event.type == "task.unclaimed"
        and event.team_id == "backend:acme.com"
        and event.task_ref == "backend-777"
        and event.alias == "alice"
        for event in published_team
    )
    assert {str(workspace_id), str(agent_id)} in [
        set(ids) for ids in cleared_workspaces
    ]


@pytest.mark.asyncio
async def test_mutation_handler_backfills_from_did_aw_from_agent_id(
    aweb_cloud_db, monkeypatch
):
    agent_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ('backend:acme.com', 'acme.com', 'backend', 'did:key:z6Mkteam')
        """
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.agents}} (agent_id, team_id, did_key, did_aw, alias, identity_scope, role, inbound_mode)
        VALUES ($1, 'backend:acme.com', 'did:key:z6Mkalice', 'did:aw:alice', 'alice', 'global', 'developer', 'open')
        """,
        agent_id,
    )

    await aweb_cloud_db.aweb_db.execute(
        "UPDATE {{tables.agents}} SET did_aw_verified_key=did_key WHERE agent_id=$1",
        agent_id,
    )
    seen: dict[str, str] = {}

    def _capture_translate(event_type: str, ctx: dict):
        seen["event_type"] = event_type
        seen["from_did_aw"] = str(ctx.get("from_did_aw") or "")
        return None

    monkeypatch.setattr(mutation_hooks, "_translate", _capture_translate)
    monkeypatch.setattr(
        mutation_hooks, "_translate_team_event", lambda event_type, ctx: None
    )

    handler = mutation_hooks.create_mutation_handler(
        redis=None, db_infra=_DbShim(aweb_cloud_db.aweb_db)
    )
    await handler(
        "message.sent",
        {
            "team_id": "backend:acme.com",
            "from_agent_id": str(agent_id),
            "to_agent_id": str(uuid4()),
            "message_id": str(uuid4()),
            "subject": "hello",
        },
    )

    assert seen["event_type"] == "message.sent"
    assert seen["from_did_aw"] == "did:aw:alice"


@pytest.mark.asyncio
async def test_mutation_handler_backfills_actor_workspace_id_from_agent_id(
    aweb_cloud_db, monkeypatch
):
    agent_id = uuid4()
    workspace_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.workspaces}} (workspace_id, team_id, agent_id, alias, workspace_type)
        VALUES ($1, 'backend:acme.com', $2, 'alice', 'manual')
        """,
        workspace_id,
        agent_id,
    )

    seen: dict[str, str] = {}

    def _capture_translate(event_type: str, ctx: dict):
        seen["event_type"] = event_type
        seen["actor_workspace_id"] = str(ctx.get("actor_workspace_id") or "")
        return None

    monkeypatch.setattr(mutation_hooks, "_translate", _capture_translate)
    monkeypatch.setattr(
        mutation_hooks, "_translate_team_event", lambda event_type, ctx: None
    )

    handler = mutation_hooks.create_mutation_handler(
        redis=None, db_infra=_DbShim(aweb_cloud_db.aweb_db)
    )
    await handler(
        "task.created",
        {
            "team_id": "backend:acme.com",
            "actor_agent_id": str(agent_id),
            "task_ref": "backend-1234",
            "title": "Fix workspace split",
        },
    )

    assert seen["event_type"] == "task.created"
    assert seen["actor_workspace_id"] == str(workspace_id)


def test_translate_uses_workspace_ids_for_workspace_oriented_events():
    actor_workspace_id = str(uuid4())
    holder_workspace_id = str(uuid4())

    task_event = mutation_hooks._translate(
        "task.created",
        {
            "actor_agent_id": str(uuid4()),
            "actor_workspace_id": actor_workspace_id,
            "team_id": "backend:acme.com",
            "task_ref": "backend-1234",
            "title": "Fix workspace split",
        },
    )
    reservation_event = mutation_hooks._translate(
        "reservation.acquired",
        {
            "holder_agent_id": str(uuid4()),
            "holder_workspace_id": holder_workspace_id,
            "resource_key": "repo:backend",
            "ttl_seconds": 60,
        },
    )

    assert isinstance(task_event, TaskCreatedEvent)
    assert task_event.workspace_id == actor_workspace_id
    assert isinstance(reservation_event, ReservationAcquiredEvent)
    assert reservation_event.workspace_id == holder_workspace_id


def test_translate_redacts_encrypted_mail_subjects():
    delivered = mutation_hooks._translate(
        "message.sent",
        {
            "to_agent_id": str(uuid4()),
            "from_agent_id": str(uuid4()),
            "message_id": str(uuid4()),
            "subject": "secret subject",
            "content_mode": "encrypted_v2",
        },
    )
    assert isinstance(delivered, MessageDeliveredEvent)
    assert delivered.subject == ""
    assert delivered.encrypted is True
    assert delivered.content_mode == "encrypted_v2"

    team_event = mutation_hooks._translate_team_event(
        "message.sent",
        {
            "team_id": "backend:acme.com",
            "from_alias": "alice",
            "to_alias": "bob",
            "message_id": str(uuid4()),
            "subject": "secret subject",
            "content_mode": "encrypted_v2",
        },
    )
    assert team_event is None


@pytest.mark.asyncio
async def test_mutation_handler_publishes_dashboard_team_events(
    aweb_cloud_db, monkeypatch
):
    published: list[object] = []

    async def _capture_publish_team(_redis, event):
        published.append(event)
        return 1

    monkeypatch.setattr(mutation_hooks, "publish_team_event", _capture_publish_team)

    handler = mutation_hooks.create_mutation_handler(
        redis=None, db_infra=_DbShim(aweb_cloud_db.aweb_db)
    )

    await handler(
        "message.acknowledged",
        {
            "team_id": "backend:acme.com",
            "alias": "bob",
            "from_alias": "alice",
            "subject": "Ship dashboard events",
        },
    )
    await handler(
        "chat.message_sent",
        {
            "team_id": "backend:acme.com",
            "from_alias": "alice",
            "to_aliases": ["bob", "carol"],
            "preview": "short preview",
        },
    )
    await handler(
        "task.status_changed",
        {
            "team_id": "backend:acme.com",
            "task_ref": "backend-1234",
            "title": "Ship dashboard events",
            "old_status": "open",
            "new_status": "closed",
        },
    )
    await handler(
        "task.claimed",
        {
            "team_id": "backend:acme.com",
            "task_ref": "backend-1234",
            "title": "Ship dashboard events",
            "alias": "alice",
        },
    )
    await handler(
        "task.unclaimed",
        {
            "team_id": "backend:acme.com",
            "task_ref": "backend-1234",
            "title": "Ship dashboard events",
            "alias": "alice",
        },
    )
    await handler(
        "reservation.acquired",
        {
            "team_id": "backend:acme.com",
            "alias": "alice",
            "resource_key": "repo:backend",
        },
    )
    await handler(
        "reservation.released",
        {
            "team_id": "backend:acme.com",
            "alias": "alice",
            "resource_key": "repo:backend",
        },
    )
    await handler(
        "reservation.renewed",
        {
            "team_id": "backend:acme.com",
            "alias": "alice",
            "resource_key": "repo:backend",
        },
    )

    assert len(published) == 6
    assert all(event.team_id == "backend:acme.com" for event in published)

    assert isinstance(published[0], TeamTaskStatusChangedEvent)
    assert published[0].task_ref == "backend-1234"
    assert published[0].title == "Ship dashboard events"
    assert published[0].old_status == "open"
    assert published[0].new_status == "closed"

    assert isinstance(published[1], TeamTaskClaimedEvent)
    assert published[1].task_ref == "backend-1234"
    assert published[1].title == "Ship dashboard events"
    assert published[1].alias == "alice"

    assert isinstance(published[2], TeamTaskUnclaimedEvent)
    assert published[2].task_ref == "backend-1234"
    assert published[2].title == "Ship dashboard events"
    assert published[2].alias == "alice"

    assert isinstance(published[3], TeamReservationAcquiredEvent)
    assert published[3].alias == "alice"
    assert published[3].paths == ["repo:backend"]

    assert isinstance(published[4], TeamReservationReleasedEvent)
    assert published[4].alias == "alice"
    assert published[4].paths == ["repo:backend"]

    assert isinstance(published[5], TeamReservationRenewedEvent)
    assert published[5].alias == "alice"
    assert published[5].paths == ["repo:backend"]


def test_translate_task_claim_events():
    claimed = mutation_hooks._translate(
        "task.claimed",
        {
            "workspace_id": "workspace-1",
            "task_ref": "backend-1234",
            "alias": "alice",
            "title": "Claimed task",
        },
    )
    assert isinstance(claimed, TaskClaimedEvent)
    assert claimed.workspace_id == "workspace-1"
    assert claimed.task_ref == "backend-1234"
    assert claimed.alias == "alice"
    assert claimed.title == "Claimed task"

    unclaimed = mutation_hooks._translate(
        "task.unclaimed",
        {
            "workspace_id": "workspace-1",
            "task_ref": "backend-1234",
            "alias": "alice",
            "title": "Claimed task",
        },
    )
    assert isinstance(unclaimed, TaskUnclaimedEvent)
    assert unclaimed.workspace_id == "workspace-1"
    assert unclaimed.task_ref == "backend-1234"
    assert unclaimed.alias == "alice"
    assert unclaimed.title == "Claimed task"


@pytest.mark.asyncio
async def test_task_status_changed_cascade_publishes_one_team_status_event(
    mutation_server,
):
    env = mutation_server
    task = await env.rest_task(
        "pilot", "POST", "/v1/tasks", {"title": "Ship dashboard events"}
    )
    env.app.state.on_mutation = mutation_hooks.create_mutation_handler(
        env.redis, env.app.state.db
    )
    before = len(env.published)
    await env.rest_task(
        "pilot", "PATCH", f"/v1/tasks/{task['task_ref']}", {"status": "in_progress"}
    )
    observed = env.published[before:]
    team = [
        event
        for channel, event in observed
        if channel == f"team-events:{MUTATION_TEAM}"
    ]
    status = [event for event in team if event["type"] == "task.status_changed"]
    assert len(status) == 1
    assert status[0]["task_ref"] == task["task_ref"]
    assert (status[0]["old_status"], status[0]["new_status"]) == ("open", "in_progress")
    assert any(event["type"] == "task.claimed" for event in team)
    assert any(
        channel == f"events:{env.workspaces['pilot']}" for channel, _ in observed
    )


@pytest.mark.asyncio
async def test_task_status_changed_claims_with_workspace_id_not_agent_id(
    mutation_server,
):
    env = mutation_server
    task = await env.rest_task(
        "pilot", "POST", "/v1/tasks", {"title": "Fix workspace split"}
    )
    assert str(env.workspaces["pilot"]) != env.agents["pilot"]
    env.app.state.on_mutation = mutation_hooks.create_mutation_handler(
        env.redis, env.app.state.db
    )
    before = len(env.published)
    await env.rest_task(
        "pilot", "PATCH", f"/v1/tasks/{task['task_ref']}", {"status": "in_progress"}
    )
    claim = await env.db.fetch_one(
        "SELECT workspace_id FROM {{tables.task_claims}} WHERE team_id=$1 AND task_ref=$2",
        MUTATION_TEAM,
        task["task_ref"],
    )
    assert claim["workspace_id"] == env.workspaces["pilot"]
    assert any(
        channel == f"events:{env.workspaces['pilot']}"
        and event["type"] == "task.claimed"
        for channel, event in env.published[before:]
    )


@pytest.mark.asyncio
async def test_status_change_cascade_announces_released_claims_and_changes_no_claim(
    mutation_server, caplog
):
    env = mutation_server
    task = await env.rest_task(
        "pilot", "POST", "/v1/tasks", {"title": "Release in the transaction"}
    )
    path = f"/v1/tasks/{task['task_ref']}"
    await env.rest_task("pilot", "PATCH", path, {"status": "in_progress"})
    held = HeldMutationEvents()
    committed = []

    async def retain(event_type, context):
        committed.append((event_type, dict(context)))
        return await held.record(event_type, context)

    env.app.state.on_mutation = retain
    await env.rest_task("pilot", "PATCH", path, {"status": "closed"})
    closed = [context for kind, context in committed if kind == "task.status_changed"]
    assert len(closed) == 1
    assert closed[0]["released_claim_workspace_ids"] == [str(env.workspaces["pilot"])]
    # A later real writer reopens and claims before the earlier commit's hook
    # is delivered. The original event cannot release this new claim.
    env.app.state.on_mutation = None
    await env.rest_task("bob", "PATCH", path, {"status": "open"})
    await env.rest_task("bob", "PATCH", path, {"status": "in_progress"})
    handler = mutation_hooks.create_mutation_handler(env.redis, env.app.state.db)
    before = len(env.published)
    with caplog.at_level("WARNING"):
        await held.fire(handler)
        await env.rest_task("pilot", "GET", path)
        announced = env.published[before:]
        omitted = dict(closed[0])
        omitted.pop("released_claim_workspace_ids")
        before_empty = len(env.published)
        await handler(
            "task.status_changed", {**closed[0], "released_claim_workspace_ids": []}
        )
        await handler("task.status_changed", omitted)
        await env.rest_task("pilot", "GET", path)
    assert caplog.records == []
    workspace_channel = f"events:{env.workspaces['pilot']}"
    team_channel = f"team-events:{MUTATION_TEAM}"
    unclaimed = [
        (channel, event)
        for channel, event in announced
        if event["type"] == "task.unclaimed"
    ]
    assert [
        (channel, event["task_ref"], event["alias"]) for channel, event in unclaimed
    ] == [
        (workspace_channel, task["task_ref"], "pilot"),
        (team_channel, task["task_ref"], "pilot"),
    ]
    assert (
        len(
            [
                event
                for channel, event in announced
                if channel == team_channel and event["type"] == "task.status_changed"
            ]
        )
        == 1
    )
    empty = env.published[before_empty:]
    assert not any(event["type"] == "task.unclaimed" for _, event in empty)
    assert (
        len(
            [
                event
                for channel, event in empty
                if channel == team_channel and event["type"] == "task.status_changed"
            ]
        )
        == 2
    )
    remaining = await env.db.fetch_all(
        "SELECT workspace_id FROM {{tables.task_claims}} WHERE team_id=$1 AND task_ref=$2",
        MUTATION_TEAM,
        task["task_ref"],
    )
    assert [row["workspace_id"] for row in remaining] == [env.workspaces["bob"]]


@pytest.mark.asyncio
async def test_a_chat_event_uses_the_aliases_and_preview_its_sender_supplied(
    aweb_cloud_db, monkeypatch
):
    import asyncpg.connection

    published: list[object] = []

    async def _capture_publish(_redis, event):
        published.append(event)
        return 1

    monkeypatch.setattr(mutation_hooks, "publish_event", _capture_publish)
    chat_reads: list[str] = []
    execute = asyncpg.connection.Connection._execute

    async def observed(connection, query, *args, **kwargs):
        if "chat_participants" in query or "chat_messages" in query:
            chat_reads.append(query)
        return await execute(connection, query, *args, **kwargs)

    monkeypatch.setattr(asyncpg.connection.Connection, "_execute", observed)
    import os

    from redis.asyncio import Redis

    async with Redis.from_url(
        os.environ.get("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True
    ) as redis:
        handler = mutation_hooks.create_mutation_handler(
            redis=redis, db_infra=_DbShim(aweb_cloud_db.aweb_db)
        )
        await _send_supplied_chat_event(handler)

    chat_events = [event for event in published if isinstance(event, ChatMessageEvent)]
    assert len(chat_events) == 1
    assert chat_events[0].to_aliases == ["bob"]
    assert chat_events[0].preview == "hello bob"
    assert chat_reads == []


@pytest.mark.asyncio
@pytest.mark.parametrize("same_workspace", [False, True])
async def test_mail_event_batches_presence_without_shifting_missing_hashes(
    mutation_server, monkeypatch, same_workspace
):
    from aweb.presence import clear_workspace_presence, update_agent_presence
    from redis.asyncio.client import Pipeline

    redis = mutation_server.redis
    recipient = str(uuid4())
    sender = recipient if same_workspace else str(uuid4())
    await update_agent_presence(
        redis, workspace_id=recipient, alias="recipient", team_id=MUTATION_TEAM
    )
    batches = []
    original = Pipeline.execute

    async def observe(pipeline, *args, **kwargs):
        keys = [
            commands[1]
            for commands, _ in pipeline.command_stack
            if commands[0] == "HGETALL"
        ]
        if keys:
            batches.append(keys)
        return await original(pipeline, *args, **kwargs)

    monkeypatch.setattr(Pipeline, "execute", observe)
    event = MessageDeliveredEvent(workspace_id=recipient, from_workspace=sender)
    try:
        await mutation_hooks._enrich(event, redis, _DbShim(mutation_server.db), {})
        expected_keys = list(
            dict.fromkeys((f"presence:{sender}", f"presence:{recipient}"))
        )
        assert batches == [expected_keys]
        assert event.from_alias == ("recipient" if same_workspace else "")
        assert event.to_alias == "recipient"
    finally:
        await clear_workspace_presence(redis, [recipient])


async def _send_supplied_chat_event(handler):
    await handler(
        "chat.message_sent",
        {
            "team_id": "backend:acme.com",
            "session_id": str(uuid4()),
            "message_id": str(uuid4()),
            "from_agent_id": str(uuid4()),
            "from_alias": "alice",
            "to_aliases": ["bob"],
            "preview": "hello bob",
        },
    )
