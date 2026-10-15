"""Human assignment and the dashboard's assignment wake contract.

Real task router, service, Postgres and mutation translation; only the
already-authenticated team identity and Redis publish boundary are supplied.
"""
import json
from uuid import UUID, uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from aweb.coordination.tasks_service import create_task, update_task
from aweb.mutation_hooks import create_mutation_handler
from aweb.service_errors import ValidationError
from test_tasks_http import TEAM_ID, _build_tasks_app, _seed_team


class RecordingRedis:
    def __init__(self):
        self.events = []

    async def publish(self, channel, message):
        if channel == f"team-events:{TEAM_ID}":
            self.events.append(json.loads(message))
        return 0


async def _member(db, alias, *, human=False, team_id=TEAM_ID, deleted=False):
    member_id = uuid4()
    await db.execute(
        """INSERT INTO {{tables.agents}}
           (agent_id, team_id, did_key, alias, agent_type, identity_scope, deleted_at)
           VALUES ($1, $2, $3, $4, $5, 'local', CASE WHEN $6 THEN NOW() END)""",
        member_id, team_id, f"did:key:{member_id}", alias,
        "human" if human else "agent", deleted,
    )
    return member_id


@pytest.mark.asyncio
@pytest.mark.parametrize("by_id", [False, True])
async def test_human_is_a_valid_assignee_for_create_update_and_filter(aweb_cloud_db, by_id):
    db = aweb_cloud_db.aweb_db
    await _seed_team(db)
    human_id = await _member(db, "requester", human=True)
    await _member(db, "alice")
    app = _build_tasks_app(db)
    target = str(human_id) if by_id else "requester"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        made = await client.post("/v1/tasks", json={"title": "Approve the proposal", "assignee_alias": target})
        assert made.status_code == 200, made.text
        assert made.json()["assignee_alias"] == "requester"
        ref = made.json()["task_ref"]
        reassigned = await client.patch(f"/v1/tasks/{ref}", json={"assignee_alias": "alice"})
        assert reassigned.status_code == 200, reassigned.text
        assigned = await client.patch(f"/v1/tasks/{ref}", json={"assignee_alias": target})
        assert assigned.status_code == 200, assigned.text
        assert assigned.json()["assignee_alias"] == "requester"
        listed = await client.get("/v1/tasks", params={"assignee_alias": target})
        assert listed.status_code == 200, listed.text
        assert [task["task_ref"] for task in listed.json()["tasks"]] == [ref]


@pytest.mark.asyncio
@pytest.mark.parametrize("invalid", ["missing", "deleted", "other-team"])
@pytest.mark.parametrize("by_id", [False, True])
async def test_human_assignment_still_requires_a_live_member_of_this_team(aweb_cloud_db, invalid, by_id):
    db = aweb_cloud_db.aweb_db
    await _seed_team(db)
    app = _build_tasks_app(db)
    member_id = uuid4()
    if invalid == "other-team":
        await db.execute("""INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
                          VALUES ('other:acme.com', 'acme.com', 'other', 'did:key:other-team')""")
    if invalid != "missing":
        member_id = await _member(db, "unavailable", human=True,
                                  team_id="other:acme.com" if invalid == "other-team" else TEAM_ID,
                                  deleted=invalid == "deleted")
    target = str(member_id) if by_id else "unavailable"
    with pytest.raises(ValidationError, match="Assignee agent not found in this team"):
        await create_task(app.state.db, team_id=TEAM_ID, created_by_alias="alice", title="Refuse", assignee_alias=target)
    made = await create_task(app.state.db, team_id=TEAM_ID, created_by_alias="alice", title="Unassigned")
    with pytest.raises(ValidationError, match="Assignee agent not found in this team"):
        await update_task(app.state.db, team_id=TEAM_ID, ref=made["task_ref"], actor_alias="alice", assignee_alias=target)
    assert await db.fetch_value("SELECT assignee_alias FROM {{tables.tasks}} WHERE task_id = $1", UUID(made["task_id"])) is None


@pytest.mark.asyncio
async def test_team_task_created_and_status_events_carry_the_human_assignee(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    await _seed_team(db)
    await _member(db, "requester", human=True)
    redis = RecordingRedis()
    app = _build_tasks_app(db)
    app.state.on_mutation = create_mutation_handler(redis, app.state.db)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        made = await client.post("/v1/tasks", json={"title": "Approve", "assignee_alias": "requester"})
        assert made.status_code == 200, made.text
        ref = made.json()["task_ref"]
        closed = await client.patch(f"/v1/tasks/{ref}", json={"status": "closed"})
        assert closed.status_code == 200, closed.text
    assert [event["type"] for event in redis.events] == ["task.created", "task.status_changed"]
    assert [event["assignee_alias"] for event in redis.events] == ["requester", "requester"]
    for event in redis.events:
        assert event["team_id"] == TEAM_ID


@pytest.mark.asyncio
async def test_assignment_changes_wake_once_with_old_and_new_aliases(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    await _seed_team(db)
    human_id = await _member(db, "requester", human=True)
    await _member(db, "alice")
    redis = RecordingRedis()
    app = _build_tasks_app(db)
    app.state.on_mutation = create_mutation_handler(redis, app.state.db)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        made = await client.post("/v1/tasks", json={"title": "Question"})
        assert made.status_code == 200, made.text
        ref = made.json()["task_ref"]
        for changes in (
            {"assignee_alias": "requester"},
            {"assignee_alias": str(human_id)},  # Same resolved alias: no event.
            {"notes": "No assignment change"},
            {"assignee_alias": None},
            {"assignee_alias": None},  # Already unassigned: no event.
            {"assignee_alias": "requester", "status": "closed"},
            {"status": "in_progress"},  # Claim implicitly assigns the actor.
        ):
            changed = await client.patch(f"/v1/tasks/{ref}", json=changes)
            assert changed.status_code == 200, changed.text
            assert "old_assignee_alias" not in changed.json()
    events = [event for event in redis.events if event["type"] == "task.assignee_changed"]
    assert [(event["old_assignee_alias"], event["assignee_alias"]) for event in events] == [
        (None, "requester"), ("requester", None), (None, "requester"), ("requester", "alice"),
    ]
    for event in events:
        assert event["team_id"] == TEAM_ID
        assert event["task_ref"] == ref
        assert event["title"] == "Question"
        assert event["alias"] == "alice"
    assert [event["new_status"] for event in redis.events if event["type"] == "task.status_changed"] == ["closed", "in_progress"]
