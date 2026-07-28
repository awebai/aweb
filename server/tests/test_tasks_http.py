from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

import aweb.coordination.routes.tasks as tasks_routes
from aweb.coordination.routes.tasks import router as tasks_router
from aweb.coordination.tasks_service import (
    get_task,
    list_active_work,
    list_blocked_tasks,
    list_ready_tasks,
)
from aweb.team_auth_deps import TeamIdentity


TEAM_ID = "backend:acme.com"


class _DbShim:
    def __init__(self, aweb_db) -> None:
        self._db = aweb_db

    def get_manager(self, name: str = "aweb"):
        return self._db


def _build_tasks_app(aweb_db) -> FastAPI:
    app = FastAPI()
    app.include_router(tasks_router)
    app.state.db = _DbShim(aweb_db)
    app.state.on_mutation = None
    return app


async def _fake_team_identity(request, db_infra) -> TeamIdentity:
    return TeamIdentity(
        team_id=TEAM_ID,
        alias="alice",
        did_key="did:key:z6Mkalice",
        did_aw="did:aw:alice",
        address="acme.com/alice",
        agent_id=str(uuid4()),
        identity_scope="global",
        certificate_id="cert-001",
    )


async def _seed_team(aweb_db) -> None:
    await aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, 'acme.com', 'backend', 'did:key:z6Mkteam')
        ON CONFLICT DO NOTHING
        """,
        TEAM_ID,
    )


async def _insert_task(
    aweb_db,
    *,
    task_id,
    task_number: int,
    root_task_seq: int,
    suffix: str,
    title: str,
    status: str = "open",
    updated_at=None,
    parent_task_id=None,
    assignee_alias=None,
) -> None:
    await aweb_db.execute(
        """
        INSERT INTO {{tables.tasks}} (
            task_id, team_id, task_number, root_task_seq, task_ref_suffix, title,
            status, priority, task_type, created_at, updated_at,
            parent_task_id, assignee_alias
        )
        VALUES (
            $1, $2, $3, $4, $5, $6,
            $7, 2, 'task', $8, $9, $10, $11
        )
        """,
        task_id,
        TEAM_ID,
        task_number,
        root_task_seq,
        suffix,
        title,
        status,
        datetime(2026, 4, 11, 12, 0, tzinfo=timezone.utc),
        updated_at,
        parent_task_id,
        assignee_alias,
    )


@pytest.mark.asyncio
async def test_task_routes_filter_reparent_and_unassign(aweb_cloud_db, monkeypatch):
    monkeypatch.setattr(tasks_routes, "get_team_identity", _fake_team_identity)
    app = _build_tasks_app(aweb_cloud_db.aweb_db)
    await _seed_team(aweb_cloud_db.aweb_db)

    first_parent_id = uuid4()
    second_parent_id = uuid4()
    child_id = uuid4()
    await _insert_task(
        aweb_cloud_db.aweb_db,
        task_id=first_parent_id,
        task_number=1,
        root_task_seq=1,
        suffix="aaaa",
        title="First parent",
    )
    await _insert_task(
        aweb_cloud_db.aweb_db,
        task_id=second_parent_id,
        task_number=2,
        root_task_seq=2,
        suffix="aaab",
        title="Second parent",
    )
    await _insert_task(
        aweb_cloud_db.aweb_db,
        task_id=child_id,
        task_number=3,
        root_task_seq=1,
        suffix="aaaa.1",
        title="Child",
        parent_task_id=first_parent_id,
        assignee_alias="alice",
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        listed = await client.get("/v1/tasks", params={"parent_task_id": "backend-aaaa"})
        moved = await client.patch(
            "/v1/tasks/backend-aaaa.1",
            json={"parent_task_id": "backend-aaab", "assignee_alias": None},
        )
        cleared = await client.patch(
            "/v1/tasks/backend-aaaa.1",
            json={"parent_task_id": None},
        )

    assert listed.status_code == 200, listed.text
    assert [task["task_id"] for task in listed.json()["tasks"]] == [str(child_id)]
    assert moved.status_code == 200, moved.text
    assert moved.json()["parent_task_id"] == str(second_parent_id)
    assert moved.json()["assignee_alias"] is None
    assert cleared.status_code == 200, cleared.text
    assert cleared.json()["parent_task_id"] is None


@pytest.mark.asyncio
async def test_combined_reparent_and_claim_uses_new_hierarchy_apex(aweb_cloud_db, monkeypatch):
    monkeypatch.setattr(tasks_routes, "get_team_identity", _fake_team_identity)
    app = _build_tasks_app(aweb_cloud_db.aweb_db)
    await _seed_team(aweb_cloud_db.aweb_db)

    first_epic_id = uuid4()
    second_epic_id = uuid4()
    child_id = uuid4()
    await _insert_task(
        aweb_cloud_db.aweb_db,
        task_id=first_epic_id,
        task_number=1,
        root_task_seq=1,
        suffix="aaaa",
        title="First epic",
    )
    await _insert_task(
        aweb_cloud_db.aweb_db,
        task_id=second_epic_id,
        task_number=2,
        root_task_seq=2,
        suffix="aaab",
        title="Second epic",
    )
    await aweb_cloud_db.aweb_db.execute(
        "UPDATE {{tables.tasks}} SET task_type = 'epic' WHERE task_id = ANY($1::uuid[])",
        [first_epic_id, second_epic_id],
    )
    await _insert_task(
        aweb_cloud_db.aweb_db,
        task_id=child_id,
        task_number=3,
        root_task_seq=1,
        suffix="aaaa.1",
        title="Child",
        parent_task_id=first_epic_id,
    )

    repo_id = uuid4()
    workspace_id = uuid4()
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.repos}} (id, team_id, origin_url, canonical_origin, name, created_at)
        VALUES ($1, $2, 'https://example.com/acme/backend.git', 'backend', 'backend', $3)
        """,
        repo_id,
        TEAM_ID,
        datetime(2026, 4, 11, 12, 0, tzinfo=timezone.utc),
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.workspaces}} (
            workspace_id, team_id, agent_id, repo_id, alias, human_name,
            role, hostname, workspace_path, created_at, updated_at
        )
        VALUES ($1, $2, $3, $4, 'alice', 'Alice', 'developer', 'mac.local', '/tmp/backend', $5, $5)
        """,
        workspace_id,
        TEAM_ID,
        uuid4(),
        repo_id,
        datetime(2026, 4, 11, 12, 0, tzinfo=timezone.utc),
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.patch(
            "/v1/tasks/backend-aaaa.1",
            json={"parent_task_id": "backend-aaab", "status": "in_progress"},
        )

    assert response.status_code == 200, response.text
    claim = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT apex_task_ref FROM {{tables.task_claims}} WHERE workspace_id = $1",
        workspace_id,
    )
    workspace = await aweb_cloud_db.aweb_db.fetch_one(
        "SELECT focus_task_ref FROM {{tables.workspaces}} WHERE workspace_id = $1",
        workspace_id,
    )
    assert claim["apex_task_ref"] == "backend-aaab"
    assert workspace["focus_task_ref"] == "backend-aaab"


@pytest.mark.asyncio
async def test_add_dependency_route_uses_service_result_keys(aweb_cloud_db, monkeypatch):
    monkeypatch.setattr(tasks_routes, "get_team_identity", _fake_team_identity)
    app = _build_tasks_app(aweb_cloud_db.aweb_db)
    await _seed_team(aweb_cloud_db.aweb_db)

    task_id = uuid4()
    dep_id = uuid4()
    await _insert_task(
        aweb_cloud_db.aweb_db,
        task_id=task_id,
        task_number=1,
        root_task_seq=1,
        suffix="aaaa",
        title="Primary task",
    )
    await _insert_task(
        aweb_cloud_db.aweb_db,
        task_id=dep_id,
        task_number=2,
        root_task_seq=2,
        suffix="aaab",
        title="Dependency task",
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/v1/tasks/backend-aaaa/deps",
            json={"depends_on": "backend-aaab"},
        )

    assert resp.status_code == 200
    assert resp.json() == {
        "task_id": str(task_id),
        "depends_on_id": str(dep_id),
    }


@pytest.mark.asyncio
async def test_remove_dependency_route_uses_service_result_keys(aweb_cloud_db, monkeypatch):
    monkeypatch.setattr(tasks_routes, "get_team_identity", _fake_team_identity)
    app = _build_tasks_app(aweb_cloud_db.aweb_db)
    await _seed_team(aweb_cloud_db.aweb_db)

    task_id = uuid4()
    dep_id = uuid4()
    await _insert_task(
        aweb_cloud_db.aweb_db,
        task_id=task_id,
        task_number=1,
        root_task_seq=1,
        suffix="aaaa",
        title="Primary task",
    )
    await _insert_task(
        aweb_cloud_db.aweb_db,
        task_id=dep_id,
        task_number=2,
        root_task_seq=2,
        suffix="aaab",
        title="Dependency task",
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.task_dependencies}} (task_id, depends_on_id, team_id)
        VALUES ($1, $2, $3)
        """,
        task_id,
        dep_id,
        TEAM_ID,
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.delete("/v1/tasks/backend-aaaa/deps/backend-aaab")

    assert resp.status_code == 200
    assert resp.json() == {
        "task_id": str(task_id),
        "removed_depends_on_id": str(dep_id),
    }


@pytest.mark.asyncio
async def test_create_task_mutation_context_includes_actor_did_aw(aweb_cloud_db, monkeypatch):
    captured: dict[str, dict] = {}

    async def _capture(event_type: str, context: dict) -> None:
        captured["event_type"] = event_type
        captured["context"] = dict(context)

    monkeypatch.setattr(tasks_routes, "get_team_identity", _fake_team_identity)
    app = _build_tasks_app(aweb_cloud_db.aweb_db)
    app.state.on_mutation = _capture
    await _seed_team(aweb_cloud_db.aweb_db)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.post(
            "/v1/tasks",
            json={"title": "Emit did:aw in mutation context"},
        )

    assert resp.status_code == 200, resp.text
    assert captured["event_type"] == "task.created"
    assert captured["context"]["actor_did_aw"] == "did:aw:alice"


@pytest.mark.asyncio
async def test_get_task_allows_null_updated_at(aweb_cloud_db):
    db = _DbShim(aweb_cloud_db.aweb_db)
    await _seed_team(aweb_cloud_db.aweb_db)
    task_id = uuid4()
    await _insert_task(
        aweb_cloud_db.aweb_db,
        task_id=task_id,
        task_number=1,
        root_task_seq=1,
        suffix="aaaa",
        title="Task without updates",
    )

    task = await get_task(db, team_id=TEAM_ID, ref="backend-aaaa")

    assert task["task_id"] == str(task_id)
    assert task["updated_at"] is None


@pytest.mark.asyncio
async def test_list_active_work_allows_null_updated_at(aweb_cloud_db):
    db = _DbShim(aweb_cloud_db.aweb_db)
    await _seed_team(aweb_cloud_db.aweb_db)
    task_id = uuid4()
    workspace_id = uuid4()
    agent_id = uuid4()
    repo_id = uuid4()
    await _insert_task(
        aweb_cloud_db.aweb_db,
        task_id=task_id,
        task_number=1,
        root_task_seq=1,
        suffix="aaaa",
        title="Active task without updates",
        status="in_progress",
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.repos}} (id, team_id, origin_url, canonical_origin, name, created_at)
        VALUES ($1, $2, $3, $4, $5, $6)
        """,
        repo_id,
        TEAM_ID,
        "https://example.com/acme/backend.git",
        "backend",
        "backend",
        datetime(2026, 4, 11, 12, 0, tzinfo=timezone.utc),
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.workspaces}} (
            workspace_id, team_id, agent_id, repo_id, alias, human_name,
            role, hostname, workspace_path, last_seen_at, created_at, updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11)
        """,
        workspace_id,
        TEAM_ID,
        agent_id,
        repo_id,
        "alice",
        "Alice",
        "developer",
        "mac.local",
        "/tmp/backend",
        datetime(2026, 4, 12, 12, 0, tzinfo=timezone.utc),
        datetime(2026, 4, 11, 12, 0, tzinfo=timezone.utc),
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.task_claims}} (
            team_id, workspace_id, alias, human_name, task_ref, claimed_at
        )
        VALUES ($1, $2, $3, $4, $5, $6)
        """,
        TEAM_ID,
        workspace_id,
        "alice",
        "Alice",
        "backend-aaaa",
        datetime(2026, 4, 11, 12, 0, tzinfo=timezone.utc),
    )

    tasks = await list_active_work(db, team_id=TEAM_ID)

    assert len(tasks) == 1
    assert tasks[0]["task_id"] == str(task_id)
    assert tasks[0]["updated_at"] is None
    assert tasks[0]["workspace_id"] == str(workspace_id)
    assert tasks[0]["owner_alias"] == "alice"
    assert tasks[0]["owner_last_seen_at"] == "2026-04-12T12:00:00+00:00"
    assert tasks[0]["canonical_origin"] == "backend"
    assert tasks[0]["branch"] is None


@pytest.mark.asyncio
async def test_list_ready_tasks_allows_null_updated_at(aweb_cloud_db):
    db = _DbShim(aweb_cloud_db.aweb_db)
    await _seed_team(aweb_cloud_db.aweb_db)
    task_id = uuid4()
    await _insert_task(
        aweb_cloud_db.aweb_db,
        task_id=task_id,
        task_number=1,
        root_task_seq=1,
        suffix="aaaa",
        title="Ready task without updates",
    )

    tasks = await list_ready_tasks(db, team_id=TEAM_ID)

    assert len(tasks) == 1
    assert tasks[0]["task_id"] == str(task_id)
    assert tasks[0]["updated_at"] is None


@pytest.mark.asyncio
async def test_list_blocked_tasks_allows_null_updated_at(aweb_cloud_db):
    db = _DbShim(aweb_cloud_db.aweb_db)
    await _seed_team(aweb_cloud_db.aweb_db)
    blocked_id = uuid4()
    blocker_id = uuid4()
    await _insert_task(
        aweb_cloud_db.aweb_db,
        task_id=blocked_id,
        task_number=1,
        root_task_seq=1,
        suffix="aaaa",
        title="Blocked task without updates",
    )
    await _insert_task(
        aweb_cloud_db.aweb_db,
        task_id=blocker_id,
        task_number=2,
        root_task_seq=2,
        suffix="aaab",
        title="Open blocker",
    )
    await aweb_cloud_db.aweb_db.execute(
        """
        INSERT INTO {{tables.task_dependencies}} (task_id, depends_on_id, team_id)
        VALUES ($1, $2, $3)
        """,
        blocked_id,
        blocker_id,
        TEAM_ID,
    )

    tasks = await list_blocked_tasks(db, team_id=TEAM_ID)

    assert len(tasks) == 1
    assert tasks[0]["task_id"] == str(blocked_id)
    assert tasks[0]["updated_at"] is None
