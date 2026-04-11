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
        lifetime="persistent",
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
) -> None:
    await aweb_db.execute(
        """
        INSERT INTO {{tables.tasks}} (
            task_id, team_id, task_number, root_task_seq, task_ref_suffix, title,
            status, priority, task_type, created_at, updated_at
        )
        VALUES (
            $1, $2, $3, $4, $5, $6,
            $7, 2, 'task', $8, $9
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
    )


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
    await _insert_task(
        aweb_cloud_db.aweb_db,
        task_id=task_id,
        task_number=1,
        root_task_seq=1,
        suffix="aaaa",
        title="Active task without updates",
        status="in_progress",
    )

    tasks = await list_active_work(db, team_id=TEAM_ID)

    assert len(tasks) == 1
    assert tasks[0]["task_id"] == str(task_id)
    assert tasks[0]["updated_at"] is None


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
