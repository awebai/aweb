"""Test that list_tasks filters by q parameter (task_ref or title ILIKE)."""

from __future__ import annotations

import uuid

import pytest

from aweb.coordination.tasks_service import list_tasks


class _DbInfra:
    def __init__(self, *, server_db, aweb_db) -> None:
        self._server_db = server_db
        self._aweb_db = aweb_db

    def get_manager(self, name: str = "aweb"):
        if name == "server":
            return self._server_db
        if name == "aweb":
            return self._aweb_db
        raise KeyError(name)


async def _seed_project_and_tasks(server_db, aweb_db):
    """Create a project with three tasks for search testing."""
    project_id = uuid.uuid4()

    await server_db.execute(
        """
        INSERT INTO {{tables.projects}} (id, slug, name)
        VALUES ($1, 'myproj', 'My Project')
        """,
        project_id,
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.projects}} (project_id, slug, name)
        VALUES ($1, 'myproj', 'My Project')
        """,
        project_id,
    )

    tasks = [
        (uuid.uuid4(), 1, 1, "aaaa", "Fix login bug"),
        (uuid.uuid4(), 2, 2, "aabb", "Add search feature"),
        (uuid.uuid4(), 3, 3, "aacc", "Update documentation"),
    ]
    for task_id, num, seq, suffix, title in tasks:
        await server_db.execute(
            """
            INSERT INTO {{tables.tasks}}
                (task_id, project_id, task_number, root_task_seq, task_ref_suffix, title,
                 status, priority, task_type)
            VALUES ($1, $2, $3, $4, $5, $6, 'open', 2, 'task')
            """,
            task_id, project_id, num, seq, suffix, title,
        )

    return str(project_id)


@pytest.mark.asyncio
async def test_search_by_title_substring(aweb_cloud_db):
    db = _DbInfra(server_db=aweb_cloud_db.oss_db, aweb_db=aweb_cloud_db.aweb_db)
    project_id = await _seed_project_and_tasks(aweb_cloud_db.oss_db, aweb_cloud_db.aweb_db)

    results = await list_tasks(db, project_id=project_id, q="login")
    assert len(results) == 1
    assert results[0]["title"] == "Fix login bug"


@pytest.mark.asyncio
async def test_search_by_task_ref(aweb_cloud_db):
    db = _DbInfra(server_db=aweb_cloud_db.oss_db, aweb_db=aweb_cloud_db.aweb_db)
    project_id = await _seed_project_and_tasks(aweb_cloud_db.oss_db, aweb_cloud_db.aweb_db)

    results = await list_tasks(db, project_id=project_id, q="myproj-aabb")
    assert len(results) == 1
    assert results[0]["title"] == "Add search feature"


@pytest.mark.asyncio
async def test_search_case_insensitive(aweb_cloud_db):
    db = _DbInfra(server_db=aweb_cloud_db.oss_db, aweb_db=aweb_cloud_db.aweb_db)
    project_id = await _seed_project_and_tasks(aweb_cloud_db.oss_db, aweb_cloud_db.aweb_db)

    results = await list_tasks(db, project_id=project_id, q="DOCUMENTATION")
    assert len(results) == 1
    assert results[0]["title"] == "Update documentation"


@pytest.mark.asyncio
async def test_search_no_match(aweb_cloud_db):
    db = _DbInfra(server_db=aweb_cloud_db.oss_db, aweb_db=aweb_cloud_db.aweb_db)
    project_id = await _seed_project_and_tasks(aweb_cloud_db.oss_db, aweb_cloud_db.aweb_db)

    results = await list_tasks(db, project_id=project_id, q="nonexistent")
    assert len(results) == 0


@pytest.mark.asyncio
async def test_search_returns_all_when_q_is_none(aweb_cloud_db):
    db = _DbInfra(server_db=aweb_cloud_db.oss_db, aweb_db=aweb_cloud_db.aweb_db)
    project_id = await _seed_project_and_tasks(aweb_cloud_db.oss_db, aweb_cloud_db.aweb_db)

    results = await list_tasks(db, project_id=project_id)
    assert len(results) == 3
