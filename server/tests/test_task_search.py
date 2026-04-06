"""Test that list_tasks filters by q parameter (task_ref or title ILIKE)."""

from __future__ import annotations

import uuid

import pytest

from aweb.coordination.tasks_service import list_tasks


class _DbShim:
    def __init__(self, aweb_db) -> None:
        self._db = aweb_db

    def get_manager(self, name: str = "aweb"):
        return self._db


TEAM_ADDRESS = "acme.com/myproj"


async def _seed_team_and_tasks(aweb_db):
    """Create a team with three tasks for search testing."""
    await aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_address, namespace, team_name, team_did_key)
        VALUES ($1, 'acme.com', 'myproj', 'did:key:z6Mktest')
        ON CONFLICT DO NOTHING
        """,
        TEAM_ADDRESS,
    )

    tasks = [
        (uuid.uuid4(), 1, 1, "aaaa", "Fix login bug"),
        (uuid.uuid4(), 2, 2, "aabb", "Add search feature"),
        (uuid.uuid4(), 3, 3, "aacc", "Update documentation"),
    ]
    for task_id, num, seq, suffix, title in tasks:
        await aweb_db.execute(
            """
            INSERT INTO {{tables.tasks}}
                (task_id, team_address, task_number, root_task_seq, task_ref_suffix, title,
                 status, priority, task_type)
            VALUES ($1, $2, $3, $4, $5, $6, 'open', 2, 'task')
            """,
            task_id, TEAM_ADDRESS, num, seq, suffix, title,
        )


@pytest.mark.asyncio
async def test_search_by_title_substring(aweb_cloud_db):
    db = _DbShim(aweb_cloud_db.aweb_db)
    await _seed_team_and_tasks(aweb_cloud_db.aweb_db)

    results = await list_tasks(db, team_address=TEAM_ADDRESS, q="login")
    assert len(results) == 1
    assert results[0]["title"] == "Fix login bug"


@pytest.mark.asyncio
async def test_search_by_task_ref(aweb_cloud_db):
    db = _DbShim(aweb_cloud_db.aweb_db)
    await _seed_team_and_tasks(aweb_cloud_db.aweb_db)

    results = await list_tasks(db, team_address=TEAM_ADDRESS, q="myproj-aabb")
    assert len(results) == 1
    assert results[0]["title"] == "Add search feature"


@pytest.mark.asyncio
async def test_search_case_insensitive(aweb_cloud_db):
    db = _DbShim(aweb_cloud_db.aweb_db)
    await _seed_team_and_tasks(aweb_cloud_db.aweb_db)

    results = await list_tasks(db, team_address=TEAM_ADDRESS, q="DOCUMENTATION")
    assert len(results) == 1
    assert results[0]["title"] == "Update documentation"


@pytest.mark.asyncio
async def test_search_no_match(aweb_cloud_db):
    db = _DbShim(aweb_cloud_db.aweb_db)
    await _seed_team_and_tasks(aweb_cloud_db.aweb_db)

    results = await list_tasks(db, team_address=TEAM_ADDRESS, q="nonexistent")
    assert len(results) == 0


@pytest.mark.asyncio
async def test_search_escapes_ilike_wildcards(aweb_cloud_db):
    db = _DbShim(aweb_cloud_db.aweb_db)
    await _seed_team_and_tasks(aweb_cloud_db.aweb_db)

    # "%" and "_" are ILIKE wildcards — they must not match everything
    results = await list_tasks(db, team_address=TEAM_ADDRESS, q="%")
    assert len(results) == 0

    results = await list_tasks(db, team_address=TEAM_ADDRESS, q="_")
    assert len(results) == 0


@pytest.mark.asyncio
async def test_search_returns_all_when_q_is_none(aweb_cloud_db):
    db = _DbShim(aweb_cloud_db.aweb_db)
    await _seed_team_and_tasks(aweb_cloud_db.aweb_db)

    results = await list_tasks(db, team_address=TEAM_ADDRESS)
    assert len(results) == 3
