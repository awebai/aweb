"""Test that list_tasks filters by q parameter (task_ref or title ILIKE)."""

from __future__ import annotations

import asyncio
import uuid
from contextlib import asynccontextmanager

import pytest

from aweb.coordination.tasks_service import create_task, list_tasks, update_task
from aweb.service_errors import ValidationError


class _DbShim:
    def __init__(self, aweb_db) -> None:
        self._db = aweb_db

    def get_manager(self, name: str = "aweb"):
        return self._db


class _CycleCheckBarrier:
    def __init__(self) -> None:
        self.arrivals = 0
        self.both_arrived = asyncio.Event()

    async def arrive(self) -> None:
        self.arrivals += 1
        if self.arrivals == 2:
            self.both_arrived.set()
        try:
            await asyncio.wait_for(self.both_arrived.wait(), timeout=0.2)
        except TimeoutError:
            pass


class _BarrierTransaction:
    def __init__(self, transaction, barrier: _CycleCheckBarrier) -> None:
        self._transaction = transaction
        self._barrier = barrier

    def __getattr__(self, name):
        return getattr(self._transaction, name)

    async def fetch_one(self, query, *args):
        if "WITH RECURSIVE descendants AS" in query:
            await self._barrier.arrive()
        return await self._transaction.fetch_one(query, *args)


class _BarrierManager:
    def __init__(self, manager) -> None:
        self._manager = manager
        self._barrier = _CycleCheckBarrier()

    def __getattr__(self, name):
        return getattr(self._manager, name)

    @asynccontextmanager
    async def transaction(self):
        async with self._manager.transaction() as transaction:
            yield _BarrierTransaction(transaction, self._barrier)


TEAM_ADDRESS = "myproj:acme.com"


async def _seed_team(aweb_db):
    await aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, 'acme.com', 'myproj', 'did:key:z6Mktest')
        ON CONFLICT DO NOTHING
        """,
        TEAM_ADDRESS,
    )


async def _seed_team_and_tasks(aweb_db):
    """Create a team with three tasks for search testing."""
    await _seed_team(aweb_db)

    tasks = [
        (uuid.uuid4(), 1, 1, "aaaa", "Fix login bug"),
        (uuid.uuid4(), 2, 2, "aabb", "Add search feature"),
        (uuid.uuid4(), 3, 3, "aacc", "Update documentation"),
    ]
    for task_id, num, seq, suffix, title in tasks:
        await aweb_db.execute(
            """
            INSERT INTO {{tables.tasks}}
                (task_id, team_id, task_number, root_task_seq, task_ref_suffix, title,
                 status, priority, task_type)
            VALUES ($1, $2, $3, $4, $5, $6, 'open', 2, 'task')
            """,
            task_id, TEAM_ADDRESS, num, seq, suffix, title,
        )


@pytest.mark.asyncio
async def test_search_by_title_substring(aweb_cloud_db):
    db = _DbShim(aweb_cloud_db.aweb_db)
    await _seed_team_and_tasks(aweb_cloud_db.aweb_db)

    results = await list_tasks(db, team_id=TEAM_ADDRESS, q="login")
    assert len(results) == 1
    assert results[0]["title"] == "Fix login bug"


@pytest.mark.asyncio
async def test_search_by_task_ref(aweb_cloud_db):
    db = _DbShim(aweb_cloud_db.aweb_db)
    await _seed_team_and_tasks(aweb_cloud_db.aweb_db)

    results = await list_tasks(db, team_id=TEAM_ADDRESS, q="myproj-aabb")
    assert len(results) == 1
    assert results[0]["title"] == "Add search feature"


@pytest.mark.asyncio
async def test_search_case_insensitive(aweb_cloud_db):
    db = _DbShim(aweb_cloud_db.aweb_db)
    await _seed_team_and_tasks(aweb_cloud_db.aweb_db)

    results = await list_tasks(db, team_id=TEAM_ADDRESS, q="DOCUMENTATION")
    assert len(results) == 1
    assert results[0]["title"] == "Update documentation"


@pytest.mark.asyncio
async def test_search_no_match(aweb_cloud_db):
    db = _DbShim(aweb_cloud_db.aweb_db)
    await _seed_team_and_tasks(aweb_cloud_db.aweb_db)

    results = await list_tasks(db, team_id=TEAM_ADDRESS, q="nonexistent")
    assert len(results) == 0


@pytest.mark.asyncio
async def test_search_escapes_ilike_wildcards(aweb_cloud_db):
    db = _DbShim(aweb_cloud_db.aweb_db)
    await _seed_team_and_tasks(aweb_cloud_db.aweb_db)

    # "%" and "_" are ILIKE wildcards — they must not match everything
    results = await list_tasks(db, team_id=TEAM_ADDRESS, q="%")
    assert len(results) == 0

    results = await list_tasks(db, team_id=TEAM_ADDRESS, q="_")
    assert len(results) == 0


@pytest.mark.asyncio
async def test_search_returns_all_when_q_is_none(aweb_cloud_db):
    db = _DbShim(aweb_cloud_db.aweb_db)
    await _seed_team_and_tasks(aweb_cloud_db.aweb_db)

    results = await list_tasks(db, team_id=TEAM_ADDRESS)
    assert len(results) == 3


@pytest.mark.asyncio
async def test_list_tasks_filters_by_parent_ref(aweb_cloud_db):
    db = _DbShim(aweb_cloud_db.aweb_db)
    await _seed_team(aweb_cloud_db.aweb_db)
    parent = await create_task(db, team_id=TEAM_ADDRESS, created_by_alias="alice", title="Parent")
    child = await create_task(
        db,
        team_id=TEAM_ADDRESS,
        created_by_alias="alice",
        title="Child",
        parent_task_id=parent["task_ref"],
    )
    await create_task(db, team_id=TEAM_ADDRESS, created_by_alias="alice", title="Other root")

    results = await list_tasks(db, team_id=TEAM_ADDRESS, parent_task_id=parent["task_ref"])

    assert [task["task_id"] for task in results] == [child["task_id"]]


@pytest.mark.asyncio
async def test_update_task_reparents_clears_and_rejects_cycles(aweb_cloud_db):
    db = _DbShim(aweb_cloud_db.aweb_db)
    await _seed_team(aweb_cloud_db.aweb_db)
    first_parent = await create_task(db, team_id=TEAM_ADDRESS, created_by_alias="alice", title="First")
    second_parent = await create_task(db, team_id=TEAM_ADDRESS, created_by_alias="alice", title="Second")
    child = await create_task(
        db,
        team_id=TEAM_ADDRESS,
        created_by_alias="alice",
        title="Child",
        parent_task_id=first_parent["task_ref"],
    )

    moved = await update_task(
        db,
        team_id=TEAM_ADDRESS,
        ref=child["task_ref"],
        actor_alias="alice",
        parent_task_id=second_parent["task_ref"],
    )
    assert moved["parent_task_id"] == second_parent["task_id"]

    cleared = await update_task(
        db,
        team_id=TEAM_ADDRESS,
        ref=child["task_ref"],
        actor_alias="alice",
        parent_task_id=None,
    )
    assert cleared["parent_task_id"] is None

    await update_task(
        db,
        team_id=TEAM_ADDRESS,
        ref=child["task_ref"],
        actor_alias="alice",
        parent_task_id=first_parent["task_ref"],
    )
    with pytest.raises(ValidationError, match="cycle"):
        await update_task(
            db,
            team_id=TEAM_ADDRESS,
            ref=first_parent["task_ref"],
            actor_alias="alice",
            parent_task_id=child["task_ref"],
        )


@pytest.mark.asyncio
async def test_concurrent_reparents_cannot_commit_a_cycle(aweb_cloud_db):
    manager = aweb_cloud_db.aweb_db
    setup_db = _DbShim(manager)
    await _seed_team(manager)
    second = await create_task(
        setup_db, team_id=TEAM_ADDRESS, created_by_alias="alice", title="Second"
    )
    first = await create_task(
        setup_db,
        team_id=TEAM_ADDRESS,
        created_by_alias="alice",
        title="First",
        parent_task_id=second["task_ref"],
    )
    third = await create_task(
        setup_db, team_id=TEAM_ADDRESS, created_by_alias="alice", title="Third"
    )
    concurrent_db = _DbShim(_BarrierManager(manager))

    results = await asyncio.gather(
        update_task(
            concurrent_db,
            team_id=TEAM_ADDRESS,
            ref=third["task_ref"],
            actor_alias="alice",
            parent_task_id=first["task_ref"],
        ),
        update_task(
            concurrent_db,
            team_id=TEAM_ADDRESS,
            ref=second["task_ref"],
            actor_alias="alice",
            parent_task_id=third["task_ref"],
        ),
        return_exceptions=True,
    )

    assert sum(isinstance(result, ValidationError) for result in results) == 1
    rows = await manager.fetch_all(
        "SELECT task_id, parent_task_id FROM {{tables.tasks}} WHERE team_id = $1",
        TEAM_ADDRESS,
    )
    parents = {row["task_id"]: row["parent_task_id"] for row in rows}
    for task_id in parents:
        visited = set()
        current = task_id
        while current is not None:
            assert current not in visited, "committed task hierarchy contains a cycle"
            visited.add(current)
            current = parents[current]
