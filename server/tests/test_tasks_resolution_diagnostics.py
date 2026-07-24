"""Diagnostics for task ref resolution misses (default-aagh).

Production intermittently returns 404 "Task not found" for tasks that
exist and resolve on immediate retry. These tests pin the diagnostic
logging that makes each miss self-describing in server logs: the exact
lookup inputs, whether the suffix exists under any team (and if it is
soft-deleted), and the serving connection's backend pid and MVCC
snapshot so connection-level visibility anomalies can be proven.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from aweb.coordination.tasks_service import resolve_task_ref
from aweb.service_errors import NotFoundError


TEAM_ID = "backend:acme.com"
OTHER_TEAM_ID = "frontend:acme.com"

LOGGER_NAME = "aweb.coordination.tasks_service"


class _DbShim:
    def __init__(self, aweb_db) -> None:
        self._db = aweb_db

    def get_manager(self, name: str = "aweb"):
        return self._db


async def _seed_team(aweb_db, team_id: str, namespace: str, team_name: str) -> None:
    await aweb_db.execute(
        """
        INSERT INTO {{tables.teams}} (team_id, namespace, team_name, team_did_key)
        VALUES ($1, $2, $3, 'did:key:z6Mkteam')
        ON CONFLICT DO NOTHING
        """,
        team_id,
        namespace,
        team_name,
    )


async def _insert_task(
    aweb_db,
    *,
    team_id: str,
    task_id,
    task_number: int,
    suffix: str,
    title: str,
    deleted_at=None,
) -> None:
    await aweb_db.execute(
        """
        INSERT INTO {{tables.tasks}} (
            task_id, team_id, task_number, root_task_seq, task_ref_suffix, title,
            status, priority, task_type, created_at, deleted_at
        )
        VALUES ($1, $2, $3, $3, $4, $5, 'open', 2, 'task', $6, $7)
        """,
        task_id,
        team_id,
        task_number,
        suffix,
        title,
        datetime(2026, 7, 24, 12, 0, tzinfo=timezone.utc),
        deleted_at,
    )


def _miss_records(caplog):
    return [
        r
        for r in caplog.records
        if r.name == LOGGER_NAME and "task ref resolution miss" in r.getMessage()
    ]


@pytest.mark.asyncio
async def test_suffix_miss_logs_inputs_and_connection_diagnostics(aweb_cloud_db, caplog):
    db = _DbShim(aweb_cloud_db.aweb_db)
    await _seed_team(aweb_cloud_db.aweb_db, TEAM_ID, "acme.com", "backend")

    with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
        with pytest.raises(NotFoundError):
            await resolve_task_ref(db, team_id=TEAM_ID, ref="backend-zzzz")

    records = _miss_records(caplog)
    assert len(records) == 1
    message = records[0].getMessage()
    assert "'backend:acme.com'" in message
    assert "'backend-zzzz'" in message
    assert "'zzzz'" in message
    assert "suffix_matches=[]" in message
    assert "backend_pid=" in message
    assert "snapshot=" in message


@pytest.mark.asyncio
async def test_suffix_miss_reports_matches_under_other_teams_and_deleted(aweb_cloud_db, caplog):
    db = _DbShim(aweb_cloud_db.aweb_db)
    await _seed_team(aweb_cloud_db.aweb_db, TEAM_ID, "acme.com", "backend")
    await _seed_team(aweb_cloud_db.aweb_db, OTHER_TEAM_ID, "acme.com", "frontend")
    # Same suffix exists under another team, and soft-deleted under ours.
    await _insert_task(
        aweb_cloud_db.aweb_db,
        team_id=OTHER_TEAM_ID,
        task_id=uuid4(),
        task_number=1,
        suffix="aaaa",
        title="Other team's task",
    )
    await _insert_task(
        aweb_cloud_db.aweb_db,
        team_id=TEAM_ID,
        task_id=uuid4(),
        task_number=1,
        suffix="aaaa",
        title="Soft-deleted task",
        deleted_at=datetime(2026, 7, 24, 13, 0, tzinfo=timezone.utc),
    )

    with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
        with pytest.raises(NotFoundError):
            await resolve_task_ref(db, team_id=TEAM_ID, ref="backend-aaaa")

    records = _miss_records(caplog)
    assert len(records) == 1
    message = records[0].getMessage()
    assert "('frontend:acme.com', False)" in message
    assert "('backend:acme.com', True)" in message


@pytest.mark.asyncio
async def test_uuid_miss_logs_diagnostics(aweb_cloud_db, caplog):
    db = _DbShim(aweb_cloud_db.aweb_db)
    await _seed_team(aweb_cloud_db.aweb_db, TEAM_ID, "acme.com", "backend")
    missing = uuid4()

    with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
        with pytest.raises(NotFoundError):
            await resolve_task_ref(db, team_id=TEAM_ID, ref=str(missing))

    records = _miss_records(caplog)
    assert len(records) == 1
    message = records[0].getMessage()
    assert str(missing) in message
    assert "lookup=task_id" in message


@pytest.mark.asyncio
async def test_successful_resolution_logs_nothing(aweb_cloud_db, caplog):
    db = _DbShim(aweb_cloud_db.aweb_db)
    await _seed_team(aweb_cloud_db.aweb_db, TEAM_ID, "acme.com", "backend")
    task_id = uuid4()
    await _insert_task(
        aweb_cloud_db.aweb_db,
        team_id=TEAM_ID,
        task_id=task_id,
        task_number=1,
        suffix="aaaa",
        title="Existing task",
    )

    with caplog.at_level(logging.WARNING, logger=LOGGER_NAME):
        resolved = await resolve_task_ref(db, team_id=TEAM_ID, ref="backend-aaaa")

    assert resolved == task_id
    assert _miss_records(caplog) == []
