from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from aweb.closed_task_claims import release_closed_task_claims

BACKEND = "backend:acme.com"
FRONTEND = "frontend:acme.com"


async def _seed(db) -> dict:
    """Claims on closed, in-progress and open tasks in two teams.

    Stale (task closed): backend-aaaa held by ws1 and ws2, backend-aaab held by
    ws1, frontend-aaaa held by ws4. Not stale: backend-aaac (in progress) held
    by ws2, backend-aaad (open) held by ws3, and a frontend-team claim whose
    reference names the closed backend task backend-aaab.
    """
    ws = {name: uuid4() for name in ("ws1", "ws2", "ws3", "ws4", "ws5")}
    for name, team_id, focus in (
        ("ws1", BACKEND, "backend-aaab"),
        ("ws2", BACKEND, "backend-aaaa"),
        ("ws3", BACKEND, "backend-aaad"),
        ("ws4", FRONTEND, "frontend-aaaa"),
        ("ws5", FRONTEND, "backend-aaab"),
    ):
        await db.execute(
            """
            INSERT INTO {{tables.workspaces}} (
                workspace_id, team_id, agent_id, alias, human_name, role,
                workspace_type, focus_task_ref
            )
            VALUES ($1, $2, $3, $4, '', 'developer', 'manual', $5)
            """,
            ws[name],
            team_id,
            uuid4(),
            name,
            focus,
        )
    for team_id, number, suffix, status in (
        (BACKEND, 1, "aaaa", "closed"),
        (BACKEND, 2, "aaab", "closed"),
        (BACKEND, 3, "aaac", "in_progress"),
        (BACKEND, 4, "aaad", "open"),
        (FRONTEND, 1, "aaaa", "closed"),
    ):
        await db.execute(
            """
            INSERT INTO {{tables.tasks}} (team_id, task_number, task_ref_suffix, title, status)
            VALUES ($1, $2, $3, 'task', $4)
            """,
            team_id,
            number,
            suffix,
            status,
        )
    earlier = datetime.now(timezone.utc) - timedelta(hours=2)
    later = datetime.now(timezone.utc) - timedelta(hours=1)
    for team_id, name, task_ref, claimed_at in (
        (BACKEND, "ws1", "backend-aaaa", earlier),
        (BACKEND, "ws1", "backend-aaab", later),
        (BACKEND, "ws2", "backend-aaaa", earlier),
        (BACKEND, "ws2", "backend-aaac", later),
        (BACKEND, "ws3", "backend-aaad", earlier),
        (FRONTEND, "ws4", "frontend-aaaa", earlier),
        (FRONTEND, "ws5", "backend-aaab", earlier),
    ):
        await db.execute(
            """
            INSERT INTO {{tables.task_claims}} (
                team_id, workspace_id, alias, task_ref, apex_task_ref, claimed_at
            )
            VALUES ($1, $2, $3, $4, $4, $5)
            """,
            team_id,
            ws[name],
            name,
            task_ref,
            claimed_at,
        )
    return ws


async def _claims(db) -> set[tuple[str, str, str]]:
    rows = await db.fetch_all(
        "SELECT team_id, workspace_id, task_ref FROM {{tables.task_claims}}"
    )
    return {(row["team_id"], str(row["workspace_id"]), row["task_ref"]) for row in rows}


async def _focus(db) -> dict[str, str | None]:
    rows = await db.fetch_all(
        "SELECT workspace_id, focus_task_ref FROM {{tables.workspaces}}"
    )
    return {str(row["workspace_id"]): row["focus_task_ref"] for row in rows}


def _report(*, apply: bool, released: bool) -> dict:
    return {
        "apply": apply,
        "claims": 4,
        "released_claims": 4 if released else 0,
        "teams": {
            BACKEND: {"tasks": 2, "claims": 3, "released_claims": 3 if released else 0},
            FRONTEND: {"tasks": 1, "claims": 1, "released_claims": 1 if released else 0},
        },
    }


@pytest.mark.asyncio
async def test_dry_run_counts_claims_on_closed_tasks_and_changes_nothing(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    await _seed(db)
    claims_before = await _claims(db)
    focus_before = await _focus(db)

    report = await release_closed_task_claims(db)

    assert report == _report(apply=False, released=False)
    assert await _claims(db) == claims_before
    assert await _focus(db) == focus_before


@pytest.mark.asyncio
async def test_apply_releases_claims_on_closed_tasks_once(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    ws = await _seed(db)
    focus_before = await _focus(db)

    report = await release_closed_task_claims(db, apply=True)

    assert report == _report(apply=True, released=True)
    assert await _claims(db) == {
        (BACKEND, str(ws["ws2"]), "backend-aaac"),
        (BACKEND, str(ws["ws3"]), "backend-aaad"),
        (FRONTEND, str(ws["ws5"]), "backend-aaab"),
    }
    assert await _focus(db) == {
        # No claim remains and the released focus task is closed.
        str(ws["ws1"]): None,
        # The most recent remaining claim.
        str(ws["ws2"]): "backend-aaac",
        str(ws["ws3"]): focus_before[str(ws["ws3"])],
        str(ws["ws4"]): None,
        str(ws["ws5"]): focus_before[str(ws["ws5"])],
    }

    claims_after_first = await _claims(db)
    focus_after_first = await _focus(db)
    second = await release_closed_task_claims(db, apply=True)

    assert second == {"apply": True, "claims": 0, "released_claims": 0, "teams": {}}
    assert await _claims(db) == claims_after_first
    assert await _focus(db) == focus_after_first


@pytest.mark.asyncio
async def test_cli_reports_by_default_and_releases_with_apply(test_db_factory):
    import asyncio
    import os
    import sys

    from awid.db_config import build_database_config
    from pgdbm import AsyncDatabaseManager

    from aweb.db import DatabaseInfra

    base = await test_db_factory.create_db(suffix="closed_task_claims_cli")
    await base.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public")
    pool = await AsyncDatabaseManager.create_shared_pool(
        build_database_config(connection_string=base.config.get_dsn())
    )
    infra = DatabaseInfra()
    await infra.initialize(shared_pool=pool)
    db = infra.get_manager()
    try:
        await _seed(db)
        claims_before = await _claims(db)
        focus_before = await _focus(db)

        async def run_cli(*args: str) -> dict:
            process = await asyncio.create_subprocess_exec(
                sys.executable, "-c", "from aweb.cli import app; app()",
                "release-closed-task-claims", *args,
                env={**os.environ, "AWEB_DATABASE_URL": base.config.get_dsn()},
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), 20)
            assert process.returncode == 0, stderr.decode()
            return json.loads(stdout)

        assert await run_cli() == _report(apply=False, released=False)
        assert await _claims(db) == claims_before
        assert await _focus(db) == focus_before

        assert await run_cli("--apply") == _report(apply=True, released=True)
        assert len(await _claims(db)) == len(claims_before) - 4
    finally:
        await infra.close()
        await pool.close()
