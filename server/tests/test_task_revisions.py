"""Task revisions and assignment principals use the real service and database."""

from uuid import UUID
from pathlib import Path
import shutil

import pytest
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager

from aweb.coordination.tasks_service import create_task, get_task, update_task
from test_task_human_assignment_events import _member
from test_tasks_http import TEAM_ID, _DbShim, _seed_team


@pytest.mark.asyncio
async def test_upgrade_freezes_current_assignment_without_inventing_historical_identity(shared_test_pool, tmp_path):
    import aweb

    db = AsyncDatabaseManager(pool=shared_test_pool, schema="aweb")
    await db.execute('CREATE SCHEMA IF NOT EXISTS "aweb"')
    migrations = Path(aweb.__file__).parent / "migrations" / "aweb"
    revision_migration = next(migrations.glob("*_task_revisions.sql"))
    for source in migrations.glob("*.sql"):
        if source.name < revision_migration.name:
            shutil.copy2(source, tmp_path / source.name)
    await AsyncMigrationManager(db, migrations_path=str(tmp_path), module_name="aweb-aweb", migrations_table="schema_migrations").apply_pending_migrations()
    await _seed_team(db)
    human_id = await _member(db, "requester", human=True)
    await db.execute("""INSERT INTO {{tables.tasks}}
        (team_id, task_number, task_ref_suffix, title, assignee_alias, created_by_alias)
        VALUES ($1, 1, 'aaaa', 'Legacy question', 'requester', 'historical-alias')""", TEAM_ID)
    await AsyncMigrationManager(db, migrations_path=str(migrations), module_name="aweb-aweb", migrations_table="schema_migrations").apply_pending_migrations()
    row = await db.fetch_one("SELECT rev, question_rev, assignee_did, created_by_did FROM {{tables.tasks}} WHERE team_id = $1", TEAM_ID)
    assert (row["rev"], row["question_rev"]) == (1, 1)
    assert row["assignee_did"] == f"did:key:{human_id}"
    assert row["created_by_did"] is None


@pytest.mark.asyncio
async def test_task_revision_changes_and_reopen_starts_another_question(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    await _seed_team(db)
    await _member(db, "alice")
    service = _DbShim(db)
    task = await create_task(service, team_id=TEAM_ID, created_by_alias="alice", title="Decide")
    assert (task["rev"], task["question_rev"]) == (1, 1)

    async def change(**kwargs):
        return await update_task(service, team_id=TEAM_ID, ref=task["task_ref"], actor_alias="alice", **kwargs)

    edited = await change(notes="The question is unchanged")
    assert (edited["rev"], edited["question_rev"]) == (2, 1)
    closed = await change(status="closed")
    assert (closed["rev"], closed["question_rev"]) == (3, 1)
    reopened = await change(status="open")
    assert (reopened["rev"], reopened["question_rev"]) == (4, 2)
    assert reopened["closed_at"] is None
    # An already-open write must not invent another answer period.
    repeated = await change(status="open")
    assert (repeated["rev"], repeated["question_rev"]) == (5, 2)


@pytest.mark.asyncio
async def test_assignment_principal_does_not_follow_alias_reuse(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    await _seed_team(db)
    old_id = await _member(db, "requester", human=True)
    await _member(db, "alice")
    service = _DbShim(db)
    task = await create_task(service, team_id=TEAM_ID, created_by_alias="alice", title="Decide", assignee_alias="requester")
    assert task["assignee_did"] == f"did:key:{old_id}"
    await db.execute("UPDATE {{tables.agents}} SET deleted_at = NOW() WHERE agent_id = $1", old_id)
    replacement_id = await _member(db, "requester", human=True)
    read = await get_task(service, team_id=TEAM_ID, ref=task["task_ref"])
    assert read["assignee_did"] == f"did:key:{old_id}"
    # Explicit reassignment, even to the same display alias, changes authority.
    reassigned = await update_task(service, team_id=TEAM_ID, ref=task["task_ref"], actor_alias="alice", assignee_alias="requester")
    assert reassigned["assignee_did"] == f"did:key:{replacement_id}"
    cleared = await update_task(service, team_id=TEAM_ID, ref=task["task_ref"], actor_alias="alice", assignee_alias=None)
    assert cleared["assignee_did"] is None


@pytest.mark.asyncio
async def test_global_principal_uses_did_aw_and_claim_reassigns_it(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    await _seed_team(db)
    human_id = await _member(db, "requester", human=True)
    agent_id = await _member(db, "alice")
    await db.execute("UPDATE {{tables.agents}} SET did_aw = 'did:aw:human' WHERE agent_id = $1", human_id)
    service = _DbShim(db)
    task = await create_task(service, team_id=TEAM_ID, created_by_alias="alice", title="Decide", assignee_alias=str(human_id))
    assert task["assignee_did"] == "did:aw:human"
    claimed = await update_task(service, team_id=TEAM_ID, ref=task["task_ref"], actor_alias="alice", status="in_progress")
    assert claimed["assignee_did"] == f"did:key:{agent_id}"


@pytest.mark.asyncio
async def test_direct_transaction_writes_also_advance_revision(aweb_cloud_db):
    db = aweb_cloud_db.aweb_db
    await _seed_team(db)
    service = _DbShim(db)
    task = await create_task(service, team_id=TEAM_ID, created_by_alias="alice", title="Decide")
    await db.execute("UPDATE {{tables.tasks}} SET status = 'closed' WHERE task_id = $1", UUID(task["task_id"]))
    await db.execute("UPDATE {{tables.tasks}} SET status = 'in_progress' WHERE task_id = $1", UUID(task["task_id"]))
    read = await get_task(service, team_id=TEAM_ID, ref=task["task_ref"])
    assert (read["rev"], read["question_rev"]) == (3, 2)
