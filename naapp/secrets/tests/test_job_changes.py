"""Job changes use the writer's transaction, revision and prelock boundary."""

import pytest

from aweb_secrets.change import ChangeRefused
from aweb_secrets.job_changes import apply_job_change, job_prelock_ids
from aweb_secrets.jobs import JobDefinition, apply_job_migrations, current_job, job_by_digest
from tests.test_jobs import after


@pytest.fixture
async def db(test_db_factory):
    db = await test_db_factory.create_db(suffix="job_changes")
    await apply_job_migrations(db)
    yield db


def item(*, op="create", job=None):
    body = after() if job is None else job
    return {"kind": "job", "op": op, "ref": body["job_id"], "after": body}


async def apply(tx, change, *, team="team-a"):
    await apply_job_change(tx, installation_id="install-a", team_id=team, item=change)


async def test_create_replace_and_rollback_preserve_history_and_current(db):
    initial = item()
    original = JobDefinition.from_after(initial["after"])
    async with db.transaction() as tx:
        await apply(tx, initial)
    replacement = item(op="update", job={**initial["after"], "timeout_s": 120})
    revised = JobDefinition.from_after(replacement["after"])
    with pytest.raises(RuntimeError):
        async with db.transaction() as tx:
            await tx.fetch_value(
                "SELECT digest FROM {{tables.current_jobs}} WHERE installation_id=$1 AND job_id=$2 FOR UPDATE",
                "install-a",
                original.job_id,
            )
            await apply(tx, replacement)
            raise RuntimeError("caller rolls back")
    async with db.transaction() as tx:
        assert (await current_job(tx, "install-a", original.job_id)).digest == original.digest
        assert await job_by_digest(tx, "install-a", original.job_id, revised.digest) is None
        await apply(tx, replacement)
    async with db.transaction() as tx:
        assert (await current_job(tx, "install-a", original.job_id)).digest == revised.digest
        assert (
            await job_by_digest(tx, "install-a", original.job_id, original.digest)
        ).digest == original.digest


@pytest.mark.parametrize(
    "op,exists,team,code",
    [
        ("create", True, "team-a", "record_exists"),
        ("update", False, "team-a", "record_missing"),
        ("update", True, "team-b", "record_missing"),
        ("create", True, "team-b", "record_exists"),
    ],
)
async def test_scoped_create_update_never_overwrite_wrong_team(db, op, exists, team, code):
    change = item()
    if exists:
        async with db.transaction() as tx:
            await apply(tx, change)
    with pytest.raises(ChangeRefused) as refused:
        async with db.transaction() as tx:
            await apply(tx, {**change, "op": op}, team=team)
    assert refused.value.code == code


@pytest.mark.parametrize(
    "mutation",
    [
        {"kind": "operation"},
        {"op": "delete"},
        {"ref": "wrong-job"},
        {"extra": True},
        {"after": {"v": 1}},
    ],
)
async def test_invalid_items_write_nothing(db, mutation):
    with pytest.raises(ChangeRefused):
        async with db.transaction() as tx:
            await apply(tx, {**item(), **mutation})
    assert await db.fetch_value("SELECT COUNT(*) FROM {{tables.current_jobs}}") == 0


def test_prelock_ids_are_sorted_distinct_and_only_for_jobs():
    body = after()
    assert job_prelock_ids(
        [
            item(job={**body, "job_id": "z"}),
            {"kind": "runner"},
            item(job={**body, "job_id": "a"}),
            item(job={**body, "job_id": "z"}),
        ]
    ) == ("a", "z")
