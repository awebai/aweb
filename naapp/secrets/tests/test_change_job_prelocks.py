"""S10 job replacements serialize CURRENT before the B2 approval union."""

import asyncio

import asyncpg
import pytest
from aweb_naapp_testing.owner_acts import INSTALLATION_ID

from aweb_secrets.jobs import JobDefinition, apply_job_migrations, create_job, current_job
from tests.test_change_set_records import wait_blocked
from tests.test_change_sets import (
    ALICE,
    TEAM,
    change_set,
    draft,
    enrol_owner,
    grant_role,
    on_console,
)
from tests.test_change_sets import world as _world
from tests.test_jobs import after

world = _world


async def test_job_only_preparation_waits_for_current_reader_before_locking_b2(world):
    w = world
    await apply_job_migrations(w.db)
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    approval_id = await draft(w, change_set(drafter=on_console(scope), changes=[grant_role(ALICE)]))
    job = JobDefinition.from_after(after())
    async with w.db.transaction() as tx:
        await create_job(tx, INSTALLATION_ID, TEAM, job)
    ready = asyncio.get_running_loop().create_future()

    async def prepare():
        async with w.db.transaction() as tx:
            ready.set_result(await tx.fetch_value("SELECT pg_backend_pid()"))
            await w.containment.prepare_replacements(
                tx,
                installation_id=INSTALLATION_ID,
                team_id=TEAM,
                secret_ids=(),
                job_ids=(job.job_id, job.job_id),
                approval_ids=(approval_id,),
            )

    task = None
    try:
        async with w.db.transaction() as reader:
            holder = await reader.fetch_value("SELECT pg_backend_pid()")
            assert await current_job(reader, INSTALLATION_ID, job.job_id) == job
            task = asyncio.create_task(prepare())
            waiter = await asyncio.wait_for(ready, 5)
            await wait_blocked(w, waiter, holder)
            # While preparation waits on CURRENT, another transaction can still
            # obtain this B2 row. Taking B2 first would cause a lock-order cycle.
            async with w.db.transaction() as other:
                assert (
                    await other.fetch_value(
                        "SELECT approval_id FROM {{tables.approvals}} WHERE approval_id=$1 FOR UPDATE NOWAIT",
                        approval_id,
                    )
                    == approval_id
                )
        await asyncio.wait_for(task, 5)
    finally:
        if task is not None:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)


async def test_preparation_locks_only_requested_installation_current_pointers(world):
    w = world
    await apply_job_migrations(w.db)
    job = JobDefinition.from_after(after())
    other_installation = "installation-other"
    async with w.db.transaction() as tx:
        await create_job(tx, INSTALLATION_ID, TEAM, job)
        await create_job(tx, other_installation, TEAM, job)
    async with w.db.transaction() as prepared:
        await w.containment.prepare_replacements(
            prepared,
            installation_id=INSTALLATION_ID,
            team_id=TEAM,
            secret_ids=(),
            job_ids=(job.job_id,),
        )
        async with w.db.transaction() as other:
            assert (
                await other.fetch_value(
                    "SELECT job_id FROM {{tables.current_jobs}} WHERE installation_id=$1 AND job_id=$2 FOR UPDATE NOWAIT",
                    other_installation,
                    job.job_id,
                )
                == job.job_id
            )
        with pytest.raises(asyncpg.LockNotAvailableError):
            async with w.db.transaction() as blocked:
                await blocked.fetch_value(
                    "SELECT job_id FROM {{tables.current_jobs}} WHERE installation_id=$1 AND job_id=$2 FOR SHARE NOWAIT",
                    INSTALLATION_ID,
                    job.job_id,
                )
