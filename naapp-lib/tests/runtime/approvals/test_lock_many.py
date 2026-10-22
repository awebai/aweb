"""Public bulk row locks over real PostgreSQL, including reverse heap order."""

import asyncio

import asyncpg
import pytest

from aweb_naapp.runtime.approvals import ApprovalState
from tests.runtime.approvals.test_approvals import mint


async def assert_locked(db, approval_id):
    with pytest.raises(asyncpg.exceptions.LockNotAvailableError):
        async with db.transaction() as tx:
            await tx.fetch_value(
                "SELECT approval_id FROM {{tables.approvals}} WHERE approval_id=$1 FOR UPDATE NOWAIT",
                approval_id,
            )


@pytest.mark.parametrize("revoke", [False, True])
@pytest.mark.parametrize("rollback", [False, True])
async def test_bulk_locks_are_sorted_and_held_through_caller_commit(world, revoke, rollback):
    class Rollback(Exception):
        pass

    db = world.store.db
    _, first = await mint(world)
    _, second = await mint(world)
    low, high = sorted([first.approval_id, second.approval_id])
    # Make an unordered UPDATE visit the high ID first, deterministically.
    await db.execute("CREATE INDEX heap_desc ON {{tables.approvals}} (approval_id DESC)")
    await db.execute("CLUSTER {{tables.approvals}} USING heap_desc")
    before = await world.audit.rows()
    original = await db.fetch_all("SELECT * FROM {{tables.approvals}} ORDER BY approval_id")
    async with db.transaction() as tx:
        await world.approvals.lock_many(tx, [])
        await world.approvals.lock_many(tx, ["missing-approval"])
    started = asyncio.get_running_loop().create_future()
    locked = asyncio.Event()
    release = asyncio.Event()

    async def worker():
        try:
            async with db.transaction() as tx:
                await tx.execute("SET LOCAL enable_indexscan=off")
                await tx.execute("SET LOCAL enable_bitmapscan=off")
                started.set_result(await tx.fetch_value("SELECT pg_backend_pid()"))
                ids = [high, low, high, "missing-approval"]
                if revoke:
                    await world.approvals.revoke_many(ids, revoked_by="owner", tx=tx)
                else:
                    await world.approvals.lock_many(tx, ids)
                locked.set()
                await release.wait()
                if rollback:
                    raise Rollback
        except Rollback:
            if not rollback:
                raise

    task = None
    try:
        async with db.transaction() as holder:
            blocker = await holder.fetch_value("SELECT pg_backend_pid()")
            await holder.fetch_value(
                "SELECT approval_id FROM {{tables.approvals}} WHERE approval_id=$1 FOR UPDATE", high
            )
            task = asyncio.create_task(worker())
            pid = await asyncio.wait_for(started, 5)
            async with asyncio.timeout(5):
                while blocker not in await db.fetch_value("SELECT pg_blocking_pids($1)", pid):
                    if task.done():
                        await task
                        pytest.fail("bulk locking finished while its high approval was locked")
                    await asyncio.sleep(0.01)
            # The low row must be locked before waiting for the high row.
            await assert_locked(db, low)
        await asyncio.wait_for(locked.wait(), 5)
        # Returning must retain both locks in the supplied transaction.
        await assert_locked(db, low)
        await assert_locked(db, high)
        assert await world.audit.rows() == before
        assert (await world.approvals.get(low)).state is ApprovalState.PENDING
        release.set()
        await asyncio.wait_for(task, 5)
    finally:
        release.set()
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    for approval_id in (low, high):
        async with db.transaction() as tx:
            assert (
                await tx.fetch_value(
                    "SELECT approval_id FROM {{tables.approvals}} WHERE approval_id=$1 FOR UPDATE NOWAIT",
                    approval_id,
                )
                == approval_id
            )
        expected = ApprovalState.REVOKED if revoke and not rollback else ApprovalState.PENDING
        assert (await world.approvals.get(approval_id)).state is expected
    if not revoke or rollback:
        assert await world.audit.rows() == before
        assert (
            await db.fetch_all("SELECT * FROM {{tables.approvals}} ORDER BY approval_id")
            == original
        )
