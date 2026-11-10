"""Closing a draft waits for B2 before locking the change row, as confirm does."""

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from aweb_naapp.runtime.approvals import ApprovalState

from tests.test_change_sets import (
    ALICE,
    CAROL,
    by_member,
    change_set,
    decide,
    draft,
    enrol_owner,
    grant_role,
)
from tests.test_change_sets import world as world


@pytest.mark.parametrize("closing", ["cancel", "expire"])
async def test_closer_waiting_for_confirming_b2_leaves_change_row_free(world, closing):  # noqa: F811
    await enrol_owner(world, ALICE, "alice@acme.com")
    change = change_set(drafter=by_member(CAROL), changes=[grant_role(CAROL)])
    approval_id = await draft(world, change)
    await decide(world, approval_id, "alice@acme.com")

    async def close():
        if closing == "expire":
            assert await world.change_sets.expire(now=datetime.now(UTC) + timedelta(hours=2)) == 1
        else:
            async with world.db.transaction() as tx:
                await world.change_sets.cancel(
                    tx, change["change_id"], cancelled_by=CAROL.principal_did
                )

    task = None
    try:
        async with world.db.transaction() as confirming_phase:
            # The actual shared B2 preparation used by confirmation. No change
            # row is held at this phase; a closer must not reverse that order.
            await world.approvals.lock_many(confirming_phase, [approval_id])
            holder = await confirming_phase.fetch_value("SELECT pg_backend_pid()")
            task = asyncio.create_task(close())
            async with asyncio.timeout(5):
                while not await world.db.fetch_value(
                    "SELECT pid FROM pg_stat_activity"
                    " WHERE $1=ANY(pg_blocking_pids(pid)) AND datname=current_database() LIMIT 1",
                    holder,
                ):
                    if task.done():
                        await task
                        pytest.fail("closer finished without waiting for the held B2 row")
                    await asyncio.sleep(0.01)
            async with world.db.transaction() as observer:
                assert (
                    await observer.fetch_value(
                        "SELECT change_id FROM {{tables.change_sets}}"
                        " WHERE change_id=$1 FOR UPDATE NOWAIT",
                        change["change_id"],
                    )
                    == change["change_id"]
                )
        await asyncio.wait_for(task, 5)
    finally:
        if task is not None:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    assert await world.db.fetch_value(
        "SELECT state FROM {{tables.change_sets}} WHERE change_id=$1", change["change_id"]
    ) == ("cancelled" if closing == "cancel" else "expired")
    assert (await world.approvals.get(approval_id)).state is ApprovalState.REVOKED
