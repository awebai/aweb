# ruff: noqa: F811 -- imported real composition fixtures.
"""Actual signed/cookie confirmation serializes with the two closing paths."""

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from aweb_secrets.change import ChangeRefused
from aweb_secrets.runners import mint_runner_id
from tests.test_aw_change_confirmation import ROOT, confirmation_journey  # noqa: F401
from tests.test_change_set_runners import runner_item
from tests.test_handoff_sessions import journey  # noqa: F401
from tests.test_owner_bootstrap import world  # noqa: F401


async def blocked_pid(db, holder, task):
    async with asyncio.timeout(5):
        while True:
            pid = await db.fetch_value(
                "SELECT pid FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid))"
                " AND datname=current_database() LIMIT 1",
                holder,
            )
            if pid is not None:
                return pid
            if task.done():
                await task
                pytest.fail("request finished before its expected PostgreSQL wait")
            await asyncio.sleep(0.01)


@pytest.mark.parametrize("closing", ["cancel", "expire"])
async def test_real_confirmation_and_closer_have_one_terminal_outcome(
    confirmation_journey, closing
):  # noqa: F811
    c = confirmation_journey
    db = c.handoff.world.db
    key, session = await c.handoff.open()
    runner = mint_runner_id()
    body = {"changes": [runner_item(runner)], "sealed": [], "reason": "Register build runner"}
    tasks = []
    async with c.browser() as (browser, headers):
        if closing == "cancel":
            drafted = await c.signed_post(key, session, ROOT, body)
        else:
            drafted = await browser.post(ROOT, json=body, headers=headers)
        assert drafted.status_code == 201
        change_id = drafted.json()["change_id"]
        path = await c.approve(browser, headers, drafted.json())

        async def confirm():
            if closing == "cancel":
                return await c.signed_post(key, session, path + "/confirm", {})
            return await browser.post(path + "/confirm", json={}, headers=headers)

        async def close():
            if closing == "expire":
                return await c.writer.expire(now=datetime.now(UTC) + timedelta(hours=2))
            try:
                async with db.transaction() as tx:
                    await c.writer.cancel(tx, change_id, cancelled_by="race-control")
            except ChangeRefused as refused:
                return refused.code
            pytest.fail("cancel committed after confirmation won")

        try:
            async with db.transaction() as observer:
                holder = await observer.fetch_value("SELECT pg_backend_pid()")
                await observer.fetch_value(
                    "SELECT change_id FROM {{tables.change_sets}} WHERE change_id=$1 FOR UPDATE",
                    change_id,
                )
                confirming = asyncio.create_task(confirm())
                tasks.append(confirming)
                # The actual confirmer reaches the change row only after it
                # retains the canonical B2 union. Establish that wait first.
                confirmer_pid = await blocked_pid(db, holder, confirming)
                closing_task = asyncio.create_task(close())
                tasks.append(closing_task)
                # The closer must queue behind that confirmer's B2 lock, not
                # acquire the change row and later reverse onto B2.
                await blocked_pid(db, confirmer_pid, closing_task)
            result = await asyncio.wait_for(confirming, 5)
            assert result.status_code == 200
            assert await asyncio.wait_for(closing_task, 5) == (
                "change_not_pending" if closing == "cancel" else 0
            )
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
    assert (
        await db.fetch_value(
            "SELECT state FROM {{tables.change_sets}} WHERE change_id=$1", change_id
        )
        == "applied"
    )
    assert await db.fetch_value("SELECT count(*) FROM {{tables.runners}}") == 1
