"""A run's path/grant union locks canonically and checks after the last wait."""

import asyncio
from dataclasses import replace
from datetime import timedelta

import pytest

from aweb_secrets import derived_lineage as lineage
from tests.test_derived_lineage import NOW, Clock, _child, _setup, _wait_for_database_lock
from tests.test_records_store import INSTALLATION, SECRET, TEAM
from tests.test_records_store import db as db


async def test_forest_discovery_order_cannot_prelock_a_later_sibling(db):
    async with db.transaction() as tx:
        await _setup(tx)
        first = await _child(tx, child_id="sec_a_child", dispatch="first")
        later = await _child(tx, child_id="sec_z_child", dispatch="later")
    pid = asyncio.Future()

    async def submit():
        async with db.transaction() as tx:
            pid.set_result(await tx.fetch_value("SELECT pg_backend_pid()"))
            paths = await lineage.lock_forest(
                tx, INSTALLATION, TEAM, [later.secret_id, first.secret_id, SECRET.secret_id]
            )
            return tuple(tuple(n.secret.record.secret_id for n in path) for path in paths)

    async with db.transaction() as blocker:
        await blocker.fetch_value(
            "SELECT secret_id FROM {{tables.secrets}} WHERE secret_id=$1 FOR UPDATE",
            first.secret_id,
        )
        task = asyncio.create_task(submit())
        try:
            await _wait_for_database_lock(db, await asyncio.wait_for(asyncio.shield(pid), 3))
            async with db.transaction() as probe:
                assert (
                    await probe.fetch_value(
                        "SELECT secret_id FROM {{tables.secrets}} WHERE secret_id=$1 FOR UPDATE NOWAIT",
                        later.secret_id,
                    )
                    == later.secret_id
                )
        except BaseException:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            raise
    assert await task == (
        (SECRET.secret_id, later.secret_id),
        (SECRET.secret_id, first.secret_id),
        (SECRET.secret_id,),
    )


@pytest.mark.parametrize("expired", [False, True])
async def test_locked_forest_samples_after_the_last_unrelated_sql_wait(db, expired):
    async with db.transaction() as tx:
        await _setup(tx)
        child = await _child(tx)
    clock = Clock()
    pid = asyncio.Future()

    async def submit():
        async with db.transaction() as tx:
            paths = await lineage.lock_forest(tx, INSTALLATION, TEAM, [child.secret_id])
            forest = await lineage.lock_forest_grants(tx, paths, candidate_grant_ids=[])
            pid.set_result(await tx.fetch_value("SELECT pg_backend_pid()"))
            await tx.fetch_value("SELECT count(*) FROM {{tables.config_revisions}}")
            return forest.check(clock=clock, max_ttl_s=60)

    async with db.transaction() as blocker:
        await blocker.execute("LOCK TABLE {{tables.config_revisions}} IN ACCESS EXCLUSIVE MODE")
        task = asyncio.create_task(submit())
        try:
            await _wait_for_database_lock(db, await asyncio.wait_for(asyncio.shield(pid), 3))
            if expired:
                clock.at = NOW + timedelta(seconds=61)
        except BaseException:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            raise
    if expired:
        with pytest.raises(lineage.LineageRefused) as refused:
            await task
        assert refused.value.code == "secret_disabled"
    else:
        assert "grt_issuer01" in await task


async def test_a_grant_union_cannot_cross_installation_or_team(db):
    async with db.transaction() as tx:
        await _setup(tx)
        path = await lineage.lock_ancestry(tx, INSTALLATION, TEAM, SECRET.secret_id)
        for change in ({"installation_id": "inst_other001"}, {"team_id": "other:example.com"}):
            other = (replace(path[0], **change),)
            with pytest.raises(lineage.LineageRefused):
                await lineage.lock_forest_grants(tx, (path, other), candidate_grant_ids=[])
