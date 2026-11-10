"""Retirement serialization uses the caller's real PostgreSQL transaction."""

import asyncio
from dataclasses import replace

import pytest

from aweb_naapp.runtime.installation import AdmittedInstallation
from aweb_naapp.runtime.passkeys import prepare_retirement

INSTALLATION = AdmittedInstallation(
    app_id="example", team_id="example:team", installation_id="install-a", generation=1
)


class Rollback(Exception):
    pass


@pytest.fixture
async def db(test_db_factory):
    return await test_db_factory.create_db(suffix="retirement", schema="app")


async def wait_for_holder(db, holder, waiter, task):
    async with asyncio.timeout(5):
        while holder not in await db.fetch_value("SELECT pg_blocking_pids($1)", waiter):
            if task.done():
                await task
                pytest.fail("retirement was not serialized")
            await asyncio.sleep(0.01)
    assert not task.done()


async def acquire(db, started, installation=INSTALLATION):
    async with db.transaction() as tx:
        started.set_result(await tx.fetch_value("SELECT pg_backend_pid()"))
        await prepare_retirement(tx, installation=installation)


async def finish(task):
    if task is not None:
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("rollback", [False, True], ids=["commit", "rollback"])
async def test_same_installation_waits_until_original_transaction_ends(db, rollback):
    task = None
    try:
        try:
            async with db.transaction() as tx:
                await prepare_retirement(tx, installation=INSTALLATION)
                # A repeated call in the same transaction is reentrant.
                await prepare_retirement(tx, installation=INSTALLATION)
                holder = await tx.fetch_value("SELECT pg_backend_pid()")
                started = asyncio.get_running_loop().create_future()
                task = asyncio.create_task(
                    acquire(db, started, replace(INSTALLATION, generation=2))
                )
                waiter = await asyncio.wait_for(started, 5)
                await wait_for_holder(db, holder, waiter, task)
                if rollback:
                    raise Rollback
        except Rollback:
            pass
        await asyncio.wait_for(task, 5)
    finally:
        await finish(task)


async def test_savepoint_rollback_releases_its_retirement_lock(db):
    task = None
    try:
        async with db.transaction() as tx:
            with pytest.raises(Rollback):
                async with tx.transaction() as nested:
                    await prepare_retirement(nested, installation=INSTALLATION)
                    holder = await nested.fetch_value("SELECT pg_backend_pid()")
                    started = asyncio.get_running_loop().create_future()
                    task = asyncio.create_task(acquire(db, started))
                    waiter = await asyncio.wait_for(started, 5)
                    await wait_for_holder(db, holder, waiter, task)
                    raise Rollback
            # The outer transaction is still alive; the inner lock is gone.
            await asyncio.wait_for(task, 5)
            assert await tx.fetch_value("SELECT 1") == 1
    finally:
        await finish(task)


@pytest.mark.parametrize(
    "other",
    [
        replace(INSTALLATION, app_id="another-app"),
        replace(INSTALLATION, team_id="example:another-team"),
        replace(INSTALLATION, installation_id="install-b"),
    ],
    ids=["app", "team", "installation"],
)
async def test_another_serialization_scope_does_not_wait(db, other):
    async with db.transaction() as tx:
        await prepare_retirement(tx, installation=INSTALLATION)
        started = asyncio.get_running_loop().create_future()
        await asyncio.wait_for(acquire(db, started, other), 5)


async def test_ended_transaction_cannot_take_an_ephemeral_lock(db):
    async with db.transaction() as tx:
        pass
    with pytest.raises(ValueError, match="live transaction"):
        await prepare_retirement(tx, installation=INSTALLATION)
