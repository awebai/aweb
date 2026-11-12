"""Real confirmations/console narrowing prepare the whole S3 union upstream."""

import asyncio

import asyncpg
import pytest
from aweb_naapp.console import COOKIE_NAME
from starlette.requests import Request

from aweb_secrets import run_pin_store
from aweb_secrets.change import ChangeRefused
from aweb_secrets.owners import owner_scope
from aweb_secrets.revisions import bump_config_revision
from aweb_secrets.secret import SecretRecord
from tests.test_change_set_containment import confirm, pending_change, seal, value_item
from tests.test_change_sets import ALICE
from tests.test_console_changes import clients, sign_in
from tests.test_run_dispatch_service import setup
from tests.test_use_approvals import SECRET, TEAM
from tests.test_use_approvals import uses as uses
from tests.test_use_approvals import world as world


async def blocked(db, waiter, holder, task):
    async with asyncio.timeout(5):
        while holder not in await db.fetch_value("SELECT pg_blocking_pids($1)", waiter):
            if task.done():
                await task
                pytest.fail("real transaction never reached the selected lock wait")
            await asyncio.sleep(0.01)


async def test_confirm_A_and_console_disable_B_share_assignment_without_revision_inversion(uses):
    context = await setup(uses, paired=True)
    await context.assigned()
    w, db = uses.world, uses.world.db
    root = SecretRecord.from_after(SECRET)
    secondary, _ = context.secondary
    async with db.transaction() as tx:
        await bump_config_revision(tx, w.admitted.installation_id)
    replacement = await seal(w, root)
    change, _ = await pending_change(w, [value_item(root, replacement.version)], [replacement])
    disposed, applying = (
        asyncio.get_running_loop().create_future(),
        asyncio.get_running_loop().create_future(),
    )
    resume = asyncio.Event()
    actual_discard = run_pin_store.discard_secret
    disabling_task = applying_task = None

    async def pause_real_disposal(tx, **kwargs):
        count = await actual_discard(tx, **kwargs)
        if kwargs["secret_id"] == secondary.secret_id:
            disposed.set_result(await tx.fetch_value("SELECT pg_backend_pid()"))
            await resume.wait()
        return count

    async def apply():
        with pytest.raises(ChangeRefused) as refused:
            async with db.transaction() as tx:
                applying.set_result(await tx.fetch_value("SELECT pg_backend_pid()"))
                await confirm(w, tx, change)
        assert refused.value.code == "base_revision_stale"

    run_pin_store.discard_secret = pause_real_disposal
    try:
        async with clients(w) as (human, _):
            scope = owner_scope(w.admitted.installation_id, TEAM, ALICE.principal_did)
            await sign_in(w, human, scope)
            session = await w.console.sessions.current(
                Request(
                    {
                        "type": "http",
                        "method": "GET",
                        "path": "/session",
                        "headers": [
                            (b"cookie", (COOKIE_NAME + "=" + human.cookies[COOKIE_NAME]).encode())
                        ],
                    }
                )
            )
            disabling_task = asyncio.create_task(
                w.containment.by_console(
                    admitted=w.admitted,
                    session=session,
                    request_id="disable-second-slot",
                    action="disable-secret",
                    target=secondary.secret_id,
                )
            )
            holder = await asyncio.wait_for(disposed, 5)
            applying_task = asyncio.create_task(apply())
            waiter = await asyncio.wait_for(applying, 5)
            await blocked(db, waiter, holder, applying_task)
            revision_locked = False
            try:
                async with db.transaction() as observer:
                    assert (
                        await observer.fetch_value(
                            "SELECT revision FROM {{tables.config_revisions}}"
                            " WHERE installation_id=$1 FOR UPDATE NOWAIT",
                            w.admitted.installation_id,
                        )
                        == change["base_revision"]
                    )
            except asyncpg.LockNotAvailableError:
                revision_locked = True
            # The old late-S3 path held revision here while waiting on B.
            assert not revision_locked
            resume.set()
            await asyncio.wait_for(asyncio.gather(disabling_task, applying_task), 5)
        assert (
            await db.fetch_value(
                "SELECT active_version FROM {{tables.secrets}} WHERE secret_id=$1", root.secret_id
            )
            == 1
        )
        assert (
            await db.fetch_value(
                "SELECT state FROM {{tables.secrets}} WHERE secret_id=$1", secondary.secret_id
            )
            == "disabled"
        )
        assert (
            await db.fetch_value(
                "SELECT count(*) FROM {{tables.run_redaction_pins}} WHERE secret_id=$1",
                root.secret_id,
            )
            == 1
        )
    finally:
        for task in (disabling_task, applying_task):
            if task is not None and not task.done():
                task.cancel()
        resume.set()
        await asyncio.gather(
            *(t for t in (disabling_task, applying_task) if t is not None), return_exceptions=True
        )
        run_pin_store.discard_secret = actual_discard


async def test_whole_forest_waits_on_later_dispatch_before_any_earlier_pin_lock(uses):
    first = await setup(uses)
    await first.assigned()
    second = await setup(uses, variant="secondforest")
    await second.assigned()
    w, db = uses.world, uses.world.db
    dispatches = [
        row["dispatch_id"]
        for row in await db.fetch_all(
            "SELECT dispatch_id FROM {{tables.run_redaction_pins}} ORDER BY dispatch_id"
        )
    ]
    assert len(dispatches) == 2
    roots = [
        row["secret_id"] for row in await db.fetch_all("SELECT secret_id FROM {{tables.secrets}}")
    ]
    ready = asyncio.get_running_loop().create_future()

    async def prepare():
        async with db.transaction() as tx:
            await w.fence.check(tx, w.admitted)
            ready.set_result(await tx.fetch_value("SELECT pg_backend_pid()"))
            await w.containment.prepare_replacements(
                tx,
                installation_id=w.admitted.installation_id,
                team_id=TEAM,
                secret_ids=tuple(roots),
            )

    task = None
    try:
        async with db.transaction() as barrier:
            holder = await barrier.fetch_value("SELECT pg_backend_pid()")
            await barrier.fetch_one(
                "SELECT dispatch_id FROM {{tables.dispatches}} WHERE dispatch_id=$1 FOR UPDATE",
                dispatches[1],
            )
            task = asyncio.create_task(prepare())
            waiter = await asyncio.wait_for(ready, 5)
            await blocked(db, waiter, holder, task)
            pin_locked = False
            try:
                async with db.transaction() as observer:
                    assert (
                        len(
                            await observer.fetch_all(
                                "SELECT secret_id FROM {{tables.run_redaction_pins}} WHERE dispatch_id=$1 FOR UPDATE NOWAIT",
                                dispatches[0],
                            )
                        )
                        == 1
                    )
            except asyncpg.LockNotAvailableError:
                pin_locked = True
            assert not pin_locked
        await asyncio.wait_for(task, 5)
    finally:
        if task is not None:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
