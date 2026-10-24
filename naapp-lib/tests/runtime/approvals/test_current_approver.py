"""Current B3 authority in the caller's transaction, with real PG and passkeys."""
# ruff: noqa: F811 -- pw is the imported real passkey composition fixture.

import asyncio
from copy import copy
from datetime import timedelta

import asyncpg
import pytest
from aweb_naapp_testing.webauthn import SoftAuthenticator
from pgdbm.core import TransactionManager

from tests.runtime.approvals.support import SCOPE
from tests.runtime.approvals.test_dispatch_fence import held_locks
from tests.runtime.approvals.test_passkeys import (
    ORIGIN,
    ceremony,
    decide,
    designate,
    enrol,
    mint,
    pw,  # noqa: F401
)


async def check(pw, tx, prepared, subject, scope=SCOPE):
    return await pw.passkeys.check_current_approver(tx, prepared, scope=scope, subject=subject)


async def snapshot(tx):
    return [
        await tx.fetch_all("SELECT * FROM {{tables." + table + "}} ORDER BY 1")
        for table in (
            "passkey_approvers",
            "passkey_credentials",
            "passkey_assertions",
            "audit_outbox",
        )
    ]


async def test_check_is_repeatable_read_only_and_does_not_acquire_locks(pw):
    approver, device = await enrol(pw)
    approval = await mint(pw)
    decided = await decide(pw, approval, await ceremony(pw, approval, device))
    assert decided.decided_by is not None
    # An APPROVE proof must remain unusable as LOGIN evidence.
    assert not await pw.passkeys.login_evidence_is_current(
        SCOPE, approver.subject, decided.decided_by.evidence_ref
    )
    async with pw.passkeys.db.transaction() as tx:
        before = await snapshot(tx)
        prepared = await pw.passkeys.prepare_current_approvers(tx, [(SCOPE, approver.subject)])
        locks = await held_locks(tx)
        assert await check(pw, tx, prepared, approver.subject)
        await tx.execute("SELECT pg_sleep(0.001)")
        assert await check(pw, tx, prepared, approver.subject)
        assert await held_locks(tx) == locks
        assert await snapshot(tx) == before
        assert not await check(pw, tx, prepared, approver.subject, "another-scope")
        assert not await check(pw, tx, prepared, "another-subject")


@pytest.mark.parametrize("change", ["retire", "credential", "future", "missing"])
async def test_check_reads_same_transaction_changes_and_samples_live_time(pw, change):
    approver, _ = await enrol(pw)
    async with pw.passkeys.db.transaction() as tx:
        prepared = await pw.passkeys.prepare_current_approvers(tx, [(SCOPE, approver.subject)])
        if change == "retire":
            await tx.execute("UPDATE {{tables.passkey_approvers}} SET superseded_at=$1", pw.clock())
        elif change == "credential":
            await tx.execute("UPDATE {{tables.passkey_credentials}} SET revoked_at=$1", pw.clock())
        elif change == "missing":
            await tx.execute("DELETE FROM {{tables.passkey_credentials}}")
        else:
            await tx.execute(
                "UPDATE {{tables.passkey_approvers}} SET effective_at=$1",
                pw.clock() + timedelta(hours=1),
            )
        assert not await check(pw, tx, prepared, approver.subject)
        if change == "future":
            pw.clock.advance(timedelta(hours=1))
            assert await check(pw, tx, prepared, approver.subject)


async def test_no_credential_or_missing_pair_cannot_gain_authority_after_prepare(pw):
    designation = await designate(pw, "human@example.com")
    subject = designation.approver.subject
    token = pw.contacts.last("human@example.com")
    device = SoftAuthenticator(ORIGIN)
    registration = device.create(await pw.passkeys.enrolment_options(token))
    async with pw.passkeys.db.transaction() as tx:
        prepared = await pw.passkeys.prepare_current_approvers(
            tx, [(SCOPE, subject), ("wrong-scope", subject)]
        )
        assert not await check(pw, tx, prepared, subject)
        # Real enrolment on another connection cannot heal the old preparation.
        await pw.passkeys.complete_enrolment(token, registration)
        assert not await check(pw, tx, prepared, subject)
        assert not await check(pw, tx, prepared, subject, "wrong-scope")
        fresh = await pw.passkeys.prepare_current_approvers(tx, [(SCOPE, subject)])
        assert await check(pw, tx, fresh, subject)


async def test_original_wrapper_transaction_and_savepoint_lifetime(pw):
    approver, _ = await enrol(pw)
    db = pw.passkeys.db
    async with db.transaction() as tx:
        prepared = await pw.passkeys.prepare_current_approvers(tx, [(SCOPE, approver.subject)])
        async with tx.transaction():
            assert await check(pw, tx, prepared, approver.subject)
        wrapper = TransactionManager(tx.connection, db)
        assert not await check(pw, wrapper, prepared, approver.subject)
        assert not await copy(pw.passkeys).check_current_approver(
            tx, prepared, scope=SCOPE, subject=approver.subject
        )
        async with db.transaction() as other:
            assert not await check(pw, other, prepared, approver.subject)
    assert not await check(pw, tx, prepared, approver.subject)
    async with db.transaction() as later:
        assert not await check(pw, later, prepared, approver.subject)
        await later.execute("SAVEPOINT preparation")
        rolled_back = await pw.passkeys.prepare_current_approvers(
            later, [(SCOPE, approver.subject)]
        )
        await later.execute("ROLLBACK TO SAVEPOINT preparation")
        assert not await check(pw, later, rolled_back, approver.subject)
        fresh = await pw.passkeys.prepare_current_approvers(later, [(SCOPE, approver.subject)])
        assert await check(pw, later, fresh, approver.subject)
        assert not await check(pw, later, rolled_back, approver.subject)


async def test_prepare_rejects_repeatable_read(pw):
    async with pw.passkeys.db.transaction() as tx:
        await tx.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        with pytest.raises(ValueError):
            await pw.passkeys.prepare_current_approvers(tx, [(SCOPE, "subject")])


@pytest.mark.parametrize("blocked", ["designation", "credential"])
async def test_batch_holds_complete_designation_union_before_credentials(pw, blocked):
    first, first_device = await enrol(pw)
    second = await designate(pw, "other@example.com", scope="zz-later-scope")
    second_device = SoftAuthenticator(ORIGIN)
    token = pw.contacts.last("other@example.com")
    await pw.passkeys.complete_enrolment(
        token, second_device.create(await pw.passkeys.enrolment_options(token))
    )
    pairs = [
        ("zz-later-scope", second.approver.subject),
        (SCOPE, first.subject),
        (SCOPE, first.subject),
    ]
    db = pw.passkeys.db
    started = asyncio.get_running_loop().create_future()
    ready, release = asyncio.Event(), asyncio.Event()

    async def worker():
        async with db.transaction() as tx:
            started.set_result(await tx.fetch_value("SELECT pg_backend_pid()"))
            prepared = await pw.passkeys.prepare_current_approvers(tx, pairs)
            ready.set()
            await release.wait()
            for scope, subject in pairs:
                assert await check(pw, tx, prepared, subject, scope)

    task = None
    try:
        async with db.transaction() as holder:
            blocker = await holder.fetch_value("SELECT pg_backend_pid()")
            if blocked == "designation":
                await holder.fetch_value(
                    "SELECT subject FROM {{tables.passkey_approvers}} WHERE subject=$1 FOR UPDATE",
                    second.approver.subject,
                )
            else:
                await holder.fetch_value(
                    "SELECT credential_id FROM {{tables.passkey_credentials}} "
                    "WHERE subject=$1 FOR UPDATE",
                    second.approver.subject,
                )
            task = asyncio.create_task(worker())
            pid = await asyncio.wait_for(started, 5)
            async with asyncio.timeout(5):
                while blocker not in await db.fetch_value("SELECT pg_blocking_pids($1)", pid):
                    if task.done():
                        await task
                    await asyncio.sleep(0.01)
            if blocked == "designation":
                # The earlier credential must stay free while later designation blocks.
                async with db.transaction() as observer:
                    assert await observer.fetch_value(
                        "SELECT credential_id FROM {{tables.passkey_credentials}} "
                        "WHERE subject=$1 FOR UPDATE NOWAIT",
                        first.subject,
                    ) == next(iter(first_device.credentials))
            else:
                # Both designation rows are held before waiting on credentials.
                with pytest.raises(asyncpg.exceptions.LockNotAvailableError):
                    async with db.transaction() as observer:
                        await observer.fetch_value(
                            "SELECT subject FROM {{tables.passkey_approvers}} "
                            "WHERE subject=$1 FOR UPDATE NOWAIT",
                            first.subject,
                        )
        await asyncio.wait_for(ready.wait(), 5)
        for _, subject in pairs[:2]:
            for table, column in [
                ("passkey_approvers", "subject"),
                ("passkey_credentials", "credential_id"),
            ]:
                with pytest.raises(asyncpg.exceptions.LockNotAvailableError):
                    async with db.transaction() as observer:
                        await observer.fetch_value(
                            "SELECT " + column + " FROM {{tables." + table + "}} "
                            "WHERE subject=$1 FOR UPDATE NOWAIT",
                            subject,
                        )
        release.set()
        await asyncio.wait_for(task, 5)
    finally:
        release.set()
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
