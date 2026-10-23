"""Final publication checks over real B2 and app authority tables, without mocks."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import timedelta

import asyncpg
import pytest
from pgdbm.core import TransactionManager

from aweb_naapp.runtime.approvals import Assurance, DispatchOutcome, Refusal
from tests.runtime.approvals.support import policy
from tests.runtime.approvals.test_approvals import REQUEST, approved, decide, mint, refusal


class DatabaseAuthority:
    """An app's tx-only policy/designation source; all reads are real SQL."""

    def __init__(self, world):
        self.world = world
        self.after_read = None
        self.min_assurance = Assurance.PASSKEY
        self.prepared_batches = []

    async def create(self):
        await self.world.store.db.execute(
            "CREATE TABLE {{tables.dispatch_authority}} (policy_ref text PRIMARY KEY, "
            "version int NOT NULL, current_decider boolean NOT NULL)"
        )
        await self.world.store.db.execute(
            "INSERT INTO {{tables.dispatch_authority}} VALUES ('send-charge', 1, true)"
        )

    async def prepare(self, tx, approvals):
        self.prepared_batches.append(tuple(a.approval_id for a in approvals))
        await tx.fetch_all(
            "SELECT * FROM {{tables.dispatch_authority}} WHERE policy_ref = ANY($1::text[]) "
            "ORDER BY policy_ref FOR SHARE",
            sorted({a.policy_ref for a in approvals}),
        )

    async def read(self, tx, approval):
        from aweb_naapp.runtime.approvals import DispatchAuthorityState

        row = await tx.fetch_one(
            "SELECT * FROM {{tables.dispatch_authority}} WHERE policy_ref=$1", approval.policy_ref
        )
        if self.after_read is not None:
            await self.after_read()
        return DispatchAuthorityState(
            policy=None
            if row is None
            else policy(
                policy_ref=approval.policy_ref,
                version=row["version"],
                min_assurance=self.min_assurance,
            ),
            decider_current=False if row is None else row["current_decider"],
        )


async def admitted(world, request=REQUEST, policy_ref="send-charge"):
    _, pending = await mint(world, request, policy_ref=policy_ref)
    approval = await decide(world, pending)
    result = await world.approvals.admit(approval.approval_id, request, "op-1")
    assert result.may_send
    return approval


async def authority(world):
    source = DatabaseAuthority(world)
    await source.create()
    return source


async def prepare(world, tx, approval, source, request=REQUEST, operation="op-1"):
    return await world.approvals.prepare_dispatch(
        tx, approval.approval_id, request, operation, authority=source
    )


async def rows(world, tx):
    # Every primitive-owned table: preparation/checking must leave all unchanged.
    return [
        await tx.fetch_all("SELECT * FROM {{tables." + table + "}} ORDER BY 1")
        for table in (
            "approvals",
            "approval_candidates",
            "approval_links",
            "approval_requests",
            "audit_outbox",
        )
    ]


async def test_final_check_passes_repeatedly_without_writing_or_rearming(world):
    a = await admitted(world)
    source = await authority(world)
    async with world.store.db.transaction() as tx:
        before = await rows(world, tx)
        prepared = await prepare(world, tx, a, source)
        assert prepared.expires_at == a.expires_at
        assert await world.approvals.check_dispatch(tx, prepared) is None
        # The caller can perform awaited outbox work before its final check.
        await tx.execute("SELECT pg_sleep(0.001)")
        assert await world.approvals.check_dispatch(tx, prepared) is None
        assert await rows(world, tx) == before
        stable = await world.approvals.retrieve(a.approval_id, REQUEST, "op-1", tx=tx)
        assert stable is not None and not stable.may_send
        assert not (await world.approvals.admit(a.approval_id, REQUEST, "op-1", tx=tx)).may_send


@pytest.mark.parametrize("change", ["revoke", "expiry", "policy", "retire", "missing_policy"])
async def test_committed_change_between_admission_and_final_check_refuses(world, change):
    a = await admitted(world)
    source = await authority(world)
    expected = {
        "revoke": Refusal.REVOKED,
        "expiry": Refusal.EXPIRED,
        "policy": Refusal.POLICY_CHANGED,
        "retire": Refusal.APPROVER_RETIRED,
        "missing_policy": Refusal.POLICY_UNKNOWN,
    }[change]
    if change == "revoke":
        # Public revocation stops a known-unsent attempt; dispatched history stays intact.
        await world.approvals.record_outcome(a.approval_id, "op-1", DispatchOutcome.NOT_SENT)
        await world.approvals.revoke(a.approval_id, revoked_by="owner")
    elif change == "expiry":
        world.clock.advance(timedelta(minutes=11))
    else:
        async with world.store.db.transaction() as other:
            if change == "policy":
                await other.execute("UPDATE {{tables.dispatch_authority}} SET version=2")
            elif change == "retire":
                await other.execute(
                    "UPDATE {{tables.dispatch_authority}} SET current_decider=false"
                )
            else:
                await other.execute("DELETE FROM {{tables.dispatch_authority}}")
    async with world.store.db.transaction() as tx:
        prepared = await prepare(world, tx, a, source)
        before = await rows(world, tx)
        assert await refusal(world.approvals.check_dispatch(tx, prepared)) is expected
        assert await rows(world, tx) == before
    # Stable retrieval must still succeed after expiry/policy/designation changes.
    if change != "revoke":
        stable = await world.approvals.retrieve(a.approval_id, REQUEST, "op-1")
        assert stable is not None and not stable.may_send


@pytest.mark.parametrize("when", ["after_prepare", "during_read"])
async def test_expiry_is_sampled_after_last_await(world, when):
    a = await admitted(world)
    source = await authority(world)
    async with world.store.db.transaction() as tx:
        prepared = await prepare(world, tx, a, source)
        if when == "after_prepare":
            world.clock.advance(timedelta(minutes=10))
        else:

            async def advance_after_await():
                await tx.execute("SELECT pg_sleep(0.001)")
                world.clock.advance(timedelta(minutes=10))

            source.after_read = advance_after_await
        assert await refusal(world.approvals.check_dispatch(tx, prepared)) is Refusal.EXPIRED


async def test_final_check_requires_the_deciders_current_minimum_assurance(world):
    _, a = await mint(world, policy_ref="internal-edit")
    await decide(world, a, assurance=Assurance.MEMBER_SESSION)
    await world.approvals.admit(a.approval_id, REQUEST, "op-1")
    source = await authority(world)
    await world.store.db.execute(
        "INSERT INTO {{tables.dispatch_authority}} VALUES ('internal-edit',1,true)"
    )
    async with world.store.db.transaction() as tx:
        prepared = await prepare(world, tx, a, source)
        assert (
            await refusal(world.approvals.check_dispatch(tx, prepared))
            is Refusal.ASSURANCE_INSUFFICIENT
        )


@pytest.mark.parametrize(
    "outcome", [o for o in DispatchOutcome if o is not DispatchOutcome.DISPATCHING]
)
async def test_only_original_dispatching_attempt_can_pass(world, outcome):
    a = await admitted(world)
    source = await authority(world)
    if outcome in (
        DispatchOutcome.COMPLETED,
        DispatchOutcome.NOT_SENT,
        DispatchOutcome.OUTCOME_UNKNOWN,
    ):
        await world.approvals.record_outcome(
            a.approval_id,
            "op-1",
            outcome,
            response_status="200" if outcome is DispatchOutcome.COMPLETED else None,
        )
    else:
        await world.approvals.reconcile(
            a.approval_id,
            "op-1",
            outcome,
            reconciled_by="owner",
        )
    async with world.store.db.transaction() as tx:
        prepared = await prepare(world, tx, a, source)
        assert (
            await refusal(world.approvals.check_dispatch(tx, prepared)) is Refusal.OUTCOME_INVALID
        )


@pytest.mark.parametrize("wrong", ["request", "operation", "missing", "not_consumed"])
async def test_prepare_binds_exact_original_request_and_operation(world, wrong):
    a = await (approved(world) if wrong == "not_consumed" else admitted(world))
    source = await authority(world)
    if wrong == "missing":
        a = replace(a, approval_id="missing")
    expected = {
        "request": Refusal.REQUEST_MISMATCH,
        "operation": Refusal.OPERATION_MISMATCH,
        "missing": Refusal.NOT_FOUND,
        "not_consumed": Refusal.OPERATION_MISMATCH,
    }[wrong]
    async with world.store.db.transaction() as tx:
        assert (
            await refusal(
                prepare(
                    world,
                    tx,
                    a,
                    source,
                    request={**REQUEST, "source_version": 2} if wrong == "request" else REQUEST,
                    operation="op-other" if wrong == "operation" else "op-1",
                )
            )
            is expected
        )


async def test_final_read_sees_same_tx_changes_and_original_deadline_is_immutable(world):
    a = await admitted(world)
    source = await authority(world)
    async with world.store.db.transaction() as tx:
        prepared = await prepare(world, tx, a, source)
        # A producer's own updates after prepare cannot escape the final fence.
        await tx.execute("UPDATE {{tables.dispatch_authority}} SET current_decider=false")
        assert (
            await refusal(world.approvals.check_dispatch(tx, prepared)) is Refusal.APPROVER_RETIRED
        )
        await tx.execute("UPDATE {{tables.dispatch_authority}} SET current_decider=true")
        await tx.execute("UPDATE {{tables.approvals}} SET expires_at=expires_at+interval '1 hour'")
        world.clock.advance(timedelta(minutes=10))
        assert prepared.expires_at == a.expires_at
        assert await refusal(world.approvals.check_dispatch(tx, prepared)) is Refusal.EXPIRED


async def test_preparation_is_bound_to_original_outer_tx_and_live_connection(world):
    a = await admitted(world)
    source = await authority(world)
    async with world.store.db.transaction() as tx:
        prepared = await prepare(world, tx, a, source)
        # The store creates its own nested wrappers internally, not the handle's owner.
        async with world.store.locked(a.approval_id, tx):
            await world.approvals.check_dispatch(tx, prepared)
        different_wrapper = TransactionManager(tx.connection, world.store.db)
        assert (
            await refusal(world.approvals.check_dispatch(different_wrapper, prepared))
            is Refusal.DISPATCH_NOT_PREPARED
        )
        async with world.store.db.transaction() as other:
            assert (
                await refusal(world.approvals.check_dispatch(other, prepared))
                is Refusal.DISPATCH_NOT_PREPARED
            )
    async with world.store.db.transaction() as later:
        assert (
            await refusal(world.approvals.check_dispatch(later, prepared))
            is Refusal.DISPATCH_NOT_PREPARED
        )


async def test_preparation_rolled_back_to_savepoint_is_not_reusable(world):
    class Rollback(Exception):
        pass

    a = await admitted(world)
    source = await authority(world)
    async with world.store.db.transaction() as tx:
        try:
            async with tx.transaction():
                # Even when the app passes its outer wrapper, rollback releases the locks.
                prepared = await prepare(world, tx, a, source)
                raise Rollback
        except Rollback:
            pass
        assert (
            await refusal(world.approvals.check_dispatch(tx, prepared))
            is Refusal.DISPATCH_NOT_PREPARED
        )
        prepared = await prepare(world, tx, a, source)
        await world.approvals.check_dispatch(tx, prepared)


async def test_preparation_requires_read_committed_not_a_stale_transaction_snapshot(world):
    a = await admitted(world)
    source = await authority(world)
    async with world.store.db.transaction() as tx:
        await tx.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
        assert await refusal(prepare(world, tx, a, source)) is Refusal.DISPATCH_NOT_PREPARED


async def held_locks(tx):
    return await tx.fetch_all(
        "SELECT locktype,database,relation,page,tuple,virtualxid,transactionid::text,"
        "classid,objid,objsubid,mode,granted FROM pg_locks "
        "WHERE pid=pg_backend_pid() ORDER BY 1,2,3,4,5,6,7,8,9,10,11"
    )


async def test_final_check_acquires_no_new_locks_and_does_not_write(world):
    a = await admitted(world)
    source = await authority(world)
    async with world.store.db.transaction() as tx:
        prepared = await prepare(world, tx, a, source)
        before = await rows(world, tx)
        locks = await held_locks(tx)
        for _ in range(2):
            await world.approvals.check_dispatch(tx, prepared)
        assert await held_locks(tx) == locks
        assert await rows(world, tx) == before


@pytest.mark.parametrize("blocked", ["authority_union", "row_union"])
async def test_batch_prepares_whole_authority_union_before_b2_rows_and_requests(world, blocked):
    from aweb_naapp.runtime.approvals import DispatchBinding

    world.policies.set(policy(policy_ref="send-charge-a"))
    world.policies.set(policy(policy_ref="send-charge-z"))
    first = await admitted(world, policy_ref="send-charge-a")
    other_request = {**REQUEST, "source_version": 2}
    second = await admitted(world, other_request, policy_ref="send-charge-z")
    source = await authority(world)
    db = world.store.db
    await db.executemany(
        "INSERT INTO {{tables.dispatch_authority}} VALUES ($1,1,true)",
        [(first.policy_ref,), (second.policy_ref,)],
    )
    items = [(first, REQUEST), (second, other_request)]
    if blocked == "row_union":
        # Block the later approval in the promised sorted B2 row order.
        items.sort(key=lambda item: item[0].approval_id)
    started = asyncio.get_running_loop().create_future()
    ready = asyncio.Event()
    release = asyncio.Event()

    async def worker():
        async with db.transaction() as tx:
            started.set_result(await tx.fetch_value("SELECT pg_backend_pid()"))
            prepared = await world.approvals.prepare_dispatches(
                tx,
                [DispatchBinding(a.approval_id, request, "op-1") for a, request in items],
                authority=source,
            )
            ready.set()
            await release.wait()
            for handle in prepared:
                await world.approvals.check_dispatch(tx, handle)

    task = None
    try:
        async with db.transaction() as holder:
            blocker = await holder.fetch_value("SELECT pg_backend_pid()")
            if blocked == "authority_union":
                # Distinct authority rows: the first can be prepared immediately,
                # but the later one blocks the complete authority batch.
                await holder.fetch_value(
                    "SELECT policy_ref FROM {{tables.dispatch_authority}} "
                    "WHERE policy_ref=$1 FOR UPDATE",
                    second.policy_ref,
                )
            else:
                await holder.fetch_value(
                    "SELECT approval_id FROM {{tables.approvals}} WHERE approval_id=$1 FOR UPDATE",
                    items[-1][0].approval_id,
                )
            task = asyncio.create_task(worker())
            pid = await asyncio.wait_for(started, 5)
            async with asyncio.timeout(5):
                while blocker not in await db.fetch_value("SELECT pg_blocking_pids($1)", pid):
                    if task.done():
                        await task
                    await asyncio.sleep(0.01)
            # The real SQL adapter must see the complete union in ONE invocation.
            assert len(source.prepared_batches) == 1
            assert set(source.prepared_batches[0]) == {first.approval_id, second.approval_id}
            if blocked == "authority_union":
                # Even the earlier item's B2 row stays free while later authority blocks.
                for a in (first, second):
                    async with db.transaction() as observer:
                        assert (
                            await observer.fetch_value(
                                "SELECT approval_id FROM {{tables.approvals}} "
                                "WHERE approval_id=$1 FOR UPDATE NOWAIT",
                                a.approval_id,
                            )
                            == a.approval_id
                        )
            else:
                # The earlier row is held before waiting for the later row;
                # neither request advisory lock may have been acquired yet.
                with pytest.raises(asyncpg.exceptions.LockNotAvailableError):
                    async with db.transaction() as observer:
                        await observer.fetch_value(
                            "SELECT approval_id FROM {{tables.approvals}} "
                            "WHERE approval_id=$1 FOR UPDATE NOWAIT",
                            items[0][0].approval_id,
                        )
            for a in (first, second):
                async with db.transaction() as observer:
                    assert await observer.fetch_value(
                        "SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))",
                        "aweb_naapp_approvals:" + a.request_sha256,
                    )
        await asyncio.wait_for(ready.wait(), 5)
        for a in (first, second):
            with pytest.raises(asyncpg.exceptions.LockNotAvailableError):
                async with db.transaction() as observer:
                    await observer.fetch_value(
                        "SELECT approval_id FROM {{tables.approvals}} WHERE approval_id=$1 FOR UPDATE NOWAIT",
                        a.approval_id,
                    )
            async with db.transaction() as observer:
                assert not await observer.fetch_value(
                    "SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))",
                    "aweb_naapp_approvals:" + a.request_sha256,
                )
        release.set()
        await asyncio.wait_for(task, 5)
    finally:
        release.set()
        if task is not None and not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
