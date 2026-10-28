"""Repeat observations use the authorized original, without changing its control."""

import asyncio
from dataclasses import replace
from uuid import uuid4

import pytest
from aweb_naapp.dispatch import State
from aweb_naapp.runtime.installation import InstallationRefused

from aweb_secrets.reconciliation_reads import ReconciliationReads
from aweb_secrets.use_audit import UseAuditUnavailable
from tests.test_broker_audit import db as db
from tests.test_broker_audit import fence as fence
from tests.test_broker_audit import prepared
from tests.test_broker_fence import authority
from tests.test_status_service import snapshot


async def uncertain(db, fence):
    request, admission, dispatch_id, machine = await prepared(db, fence)
    async with db.transaction() as tx:
        await machine.admit(
            tx, dispatch_id, fence=authority(fence, admission, request, dispatch_id)
        )
        await machine.begin_dispatch(
            tx, dispatch_id, fence=authority(fence, admission, request, dispatch_id)
        )
        assert await machine.outcome_unknown(tx, dispatch_id, {"state": "outcome_unknown"})
    return admission, dispatch_id, machine


async def observed_repeat(tx, original_id):
    # Persist only the S3 observation fixture. These reader tests do not claim
    # to implement or execute the app's separately owned automatic repeat.
    repeat_id = uuid4()
    await tx.execute(
        "INSERT INTO {{tables.dispatches}}"
        " (dispatch_id,subject,action,retry_exempt,state,continues)"
        " SELECT $1,subject,action,retry_exempt,'received',dispatch_id"
        " FROM {{tables.dispatches}} WHERE dispatch_id=$2",
        repeat_id,
        original_id,
    )
    return repeat_id


async def test_broker_repeat_states_are_read_only_and_keep_the_original_pins(db, fence):
    admission, original_id, machine = await uncertain(db, fence)
    reads = ReconciliationReads()
    scope, ref = admission.installation, admission.intent_id
    async with db.transaction() as tx:
        original = await reads.get(tx, scope=scope, reconcile_ref=ref)
        assert original is not None and original.repeat_state is None
        repeat_id = await observed_repeat(tx, original_id)
    for state in (
        State.RECEIVED,
        State.ADMITTED,
        State.DISPATCHING,
        State.NOT_SENT,
        State.OUTCOME_UNKNOWN,
        State.COMPLETED,
        State.REFUSED,
        State.CANCELLED,
    ):
        await db.execute(
            "UPDATE {{tables.dispatches}} SET state=$2,"
            " sweep_after=clock_timestamp()+interval '60 seconds' WHERE dispatch_id=$1",
            repeat_id,
            state.value,
        )
        before = await snapshot(db)
        async with db.transaction() as tx:
            await tx.execute("SET TRANSACTION READ ONLY")
            view = await reads.get(tx, scope=scope, reconcile_ref=ref)
        assert view is not None and view.repeat_state is state
        assert view.original == original.original and view.state is State.OUTCOME_UNKNOWN
        assert await snapshot(db) == before
    await db.execute(
        "UPDATE {{tables.dispatches}} SET state='outcome_unknown' WHERE dispatch_id=$1", repeat_id
    )
    async with db.transaction() as tx:
        await machine.reconcile(tx, original_id, State.RECONCILED_UNKNOWN, {"state": "closed"})
    before = await snapshot(db)
    async with db.transaction() as blocker:
        await blocker.fetch_one(
            "SELECT dispatch_id FROM {{tables.dispatches}} WHERE dispatch_id=ANY($1) FOR UPDATE",
            [original_id, repeat_id],
        )
        async with db.transaction() as tx:
            await tx.execute("SET TRANSACTION READ ONLY")
            settled = await asyncio.wait_for(reads.get(tx, scope=scope, reconcile_ref=ref), 1)
    assert settled is not None and settled.state is State.RECONCILED_UNKNOWN
    assert settled.repeat_state is State.OUTCOME_UNKNOWN
    assert settled.original == original.original
    assert await snapshot(db) == before


@pytest.mark.parametrize("fault", ["subject", "action", "retry_exempt", "multiple"])
async def test_corrupt_repeat_association_refuses_only_after_original_scope_is_authorized(
    db, fence, fault
):
    admission, original_id, _ = await uncertain(db, fence)
    scope, ref = admission.installation, admission.intent_id
    reads = ReconciliationReads()
    async with db.transaction() as tx:
        repeat_id = await observed_repeat(tx, original_id)
        if fault == "multiple":
            await tx.execute("DROP INDEX {{tables.idx_dispatches_continues}}")
            await observed_repeat(tx, original_id)
        elif fault == "retry_exempt":
            await tx.execute(
                "UPDATE {{tables.dispatches}} SET retry_exempt=NOT retry_exempt WHERE dispatch_id=$1",
                repeat_id,
            )
        else:
            await tx.execute(
                "UPDATE {{tables.dispatches}} SET " + fault + "='other' WHERE dispatch_id=$1",
                repeat_id,
            )
    before = await snapshot(db)
    async with db.transaction() as tx:
        await tx.execute("SET TRANSACTION READ ONLY")
        for foreign in (
            replace(scope, app_id="other"),
            replace(scope, installation_id="other"),
            replace(scope, team_id="other:example.com"),
        ):
            assert await reads.get(tx, scope=foreign, reconcile_ref=ref) is None
        with pytest.raises(InstallationRefused) as refused:
            await reads.get(
                tx, scope=replace(scope, generation=scope.generation + 1), reconcile_ref=ref
            )
        assert refused.value.code == "generation_superseded"
        with pytest.raises(UseAuditUnavailable):
            await reads.get(tx, scope=scope, reconcile_ref=ref)
    assert await snapshot(db) == before
