"""Actual controls, current caller authority and S3 settlements over PostgreSQL."""

import asyncio
from datetime import timedelta

import pytest
from aweb_naapp.dispatch import State
from aweb_naapp.roles import unassign
from aweb_naapp.runtime.approvals import (
    ApprovalRefused,
    ApprovalState,
    Assurance,
    Decision,
    Refusal,
)
from fastapi import HTTPException

from aweb_secrets import records
from aweb_secrets.owners import OWNER_ROLE
from aweb_secrets.reconciliation_service import ReconciliationRefused
from tests.reconciliation_world import OwnerFence, service_world
from tests.test_broker_audit import envelopes
from tests.test_change_sets import ALICE
from tests.test_run_status import snapshot as run_snapshot
from tests.test_use_approvals import uses as uses
from tests.test_use_approvals import world as world


async def snapshot(db):
    result = await run_snapshot(db)
    for table in (
        "reconciliation_controls",
        "reconciliation_control_events",
        "reconciliation_control_proofs",
    ):
        result[table] = [
            dict(row)
            for row in await db.fetch_all("SELECT * FROM {{tables." + table + "}} ORDER BY 1")
        ]
    return result


async def mint(uses, service, console, session, ref, outcome="completed"):
    async with uses.world.db.transaction() as tx:
        pending = await service.mint(
            tx,
            reconcile_ref=ref,
            outcome=outcome,
            fence=OwnerFence(console, session, uses.world.admitted),
        )
    await uses.approvals.deliver(pending)
    return pending


async def approve(uses, pending):
    [delivery] = pending.deliveries
    options = await uses.approvals.challenge(
        pending.approval.approval_id,
        Decision.APPROVE,
        Assurance.PASSKEY,
        link_token=delivery.link_token,
    )
    await uses.approvals.decide(
        pending.approval.approval_id,
        Decision.APPROVE,
        Assurance.PASSKEY,
        uses.world.devices["alice@acme.com"].get(dict(options)),
        link_token=delivery.link_token,
    )


@pytest.mark.parametrize("approval_required", [False, True])
@pytest.mark.parametrize(
    "outcome,state",
    [
        ("completed", State.RECONCILED_COMPLETED),
        ("failed", State.RECONCILED_FAILED),
        ("unknown-closed", State.RECONCILED_UNKNOWN),
    ],
)
async def test_exact_fresh_approve_settles_once_without_open_send_or_availability_gate(
    uses, outcome, state, approval_required
):
    context, original, service, console, session = await service_world(
        uses, approval_required=approval_required
    )
    db, scope = uses.world.db, uses.world.admitted
    pending = await mint(uses, service, console, session, original.original.reconcile_ref, outcome)
    async with db.transaction() as tx:
        presentation = await service.present(
            tx, pending=pending, fence=OwnerFence(console, session, scope)
        )
        assert presentation.personal_token == pending.deliveries[0].link_token
        assert presentation.personal_token not in repr(presentation)
        assert presentation.status.delivery_status.value == "delivered"
    before = await snapshot(db)
    with pytest.raises(ApprovalRefused):
        async with db.transaction() as tx:
            await service.settle(
                tx,
                approval_id=pending.approval.approval_id,
                fence=OwnerFence(console, session, scope),
            )
    assert await snapshot(db) == before
    await approve(uses, pending)
    context.available[0] = False
    resource = original.original.resources[0]
    async with db.transaction() as tx:
        await records.set_active_version(
            tx, scope.installation_id, scope.team_id, resource.secret_id, resource.version + 1
        )
    async with db.transaction() as tx:
        receipt = await service.settle(
            tx, approval_id=pending.approval.approval_id, fence=OwnerFence(console, session, scope)
        )
    assert receipt.state == state.value and receipt.reconcile_ref == original.original.reconcile_ref
    assert context.credential not in repr(receipt)
    assert (
        await db.fetch_value(
            "SELECT state FROM {{tables.dispatches}} WHERE dispatch_id=$1",
            original.original.dispatch_id,
        )
        == state.value
    )
    assert (await uses.approvals.get(pending.approval.approval_id)).state is ApprovalState.CONSUMED
    [event] = [
        event for event in await envelopes(db) if event["payload"].get("action") == "reconciled"
    ]
    assert event["payload"]["dispatch_state"] == state.value
    [original_event] = [
        previous
        for previous in await envelopes(db)
        if previous["payload"].get("dispatch_id") == event["payload"]["dispatch_id"]
        and previous["payload"].get("dispatch_state") == "outcome_unknown"
    ]
    assert event["actor"] == original_event["actor"]
    async with db.transaction() as tx:
        originals = await context.arguments["use_audit"].dispatch_approvals(
            tx, original.original.dispatch_id
        )
        if approval_required:
            assert len(originals) == 1
        assert all(approval.dispatch_outcome.value == state.value for approval in originals)
    settled = await snapshot(db)
    async with db.transaction() as tx:
        again = await service.settle(
            tx, approval_id=pending.approval.approval_id, fence=OwnerFence(console, session, scope)
        )
        status = await service.status(tx, scope=scope, approval_id=pending.approval.approval_id)
    assert again == receipt and await snapshot(db) == settled
    assert status is not None and "personal_token" not in repr(status)


async def test_competing_outcomes_preserve_one_settlement_and_roll_back_the_loser(uses):
    _, original, service, console, session = await service_world(uses)
    db, scope = uses.world.db, uses.world.admitted
    first = await mint(uses, service, console, session, original.original.reconcile_ref)
    second = await mint(uses, service, console, session, original.original.reconcile_ref, "failed")
    await approve(uses, first)
    await approve(uses, second)

    async def settle(pending):
        async with db.transaction() as tx:
            # Catch inside the outer tx: the service's savepoint must undo its
            # losing consumption, audit and original B2 consequences itself.
            try:
                return await service.settle(
                    tx,
                    approval_id=pending.approval.approval_id,
                    fence=OwnerFence(console, session, scope),
                )
            except ReconciliationRefused as exc:
                return exc.code

    results = await asyncio.gather(settle(first), settle(second))
    assert sum(result == "reconciliation_conflict" for result in results) == 1
    assert [
        a.state for a in [await uses.approvals.get(p.approval.approval_id) for p in (first, second)]
    ].count(ApprovalState.CONSUMED) == 1
    assert len([e for e in await envelopes(db) if e["payload"].get("action") == "reconciled"]) == 1


async def test_owner_revocation_prevents_postcommit_token_presentation(uses):
    _, original, service, console, session = await service_world(uses)
    pending = await mint(uses, service, console, session, original.original.reconcile_ref)
    async with uses.world.db.transaction() as tx:
        await unassign(tx, ALICE, OWNER_ROLE)
    with pytest.raises(HTTPException) as refused:
        async with uses.world.db.transaction() as tx:
            await service.present(
                tx, pending=pending, fence=OwnerFence(console, session, uses.world.admitted)
            )
    assert refused.value.status_code == 403


async def test_expiry_during_the_original_s3_lock_wait_rolls_back_all_settlement_effects(uses):
    _, original, service, console, session = await service_world(uses)
    db, scope = uses.world.db, uses.world.admitted
    pending = await mint(uses, service, console, session, original.original.reconcile_ref)
    await approve(uses, pending)
    before = await snapshot(db)
    async with db.transaction() as blocker:
        await blocker.fetch_one(
            "SELECT dispatch_id FROM {{tables.dispatches}} WHERE dispatch_id=$1 FOR UPDATE",
            original.original.dispatch_id,
        )

        async def settle():
            async with db.transaction() as tx:
                with pytest.raises(ApprovalRefused) as refused:
                    await service.settle(
                        tx,
                        approval_id=pending.approval.approval_id,
                        fence=OwnerFence(console, session, scope),
                    )
                assert refused.value.reason is Refusal.EXPIRED

        task = asyncio.create_task(settle())
        for _ in range(500):
            if await db.fetch_value(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%dispatches%FOR UPDATE%')"
            ):
                break
            await asyncio.sleep(0.01)
        else:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            pytest.fail("settlement did not reach the original S3 lock")
        uses.clock.now += timedelta(minutes=6)
    await asyncio.wait_for(task, 5)
    assert await snapshot(db) == before
