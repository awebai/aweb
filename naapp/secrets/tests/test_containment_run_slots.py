"""Containment uses the shared run-slot associations, on real PostgreSQL."""

import json

import asyncpg
import pytest
from aweb_naapp.roles import principal_key

from aweb_secrets.containment import ContainmentRefused
from tests.test_change_sets import TEAM, world  # noqa: F401
from tests.test_containment_console import authorize, finance_session
from tests.test_containment_service import act, service
from tests.test_run_approvals import plan_for, request
from tests.test_use_approvals import _member
from tests.test_use_approvals import uses as uses  # noqa: F401


async def test_owner_revokes_only_the_named_run_slot(uses):
    plan = await plan_for(uses)
    pending = await request(uses, plan)
    ids = [item.pending.approval.approval_id for item in pending]
    svc = await service(uses)
    await act(svc, uses, "revoke-approvals", ids[0])
    assert (await uses.approvals.get(ids[0])).state.value == "revoked"
    assert (await uses.approvals.get(ids[1])).state.value == "pending"


async def test_member_run_slot_revocation_needs_its_current_source_coverage(uses):
    approver = _member(8)
    plan = await plan_for(uses)
    await uses.world.db.execute(
        "UPDATE {{tables.approvers}} SET principal_did=$1 WHERE approver_ref='finance'",
        principal_key(approver).principal_did,
    )
    pending = await request(uses, plan)
    ids = [item.pending.approval.approval_id for item in pending]
    svc = await service(uses)
    await uses.world.db.execute(
        "UPDATE {{tables.approvers}} SET covers=$1::jsonb WHERE approver_ref='finance'",
        json.dumps([plan.slots[1].source_id]),
    )
    with pytest.raises(ContainmentRefused):
        await svc.by_member(
            grant=uses.grant,
            principal=approver,
            request_id="uncovered",
            action="revoke-approvals",
            target=ids[0],
        )
    assert (await uses.approvals.get(ids[0])).state.value == "pending"
    await svc.by_member(
        grant=uses.grant,
        principal=approver,
        request_id="covered",
        action="revoke-approvals",
        target=ids[1],
    )
    assert (await uses.approvals.get(ids[1])).state.value == "revoked"


async def test_console_full_plan_view_does_not_broaden_run_slot_coverage(uses):
    plan = await plan_for(uses)
    pending = await request(uses, plan)
    svc = await service(uses)
    session = await finance_session(uses)
    await uses.world.db.execute(
        "UPDATE {{tables.approvers}} SET covers=$1::jsonb WHERE approver_ref='finance'",
        json.dumps([plan.slots[1].source_id]),
    )
    with pytest.raises(ContainmentRefused) as refused:
        await authorize(
            svc, uses, session, "revoke-approvals", pending[0].pending.approval.approval_id
        )
    assert refused.value.code == "coverage_denied"
    assert not await authorize(
        svc, uses, session, "revoke-approvals", pending[1].pending.approval.approval_id
    )


async def test_replacement_prelocks_run_slot_approvals_before_any_callback(uses):
    plan = await plan_for(uses)
    pending = await request(uses, plan)
    svc = await service(uses)
    async with uses.world.db.transaction() as tx:
        installed = await uses.world.fence.admit(tx, uses.grant)
        await svc.prepare_replacements(
            tx,
            installation_id=installed.installation_id,
            team_id=TEAM,
            secret_ids=(plan.slots[0].source_id,),
        )
        # A different PG connection can lock the neighbor but must wait for
        # this slot before it can retire/consume it.
        async with uses.world.db.transaction() as other:
            await uses.approvals.lock_many(other, [pending[1].pending.approval.approval_id])
            await other.execute("SET LOCAL lock_timeout='100ms'")
            with pytest.raises(asyncpg.LockNotAvailableError):
                await uses.approvals.lock_many(other, [pending[0].pending.approval.approval_id])
