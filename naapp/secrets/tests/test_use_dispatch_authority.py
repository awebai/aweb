"""The S13 authority adapter uses actual B2, B3 and held app authority."""

from dataclasses import replace

import pytest

from aweb_secrets import records
from aweb_secrets.admission import Admission
from aweb_secrets.use_approvals import admit_approved_use
from aweb_secrets.use_audit import UseAuditUnavailable
from aweb_secrets.use_dispatch_authority import UseDispatchAuthority
from tests.test_use_approvals import REQUESTER, approve
from tests.test_use_approvals import uses as uses
from tests.test_use_approvals import world as world
from tests.test_use_audit import composition


async def approved(uses):
    audit, view, pending, _, dispatch_id = await composition(uses)
    with audit.prepared_view(view):
        await approve(uses, pending, "finance@acme.com")
    approval = await uses.approvals.get(pending.pending.approval.approval_id)
    row = await uses.world.db.fetch_one("SELECT * FROM {{tables.intents}}")
    admission = Admission(
        intent_id=row["intent_id"],
        replayed=True,
        approval_required=True,
        grant_id=row["grant_id"],
        policy_digest=row["policy_digest"],
        installation=uses.world.admitted,
    )
    return approval, admission, dispatch_id


async def test_actual_consumption_and_final_b2_check_use_prepared_current_b3(uses):
    approval, admission, dispatch_id = await approved(uses)
    adapter = UseDispatchAuthority(
        principal=REQUESTER, admission=admission, passkeys=uses.world.passkeys
    )
    async with uses.world.db.transaction() as tx:
        await uses.world.fence.check(tx, admission.installation)
        await adapter.prepare(tx, [approval])
        consumed = await admit_approved_use(
            tx, uses.approvals, intent_id=admission.intent_id, dispatch_id=dispatch_id
        )
        assert consumed.refusal is None and consumed.admission.may_send
        link = await tx.fetch_one("SELECT request FROM {{tables.use_approvals}}")
        import json

        prepared = await uses.approvals.prepare_dispatch(
            tx,
            approval.approval_id,
            json.loads(link["request"]),
            str(dispatch_id),
            authority=adapter,
        )
        await uses.approvals.check_dispatch(tx, prepared)


@pytest.mark.parametrize("change", ["grant", "coverage"])
async def test_withdrawal_before_preparation_is_not_current_dispatch_authority(uses, change):
    approval, admission, _ = await approved(uses)
    async with uses.world.db.transaction() as tx:
        if change == "grant":
            await records.revoke_grant(
                tx, admission.installation.installation_id, admission.grant_id
            )
        else:
            await tx.execute("DELETE FROM {{tables.approvers}}")
    adapter = UseDispatchAuthority(
        principal=REQUESTER, admission=admission, passkeys=uses.world.passkeys
    )
    async with uses.world.db.transaction() as tx:
        await uses.world.fence.check(tx, admission.installation)
        await adapter.prepare(tx, [approval])
        state = await adapter.read(tx, approval)
        assert state.policy is None if change == "grant" else not state.decider_current


async def test_another_scope_or_another_transaction_cannot_reuse_preparation(uses):
    approval, admission, _ = await approved(uses)
    adapter = UseDispatchAuthority(
        principal=REQUESTER, admission=admission, passkeys=uses.world.passkeys
    )
    async with uses.world.db.transaction() as tx:
        await uses.world.fence.check(tx, admission.installation)
        await adapter.prepare(tx, [approval])
        with pytest.raises(UseAuditUnavailable):
            await adapter.read(tx, replace(approval, policy_ref="secrets.run|elsewhere"))
    async with uses.world.db.transaction() as other:
        with pytest.raises(UseAuditUnavailable):
            await adapter.read(other, approval)
        with pytest.raises(UseAuditUnavailable):
            await adapter.prepare(other, [approval])


async def test_final_read_sees_coverage_withdrawn_in_its_original_transaction(uses):
    approval, admission, _ = await approved(uses)
    adapter = UseDispatchAuthority(
        principal=REQUESTER, admission=admission, passkeys=uses.world.passkeys
    )
    async with uses.world.db.transaction() as tx:
        await uses.world.fence.check(tx, admission.installation)
        await adapter.prepare(tx, [approval])
        assert (await adapter.read(tx, approval)).decider_current
        await tx.execute("DELETE FROM {{tables.approvers}}")
        assert not (await adapter.read(tx, approval)).decider_current
