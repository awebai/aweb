"""Token-dependent roots invalidate without fabricating a replacement version."""

import pytest
from aweb_naapp.roles import hold_role, principal_key
from aweb_naapp.runtime.approvals import ApprovalState
from aweb_naapp_testing.owner_acts import INSTALLATION_ID

from aweb_secrets import records
from aweb_secrets.custody import CustodyUnavailable
from aweb_secrets.owners import OWNER_ROLE
from tests.test_change_sets import TEAM, world  # noqa: F401
from tests.test_containment import seal
from tests.test_containment_service import service
from tests.test_use_approval_lineage import child, request_child, seed
from tests.test_use_approvals import REQUESTER, approve
from tests.test_use_approvals import uses as _uses

uses = _uses


@pytest.mark.parametrize("root_disabled", [False, True])
@pytest.mark.parametrize("rollback", [False, True])
async def test_invalidation_all_versions_and_descendants_preserves_root_and_siblings(
    uses, root_disabled, rollback
):  # noqa: F811
    await seed(uses)
    root, _ = await child(uses)
    old = await request_child(uses, root)
    async with uses.world.db.transaction() as tx:
        await records.set_active_version(tx, INSTALLATION_ID, TEAM, root.secret_id, 2)
    current = await request_child(uses, root)
    await approve(uses, current[2], "finance@acme.com")
    descendant, _ = await child(uses, secret_id="sec_grand001", parent=root.secret_id)
    below = await request_child(uses, descendant)
    sibling, _ = await child(uses, secret_id="sec_other001")
    untouched = await request_child(uses, sibling)
    contexts = [await seal(uses, item.secret_id) for item in (root, descendant, sibling)]
    if root_disabled:
        async with uses.world.db.transaction() as tx:
            await tx.execute(
                "UPDATE {{tables.secrets}} SET state='disabled' WHERE secret_id=$1",
                root.secret_id,
            )
            await uses.world.custody.disable(
                tx, installation_id=INSTALLATION_ID, team_id=TEAM, secret_id=root.secret_id
            )
    svc = await service(uses)
    try:
        async with uses.world.db.transaction() as tx:
            await uses.world.fence.admit(tx, uses.grant)
            assert await hold_role(tx, principal_key(REQUESTER), OWNER_ROLE)
            await svc.prepare_replacements(
                tx, installation_id=INSTALLATION_ID, team_id=TEAM, secret_ids=(root.secret_id,)
            )
            affected = await svc.invalidate_value_consequences(
                tx,
                installation_id=INSTALLATION_ID,
                team_id=TEAM,
                secret_id=root.secret_id,
                revoked_by="confirming-owner",
            )
            assert set(affected) == {root.secret_id, descendant.secret_id}
            if rollback:
                raise RuntimeError("abort confirming transaction")
    except RuntimeError as error:
        if not rollback or str(error) != "abort confirming transaction":
            raise
    expected = (ApprovalState.PENDING, ApprovalState.APPROVED, ApprovalState.PENDING)
    for index, item in enumerate((old, current, below)):
        approval = await uses.approvals.get(item[2].pending.approval.approval_id)
        assert approval.state == (expected[index] if rollback else ApprovalState.REVOKED)
    assert (
        await uses.approvals.get(untouched[2].pending.approval.approval_id)
    ).state == ApprovalState.PENDING
    async with uses.world.db.transaction() as tx:
        stored = await records.secret_by_ref(tx, INSTALLATION_ID, TEAM, root.ref)
        assert stored.state == ("disabled" if root_disabled else "active")
        assert stored.active_version == 2  # ChangeSets owns clearing/activation.
        stored_child = await records.secret_by_ref(tx, INSTALLATION_ID, TEAM, descendant.ref)
        assert stored_child.state == ("active" if rollback else "disabled")
        assert (
            await records.secret_by_ref(tx, INSTALLATION_ID, TEAM, sibling.ref)
        ).state == "active"
    if root_disabled:
        with pytest.raises(CustodyUnavailable):
            await uses.world.custody.opener.open(contexts[0])
    else:
        assert await uses.world.custody.opener.open(contexts[0]) is not None
    if rollback:
        assert await uses.world.custody.opener.open(contexts[1]) is not None
    else:
        with pytest.raises(CustodyUnavailable):
            await uses.world.custody.opener.open(contexts[1])
    assert await uses.world.custody.opener.open(contexts[2]) is not None
