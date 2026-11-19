"""Actual owner policy/directory reads share the caller's visibility and rollback."""

import pytest
from aweb_naapp.roles import unassign

from aweb_secrets.change_sets import ChangeSetPolicies, change_policy_ref
from aweb_secrets.owners import OWNER_ROLE
from tests.test_change_sets import ALICE, enrol_owner

pytest_plugins = ("tests.test_change_sets",)


class RollBack(Exception):
    pass


async def test_owner_policy_and_directory_see_the_callers_uncommitted_revocation(world):
    scope = await enrol_owner(world, ALICE, "alice@acme.com")
    ref = change_policy_ref(world.admitted.installation_id, world.admitted.team_id)
    policies = ChangeSetPolicies(world.db, world.directory)
    before = await policies.current(ref)
    assert before is not None
    approver = await world.passkeys.designated_approver(scope)
    assert approver is not None
    with pytest.raises(RollBack):
        async with world.db.transaction() as tx:
            await world.fence.check(tx, world.admitted)
            await unassign(tx, ALICE, OWNER_ROLE)
            assert await policies.current(ref, tx=tx) is None
            assert await world.directory.candidates(before, {}, tx=tx) == []
            assert not await world.directory.is_current(scope, approver.subject, tx=tx)
            raise RollBack()
    assert await policies.current(ref) == before
    assert await world.directory.is_current(scope, approver.subject)


async def test_mint_and_read_own_uncommitted_approval_then_roll_back_every_effect(world):
    await enrol_owner(world, ALICE, "alice@acme.com")
    ref = change_policy_ref(world.admitted.installation_id, world.admitted.team_id)
    with pytest.raises(RollBack):
        async with world.db.transaction() as tx:
            await world.fence.check(tx, world.admitted)
            pending = await world.approvals.mint(
                request={"operation": "transaction-visibility"},
                policy_ref=ref,
                requested_by="agent-1",
                tx=tx,
            )
            approval = pending.approval
            assert await world.approvals.get(approval.approval_id, tx=tx) == approval
            assert await world.approvals.for_request(approval.request_ref, tx=tx) == approval
            assert (
                await world.approvals.requester_view(approval.request_ref, "agent-1", tx=tx)
                == pending.view
            )
            raise RollBack()
    assert await world.approvals.get(approval.approval_id) is None
    assert (
        await world.db.fetch_value(
            "SELECT count(*) FROM {{tables.audit_outbox}} WHERE kind='approval_requested'"
        )
        == 0
    )
