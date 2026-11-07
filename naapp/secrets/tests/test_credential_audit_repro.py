"""Root consumer regressions exercise the canonical writer order and resolver."""

import pytest
from aweb_naapp.runtime.credential_audit import GovernanceUnavailable

from tests.test_change_sets import (
    ALICE,
    TEAM,
    by_member,
    change_set,
    decide,
    designate_approver,
    draft,
    enrol_owner,
)
from tests.test_credential_audit import audit_for, designate, events, target
from tests.test_credential_audit import world as world


async def test_canonical_approver_writer_binds_metadata_before_designation_audit(world):
    await enrol_owner(world, ALICE, "owner@example.com")
    audit = await audit_for(world)
    item = designate_approver("finance", "finance@example.com", ["sec_19ab42"])
    request = change_set(drafter=by_member(ALICE), changes=[item])
    approval_id = await draft(world, request)
    await decide(world, approval_id, "owner@example.com")
    async with world.db.transaction() as tx:
        await world.fence.check(tx, world.admitted)
        evidence = await world.passkeys.owner_approval(
            tx,
            world.approvals,
            approval_id=approval_id,
            request=request,
            operation_id="create-finance-with-audit",
        )
        assert not await tx.fetch_value("SELECT count(*) FROM {{tables.approvers}}")
        with audit.approved(world.admitted, evidence, target()):
            # This is the actual effect called by ChangeSets.confirm, without
            # the fixture's hand-written record_approver-before-designate order.
            [designation] = await world.change_sets._apply(
                tx, request, item, evidence, ALICE.principal_did
            )
        row = await tx.fetch_one(
            "SELECT scope,change_id FROM {{tables.approvers}} "
            "WHERE installation_id=$1 AND team_id=$2 AND approver_ref='finance'",
            world.admitted.installation_id,
            TEAM,
        )
        assert row["scope"] == designation.approver.scope
        assert row["change_id"] == request["change_id"]
    [recorded] = await events(world)
    assert recorded["payload"]["act"] == "role.designated"
    assert recorded["payload"]["approval_id"] == approval_id


async def test_unavailable_scope_resolver_is_a_fixed_governance_refusal(world):
    audit = await audit_for(world)
    # B3 writes the link before emit resolves the new designation. Expiry at
    # that actual SQL boundary must retain the caller's fixed503 contract.
    await world.db.execute(
        "CREATE FUNCTION expire_designation_context() RETURNS trigger LANGUAGE plpgsql AS $$ "
        "BEGIN UPDATE {{tables.installation_fences}} "
        "SET fresh_until=clock_timestamp()-interval '1 second'; RETURN NEW; END $$"
    )
    await world.db.execute(
        "CREATE TRIGGER expire_designation_context AFTER INSERT ON {{tables.passkey_enrolments}} "
        "FOR EACH ROW EXECUTE FUNCTION expire_designation_context()"
    )
    with pytest.raises(GovernanceUnavailable) as refused:
        await designate(world, audit)
    assert (refused.value.status, refused.value.code) == (503, "release_context_unavailable")
    for table in (
        "passkey_approvers",
        "passkey_enrolments",
        "owner_act_nonces",
        "owner_principals",
        "outbox_events",
    ):
        assert await world.db.fetch_value("SELECT count(*) FROM {{tables." + table + "}}") == 0
