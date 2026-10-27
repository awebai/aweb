"""Pending-contact completion keeps the scheduling APPROVE and candidate identity."""

import json
from datetime import UTC, datetime

import pytest
from aweb_naapp.runtime.credential_audit import GovernanceUnavailable
from aweb_naapp.runtime.passkeys import ContactChangeRefused, contact_sha256
from aweb_naapp_testing.webauthn import SoftAuthenticator

from aweb_secrets.owners import approver_scope
from tests.test_change_sets import (
    ALICE,
    ORIGIN,
    TEAM,
    by_member,
    change_approver_contact,
    change_set,
    decide,
)
from tests.test_credential_audit import approved_designation, events, target
from tests.test_credential_audit import world as world


async def schedule(world, *, prepared=True):
    audit, contact, _, _ = await approved_designation(world)
    token = world.inbox.enrolments[contact][-1]
    enrolment = await audit.prepare_enrolment(token)
    with audit.prepared(enrolment):
        await world.passkeys.complete_enrolment(
            token,
            SoftAuthenticator(ORIGIN).create(await world.passkeys.enrolment_options(token)),
            fence=enrolment,
        )
    new_contact = "new-finance@example.com"
    request = change_set(
        drafter=by_member(ALICE),
        changes=[change_approver_contact("finance", new_contact)],
    )
    async with world.db.transaction() as tx:
        pending = await world.change_sets.draft(tx, request)
    await world.approvals.deliver(pending)
    approval_id = pending.approval.approval_id
    await decide(world, approval_id, "owner@example.com")
    scope = approver_scope(world.admitted.installation_id, TEAM, "finance")
    async with world.db.transaction() as tx:
        await world.fence.check(tx, world.admitted)
        evidence = await world.passkeys.owner_approval(
            tx,
            world.approvals,
            approval_id=approval_id,
            request=request,
            operation_id="change-finance-contact",
        )
        context = (
            audit.approved(world.admitted, evidence, target()) if prepared else audit.prepared(None)
        )
        with context:
            change = await world.passkeys.change_contact_by_owner(
                tx, scope=scope, new_contact=new_contact, evidence=evidence
            )
        await world.fence.check(tx, world.admitted)
    await world.passkeys.send_notices(change)
    return audit, scope, contact, new_contact, change.proof_token, approval_id


async def test_proof_records_the_same_candidate_and_original_schedule_authority(world):
    audit, scope, old_contact, new_contact, token, approval_id = await schedule(world)
    prepared = await audit.prepare_contact_proof(token)
    with audit.prepared(prepared):
        effective_at = await world.passkeys.prove_contact(token, fence=prepared)
    _, _, scheduled, proven = await events(world)
    assert effective_at > datetime.now(UTC)
    assert (await world.passkeys.designated_approver(scope)).contact == old_contact
    assert scheduled["payload"]["reason_code"] == "contact_change_scheduled"
    assert proven["payload"]["reason_code"] == "contact_proven"
    for event in (scheduled, proven):
        assert event["payload"]["act"] == "credential.enrolled"
        assert event["payload"]["direction"] == "widening"
        assert event["payload"]["resource_type"] == "pending_contact"
        assert event["payload"]["authority"] == "passkey_session"
        assert event["payload"]["approval_id"] == approval_id
        assert event["actor"] == {"authority_mode": "system", "attestations": []}
    assert scheduled["payload"]["resource_ref"] == proven["payload"]["resource_ref"]
    assert scheduled["payload"]["after_ref"] == proven["payload"]["before_ref"]
    assert proven["payload"]["after_ref"] != proven["payload"]["before_ref"]
    assert (
        scheduled["payload"]["approval_evidence_sha256"]
        == proven["payload"]["approval_evidence_sha256"]
    )
    serialized = json.dumps([scheduled, proven])
    assert all(
        private not in serialized
        for private in (old_contact, new_contact, contact_sha256(new_contact), token, scope)
    )
    with pytest.raises(ContactChangeRefused):
        prepared = await audit.prepare_contact_proof(token)
        with audit.prepared(prepared):
            await world.passkeys.prove_contact(token, fence=prepared)
    assert len(await events(world)) == 4


async def test_scheduling_without_the_actual_owner_audit_context_rolls_back(world):
    with pytest.raises(GovernanceUnavailable):
        await schedule(world, prepared=False)
    assert await world.db.fetch_value("SELECT count(*) FROM {{tables.passkey_contact_proofs}}") == 0
    assert (
        await world.db.fetch_value(
            "SELECT count(*) FROM {{tables.passkey_approvers}} WHERE pending_contact IS NOT NULL"
        )
        == 0
    )
    assert len(await events(world)) == 2


async def test_contact_proof_without_effect_preparation_cannot_commit(world):
    audit, _, _, _, token, _ = await schedule(world)
    prepared = await audit.prepare_contact_proof(token)
    with pytest.raises(GovernanceUnavailable), audit.prepared(prepared):
        await world.passkeys.prove_contact(token)
    assert (
        await world.db.fetch_value(
            "SELECT count(*) FROM {{tables.passkey_contact_proofs}} WHERE used_at IS NOT NULL"
        )
        == 0
    )
    assert len(await events(world)) == 3


async def test_expiry_after_contact_enqueue_rolls_back_proof_and_candidate_state(world):
    audit, _, _, _, token, _ = await schedule(world)
    await world.db.execute(
        "CREATE FUNCTION expire_contact_fence() RETURNS trigger LANGUAGE plpgsql AS $$ "
        "BEGIN UPDATE {{tables.installation_fences}} "
        "SET fresh_until=clock_timestamp()-interval '1 second'; RETURN NEW; END $$"
    )
    await world.db.execute(
        "CREATE TRIGGER expire_contact_fence AFTER INSERT ON {{tables.outbox_events}} "
        "FOR EACH ROW EXECUTE FUNCTION expire_contact_fence()"
    )
    prepared = await audit.prepare_contact_proof(token)
    with pytest.raises(ContactChangeRefused), audit.prepared(prepared):
        await world.passkeys.prove_contact(token, fence=prepared)
    assert (
        await world.db.fetch_value(
            "SELECT count(*) FROM {{tables.passkey_contact_proofs}} WHERE used_at IS NOT NULL"
        )
        == 0
    )
    assert (
        await world.db.fetch_value(
            "SELECT count(*) FROM {{tables.passkey_approvers}} WHERE pending_contact_proven_at IS NOT NULL"
        )
        == 0
    )
    assert len(await events(world)) == 3
