"""B3 TOFU completion retains its consumed authority and real signed outbox atomically."""

import asyncio
import hashlib
import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from aweb_naapp.hooks.envelope import verify
from aweb_naapp.hooks.producer import Registration, RegistrationView
from aweb_naapp.hooks.strictjson import Refused
from aweb_naapp.roles import assign
from aweb_naapp.runtime.approvals import PgApprovalStore
from aweb_naapp.runtime.passkeys import EnrolmentRefused, contact_sha256
from aweb_naapp_testing.owner_acts import INSTALLATION_ID
from aweb_naapp_testing.webauthn import SoftAuthenticator

from aweb_secrets.credential_audit import CredentialAudit, GovernanceUnavailable
from aweb_secrets.owners import OWNER_ROLE, owner_scope, record_owner
from tests.test_change_sets import ALICE, APP_ID, ORIGIN, TEAM
from tests.test_change_sets import world as _world

world = _world


def target():
    now = datetime.now(UTC)
    return RegistrationView(
        TEAM,
        "post-governance-hook",
        now,
        timedelta(seconds=60),
        (
            Registration(
                str(uuid4()),
                "https://logs.example.com",
                "POST",
                "/hooks/ingest",
                now - timedelta(minutes=1),
            ),
        ),
    )


async def audit_for(world, *, registration_view=None, shared_producer=None):
    async def default_view(team_id):
        assert team_id == TEAM
        return target()

    store = PgApprovalStore(world.db)

    async def approval(tx, approval_id):
        return await store.get_in(approval_id, tx)

    audit = CredentialAudit(
        db=world.db,
        app_id=APP_ID,
        fence=world.fence,
        contexts=world.passkeys._proof_context,
        owner_act_scope=world.owner.verifier.scope,
        producer=shared_producer or world.credential_audit._producer,
        passkeys=lambda: world.passkeys,
        approval=approval,
        registration_view=registration_view or default_view,
        max_backlog_age=timedelta(minutes=5),
    )
    await audit.migrate()
    world.passkeys._audit = audit
    world.credential_audit = audit
    world.change_sets._credential_audit = audit
    world.containment.credential_audit = audit
    if not hasattr(world, "audit_event_start"):
        world.audit_event_start = await world.db.fetch_value(
            "SELECT COALESCE(max(position),0) FROM {{tables.outbox_events}}"
        )
    return audit


async def designate(
    world,
    audit,
    *,
    prepare=True,
    wrong_artifact=False,
    act_kind="app-role.designate",
    contact="owner@example.com",
):
    scope = owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did)
    subject = {
        "app_id": APP_ID,
        "installation_id": INSTALLATION_ID,
        "role": scope,
        "contact_sha256": contact_sha256(contact),
    }
    signing, signature = world.owner.sign(act_kind, subject)
    act = await world.owner.verifier.prepare(signing, signature, team_id=TEAM)
    original = signing
    if wrong_artifact:
        signing, signature = world.owner.sign(act_kind, subject)
    prepared = (
        await audit.prepare_owner_act(world.admitted, signing=signing, signature=signature)
        if prepare
        else None
    )
    with audit.prepared(prepared):
        async with world.db.transaction() as tx:
            await world.fence.check(tx, world.admitted)
            consumed = await world.owner.verifier.consume_in(tx, act, expected_subject=subject)
            await record_owner(tx, installation_id=INSTALLATION_ID, principal=ALICE)
            await assign(tx, ALICE, OWNER_ROLE)
            designation = await world.passkeys.designate(
                tx, scope=scope, contact=contact, evidence=consumed
            )
            await world.fence.check(tx, world.admitted)
    await world.passkeys.deliver(designation)
    return scope, contact, hashlib.sha256(original).hexdigest()


async def events(world):
    rows = await world.db.fetch_all(
        "SELECT payload,signature FROM {{tables.outbox_events}} WHERE position > $1 ORDER BY position",
        world.audit_event_start,
    )
    return [verify(bytes(row["payload"]), row["signature"], team_id=TEAM).fields for row in rows]


async def test_enrolment_reuses_original_artifact_after_nonce_retention_ends(world):
    audit = await audit_for(world)
    scope, contact, commitment = await designate(world, audit)
    [first] = await events(world)
    assert first["payload"]["act"] == "role.designated"
    assert first["payload"]["owner_act_sha256"] == commitment
    # Consumed nonces are prunable; the completion must retain its own original artifact.
    await world.db.execute("DELETE FROM {{tables.owner_act_nonces}}")
    token = world.inbox.enrolments[contact][-1]
    options = await world.passkeys.enrolment_options(token)
    device = SoftAuthenticator(ORIGIN)
    prepared = await audit.prepare_enrolment(token)
    with audit.prepared(prepared):
        await world.passkeys.complete_enrolment(token, device.create(options), fence=prepared)
    first, completed = await events(world)
    assert completed["payload"]["act"] == "credential.enrolled"
    assert completed["payload"]["authority"] == "owner_act"
    assert completed["payload"]["owner_act_sha256"] == commitment
    assert completed["actor"] == {"authority_mode": "system", "attestations": []}
    serialized = json.dumps(completed)
    assert all(
        private not in serialized for private in (contact, contact_sha256(contact), token, scope)
    )
    assert await world.passkeys.is_current(
        scope, (await world.passkeys.designated_approver(scope)).subject
    )


@pytest.mark.parametrize("problem", ["missing", "another-artifact"])
async def test_missing_or_mismatched_context_rolls_back_designation_nonce_and_hook(world, problem):
    audit = await audit_for(world)
    with pytest.raises(GovernanceUnavailable):
        await designate(
            world, audit, prepare=problem != "missing", wrong_artifact=problem == "another-artifact"
        )
    for table in ("passkey_approvers", "owner_act_nonces", "outbox_events", "owner_principals"):
        assert await world.db.fetch_value("SELECT count(*) FROM {{tables." + table + "}}") == 0


async def test_completion_without_a_current_audit_target_rolls_back_then_retries(world):
    available = True

    async def registration_view(team_id):
        assert team_id == TEAM
        return target() if available else None

    audit = await audit_for(world, registration_view=registration_view)
    _, contact, _ = await designate(world, audit)
    token = world.inbox.enrolments[contact][-1]
    available = False
    device = SoftAuthenticator(ORIGIN)
    options = await world.passkeys.enrolment_options(token)
    prepared = await audit.prepare_enrolment(token)
    with pytest.raises(Refused) as refused, audit.prepared(prepared):
        await world.passkeys.complete_enrolment(token, device.create(options), fence=prepared)
    assert refused.value.code == "audit_target_unavailable"
    assert await world.db.fetch_value("SELECT count(*) FROM {{tables.passkey_credentials}}") == 0
    assert (
        await world.db.fetch_value(
            "SELECT count(*) FROM {{tables.passkey_enrolments}} WHERE used_at IS NOT NULL"
        )
        == 0
    )
    assert len(await events(world)) == 1
    available = True
    options = await world.passkeys.enrolment_options(token)
    prepared = await audit.prepare_enrolment(token)
    with audit.prepared(prepared):
        await world.passkeys.complete_enrolment(token, device.create(options), fence=prepared)
    assert len(await events(world)) == 2


async def test_context_without_effect_fence_cannot_commit_completion(world):
    audit = await audit_for(world)
    _, contact, _ = await designate(world, audit)
    token = world.inbox.enrolments[contact][-1]
    device = SoftAuthenticator(ORIGIN)
    options = await world.passkeys.enrolment_options(token)
    prepared = await audit.prepare_enrolment(token)
    with pytest.raises(GovernanceUnavailable), audit.prepared(prepared):
        await world.passkeys.complete_enrolment(token, device.create(options))
    assert await world.db.fetch_value("SELECT count(*) FROM {{tables.passkey_credentials}}") == 0
    assert len(await events(world)) == 1


async def test_final_f6_expiry_after_signed_enqueue_rolls_back_completion(world):
    audit = await audit_for(world)
    _, contact, _ = await designate(world, audit)
    await world.db.execute(
        "CREATE FUNCTION expire_credential_fence() RETURNS trigger LANGUAGE plpgsql AS $$ "
        "BEGIN UPDATE {{tables.installation_fences}} "
        "SET fresh_until=clock_timestamp()-interval '1 second'; RETURN NEW; END $$"
    )
    await world.db.execute(
        "CREATE TRIGGER expire_credential_fence AFTER INSERT ON {{tables.outbox_events}} "
        "FOR EACH ROW EXECUTE FUNCTION expire_credential_fence()"
    )
    token = world.inbox.enrolments[contact][-1]
    device = SoftAuthenticator(ORIGIN)
    options = await world.passkeys.enrolment_options(token)
    prepared = await audit.prepare_enrolment(token)
    with pytest.raises(EnrolmentRefused), audit.prepared(prepared):
        await world.passkeys.complete_enrolment(token, device.create(options), fence=prepared)
    assert await world.db.fetch_value("SELECT count(*) FROM {{tables.passkey_credentials}}") == 0
    assert (
        await world.db.fetch_value(
            "SELECT count(*) FROM {{tables.passkey_enrolments}} WHERE used_at IS NOT NULL"
        )
        == 0
    )
    assert len(await events(world)) == 1


async def approved_designation(world):
    from aweb_naapp.runtime.approvals import Assurance, Decision
    from aweb_naapp.runtime.passkeys import PasskeyInstallationContext

    from aweb_secrets.approvers import record_approver
    from aweb_secrets.owners import approver_scope
    from tests.test_change_sets import by_member, change_set, enrol_owner
    from tests.test_use_approvals import designate_approver

    owner_contact, target_contact = "owner@example.com", "finance@example.com"
    await enrol_owner(world, ALICE, owner_contact)
    audit = await audit_for(world)
    request = change_set(
        drafter=by_member(ALICE),
        changes=[designate_approver("finance", target_contact, ["sec_19ab42"])],
    )
    async with world.db.transaction() as tx:
        pending = await world.change_sets.draft(tx, request)
    await world.approvals.deliver(pending)
    approval_id = pending.approval.approval_id
    [token] = [token for aid, token in world.inbox.links[owner_contact] if aid == approval_id]
    options = await world.approvals.challenge(
        approval_id, Decision.APPROVE, Assurance.PASSKEY, link_token=token
    )
    await world.approvals.decide(
        approval_id,
        Decision.APPROVE,
        Assurance.PASSKEY,
        world.devices[owner_contact].get(dict(options)),
        link_token=token,
    )
    scope = approver_scope(INSTALLATION_ID, TEAM, "finance")
    async with world.db.transaction() as tx:
        await world.fence.check(tx, world.admitted)
        evidence = await world.passkeys.owner_approval(
            tx,
            world.approvals,
            approval_id=approval_id,
            request=request,
            operation_id="designate-finance",
        )
        await record_approver(
            tx,
            installation_id=INSTALLATION_ID,
            team_id=TEAM,
            approver_ref="finance",
            scope=scope,
            covers=["sec_19ab42"],
            principal_did=None,
            change_id=request["change_id"],
        )
        with audit.approved(world.admitted, evidence, target()):
            designation = await world.passkeys.designate(
                tx, scope=scope, contact=target_contact, evidence=evidence
            )
        approval = await PgApprovalStore(world.db).get_in(approval_id, tx)
        commitment = await world.passkeys.evidence_commitment(
            approval.decided_by.evidence_ref,
            context=PasskeyInstallationContext(APP_ID, TEAM, INSTALLATION_ID, 1),
            scope=evidence.approver_scope,
            subject=evidence.approver_subject,
            purpose="approve",
            tx=tx,
        )
    await world.passkeys.deliver(designation)
    return audit, target_contact, approval_id, commitment


async def test_owner_approval_designation_uses_the_actual_retained_approve_proof(world):
    _, _, approval_id, commitment = await approved_designation(world)
    [event] = await events(world)
    assert event["payload"]["act"] == "role.designated"
    assert event["actor"] == {"authority_mode": "system", "attestations": []}
    assert event["payload"]["authority"] == "passkey_session"
    assert event["payload"]["approval_id"] == approval_id
    assert event["payload"]["approval_evidence_sha256"] == commitment
    assert "owner_act_sha256" not in event["payload"]


async def test_owner_approval_completion_uses_the_actual_retained_approve_proof(world):
    audit, target_contact, approval_id, commitment = await approved_designation(world)
    token = world.inbox.enrolments[target_contact][-1]
    options = await world.passkeys.enrolment_options(token)
    prepared = await audit.prepare_enrolment(token)
    with audit.prepared(prepared):
        await world.passkeys.complete_enrolment(
            token, SoftAuthenticator(ORIGIN).create(options), fence=prepared
        )
    recorded = await events(world)
    assert [event["payload"]["act"] for event in recorded] == [
        "role.designated",
        "credential.enrolled",
    ]
    for event in recorded:
        assert event["actor"] == {"authority_mode": "system", "attestations": []}
        assert event["payload"]["authority"] == "passkey_session"
        assert event["payload"]["approval_id"] == approval_id
        assert event["payload"]["approval_evidence_sha256"] == commitment
        assert "owner_act_sha256" not in event["payload"]


async def test_recovery_and_new_key_keep_the_original_recovery_authority_and_cooling_off(world):
    audit = await audit_for(world)
    scope, contact, _ = await designate(world, audit)
    token = world.inbox.enrolments[contact][-1]
    prepared = await audit.prepare_enrolment(token)
    with audit.prepared(prepared):
        await world.passkeys.complete_enrolment(
            token,
            SoftAuthenticator(ORIGIN).create(await world.passkeys.enrolment_options(token)),
            fence=prepared,
        )
    _, recovered_contact, commitment = await designate(
        world, audit, act_kind="app-credential.recover", contact="recovered@example.com"
    )
    token = world.inbox.enrolments[recovered_contact][-1]
    prepared = await audit.prepare_enrolment(token)
    with audit.prepared(prepared):
        recovered = await world.passkeys.complete_enrolment(
            token,
            SoftAuthenticator(ORIGIN).create(await world.passkeys.enrolment_options(token)),
            fence=prepared,
        )
    recorded = await events(world)
    assert [event["payload"]["act"] for event in recorded] == [
        "role.designated",
        "credential.enrolled",
        "credential.recovered",
        "credential.enrolled",
    ]
    assert recorded[-2]["payload"]["owner_act_sha256"] == commitment
    assert recorded[-1]["payload"]["owner_act_sha256"] == commitment
    assert recorded[-1]["actor"] == {"authority_mode": "system", "attestations": []}
    effective_at = await world.db.fetch_value(
        "SELECT effective_at FROM {{tables.credential_authorizations}} WHERE subject=$1",
        recovered.subject,
    )
    assert effective_at > datetime.now(UTC) + timedelta(hours=71)
    assert not await world.passkeys.is_current(scope, recovered.subject)
    assert await world.passkeys.designated_approver(scope) is None


async def test_parallel_completion_consumes_one_link_without_a_second_key_or_hook(world):
    audit = await audit_for(world)
    _, contact, _ = await designate(world, audit)
    token = world.inbox.enrolments[contact][-1]
    options = [await world.passkeys.enrolment_options(token) for _ in range(2)]
    prepared = [await audit.prepare_enrolment(token) for _ in range(2)]

    async def complete(index):
        with audit.prepared(prepared[index]):
            return await world.passkeys.complete_enrolment(
                token, SoftAuthenticator(ORIGIN).create(options[index]), fence=prepared[index]
            )

    results = await asyncio.wait_for(
        asyncio.gather(complete(0), complete(1), return_exceptions=True), 10
    )
    assert sum(not isinstance(result, Exception) for result in results) == 1
    assert all(
        not isinstance(result, Exception) or isinstance(result, EnrolmentRefused)
        for result in results
    )
    assert await world.db.fetch_value("SELECT count(*) FROM {{tables.passkey_credentials}}") == 1
    assert len(await events(world)) == 2
