"""B3 narrowing keeps actual caller authority through nested effect savepoints."""

import json
from uuid import uuid4

import pytest
from aweb_naapp.roles import assign, hold_role, principal_key
from aweb_naapp.runtime.credential_audit import GovernanceUnavailable
from aweb_naapp.runtime.passkeys import PasskeyInstallationContext
from aweb_naapp_testing.webauthn import SoftAuthenticator

from aweb_secrets.owners import OWNER_ROLE, owner_scope
from tests.test_change_sets import ALICE, APP_ID, ORIGIN, TEAM
from tests.test_containment_console import login_session, sibling_session
from tests.test_credential_audit import approved_designation, audit_for, events
from tests.test_credential_audit import world as world
from tests.test_use_approvals import REQUESTER


async def enrolled_target(world):
    audit, contact, _, _ = await approved_designation(world)
    token = world.inbox.enrolments[contact][-1]
    device = SoftAuthenticator(ORIGIN)
    prepared = await audit.prepare_enrolment(token)
    with audit.prepared(prepared):
        approver = await world.passkeys.complete_enrolment(
            token, device.create(await world.passkeys.enrolment_options(token)), fence=prepared
        )
    return audit, approver, device


async def hold_member(world, tx):
    await world.fence.check(tx, world.admitted)
    await assign(tx, principal_key(REQUESTER), OWNER_ROLE)
    assert await hold_role(tx, principal_key(REQUESTER), OWNER_ROLE)


async def test_designation_retirement_keeps_team_cert_and_signed_trace_without_target(world):
    audit, approver, _ = await enrolled_target(world)

    async def unavailable(team_id):
        raise AssertionError("narrowing must not resolve a fresh audit target")

    # Simulate a service restart with the same producer and persisted original
    # designation, while its external registration resolver is unavailable.
    audit = await audit_for(world, registration_view=unavailable, shared_producer=audit._producer)
    trace = uuid4().hex
    async with world.db.transaction() as tx:
        await hold_member(world, tx)
        prepared = await audit.prepare_containment(
            tx, admitted=world.admitted, principal=REQUESTER, signed_trace_id=trace
        )
        with audit.prepared(prepared):
            # The real containment writer removes metadata before B3.
            await tx.execute("DELETE FROM {{tables.approvers}} WHERE scope=$1", approver.scope)
            await world.passkeys.retire_in(
                tx,
                scope=approver.scope,
                subject=approver.subject,
                authorized_by=principal_key(REQUESTER).principal_did,
            )
        await world.fence.check(tx, world.admitted)
    _, _, revoked = await events(world)
    assert revoked["payload"]["act"] == "role.revoked"
    assert revoked["payload"]["direction"] == "narrowing"
    assert revoked["payload"]["subject_ref"] == approver.subject
    assert revoked["payload"]["authority"] == "team_cert"
    assert revoked["actor"]["did_key"] == REQUESTER.did_key
    assert revoked["actor"]["certificate_id"] == REQUESTER.certificate_id
    assert revoked["trace"] == {"id": trace, "origin": "signed_request"}


@pytest.mark.parametrize("last_key", [False, True])
async def test_key_revocation_distinguishes_partial_and_last_key_effects(world, last_key):
    audit, approver, device = await enrolled_target(world)
    if not last_key:
        session = await login_session(world, approver.scope, device)
        await sibling_session(world, session)
    credential_id = next(iter(device.credentials))
    async with world.db.transaction() as tx:
        await hold_member(world, tx)
        prepared = await audit.prepare_containment(tx, admitted=world.admitted, principal=REQUESTER)
        with audit.prepared(prepared):
            await world.passkeys.revoke_passkey_in(
                tx,
                scope=approver.scope,
                subject=approver.subject,
                credential_id=credential_id,
                authorized_by=principal_key(REQUESTER).principal_did,
            )
        await world.fence.check(tx, world.admitted)
    recorded = await events(world)
    assert [item["payload"]["act"] for item in recorded[2:]] == (
        ["role.revoked", "credential.revoked"] if last_key else ["credential.revoked"]
    )
    assert recorded[-1]["payload"]["resource_ref"] == recorded[1]["payload"]["resource_ref"]
    assert (await world.passkeys.designated_approver(approver.scope) is None) is last_key


async def test_session_retirement_uses_the_actual_retained_login_commitment(world):
    audit, approver, _ = await enrolled_target(world)
    scope = owner_scope(world.admitted.installation_id, TEAM, ALICE.principal_did)
    session = await login_session(world, scope, world.devices["owner@example.com"])
    async with world.db.transaction() as tx:
        await world.fence.check(tx, world.admitted)
        prepared = await audit.prepare_containment(tx, admitted=world.admitted, session=session)
        expected = await world.passkeys.evidence_commitment(
            session.evidence_ref,
            context=PasskeyInstallationContext(
                APP_ID, TEAM, world.admitted.installation_id, world.admitted.generation
            ),
            scope=session.scope,
            subject=session.subject,
            purpose="login",
            tx=tx,
        )
        with audit.prepared(prepared):
            await world.passkeys.retire_in(
                tx,
                scope=approver.scope,
                subject=approver.subject,
                authorized_by=session.subject,
            )
        await world.fence.check(tx, world.admitted)
    _, _, revoked = await events(world)
    assert revoked["payload"]["authority"] == "passkey_session"
    assert revoked["payload"]["approval_evidence_sha256"] == expected
    assert revoked["actor"] == {"authority_mode": "system", "attestations": []}
    retained = await world.db.fetch_one(
        "SELECT commitment,retained_proof FROM {{tables.credential_narrowing_authority}} "
        "WHERE authority='passkey_session'"
    )
    assert retained["commitment"] == expected
    original = await world.passkeys.retained_proof(session.evidence_ref)
    assert json.loads(retained["retained_proof"]) == original.export()


async def test_rollback_restores_designation_and_clears_the_prepared_authority(world):
    audit, approver, _ = await enrolled_target(world)
    with pytest.raises(RuntimeError, match="local effect aborted"):
        async with world.db.transaction() as tx:
            await hold_member(world, tx)
            prepared = await audit.prepare_containment(
                tx, admitted=world.admitted, principal=REQUESTER
            )
            with audit.prepared(prepared):
                await world.passkeys.retire_in(
                    tx,
                    scope=approver.scope,
                    subject=approver.subject,
                    authorized_by=principal_key(REQUESTER).principal_did,
                )
                raise RuntimeError("local effect aborted")
    assert await world.passkeys.designated_approver(approver.scope) is not None
    assert len(await events(world)) == 2
    with pytest.raises(GovernanceUnavailable):
        async with world.db.transaction() as tx:
            await world.fence.check(tx, world.admitted)
            await world.passkeys.retire_in(
                tx,
                scope=approver.scope,
                subject=approver.subject,
                authorized_by=principal_key(REQUESTER).principal_did,
            )
    assert await world.passkeys.designated_approver(approver.scope) is not None
    assert len(await events(world)) == 2


async def test_preparation_cannot_authorize_another_sql_transaction(world):
    audit, approver, _ = await enrolled_target(world)
    async with world.db.transaction() as tx:
        await hold_member(world, tx)
        prepared = await audit.prepare_containment(tx, admitted=world.admitted, principal=REQUESTER)
    with pytest.raises(GovernanceUnavailable):
        async with world.db.transaction() as tx:
            await hold_member(world, tx)
            with audit.prepared(prepared):
                await world.passkeys.retire_in(
                    tx,
                    scope=approver.scope,
                    subject=approver.subject,
                    authorized_by=principal_key(REQUESTER).principal_did,
                )
    assert await world.passkeys.designated_approver(approver.scope) is not None
    assert len(await events(world)) == 2
