"""What the shared credential recorder retains when a holding changes its own
credentials with one it already holds (Q1): each change is a credential.*
governance event under the passkey_session authority of the approving
assertion's retained proof, bound to the exact rows the change wrote in this
transaction, or the change rolls back. Real WebAuthn, real owner acts, real
recorder, real PostgreSQL."""

from __future__ import annotations

import os
from collections.abc import Awaitable, Callable
from dataclasses import replace

import pytest
from aweb_naapp_testing.webauthn import SoftAuthenticator, SoftCredential
from cryptography.hazmat.primitives.asymmetric import ec
from pgdbm.core import TransactionManager

from aweb_naapp.runtime.approvals import ApprovalRevocation, PgApprovalStore
from aweb_naapp.runtime.audit import AuditEvent, AuditKind
from aweb_naapp.runtime.credential_audit import GovernanceUnavailable
from aweb_naapp.runtime.passkeys import PasskeyInstallationContext, Passkeys, RelyingParty
from aweb_naapp.runtime.passkeys.retirement import _NAMESPACE
from tests.runtime.approvals.test_human_role_holders import holder
from tests.runtime.credential_audit.support import (
    ORIGIN,
    World,
    bind,
    designate,
    enrol,
    events,
)
from tests.runtime.credential_audit.test_human_role_audit import (
    MEMBER,
    NOTICE,
    contained,
    holding,
)
from tests.runtime.credential_audit.test_human_role_audit import designate as designate_holder

OPERATION_LOCK = 0x4F500000  # Stands in for the shared protected-operation lock.


def credential_of(device: SoftAuthenticator) -> bytes:
    [credential_id] = device.credentials
    return credential_id


async def change(
    world: World,
    scope: str,
    device: SoftAuthenticator,
    *,
    replace_id: bytes | None = None,
    passkeys: Passkeys | None = None,
    role_holds: Callable[[TransactionManager], Awaitable[None]] | None = None,
):
    """One credential change through the recorder's fence; returns the change
    and the new credential's authenticator."""
    passkeys = passkeys or world.passkeys
    new_device = SoftAuthenticator(ORIGIN)
    registration = new_device.create(dict(await passkeys.credential_registration_options(scope)))
    options = await passkeys.credential_change_options(scope, registration, replace=replace_id)
    fence = await world.recorder.prepare_credential_change(scope, role_holds=role_holds)
    with world.recorder.prepared(fence):
        result = await passkeys.change_credential(scope, device.get(dict(options)), fence=fence)
    return result, new_device


async def enrolled(world: World) -> tuple[str, SoftAuthenticator]:
    scope = await bind(world)
    await designate(world, scope)
    return scope, await enrol(world)


async def payloads(world: World) -> list[dict]:
    return [fields["payload"] for _, fields in await events(world)]


async def added_key(world: World, credential_id: bytes):
    return await world.db.fetch_one(
        "SELECT * FROM {{tables.credential_added_keys}} WHERE credential_id = $1", credential_id
    )


async def completion_ref(world: World, credential_id: bytes) -> str:
    return await world.db.fetch_value(
        "SELECT credential_ref FROM {{tables.credential_completion_links}} WHERE credential_id=$1",
        credential_id,
    )


async def commitment(world: World, scope: str, subject: str, evidence_ref: str) -> str:
    return await world.passkeys.evidence_commitment(
        evidence_ref,
        context=PasskeyInstallationContext(
            world.admitted.app_id,
            world.admitted.team_id,
            world.admitted.installation_id,
            world.admitted.generation,
        ),
        scope=scope,
        subject=subject,
        purpose="credential_change",
    )


# What is recorded


async def test_an_add_is_one_enrolment_under_its_approving_assertion(world: World):
    scope, device = await enrolled(world)
    before = len(await payloads(world))
    result, _ = await change(world, scope, device)
    [enrolled_event] = (await payloads(world))[before:]
    key = await added_key(world, result.credential_id)
    assert enrolled_event == {
        **enrolled_event,
        "act": "credential.enrolled",
        "direction": "widening",
        "subject_ref": result.subject,
        "resource_type": "passkey",
        "resource_ref": key["credential_ref"],
        "authority": "passkey_session",
        "approval_evidence_sha256": await commitment(
            world, scope, result.subject, result.evidence_ref
        ),
    }
    assert "approval_id" not in enrolled_event
    assert key["credential_ref"].startswith("key_")
    assert key["evidence_ref"] == result.evidence_ref


async def test_a_replace_enrols_the_new_key_and_revokes_the_old_under_one_commitment(
    world: World,
):
    """The enrolled key predates relying-party binding (rp_id NULL), so its
    digest is recomputed at the app's own relying party."""
    scope, device = await enrolled(world)
    assert (
        await world.db.fetch_value(
            "SELECT rp_id FROM {{tables.passkey_credentials}} WHERE credential_id = $1",
            credential_of(device),
        )
        is None
    )
    old_ref = await completion_ref(world, credential_of(device))
    before = len(await payloads(world))
    result, _ = await change(world, scope, device, replace_id=credential_of(device))
    enrolled_event, revoked = (await payloads(world))[before:]
    assert (enrolled_event["act"], revoked["act"]) == ("credential.enrolled", "credential.revoked")
    assert revoked["direction"] == "narrowing"
    assert revoked["resource_ref"] == old_ref
    assert (
        enrolled_event["approval_evidence_sha256"]
        == revoked["approval_evidence_sha256"]
        == await commitment(world, scope, result.subject, result.evidence_ref)
    )


async def test_a_replace_of_a_key_the_holding_added_names_its_own_ref(world: World):
    scope, device = await enrolled(world)
    added, new_device = await change(world, scope, device)
    ref = (await added_key(world, added.credential_id))["credential_ref"]
    before = len(await payloads(world))
    await change(world, scope, device, replace_id=added.credential_id)
    revoked = (await payloads(world))[before:][1]
    assert revoked["resource_ref"] == ref


async def test_containment_revoking_an_added_key_names_its_own_ref(world: World):
    scope, device = await enrolled(world)
    added, _ = await change(world, scope, device)
    await contained(
        world,
        lambda tx: world.passkeys.revoke_passkey_in(
            tx,
            scope=scope,
            subject=added.subject,
            credential_id=added.credential_id,
            authorized_by=MEMBER.did_aw,
        ),
    )
    revoked = (await payloads(world))[-1]
    assert revoked["act"] == "credential.revoked"
    assert (
        revoked["resource_ref"] == (await added_key(world, added.credential_id))["credential_ref"]
    )


async def test_a_holder_adds_a_key_and_its_later_revocation_names_that_key(world: World):
    scope = await holding(world)
    member = holder()
    await designate_holder(world, member, notice=NOTICE)
    added, _ = await change(world, scope, member.device)
    await contained(
        world,
        lambda tx: world.passkeys.revoke_passkey_in(
            tx,
            scope=scope,
            subject=added.subject,
            credential_id=added.credential_id,
            authorized_by=MEMBER.did_aw,
        ),
    )
    revoked = (await payloads(world))[-1]
    assert (
        revoked["resource_ref"] == (await added_key(world, added.credential_id))["credential_ref"]
    )


# The fence


async def test_the_fence_takes_the_retirement_gate_before_the_apps_role_holds(world: World):
    scope, device = await enrolled(world)
    seen = []

    async def role_holds(tx: TransactionManager) -> None:
        seen.append(
            await tx.fetch_value(
                "SELECT count(*) FROM pg_locks WHERE pid = pg_backend_pid() "
                "AND locktype = 'advisory' AND classid = $1::oid AND granted",
                _NAMESPACE,
            )
        )

    await change(world, scope, device, role_holds=role_holds)
    assert seen == [1]


async def test_the_shared_operation_lock_is_taken_before_the_fence(world: World):
    scope, device = await enrolled(world)
    new_device = SoftAuthenticator(ORIGIN)
    registration = new_device.create(
        dict(await world.passkeys.credential_registration_options(scope))
    )
    options = await world.passkeys.credential_change_options(scope, registration)
    recorder_fence = await world.recorder.prepare_credential_change(scope)

    class Operation:
        async def prepare(self, tx):
            await tx.execute("SELECT pg_advisory_xact_lock($1::bigint)", OPERATION_LOCK)
            return await recorder_fence.prepare(tx)

        async def check(self, tx):
            await recorder_fence.check(tx)

    with world.recorder.prepared(recorder_fence):
        result = await world.passkeys.change_credential(
            scope, device.get(dict(options)), fence=Operation()
        )
    assert await added_key(world, result.credential_id) is not None


# Each binding refuses on its own, and the change rolls back


class Tampering:
    """The B3 audit port with one fact changed in the effect transaction
    before the recorder records the event."""

    def __init__(self, world: World, tamper) -> None:
        self.world = world
        self.tamper = tamper

    async def emit(self, event: AuditEvent, tx: TransactionManager) -> None:
        event = await self.tamper(event, tx) or event
        await self.world.recorder.emit(event, tx)


def with_audit(world: World, sink) -> Passkeys:
    """The world's B3, with another audit port in front of its recorder. It
    becomes the app's one B3, which the recorder prepares through."""
    world.passkeys = Passkeys(
        world.db,
        rp=RelyingParty(origin=ORIGIN, name="example"),
        delivery=world.inbox,
        audit=sink,
        retirement=ApprovalRevocation(PgApprovalStore(world.db), world.recorder),
        enrolment_ttl=world.passkeys._enrolment_ttl,
        challenge_ttl=world.passkeys._challenge_ttl,
        proof_context=world.passkeys._proof_context,
        holding_scopes=world.passkeys._holding_scopes,
    )
    return world.passkeys


async def refused_and_rolled_back(world: World, scope: str, device, tamper, **kw) -> None:
    keys = await world.db.fetch_value("SELECT count(*) FROM {{tables.passkey_credentials}}")
    added = await world.db.fetch_value("SELECT count(*) FROM {{tables.credential_added_keys}}")
    recorded = len(await payloads(world))
    with pytest.raises(GovernanceUnavailable):
        await change(
            world, scope, device, passkeys=with_audit(world, Tampering(world, tamper)), **kw
        )
    assert await world.db.fetch_value("SELECT count(*) FROM {{tables.passkey_credentials}}") == keys
    assert len(await payloads(world)) == recorded
    assert (
        await world.db.fetch_value("SELECT count(*) FROM {{tables.credential_added_keys}}") == added
    )


async def test_an_event_naming_other_evidence_is_refused(world: World):
    scope, device = await enrolled(world)
    login = await world.passkeys.verify_login(
        scope, device.get(dict(await world.passkeys.login_options(scope)))
    )

    async def tamper(event, tx):
        return replace(event, details={**event.details, "evidence_ref": login.evidence_ref})

    await refused_and_rolled_back(world, scope, device, tamper)


async def test_evidence_of_another_ceremony_is_refused(world: World):
    """The row and the event both name a login assertion's evidence: the proof
    is not a credential change for this scope and subject."""
    scope, device = await enrolled(world)
    login = await world.passkeys.verify_login(
        scope, device.get(dict(await world.passkeys.login_options(scope)))
    )

    async def tamper(event, tx):
        await tx.execute(
            "UPDATE {{tables.passkey_credentials}} SET added_by_evidence = $2 "
            "WHERE added_by_evidence = $1",
            event.details["evidence_ref"],
            login.evidence_ref,
        )
        return replace(event, details={**event.details, "evidence_ref": login.evidence_ref})

    await refused_and_rolled_back(world, scope, device, tamper)


async def test_a_credential_not_written_in_this_transaction_is_refused(world: World):
    scope, device = await enrolled(world)

    async def tamper(event, tx):
        await tx.execute(
            "UPDATE {{tables.passkey_credentials}} SET added_in = added_in - 1 "
            "WHERE added_by_evidence = $1",
            event.details["evidence_ref"],
        )

    await refused_and_rolled_back(world, scope, device, tamper)


async def test_an_unspent_challenge_is_refused(world: World):
    scope, device = await enrolled(world)

    async def tamper(event, tx):
        await tx.execute(
            "UPDATE {{tables.passkey_challenges}} SET used_at = NULL WHERE challenge = ("
            "SELECT added_by_challenge FROM {{tables.passkey_credentials}} "
            "WHERE added_by_evidence = $1)",
            event.details["evidence_ref"],
        )

    await refused_and_rolled_back(world, scope, device, tamper)


async def test_an_approver_no_longer_current_is_refused(world: World):
    scope, device = await enrolled(world)

    async def tamper(event, tx):
        await tx.execute(
            "UPDATE {{tables.passkey_approvers}} SET superseded_at = $2 WHERE subject = $1",
            event.subject,
            event.occurred_at,
        )

    await refused_and_rolled_back(world, scope, device, tamper)


async def test_a_stored_credential_other_than_the_approved_one_is_refused(world: World):
    scope, device = await enrolled(world)
    credential = SoftCredential(
        os.urandom(32), ec.generate_private_key(ec.SECP256R1()), "app.example.com", b""
    )

    async def tamper(event, tx):
        await tx.execute(
            "UPDATE {{tables.passkey_credentials}} SET public_key = $2 "
            "WHERE added_by_evidence = $1",
            event.details["evidence_ref"],
            credential.cose_public_key(),
        )

    await refused_and_rolled_back(world, scope, device, tamper)


async def test_a_retired_credential_other_than_the_approved_one_is_refused(world: World):
    scope, device = await enrolled(world)
    added, _ = await change(world, scope, device)

    async def tamper(event, tx):
        await tx.execute(
            "UPDATE {{tables.passkey_credentials}} SET replaced_credential_id = $2 "
            "WHERE added_by_evidence = $1",
            event.details["evidence_ref"],
            added.credential_id,
        )

    await refused_and_rolled_back(world, scope, device, tamper, replace_id=credential_of(device))


async def test_an_add_recorded_as_a_replace_is_refused(world: World):
    scope, device = await enrolled(world)

    async def tamper(event, tx):
        return replace(event, kind=AuditKind.APPROVER_PASSKEY_REPLACED)

    await refused_and_rolled_back(world, scope, device, tamper)


async def test_a_replace_approval_recorded_against_an_add_is_refused(world: World):
    """The holder approved replacing a key; the row and event claim a plain
    add, which would leave the key it meant to retire live."""
    scope, device = await enrolled(world)

    async def tamper(event, tx):
        await tx.execute(
            "UPDATE {{tables.passkey_credentials}} SET replaced_credential_id = NULL "
            "WHERE added_by_evidence = $1",
            event.details["evidence_ref"],
        )
        return replace(event, kind=AuditKind.APPROVER_PASSKEY_ADDED)

    await refused_and_rolled_back(world, scope, device, tamper, replace_id=credential_of(device))


async def test_one_change_is_recorded_once(world: World):
    scope, device = await enrolled(world)

    async def tamper(event, tx):
        await world.recorder.emit(event, tx)

    await refused_and_rolled_back(world, scope, device, tamper)


async def test_an_old_committed_change_cannot_be_recorded_again(world: World):
    scope, device = await enrolled(world)
    events_before = []

    class Keep:
        async def emit(self, event, tx):
            events_before.append(event)
            await world.recorder.emit(event, tx)

    await change(world, scope, device, passkeys=with_audit(world, Keep()))
    [old] = events_before
    recorded = len(await payloads(world))
    fence = await world.recorder.prepare_credential_change(scope)
    with pytest.raises(GovernanceUnavailable):
        with world.recorder.prepared(fence):
            async with world.db.transaction() as tx:
                await fence.prepare(tx)
                await world.recorder.emit(old, tx)
    assert len(await payloads(world)) == recorded


async def test_a_change_outside_the_recorders_context_is_refused(world: World):
    scope, device = await enrolled(world)
    new_device = SoftAuthenticator(ORIGIN)
    registration = new_device.create(
        dict(await world.passkeys.credential_registration_options(scope))
    )
    options = await world.passkeys.credential_change_options(scope, registration)
    keys = await world.db.fetch_value("SELECT count(*) FROM {{tables.passkey_credentials}}")
    with pytest.raises(GovernanceUnavailable):
        await world.passkeys.change_credential(scope, device.get(dict(options)))
    assert await world.db.fetch_value("SELECT count(*) FROM {{tables.passkey_credentials}}") == keys
