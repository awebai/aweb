"""The shared credential recorder for an app whose scopes only owner acts
govern, on real PostgreSQL with a real AWID registry, real owner acts and a
software passkey: no owner approvals, and every signed event handed to the
app in the transaction that enqueued it. A role an owner act revokes is
signed as a narrowing that needs no registered hook target."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from aweb_naapp_testing.owner_acts import TEAM_ID, revocation_subject

from aweb_naapp.hooks.owner_act import Refused
from aweb_naapp.runtime.audit import AuditEvent, AuditKind
from aweb_naapp.runtime.credential_audit import GovernanceUnavailable
from aweb_naapp.runtime.passkeys import OwnerApproval
from tests.runtime.credential_audit.support import (
    ROLE,
    World,
    bind,
    designate,
    enrol,
    events,
    registration_view,
)


async def test_each_signed_event_is_handed_to_the_app_in_the_transaction_that_enqueued_it(
    world: World,
):
    scope = await bind(world)
    designating = await designate(world, scope)
    await enrol(world)
    [(designated_id, designated), (enrolled_id, enrolled)] = await events(world)
    assert designated["payload"]["act"] == "role.designated"
    assert designated["payload"]["role"] == ROLE
    assert designated["payload"]["authority"] == "owner_act"
    assert enrolled["payload"]["act"] == "credential.enrolled"
    assert [event_id for _, event_id in world.handed] == [designated_id, enrolled_id]
    assert world.handed[0][0] == designating


async def test_an_app_that_cannot_take_the_event_rolls_back_the_whole_effect(world: World):
    scope = await bind(world)
    world.fail_after_enqueue[0] = True
    with pytest.raises(RuntimeError):
        await designate(world, scope)
    assert len(world.handed) == 1
    assert await world.db.fetch_value("SELECT count(*) FROM {{tables.outbox_events}}") == 0
    assert await world.db.fetch_value("SELECT count(*) FROM {{tables.owner_act_nonces}}") == 0
    assert await world.db.fetch_value("SELECT count(*) FROM {{tables.passkey_approvers}}") == 0
    assert (
        await world.db.fetch_value("SELECT count(*) FROM {{tables.credential_authorizations}}") == 0
    )
    world.fail_after_enqueue[0] = False
    await designate(world, scope)
    assert len(await events(world)) == 1


async def test_an_app_without_owner_approvals_accepts_none(world: World):
    evidence = OwnerApproval(
        approval_id=str(uuid4()),
        approver_subject="subject",
        approver_scope=f"{ROLE}.{'0' * 32}",
        transaction_id=1,
    )
    with pytest.raises(GovernanceUnavailable):
        with world.recorder.approved(world.admitted, evidence, registration_view()):
            pass
    decided = AuditEvent(
        kind=AuditKind.APPROVAL_DECIDED,
        actor="subject",
        subject="subject",
        occurred_at=datetime.now(UTC),
        approval_id=evidence.approval_id,
        details={"policy_ref": "example.change|1"},
    )
    assert not world.recorder.is_change_approval(decided)
    with pytest.raises(GovernanceUnavailable):
        async with world.db.transaction() as tx:
            await world.recorder.emit(decided, tx)


async def holder(world: World, scope: str) -> str | None:
    return await world.db.fetch_value(
        "SELECT subject FROM {{tables.passkey_approvers}} WHERE scope=$1 AND superseded_at IS NULL",
        scope,
    )


async def revoke(
    world: World, scope: str, subject_ref: str, *, bound_to: tuple[bytes, str] | None = None
) -> tuple[int, bytes, str]:
    """The owner revokes ``subject_ref``'s role on ``scope``; returns the effect's
    transaction ID and the signed act. ``bound_to`` prepares the recorder with
    another signed act than the one consumed."""
    subject = revocation_subject(scope, subject_ref)
    signing, signature = world.owner.sign("app-role.revoke", subject)
    prepared = await world.owner.verifier.prepare(signing, signature, team_id=TEAM_ID)
    bound_signing, bound_signature = bound_to or (signing, signature)
    context = await world.recorder.prepare_owner_act(
        world.admitted, signing=bound_signing, signature=bound_signature
    )
    with world.recorder.prepared(context):
        async with world.db.transaction() as tx:
            await world.fence.check(tx, world.admitted)
            act = await world.owner.consume(tx, prepared, subject)
            await world.passkeys.retire(tx, scope=scope, evidence=act)
            await world.fence.check(tx, world.admitted)
            txid = await tx.fetch_value("SELECT txid_current()")
    return txid, signing, signature


async def designated_reader(world: World) -> tuple[str, str]:
    scope = await bind(world)
    await designate(world, scope)
    await enrol(world)
    return scope, await holder(world, scope)


async def count(world: World, table: str) -> int:
    return await world.db.fetch_value(f"SELECT count(*) FROM {{{{tables.{table}}}}}")


async def test_an_owner_act_revocation_is_signed_as_a_narrowing_in_its_transaction(world: World):
    scope, reader = await designated_reader(world)
    revoking, signing, signature = await revoke(world, scope, reader)
    assert await holder(world, scope) is None
    event_id, revoked = (await events(world))[-1]
    assert revoked["payload"] == {
        "act": "role.revoked",
        "direction": "narrowing",
        "role": ROLE,
        "subject_ref": reader,
        "authority": "owner_act",
        "owner_act_sha256": hashlib.sha256(signing).hexdigest(),
    }
    assert world.handed[-1] == (revoking, event_id)
    retained = await world.db.fetch_one(
        "SELECT * FROM {{tables.credential_narrowing_authority}} WHERE event_id=$1", event_id
    )
    assert (retained["authority"], retained["subject"]) == ("owner_act", reader)
    assert (bytes(retained["signing"]), retained["signature"]) == (signing, signature)
    assert retained["commitment"] == hashlib.sha256(signing).hexdigest()


async def test_a_revocation_narrows_when_no_hook_target_is_registered(world: World):
    scope, reader = await designated_reader(world)
    world.target_registered[0] = False
    await revoke(world, scope, reader)
    assert await holder(world, scope) is None
    assert (await events(world))[-1][1]["payload"]["act"] == "role.revoked"


async def test_a_revocation_bound_to_another_act_is_refused_and_takes_no_effect(world: World):
    scope, reader = await designated_reader(world)
    unconsumed = world.owner.sign("app-role.revoke", revocation_subject(scope, reader))
    before = await count(world, "outbox_events")
    with pytest.raises(GovernanceUnavailable):
        await revoke(world, scope, reader, bound_to=unconsumed)
    assert await holder(world, scope) == reader
    assert await count(world, "outbox_events") == before
    assert await count(world, "credential_narrowing_authority") == 0
    await revoke(world, scope, reader)
    assert await holder(world, scope) is None


async def test_a_revocation_without_an_owner_act_context_is_refused(world: World):
    scope, reader = await designated_reader(world)
    subject = revocation_subject(scope, reader)
    prepared = await world.owner.prepare("app-role.revoke", subject)
    with pytest.raises(GovernanceUnavailable):
        async with world.db.transaction() as tx:
            act = await world.owner.consume(tx, prepared, subject)
            await world.passkeys.retire(tx, scope=scope, evidence=act)
    assert await holder(world, scope) == reader
    assert await count(world, "credential_narrowing_authority") == 0


async def test_a_replayed_revocation_takes_no_second_effect(world: World):
    scope, reader = await designated_reader(world)
    _, signing, signature = await revoke(world, scope, reader)
    subject = revocation_subject(scope, reader)
    prepared = await world.owner.verifier.prepare(signing, signature, team_id=TEAM_ID)
    context = await world.recorder.prepare_owner_act(
        world.admitted, signing=signing, signature=signature
    )
    with pytest.raises(Refused) as refused:
        with world.recorder.prepared(context):
            async with world.db.transaction() as tx:
                act = await world.owner.consume(tx, prepared, subject)
                await world.passkeys.retire(tx, scope=scope, evidence=act)
    assert refused.value.code == "nonce_reused"
    assert [fields["payload"]["act"] for _, fields in await events(world)].count(
        "role.revoked"
    ) == 1


async def test_an_app_that_cannot_take_the_revocation_keeps_the_role(world: World):
    scope, reader = await designated_reader(world)
    before = await count(world, "owner_act_nonces")
    world.fail_after_enqueue[0] = True
    with pytest.raises(RuntimeError):
        await revoke(world, scope, reader)
    assert await holder(world, scope) == reader
    assert await count(world, "owner_act_nonces") == before
    assert await count(world, "credential_narrowing_authority") == 0
    world.fail_after_enqueue[0] = False
    await revoke(world, scope, reader)
    assert await holder(world, scope) is None
