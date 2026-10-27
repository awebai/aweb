"""The shared credential recorder for an app whose scopes only owner acts
govern, on real PostgreSQL with a real AWID registry, real owner acts and a
software passkey: no owner approvals, and every signed event handed to the
app in the transaction that enqueued it. A role an owner act revokes is
signed as a narrowing that needs no registered hook target."""

from __future__ import annotations

import hashlib
import os
import secrets
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from aweb_naapp_testing.owner_acts import (
    APP_ID,
    INSTALLATION_ID,
    TEAM_ID,
    TeamOwner,
    designation_subject,
    revocation_subject,
    team_owner,
)
from aweb_naapp_testing.webauthn import SoftAuthenticator
from awid_service.testing import running_registry
from pgdbm import AsyncDatabaseManager
from pgdbm.core import TransactionManager

from aweb_naapp.hooks.envelope import verify
from aweb_naapp.hooks.owner_act import Refused
from aweb_naapp.hooks.owner_act_nonces import apply_owner_act_migrations
from aweb_naapp.hooks.producer import HookProducer, Registration, RegistrationView, ServerProducer
from aweb_naapp.outbox import apply_outbox_migrations
from aweb_naapp.runtime.approvals import ApprovalRevocation, DeliveryStatus, PgApprovalStore
from aweb_naapp.runtime.audit import AuditEvent, AuditKind
from aweb_naapp.runtime.authorization import Grant
from aweb_naapp.runtime.clock import seconds_to_ns
from aweb_naapp.runtime.credential_audit import CredentialAudit, GovernanceUnavailable
from aweb_naapp.runtime.installation import (
    AdmittedInstallation,
    InstallationFence,
    apply_installation_migrations,
)
from aweb_naapp.runtime.passkeys import (
    OwnerApproval,
    PasskeyInstallationContext,
    Passkeys,
    ProofContextUnavailable,
    RelyingParty,
    installation_context,
)

ORIGIN = "https://console.example.test"
ROLE = "example.reader"
CONTACT = "reader@example.com"


class Installations:
    def __init__(self) -> None:
        self.grant = Grant(
            team_id=TEAM_ID,
            installation_id=INSTALLATION_ID,
            generation=1,
            scopes=frozenset({"example.read"}),
            fresh_until=time.monotonic_ns() + seconds_to_ns(55),
        )

    async def grant_for(self, team_id, certificate_id=None):
        return self.grant if team_id == TEAM_ID else None

    async def status_for(self, team_id):
        if team_id != TEAM_ID:
            return None
        return SimpleNamespace(
            team_id=TEAM_ID,
            app_id=APP_ID,
            state="active",
            installation_id=INSTALLATION_ID,
            generation=1,
            granted_scopes=self.grant.scopes,
            fresh_until=self.grant.fresh_until,
        )


@dataclass
class Inbox:
    enrolments: dict[str, list[str]] = field(default_factory=dict)

    async def deliver_enrolment_link(self, approver, link_token: str) -> DeliveryStatus:
        self.enrolments.setdefault(approver.contact, []).append(link_token)
        return DeliveryStatus.DELIVERED

    async def deliver_contact_proof(self, contact: str, proof_token: str) -> DeliveryStatus:
        return DeliveryStatus.DELIVERED

    async def deliver_notice(self, contact: str, notice) -> DeliveryStatus:
        return DeliveryStatus.DELIVERED


async def _binding(tx: TransactionManager, scope: str):
    return await tx.fetch_one(
        "SELECT installation_id,team_id FROM {{tables.example_bindings}} WHERE scope=$1", scope
    )


async def contexts(scope: str, *, tx: TransactionManager) -> PasskeyInstallationContext:
    """The example app's binding of a scope to its installation."""
    row = await _binding(tx, scope)
    if row is None:
        raise ProofContextUnavailable()
    return await installation_context(
        tx, app_id=APP_ID, team_id=row["team_id"], installation_id=row["installation_id"]
    )


async def role_of(
    tx: TransactionManager, *, scope: str, admitted: AdmittedInstallation
) -> str | None:
    row = await _binding(tx, scope)
    if row is None or (row["installation_id"], row["team_id"]) != (
        admitted.installation_id,
        admitted.team_id,
    ):
        return None
    return ROLE


def registration_view() -> RegistrationView:
    now = datetime.now(UTC)
    return RegistrationView(
        TEAM_ID,
        "post-governance-hook",
        now,
        timedelta(seconds=60),
        (
            Registration(
                str(uuid4()),
                "https://logs.example.test",
                "POST",
                "/hooks/ingest",
                now - timedelta(hours=1),
            ),
        ),
    )


@dataclass
class World:
    db: AsyncDatabaseManager
    owner: TeamOwner
    fence: InstallationFence
    admitted: AdmittedInstallation
    inbox: Inbox
    handed: list[tuple[int, UUID]]
    fail_after_enqueue: list[bool]
    target_registered: list[bool]
    recorder: CredentialAudit = field(init=False)
    passkeys: Passkeys = field(init=False)


@pytest.fixture
async def world(test_db_factory) -> AsyncIterator[World]:
    db = await test_db_factory.create_db(suffix="credential_audit_owner_act_app")
    registry_db = await test_db_factory.create_db(suffix="credential_audit_owner_act_app_awid")
    await db.execute(
        "CREATE TABLE {{tables.example_bindings}}"
        " (scope TEXT PRIMARY KEY, installation_id TEXT NOT NULL, team_id TEXT NOT NULL)"
    )
    for migrate in (
        apply_owner_act_migrations,
        apply_installation_migrations,
        apply_outbox_migrations,
    ):
        await migrate(db)
    store = PgApprovalStore(db)
    await store.migrate()
    installations = Installations()
    fence = InstallationFence(db, app_id=APP_ID, grants=installations)
    await fence.refresh(TEAM_ID)
    async with db.transaction() as tx:
        admitted = await fence.admit(tx, installations.grant)
    producer = HookProducer(
        ServerProducer.app(
            origin=ORIGIN,
            app_id=APP_ID,
            installation_id=INSTALLATION_ID,
            generation=1,
            kid="test-key",
            seed=os.urandom(32),
        )
    )
    handed: list[tuple[int, UUID]] = []
    fail: list[bool] = [False]
    registered: list[bool] = [True]

    async def after_enqueue(tx: TransactionManager, event_id: UUID) -> None:
        handed.append((await tx.fetch_value("SELECT txid_current()"), event_id))
        if fail[0]:
            raise RuntimeError("the app could not append the event")

    async def view(team_id: str) -> RegistrationView | None:
        assert team_id == TEAM_ID
        return registration_view() if registered[0] else None

    async with running_registry(registry_db.config.get_dsn()) as registry:
        owner = await team_owner(registry, team_id=TEAM_ID)
        inbox = Inbox()
        state = World(db, owner, fence, admitted, inbox, handed, fail, registered)
        state.recorder = CredentialAudit(
            db=db,
            app_id=APP_ID,
            fence=fence,
            contexts=contexts,
            owner_act_scope=owner.verifier.scope,
            producer=lambda **_: producer,
            passkeys=lambda: state.passkeys,
            role_of=role_of,
            registration_view=view,
            max_backlog_age=timedelta(minutes=5),
            migration_module="example_credential_audit",
            after_enqueue=after_enqueue,
        )
        await state.recorder.migrate()
        state.passkeys = Passkeys(
            db,
            rp=RelyingParty(origin=ORIGIN, name="example"),
            delivery=inbox,
            audit=state.recorder,
            retirement=ApprovalRevocation(store, state.recorder),
            enrolment_ttl=timedelta(hours=1),
            challenge_ttl=timedelta(minutes=5),
            proof_context=contexts,
        )
        await state.passkeys.migrate()
        yield state


async def bind(world: World) -> str:
    scope = f"{ROLE}.{secrets.token_hex(16)}"
    await world.db.execute(
        "INSERT INTO {{tables.example_bindings}} (scope,installation_id,team_id) VALUES($1,$2,$3)",
        scope,
        INSTALLATION_ID,
        TEAM_ID,
    )
    return scope


async def designate(world: World, scope: str) -> int:
    """The owner designates ``scope``'s reader; returns the effect's transaction ID."""
    subject = designation_subject(scope, CONTACT)
    signing, signature = world.owner.sign("app-role.designate", subject)
    prepared = await world.owner.verifier.prepare(signing, signature, team_id=TEAM_ID)
    context = await world.recorder.prepare_owner_act(
        world.admitted, signing=signing, signature=signature
    )
    with world.recorder.prepared(context):
        async with world.db.transaction() as tx:
            await world.fence.check(tx, world.admitted)
            act = await world.owner.consume(tx, prepared, subject)
            designation = await world.passkeys.designate(
                tx, scope=scope, contact=CONTACT, evidence=act
            )
            await world.fence.check(tx, world.admitted)
            txid = await tx.fetch_value("SELECT txid_current()")
    await world.passkeys.deliver(designation)
    return txid


async def events(world: World) -> list[tuple[UUID, dict]]:
    rows = await world.db.fetch_all(
        "SELECT event_id,payload,signature FROM {{tables.outbox_events}} ORDER BY position"
    )
    return [
        (row["event_id"], verify(bytes(row["payload"]), row["signature"], team_id=TEAM_ID).fields)
        for row in rows
    ]


async def enrol(world: World) -> SoftAuthenticator:
    """The designated reader enrols a passkey through the link they were sent."""
    token = world.inbox.enrolments[CONTACT][-1]
    device = SoftAuthenticator(ORIGIN)
    enrolment = await world.recorder.prepare_enrolment(token)
    with world.recorder.prepared(enrolment):
        await world.passkeys.complete_enrolment(
            token, device.create(await world.passkeys.enrolment_options(token)), fence=enrolment
        )
    return device


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
