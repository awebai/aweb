"""A non-secrets app on the shared credential recorder, on real PostgreSQL
with a real AWID registry, real owner acts and a software passkey: one
installation whose role scopes only owner acts govern, and which takes each
signed event in the transaction that enqueued it."""

from __future__ import annotations

import os
import secrets
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from aweb_naapp_testing.owner_acts import (
    APP_ID,
    AUDIENCE,
    INSTALLATION_ID,
    TEAM_ID,
    TeamOwner,
    designation_subject,
    team_owner,
)
from aweb_naapp_testing.webauthn import SoftAuthenticator
from awid_service.testing import Registry, running_registry
from pgdbm import AsyncDatabaseManager
from pgdbm.core import TransactionManager

from aweb_naapp.hooks.envelope import verify
from aweb_naapp.hooks.owner_act import APP_ACTS, HUMAN_ROLE_ACTS, LOGS_ACTS, VerifiedOwnerAct
from aweb_naapp.hooks.owner_act_nonces import apply_owner_act_migrations
from aweb_naapp.hooks.producer import HookProducer, Registration, RegistrationView, ServerProducer
from aweb_naapp.outbox import apply_outbox_migrations
from aweb_naapp.roles import apply_roles_migrations, is_holding_scope
from aweb_naapp.runtime.approvals import ApprovalRevocation, DeliveryStatus, PgApprovalStore
from aweb_naapp.runtime.authorization import Grant
from aweb_naapp.runtime.clock import seconds_to_ns
from aweb_naapp.runtime.credential_audit import CredentialAudit
from aweb_naapp.runtime.installation import (
    AdmittedInstallation,
    InstallationFence,
    apply_installation_migrations,
)
from aweb_naapp.runtime.passkeys import (
    PasskeyInstallationContext,
    Passkeys,
    ProofContextUnavailable,
    RelyingParty,
    installation_context,
)

# The owner acts' audience, so a human-role credential binds to this relying party.
ORIGIN = AUDIENCE
ROLE = "example.reader"
# The role this app declares with the human-role acts.
HOLDER_ROLE = "example.holder"
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
    notices: list[tuple[str, object]] = field(default_factory=list)

    async def deliver_enrolment_link(self, approver, link_token: str) -> DeliveryStatus:
        self.enrolments.setdefault(approver.contact, []).append(link_token)
        return DeliveryStatus.DELIVERED

    async def deliver_contact_proof(self, contact: str, proof_token: str) -> DeliveryStatus:
        return DeliveryStatus.DELIVERED

    async def deliver_notice(self, contact: str, notice) -> DeliveryStatus:
        self.notices.append((contact, notice))
        return DeliveryStatus.DELIVERED


async def _binding(tx: TransactionManager, scope: str):
    return await tx.fetch_one(
        "SELECT installation_id,team_id,role FROM {{tables.example_bindings}} WHERE scope=$1",
        scope,
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
    return row["role"]


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


# The act this app records in its own chain atomically, and so may record
# with no registered hook target (a logs legal hold).
SELF_RECORDED_ACTS = frozenset({"logs.legal_hold.set"})


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
    registry: Registry
    recorder: CredentialAudit = field(init=False)
    passkeys: Passkeys = field(init=False)


@pytest.fixture
async def world(test_db_factory) -> AsyncIterator[World]:
    db = await test_db_factory.create_db(suffix="credential_audit_owner_act_app")
    registry_db = await test_db_factory.create_db(suffix="credential_audit_owner_act_app_awid")
    await db.execute(
        "CREATE TABLE {{tables.example_bindings}}"
        " (scope TEXT PRIMARY KEY, installation_id TEXT NOT NULL, team_id TEXT NOT NULL,"
        " role TEXT NOT NULL)"
    )
    for migrate in (
        apply_owner_act_migrations,
        apply_installation_migrations,
        apply_outbox_migrations,
        apply_roles_migrations,
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
        owner = await team_owner(
            registry, team_id=TEAM_ID, acts=APP_ACTS + LOGS_ACTS + HUMAN_ROLE_ACTS
        )
        inbox = Inbox()
        state = World(db, owner, fence, admitted, inbox, handed, fail, registered, registry)
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
            ungated_acts=SELF_RECORDED_ACTS,
            human_roles=frozenset({HOLDER_ROLE}),
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
            holding_scopes=is_holding_scope,
        )
        await state.passkeys.migrate()
        yield state


async def bind(world: World, scope: str | None = None, role: str = ROLE) -> str:
    """Bind ``scope`` (a fresh one by default) to the installation, for ``role``."""
    scope = scope or f"{ROLE}.{secrets.token_hex(16)}"
    await world.db.execute(
        "INSERT INTO {{tables.example_bindings}} (scope,installation_id,team_id,role)"
        " VALUES($1,$2,$3,$4)",
        scope,
        INSTALLATION_ID,
        TEAM_ID,
        role,
    )
    return scope


async def owner_act[T](
    world: World,
    act: str,
    subject: dict,
    effect: Callable[[TransactionManager, VerifiedOwnerAct], Awaitable[T]],
) -> T:
    """The owner's act, consumed and given to ``effect`` in one fenced effect
    transaction, under the recorder's prepared act."""
    signing, signature = world.owner.sign(act, subject)
    prepared = await world.owner.verifier.prepare(signing, signature, team_id=TEAM_ID)
    context = await world.recorder.prepare_owner_act(
        world.admitted, signing=signing, signature=signature
    )
    with world.recorder.prepared(context):
        async with world.db.transaction() as tx:
            await world.fence.check(tx, world.admitted)
            verified = await world.owner.consume(tx, prepared, subject)
            result = await effect(tx, verified)
            await world.fence.check(tx, world.admitted)
    return result


async def designate(world: World, scope: str) -> int:
    """The owner designates ``scope``'s reader; returns the effect's transaction ID."""

    async def effect(tx: TransactionManager, act: VerifiedOwnerAct):
        designation = await world.passkeys.designate(tx, scope=scope, contact=CONTACT, evidence=act)
        return designation, await tx.fetch_value("SELECT txid_current()")

    designation, txid = await owner_act(
        world, "app-role.designate", designation_subject(scope, CONTACT), effect
    )
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


def hold_subject(hold_id: str) -> dict[str, str]:
    return {
        "app_id": APP_ID,
        "installation_id": INSTALLATION_ID,
        "hold_id": hold_id,
        "hold_scope": "all",
        "reason_code": "litigation",
    }


async def record_app_act(world: World, act: str, subject: dict, payload: dict) -> UUID:
    """The owner's act, consumed and recorded with ``payload`` in one effect transaction."""

    async def effect(tx: TransactionManager, verified: VerifiedOwnerAct) -> UUID:
        return await world.recorder.record_owner_act(
            tx, verified, payload, occurred_at=datetime.now(UTC)
        )

    return await owner_act(world, act, subject, effect)
