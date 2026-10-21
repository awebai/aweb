"""The approver directory secrets gives B2 (decision 34), on real PostgreSQL.

An owner decides only while both hold: its B3 designation is current, and its
principal still holds secrets.owner. Owners are designated by real team owner
acts and enrol with a real software passkey.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import timedelta

import pytest
from aweb_naapp.hooks.owner_act_nonces import apply_owner_act_migrations
from aweb_naapp.roles import PrincipalKey, apply_roles_migrations, assign, unassign
from aweb_naapp.runtime.approvals import (
    ActionPolicy,
    ApprovalRevocation,
    Approver,
    Assurance,
    DeliveryStatus,
    PgApprovalStore,
)
from aweb_naapp.runtime.audit import AuditEvent
from aweb_naapp.runtime.passkeys import Notice, Passkeys, RelyingParty
from aweb_naapp_testing.owner_acts import (
    INSTALLATION_ID,
    TeamOwner,
    designation_subject,
    team_owner,
)
from aweb_naapp_testing.webauthn import SoftAuthenticator
from awid_service.testing import running_registry
from pgdbm import AsyncDatabaseManager
from pgdbm.core import TransactionManager

from aweb_secrets.owners import (
    OWNER_ROLE,
    OwnerDirectory,
    apply_owner_migrations,
    approver_scope,
    is_owner_scope,
    owner_scope,
    record_owner,
)

ORIGIN = "https://secrets.example.com"
TEAM = "backend:acme.com"
ALICE = PrincipalKey(team_id=TEAM, principal_did="did:aw:jPUMBAvNeJo8USHNtJ81Wm7cqnk")
BOB = PrincipalKey(team_id=TEAM, principal_did="did:aw:2Uq51iFVLnqmgbVY3vLZtMD5PR87")
OTHER_INSTALLATION = "6f9619ff-8b86-4011-b42d-00c04fc964ff"


@dataclass
class Contacts:
    inbox: dict[str, list[str]] = field(default_factory=dict)
    notices: dict[str, list[Notice]] = field(default_factory=dict)

    async def deliver_enrolment_link(self, approver: Approver, link_token: str) -> DeliveryStatus:
        self.inbox.setdefault(approver.contact, []).append(link_token)
        return DeliveryStatus.DELIVERED

    async def deliver_notice(self, contact: str, notice: Notice) -> DeliveryStatus:
        self.notices.setdefault(contact, []).append(notice)
        return DeliveryStatus.DELIVERED


class Audit:
    def __init__(self, db: AsyncDatabaseManager) -> None:
        self.db = db

    async def emit(self, event: AuditEvent, transaction) -> None:
        await TransactionManager(transaction.connection, self.db).execute(
            "INSERT INTO {{tables.audit_outbox}} (kind, details) VALUES ($1, $2)",
            event.kind.value,
            json.dumps(dict(event.details)),
        )


@dataclass
class World:
    db: AsyncDatabaseManager
    passkeys: Passkeys
    directory: OwnerDirectory
    owner: TeamOwner
    contacts: Contacts


@pytest.fixture
async def world(test_db_factory) -> AsyncIterator[World]:
    db = await test_db_factory.create_db(suffix="secrets_owners")
    registry_db = await test_db_factory.create_db(suffix="secrets_owners_awid")
    await db.execute(
        "CREATE TABLE {{tables.audit_outbox}} (id SERIAL PRIMARY KEY, kind TEXT, details TEXT)"
    )
    store = PgApprovalStore(db)
    await store.migrate()
    audit = Audit(db)
    contacts = Contacts()
    passkeys = Passkeys(
        db,
        rp=RelyingParty(origin=ORIGIN, name="secrets"),
        delivery=contacts,
        audit=audit,
        retirement=ApprovalRevocation(store, audit),
        enrolment_ttl=timedelta(hours=1),
        challenge_ttl=timedelta(minutes=5),
        owner_scopes=is_owner_scope,
    )
    await passkeys.migrate()
    await apply_roles_migrations(db)
    await apply_owner_act_migrations(db)
    await apply_owner_migrations(db)
    async with running_registry(registry_db.config.get_dsn()) as registry:
        yield World(
            db=db,
            passkeys=passkeys,
            directory=OwnerDirectory(passkeys, db),
            owner=await team_owner(registry),
            contacts=contacts,
        )


def _policy(scope: str) -> ActionPolicy:
    return ActionPolicy(
        policy_ref="secrets.change",
        version=1,
        min_assurance=Assurance.PASSKEY,
        ttl=timedelta(minutes=15),
        approver_scope=scope,
    )


async def designate_owner(
    world: World, principal: PrincipalKey, contact: str, installation_id: str = INSTALLATION_ID
) -> str:
    """The team owner designates ``principal`` an owner; it enrols a passkey."""
    scope = owner_scope(installation_id, principal.team_id, principal.principal_did)
    subject = designation_subject(scope, contact)
    prepared = await world.owner.prepare("app-role.designate", subject)
    async with world.db.transaction() as tx:
        act = await world.owner.consume(tx, prepared, subject)
        designation = await world.passkeys.designate(tx, scope=scope, contact=contact, evidence=act)
        await record_owner(tx, installation_id=installation_id, principal=principal)
        await assign(tx, principal, OWNER_ROLE)
    await world.passkeys.deliver(designation)
    token = world.contacts.inbox[contact][-1]
    device = SoftAuthenticator(ORIGIN)
    await world.passkeys.complete_enrolment(
        token, device.create(await world.passkeys.enrolment_options(token))
    )
    return scope


async def test_an_enrolled_owner_holding_the_role_decides(world: World) -> None:
    scope = await designate_owner(world, ALICE, "alice@acme.com")
    approver = await world.directory.designated_approver(_policy(scope))
    assert approver is not None and approver.contact == "alice@acme.com"
    assert await world.directory.is_current(approver.subject, _policy(scope))


async def test_an_owner_whose_role_is_revoked_no_longer_decides(world: World) -> None:
    scope = await designate_owner(world, ALICE, "alice@acme.com")
    approver = await world.directory.designated_approver(_policy(scope))
    assert approver is not None
    async with world.db.transaction() as tx:
        await unassign(tx, ALICE, OWNER_ROLE)
    assert await world.directory.designated_approver(_policy(scope)) is None
    assert not await world.directory.is_current(approver.subject, _policy(scope))


async def test_revoking_one_owner_leaves_another_deciding(world: World) -> None:
    alice = await designate_owner(world, ALICE, "alice@acme.com")
    bob = await designate_owner(world, BOB, "bob@acme.com")
    async with world.db.transaction() as tx:
        await unassign(tx, ALICE, OWNER_ROLE)
    assert await world.directory.designated_approver(_policy(alice)) is None
    assert await world.directory.designated_approver(_policy(bob)) is not None


async def test_the_role_on_another_team_does_not_count(world: World) -> None:
    scope = await designate_owner(world, ALICE, "alice@acme.com")
    async with world.db.transaction() as tx:
        await unassign(tx, ALICE, OWNER_ROLE)
        await assign(tx, PrincipalKey("backend:other.com", ALICE.principal_did), OWNER_ROLE)
    assert await world.directory.designated_approver(_policy(scope)) is None


async def test_an_owner_scope_without_a_recorded_owner_has_no_approver(world: World) -> None:
    scope = owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did)
    subject = designation_subject(scope, "alice@acme.com")
    prepared = await world.owner.prepare("app-role.designate", subject)
    async with world.db.transaction() as tx:
        act = await world.owner.consume(tx, prepared, subject)
        await world.passkeys.designate(tx, scope=scope, contact="alice@acme.com", evidence=act)
        await assign(tx, ALICE, OWNER_ROLE)
    assert await world.directory.designated_approver(_policy(scope)) is None


async def test_one_principal_owns_independently_in_two_installations(world: World) -> None:
    here = await designate_owner(world, ALICE, "alice@acme.com")
    there = await designate_owner(world, ALICE, "alice@acme.com", OTHER_INSTALLATION)
    assert here != there
    first = await world.directory.designated_approver(_policy(here))
    second = await world.directory.designated_approver(_policy(there))
    assert first is not None and second is not None
    assert first.subject != second.subject
    assert not await world.directory.is_current(first.subject, _policy(there))


async def test_an_approver_scope_needs_no_owner_role(world: World) -> None:
    scope = approver_scope(INSTALLATION_ID, TEAM, "finance")
    subject = designation_subject(scope, "finance@acme.com")
    prepared = await world.owner.prepare("app-role.designate", subject)
    async with world.db.transaction() as tx:
        act = await world.owner.consume(tx, prepared, subject)
        designation = await world.passkeys.designate(
            tx, scope=scope, contact="finance@acme.com", evidence=act
        )
    await world.passkeys.deliver(designation)
    token = world.contacts.inbox["finance@acme.com"][-1]
    device = SoftAuthenticator(ORIGIN)
    await world.passkeys.complete_enrolment(
        token, device.create(await world.passkeys.enrolment_options(token))
    )
    approver = await world.directory.designated_approver(_policy(scope))
    assert approver is not None
    assert await world.directory.is_current(approver.subject, _policy(scope))
