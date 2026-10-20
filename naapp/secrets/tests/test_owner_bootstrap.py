"""Owner bootstrap and recovery through the team owner act (design §10.2, decision 33).

The team key, through aw, signs an aweb.owner-act/1 that names one
principal's owner scope and commits to its contact. Applying it gives the
principal secrets.owner and designates its B3 scope, in one transaction.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import timedelta

import pytest
from aweb_naapp.hooks.owner_act_nonces import apply_owner_act_migrations
from aweb_naapp.roles import PrincipalKey, apply_roles_migrations, has_role
from aweb_naapp.runtime.approvals import (
    ActionPolicy,
    ApprovalRevocation,
    Assurance,
    PgApprovalStore,
)
from aweb_naapp.runtime.passkeys import Passkeys, RelyingParty, contact_sha256
from aweb_naapp_testing import awid_registry
from aweb_naapp_testing.owner_acts import APP_ID, INSTALLATION_ID, TeamOwner, team_owner
from aweb_naapp_testing.webauthn import SoftAuthenticator
from nacl.signing import SigningKey

from aweb_secrets.owners import (
    OWNER_ROLE,
    OwnerDirectory,
    OwnerRequired,
    apply_owner_act,
    apply_owner_migrations,
    is_owner_scope,
    owner_scope,
)
from tests.test_owner_directory import ORIGIN, Audit, Contacts

TEAM = "demo:example.com"
ALICE = PrincipalKey(team_id=TEAM, principal_did="did:aw:jPUMBAvNeJo8USHNtJ81Wm7cqnk")
BOB = PrincipalKey(team_id=TEAM, principal_did="did:aw:2Uq51iFVLnqmgbVY3vLZtMD5PR87")


class World:
    def __init__(self, db, passkeys, owner: TeamOwner, contacts: Contacts) -> None:
        self.db = db
        self.passkeys = passkeys
        self.owner = owner
        self.contacts = contacts
        self.directory = OwnerDirectory(passkeys, db)


@pytest.fixture
async def world(test_db_factory) -> AsyncIterator[World]:
    db = await test_db_factory.create_db(suffix="secrets_bootstrap")
    registry_db = await test_db_factory.create_db(suffix="secrets_bootstrap_awid")
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
    async with awid_registry(registry_db.config.get_dsn()) as registry:
        yield World(db, passkeys, await team_owner(registry), contacts)


def _subject(principal: PrincipalKey, contact: str, installation_id: str = INSTALLATION_ID):
    return {
        "app_id": APP_ID,
        "installation_id": installation_id,
        "role": owner_scope(installation_id, principal.principal_did),
        "contact_sha256": contact_sha256(contact),
    }


async def _apply(world: World, act: str, principal, contact, *, subject=None, signer=None):
    signer = signer or world.owner
    signing, signature = signer.sign(act, subject or _subject(principal, contact))
    designation = await apply_owner_act(
        world.db,
        world.passkeys,
        world.owner.verifier,
        signing=signing,
        signature=signature,
        app_id=APP_ID,
        installation_id=INSTALLATION_ID,
        principal=principal,
        contact=contact,
    )
    await world.passkeys.deliver(designation)
    return designation


def _policy(scope: str) -> ActionPolicy:
    return ActionPolicy(
        policy_ref="secrets.change",
        version=1,
        min_assurance=Assurance.PASSKEY,
        ttl=timedelta(minutes=15),
        approver_scope=scope,
    )


async def _enrol(world: World, contact: str) -> None:
    token = world.contacts.inbox[contact][-1]
    device = SoftAuthenticator(ORIGIN)
    await world.passkeys.complete_enrolment(
        token, device.create(await world.passkeys.enrolment_options(token))
    )


async def test_the_team_owner_act_makes_the_first_owner(world: World) -> None:
    await _apply(world, "app-role.designate", ALICE, "alice@example.com")
    assert await has_role(world.db, ALICE, OWNER_ROLE)
    await _enrol(world, "alice@example.com")
    scope = owner_scope(INSTALLATION_ID, ALICE.principal_did)
    approver = await world.directory.designated_approver(_policy(scope))
    assert approver is not None and approver.contact == "alice@example.com"


async def test_a_member_signature_is_refused_as_owner_required(world: World) -> None:
    member = TeamOwner(team_key=SigningKey.generate(), verifier=world.owner.verifier)
    with pytest.raises(OwnerRequired) as refused:
        await _apply(world, "app-role.designate", ALICE, "alice@example.com", signer=member)
    assert refused.value.code == "owner_required"
    assert not await has_role(world.db, ALICE, OWNER_ROLE)
    assert world.contacts.inbox == {}


async def test_an_act_naming_another_principal_designates_nobody(world: World) -> None:
    with pytest.raises(OwnerRequired):
        await _apply(
            world,
            "app-role.designate",
            ALICE,
            "alice@example.com",
            subject=_subject(BOB, "alice@example.com"),
        )
    assert not await has_role(world.db, ALICE, OWNER_ROLE)
    assert not await has_role(world.db, BOB, OWNER_ROLE)


async def test_an_act_for_another_contact_designates_nobody(world: World) -> None:
    with pytest.raises(OwnerRequired):
        await _apply(
            world,
            "app-role.designate",
            ALICE,
            "alice@example.com",
            subject=_subject(ALICE, "attacker@example.com"),
        )
    assert world.contacts.inbox == {}


async def test_an_act_for_another_installation_designates_nobody(world: World) -> None:
    other = "6f9619ff-8b86-4011-b42d-00c04fc964ff"
    with pytest.raises(OwnerRequired):
        await _apply(
            world,
            "app-role.designate",
            ALICE,
            "alice@example.com",
            subject=_subject(ALICE, "alice@example.com", other),
        )
    assert not await has_role(world.db, ALICE, OWNER_ROLE)


async def test_an_owner_is_designated_once_and_recovered_after_the_cooling_off(
    world: World,
) -> None:
    await _apply(world, "app-role.designate", ALICE, "alice@example.com")
    await _enrol(world, "alice@example.com")
    with pytest.raises(OwnerRequired):
        await _apply(world, "app-role.designate", ALICE, "alice-new@example.com")
    designation = await _apply(world, "app-credential.recover", ALICE, "alice-new@example.com")
    assert [n.kind.value for n in world.contacts.notices["alice@example.com"]] == [
        "recovery_started"
    ]
    scope = owner_scope(INSTALLATION_ID, ALICE.principal_did)
    assert await world.passkeys.recovery_pending_until(scope) == designation.effective_at
    assert await world.directory.designated_approver(_policy(scope)) is None
