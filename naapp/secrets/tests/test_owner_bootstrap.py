"""Owner bootstrap and recovery through the team owner act (design §10.2, decision 33).

The team key, through aw, signs an aweb.owner-act/1 that names one
principal's owner scope and commits to its contact. Applying it gives the
principal secrets.owner and designates its B3 scope, in one transaction.
"""

from __future__ import annotations

import base64
import secrets
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import pytest
from aweb_naapp.hooks.owner_act import PREFIX
from aweb_naapp.hooks.owner_act_nonces import apply_owner_act_migrations
from aweb_naapp.hooks.strictjson import canonical
from aweb_naapp.roles import PrincipalKey, apply_roles_migrations, has_role
from aweb_naapp.runtime.approvals import (
    ActionPolicy,
    ApprovalRevocation,
    Assurance,
    PgApprovalStore,
)
from aweb_naapp.runtime.passkeys import Passkeys, RelyingParty, contact_sha256
from aweb_naapp_testing import awid_registry, did_key
from aweb_naapp_testing.owner_acts import (
    APP_ID,
    AUDIENCE,
    INSTALLATION_ID,
    TeamOwner,
    team_owner,
)
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
    def __init__(self, db, passkeys, owner: TeamOwner, contacts: Contacts, registry) -> None:
        self.registry = registry
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
        yield World(db, passkeys, await team_owner(registry), contacts, registry)


def _subject(principal: PrincipalKey, contact: str, installation_id: str = INSTALLATION_ID):
    return {
        "app_id": APP_ID,
        "installation_id": installation_id,
        "role": owner_scope(installation_id, principal.team_id, principal.principal_did),
        "contact_sha256": contact_sha256(contact),
    }


def _signed_by_team(key: SigningKey, team_id: str, act: str, subject: dict) -> tuple[bytes, str]:
    """An owner act genuinely signed by ``team_id``'s controller ``key``, naming that team."""
    issued = datetime.now(UTC).replace(microsecond=0)
    fields = {
        "v": 1,
        "type": "aweb.owner-act",
        "act": act,
        "team_id": team_id,
        "aud": AUDIENCE,
        "team_key_did": did_key(key),
        "subject": subject,
        "issued_at": issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": (issued + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "nonce": secrets.token_hex(16),
    }
    signing = PREFIX + canonical(fields)
    return signing, base64.b64encode(key.sign(signing).signature).decode().rstrip("=")


async def _apply(
    world: World,
    act: str,
    principal,
    contact,
    *,
    subject=None,
    signer=None,
    signed=None,
    installation_team_id: str = TEAM,
):
    signer = signer or world.owner
    if signed is not None:
        signing, signature = signed
    else:
        signing, signature = signer.sign(act, subject or _subject(principal, contact))
    designation = await apply_owner_act(
        world.db,
        world.passkeys,
        world.owner.verifier,
        signing=signing,
        signature=signature,
        app_id=APP_ID,
        installation_id=INSTALLATION_ID,
        installation_team_id=installation_team_id,
        principal=principal,
        contact=contact,
    )
    await world.passkeys.deliver(designation)
    return designation


CHANGE_REQUEST = {"type": "aweb.secrets.change", "drafter": {"via": "console", "scope": "-"}}


async def _approver(world: World, scope: str):
    found = await world.directory.candidates(_policy(scope), CHANGE_REQUEST)
    return found[0] if found else None


def _policy(scope: str, *, allow_requester_approval: bool = True) -> ActionPolicy:
    return ActionPolicy(
        policy_ref="secrets.change",
        version=1,
        min_assurance=Assurance.PASSKEY,
        ttl=timedelta(minutes=15),
        approver_scopes=(scope,),
        allow_requester_approval=allow_requester_approval,
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
    scope = owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did)
    approver = await _approver(world, scope)
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


async def test_a_teams_own_act_cannot_make_an_owner_of_another_teams_installation(
    world: World,
) -> None:
    with pytest.raises(OwnerRequired):
        await _apply(
            world,
            "app-role.designate",
            ALICE,
            "alice@example.com",
            installation_team_id="acme:other.com",
        )
    assert not await has_role(world.db, ALICE, OWNER_ROLE)
    assert not await world.db.fetch_value("SELECT count(*) FROM {{tables.owner_principals}}")
    assert world.contacts.inbox == {}


OTHER_TEAM = "other:example.com"


async def _other_team_key(world: World) -> SigningKey:
    """The genuine controller key of another team, registered in AWID."""
    key = SigningKey.generate()
    await world.registry.add_team(OTHER_TEAM, did_key(key))
    return key


async def test_another_teams_controller_cannot_designate_this_teams_member(world: World) -> None:
    other = TeamOwner(team_key=await _other_team_key(world), verifier=world.owner.verifier)
    with pytest.raises(OwnerRequired):
        await _apply(world, "app-role.designate", ALICE, "alice@example.com", signer=other)
    assert not await has_role(world.db, ALICE, OWNER_ROLE)
    assert not await world.db.fetch_value("SELECT count(*) FROM {{tables.owner_principals}}")
    assert world.contacts.inbox == {}


async def test_a_recovery_from_another_team_cannot_touch_an_owner(world: World) -> None:
    await _apply(world, "app-role.designate", ALICE, "alice@example.com")
    await _enrol(world, "alice@example.com")
    # The other team's controller signs, as its own team, a recovery of the
    # owner scope it names for its own principal with the victim's did:aw.
    impostor = PrincipalKey(team_id=OTHER_TEAM, principal_did=ALICE.principal_did)
    signed = _signed_by_team(
        await _other_team_key(world),
        OTHER_TEAM,
        "app-credential.recover",
        _subject(impostor, "attacker@example.com"),
    )
    with pytest.raises(OwnerRequired):
        await _apply(
            world, "app-credential.recover", impostor, "attacker@example.com", signed=signed
        )
    scope = owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did)
    approver = await _approver(world, scope)
    assert approver is not None and approver.contact == "alice@example.com"
    assert await world.passkeys.recovery_pending_until(scope) is None
    assert world.contacts.notices == {}
    assert not await has_role(world.db, impostor, OWNER_ROLE)


async def test_a_scope_recorded_for_another_owner_is_refused(world: World) -> None:
    scope = owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did)
    await world.db.execute(
        "INSERT INTO {{tables.owner_principals}} (scope, installation_id, team_id, principal_did)"
        " VALUES ($1, $2, $3, $4)",
        scope,
        INSTALLATION_ID,
        TEAM,
        BOB.principal_did,
    )
    with pytest.raises(OwnerRequired):
        await _apply(world, "app-role.designate", ALICE, "alice@example.com")
    assert not await has_role(world.db, ALICE, OWNER_ROLE)
    assert world.contacts.inbox == {}


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
    scope = owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did)
    assert await world.passkeys.recovery_pending_until(scope) == designation.effective_at
    assert await _approver(world, scope) is None
