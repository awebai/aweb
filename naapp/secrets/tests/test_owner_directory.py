"""The approver directory secrets gives B2 (decision 34), on real PostgreSQL.

An owner decides only while both hold: its B3 designation is current, and its
principal still holds secrets.owner. Owners are designated by real team owner
acts and enrol with a real software passkey.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tests.test_change_sets import World


import json
from dataclasses import dataclass, field
from datetime import timedelta

import pytest
from aweb_naapp.roles import (
    PrincipalKey,
    assign,
    unassign,
)
from aweb_naapp.runtime.approvals import (
    ActionPolicy,
    Approver,
    Assurance,
    DeliveryStatus,
)
from aweb_naapp.runtime.audit import AuditEvent
from aweb_naapp.runtime.passkeys import Notice
from aweb_naapp_testing.owner_acts import (
    INSTALLATION_ID,
)
from aweb_naapp_testing.webauthn import SoftAuthenticator
from pgdbm import AsyncDatabaseManager
from pgdbm.core import TransactionManager

from aweb_secrets.owners import (
    OWNER_ROLE,
    approver_scope,
    owner_scope,
)
from tests.human_owner import fixture_principal

ORIGIN = "https://secrets.example.com"
TEAM = "backend:acme.com"
ALICE = fixture_principal(TEAM, "alice")
BOB = fixture_principal(TEAM, "bob")
OTHER_INSTALLATION = "6f9619ff-8b86-4011-b42d-00c04fc964ff"


@dataclass
class Contacts:
    inbox: dict[str, list[str]] = field(default_factory=dict)
    notices: dict[str, list[Notice]] = field(default_factory=dict)
    proofs: dict[str, list[str]] = field(default_factory=dict)

    async def deliver_enrolment_link(self, approver: Approver, link_token: str) -> DeliveryStatus:
        self.inbox.setdefault(approver.contact, []).append(link_token)
        return DeliveryStatus.DELIVERED

    async def deliver_contact_proof(self, contact: str, proof_token: str) -> DeliveryStatus:
        self.proofs.setdefault(contact, []).append(proof_token)
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


@pytest.fixture
async def world(test_db_factory, tmp_path):
    # One real app composition, shared with the change-set consumer tests.
    from tests.test_change_sets import build_world

    async with build_world(test_db_factory, tmp_path) as built:
        yield built


def _policy(scope: str, *, allow_requester_approval: bool = True) -> ActionPolicy:
    return ActionPolicy(
        policy_ref="secrets.change",
        version=1,
        min_assurance=Assurance.PASSKEY,
        ttl=timedelta(minutes=15),
        approver_scopes=(scope,),
        allow_requester_approval=allow_requester_approval,
    )


CHANGE_REQUEST = {"type": "aweb.secrets.change", "drafter": {"via": "console", "scope": "-"}}


async def _approver(world: World, scope: str) -> Approver | None:
    """The approver B2 would list for a policy naming only ``scope``."""
    found = await world.directory.candidates(_policy(scope), CHANGE_REQUEST)
    return found[0] if found else None


async def designate_owner(
    world: World, principal: PrincipalKey, contact: str, installation_id: str = INSTALLATION_ID
) -> str:
    """Bind the component fixture through the canonical human-role writer."""
    from tests.human_owner import apply_holder

    assert installation_id == world.admitted.installation_id
    designation = await apply_holder(world, "human-role.designate", principal, contact)
    return designation.approver.scope


async def designate_contact(world, ref, contact, *, enrol=True):
    """The real owner-approved app path for an ordinary contact approver."""
    from aweb_secrets.revisions import config_revision
    from tests.governance import view
    from tests.test_change_sets import (
        ALICE,
        by_member,
        change_set,
        decide,
        designate_approver,
        draft,
        enrol_owner,
    )

    if (
        await world.directory.owner_of(
            world.db, owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did)
        )
        is None
    ):
        await enrol_owner(world, ALICE, "alice@acme.com")
    from aweb_secrets import records
    from aweb_secrets.secret import SecretRecord
    from tests.test_use_approvals import SECRET, SECRET_ID

    async with world.db.transaction() as tx:
        record = SecretRecord.from_after(SECRET)
        if await records.secret_by_ref(tx, INSTALLATION_ID, TEAM, record.ref) is None:
            await records.create_secret(tx, INSTALLATION_ID, TEAM, record)
    change = change_set(
        drafter=by_member(ALICE),
        changes=[designate_approver(ref, contact, [SECRET_ID])],
        base_revision=await config_revision(world.db, INSTALLATION_ID),
    )
    await decide(world, await draft(world, change), "alice@acme.com")
    async with world.db.transaction() as tx:
        confirmation = await world.change_sets.confirm(
            tx,
            change["change_id"],
            operation_id="apply-" + change["change_id"],
            fence=world.fence,
            admitted=world.admitted,
            governance_view=view(),
        )
    await world.change_sets.deliver(confirmation)
    if not enrol:
        return approver_scope(INSTALLATION_ID, TEAM, ref)
    token = world.inbox.enrolments[contact][-1]
    device = SoftAuthenticator(world.passkeys.rp.origin)
    prepared = await world.credential_audit.prepare_enrolment(token)
    with world.credential_audit.prepared(prepared):
        await world.passkeys.complete_enrolment(
            token, device.create(await world.passkeys.enrolment_options(token)), fence=prepared
        )
    world.devices[contact] = device
    return approver_scope(INSTALLATION_ID, TEAM, ref)


async def test_an_enrolled_owner_holding_the_role_decides(world: World) -> None:
    scope = await designate_owner(world, ALICE, "alice@acme.com")
    approver = await _approver(world, scope)
    assert approver is not None and approver.contact == "alice@acme.com"
    assert await world.directory.is_current(scope, approver.subject)


async def test_an_owner_whose_role_is_revoked_no_longer_decides(world: World) -> None:
    scope = await designate_owner(world, ALICE, "alice@acme.com")
    approver = await _approver(world, scope)
    assert approver is not None
    from tests.human_owner import apply_holder

    await apply_holder(world, "human-role.revoke", ALICE, None)
    assert await _approver(world, scope) is None
    assert not await world.directory.is_current(scope, approver.subject)


async def test_revoking_one_owner_leaves_another_deciding(world: World) -> None:
    alice = await designate_owner(world, ALICE, "alice@acme.com")
    bob = await designate_owner(world, BOB, "bob@acme.com")
    async with world.db.transaction() as tx:
        await unassign(tx, ALICE, OWNER_ROLE)
    assert await _approver(world, alice) is None
    assert await _approver(world, bob) is not None


async def test_the_role_on_another_team_does_not_count(world: World) -> None:
    scope = await designate_owner(world, ALICE, "alice@acme.com")
    async with world.db.transaction() as tx:
        await unassign(tx, ALICE, OWNER_ROLE)
        await assign(tx, PrincipalKey("backend:other.com", ALICE.principal_did), OWNER_ROLE)
    assert await _approver(world, scope) is None


async def test_an_owner_scope_without_a_recorded_owner_has_no_approver(world: World) -> None:
    scope = await designate_owner(world, ALICE, "alice@acme.com")
    await world.db.execute("DELETE FROM {{tables.role_holdings}} WHERE b3_scope=$1", scope)
    assert await _approver(world, scope) is None


async def test_an_owner_holding_is_bound_to_its_admitted_installation(world: World) -> None:
    here = await designate_owner(world, ALICE, "alice@acme.com")
    assert await _approver(world, here) is not None
    there = owner_scope(OTHER_INSTALLATION, TEAM, ALICE.principal_did)
    assert await _approver(world, there) is None
    assert (
        await world.directory.enrolled_owners(
            world.db, installation_id=OTHER_INSTALLATION, team_id=TEAM
        )
        == []
    )


async def test_an_approver_scope_needs_no_owner_role(world: World) -> None:
    scope = await designate_contact(world, "finance", "finance@acme.com")
    approver = await _approver(world, scope)
    assert approver is not None
    assert await world.directory.is_current(scope, approver.subject)


def _member_draft(principal: PrincipalKey) -> dict:
    return {
        "type": "aweb.secrets.change",
        "drafter": {"via": "team_auth", "principal": principal.principal_did},
    }


async def test_every_current_owner_is_a_candidate(world: World) -> None:
    alice = await designate_owner(world, ALICE, "alice@acme.com")
    bob = await designate_owner(world, BOB, "bob@acme.com")
    policy = ActionPolicy(
        policy_ref="secrets.change",
        version=1,
        min_assurance=Assurance.PASSKEY,
        ttl=timedelta(minutes=15),
        approver_scopes=(alice, bob),
        allow_requester_approval=True,
    )
    found = await world.directory.candidates(policy, _member_draft(ALICE))
    assert {(a.scope, a.principal_did) for a in found} == {
        (alice, ALICE.principal_did),
        (bob, BOB.principal_did),
    }


async def test_under_four_eyes_the_drafting_owner_is_left_out(world: World) -> None:
    alice = await designate_owner(world, ALICE, "alice@acme.com")
    bob = await designate_owner(world, BOB, "bob@acme.com")
    policy = ActionPolicy(
        policy_ref="secrets.change",
        version=1,
        min_assurance=Assurance.PASSKEY,
        ttl=timedelta(minutes=15),
        approver_scopes=(alice, bob),
        allow_requester_approval=False,
    )
    found = await world.directory.candidates(policy, _member_draft(ALICE))
    assert [a.principal_did for a in found] == [BOB.principal_did]


async def test_under_four_eyes_a_console_drafter_is_left_out(world: World) -> None:
    alice = await designate_owner(world, ALICE, "alice@acme.com")
    bob = await designate_owner(world, BOB, "bob@acme.com")
    policy = ActionPolicy(
        policy_ref="secrets.change",
        version=1,
        min_assurance=Assurance.PASSKEY,
        ttl=timedelta(minutes=15),
        approver_scopes=(alice, bob),
        allow_requester_approval=False,
    )
    console_draft = {"type": "aweb.secrets.change", "drafter": {"via": "console", "scope": alice}}
    found = await world.directory.candidates(policy, console_draft)
    assert [a.principal_did for a in found] == [BOB.principal_did]


async def test_under_four_eyes_an_approver_scope_drafter_is_left_out(world: World) -> None:
    owner = await designate_owner(world, ALICE, "alice@acme.com")
    finance = await designate_contact(world, "finance", "finance@acme.com")
    policy = ActionPolicy(
        policy_ref="secrets.change",
        version=1,
        min_assurance=Assurance.PASSKEY,
        ttl=timedelta(minutes=15),
        approver_scopes=(owner, finance),
        allow_requester_approval=False,
    )
    console_draft = {"type": "aweb.secrets.change", "drafter": {"via": "console", "scope": finance}}
    found = await world.directory.candidates(policy, console_draft)
    assert [a.scope for a in found] == [owner]


@pytest.mark.parametrize("withdrawal", ["assignment", "record"])
async def test_transaction_aware_providers_observe_shared_holding_withdrawal_and_rollback(
    world: World, withdrawal
):
    from aweb_secrets.change_sets import ChangeSetPolicies, change_policy_ref

    scope = await designate_owner(world, ALICE, "alice@acme.com")
    policy_ref = change_policy_ref(world.admitted.installation_id, TEAM)
    policies = ChangeSetPolicies(world.db, world.directory)
    policy = await policies.current(policy_ref)
    assert policy is not None
    approver = await world.passkeys.designated_approver(scope)
    assert approver is not None

    class RollBack(Exception):
        pass

    with pytest.raises(RollBack):
        async with world.db.transaction() as tx:
            await world.fence.check(tx, world.admitted)
            if withdrawal == "assignment":
                await unassign(tx, ALICE, OWNER_ROLE)
            else:
                await tx.execute("DELETE FROM {{tables.role_holdings}} WHERE b3_scope=$1", scope)
            assert await policies.current(policy_ref, tx=tx) is None
            assert await world.directory.candidates(policy, {}, tx=tx) == []
            assert not await world.directory.is_current(scope, approver.subject, tx=tx)
            raise RollBack()
    assert await policies.current(policy_ref) == policy
    assert await world.directory.is_current(scope, approver.subject)
