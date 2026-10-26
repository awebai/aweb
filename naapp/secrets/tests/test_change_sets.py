"""The change-set lifecycle (design §6.2-§6.3, decisions 54 and 61), on real PostgreSQL.

Owners are designated by real team owner acts, enrol and decide with a
software passkey through B2, and a confirmed change set applies in the
transaction that admits its approval.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from functools import partial
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from aweb_naapp.egress import InternalDestinations
from aweb_naapp.hooks.owner_act_nonces import apply_owner_act_migrations
from aweb_naapp.hooks.producer import HookProducer, ServerProducer
from aweb_naapp.outbox import apply_outbox_migrations
from aweb_naapp.roles import PrincipalKey, apply_roles_migrations, assign, has_role, unassign
from aweb_naapp.runtime.approvals import (
    Approval,
    ApprovalRefused,
    ApprovalRevocation,
    Approvals,
    ApprovalState,
    Approver,
    Assurance,
    Decision,
    DeliveryStatus,
    PgApprovalStore,
)
from aweb_naapp.runtime.authorization import Grant
from aweb_naapp.runtime.clock import seconds_to_ns
from aweb_naapp.runtime.installation import (
    AdmittedInstallation,
    InstallationFence,
    apply_installation_migrations,
)
from aweb_naapp.runtime.passkeys import Notice, Passkeys, RelyingParty
from aweb_naapp_testing.owner_acts import (
    INSTALLATION_ID,
    TeamOwner,
    designation_subject,
    team_owner,
)
from aweb_naapp_testing.webauthn import SoftAuthenticator
from awid_service.testing import running_registry
from pgdbm import AsyncDatabaseManager, AsyncMigrationManager

from aweb_secrets.app import MIGRATIONS_PATH, MODULE_NAME
from aweb_secrets.approvers import approvers_for_secret
from aweb_secrets.change import ChangeRefused
from aweb_secrets.change_policy import apply_change_policy_migrations, four_eyes, require_four_eyes
from aweb_secrets.change_sets import (
    ChangeSetPolicies,
    ChangeSets,
    DraftLimit,
    apply_change_set_migrations,
)
from aweb_secrets.containment import Containment
from aweb_secrets.custody import (
    Custody,
    CustodyUnavailable,
    LocalKeyFileProvider,
    SealContext,
    apply_custody_migrations,
    encode_value,
)
from aweb_secrets.owners import (
    OWNER_ROLE,
    OwnerDirectory,
    apply_owner_migrations,
    approver_scope,
    is_owner_scope,
    owner_scope,
    record_owner,
)
from aweb_secrets.passkey_context import PasskeyContexts
from aweb_secrets.revisions import apply_revision_migrations, bump_config_revision, config_revision
from aweb_secrets.tokens import ProcessTokenCache
from aweb_secrets.use_approvals import apply_use_approval_migrations
from tests.governance import view
from tests.test_owner_directory import Audit

ORIGIN = "https://secrets.example.com"
TEAM = "backend:acme.com"
ALICE = PrincipalKey(team_id=TEAM, principal_did="did:aw:jPUMBAvNeJo8USHNtJ81Wm7cqnk")
BOB = PrincipalKey(team_id=TEAM, principal_did="did:aw:2Uq51iFVLnqmgbVY3vLZtMD5PR87")
CAROL = PrincipalKey(
    team_id=TEAM, principal_did="did:key:z6Mko9hTggMwjSTEaJaPUfE6tqcy2xvU6BnNq3e3o8qVBiyH"
)
APP_ID = "secrets"


class Installations:
    """The installation's grant, as the app-to-team-server source reports it:
    fresh for 55 seconds from each observation, inside the fence's 60."""

    def __init__(self, *, team_id: str = TEAM, app_id: str = APP_ID) -> None:
        self.team_id = team_id
        self.app_id = app_id

    @property
    def grant(self) -> Grant:
        return Grant(
            team_id=self.team_id,
            installation_id=INSTALLATION_ID,
            generation=1,
            scopes=frozenset({"secrets:use"}),
            fresh_until=time.monotonic_ns() + seconds_to_ns(55),
        )

    async def grant_for(self, team_id: str, certificate_id: str | None = None) -> Grant | None:
        return self.grant if team_id == self.team_id else None

    async def status_for(self, team_id: str) -> SimpleNamespace | None:
        if team_id != self.team_id:
            return None
        grant = self.grant
        return SimpleNamespace(
            team_id=self.team_id,
            app_id=self.app_id,
            state="active",
            installation_id=INSTALLATION_ID,
            generation=1,
            granted_scopes=grant.scopes,
            fresh_until=grant.fresh_until,
        )


@dataclass
class Inbox:
    links: dict[str, list[tuple[str, str]]] = field(default_factory=dict)
    enrolments: dict[str, list[str]] = field(default_factory=dict)
    notices: dict[str, list[Notice]] = field(default_factory=dict)
    proofs: dict[str, list[str]] = field(default_factory=dict)

    async def deliver_enrolment_link(self, approver: Approver, link_token: str) -> DeliveryStatus:
        self.enrolments.setdefault(approver.contact, []).append(link_token)
        return DeliveryStatus.DELIVERED

    async def deliver_contact_proof(self, contact: str, proof_token: str) -> DeliveryStatus:
        self.proofs.setdefault(contact, []).append(proof_token)
        return DeliveryStatus.DELIVERED

    async def deliver_notice(self, contact: str, notice: Notice) -> DeliveryStatus:
        self.notices.setdefault(contact, []).append(notice)
        return DeliveryStatus.DELIVERED

    async def deliver_approval_link(
        self, approver: Approver, link_token: str, approval: Approval
    ) -> DeliveryStatus:
        self.links.setdefault(approver.contact, []).append((approval.approval_id, link_token))
        return DeliveryStatus.DELIVERED


@dataclass
class World:
    db: AsyncDatabaseManager
    passkeys: Passkeys
    approvals: Approvals
    change_sets: ChangeSets
    directory: OwnerDirectory
    custody: Custody
    owner: TeamOwner
    inbox: Inbox
    fence: InstallationFence
    admitted: AdmittedInstallation
    containment: Containment
    devices: dict[str, SoftAuthenticator] = field(default_factory=dict)


@pytest.fixture
async def world(test_db_factory, tmp_path: Path) -> AsyncIterator[World]:
    db = await test_db_factory.create_db(suffix="secrets_change_sets")
    registry_db = await test_db_factory.create_db(suffix="secrets_change_sets_awid")
    await db.execute(
        "CREATE TABLE {{tables.audit_outbox}} (id SERIAL PRIMARY KEY, kind TEXT, details TEXT)"
    )
    store = PgApprovalStore(db)
    await store.migrate()
    audit = Audit(db)
    inbox = Inbox()
    passkeys = Passkeys(
        db,
        rp=RelyingParty(origin=ORIGIN, name="secrets"),
        delivery=inbox,
        audit=audit,
        retirement=ApprovalRevocation(store, audit),
        enrolment_ttl=timedelta(hours=1),
        challenge_ttl=timedelta(minutes=5),
        owner_scopes=is_owner_scope,
        proof_context=PasskeyContexts(app_id=APP_ID),
    )
    await passkeys.migrate()
    await AsyncMigrationManager(
        db, migrations_path=str(MIGRATIONS_PATH), module_name=MODULE_NAME
    ).apply_pending_migrations()
    for migrate in (
        apply_roles_migrations,
        apply_owner_act_migrations,
        apply_owner_migrations,
        apply_revision_migrations,
        apply_change_policy_migrations,
        apply_custody_migrations,
        apply_change_set_migrations,
        apply_installation_migrations,
        apply_use_approval_migrations,
        apply_outbox_migrations,
    ):
        await migrate(db)
    installations = Installations()
    fence = InstallationFence(db, app_id=APP_ID, grants=installations)
    await fence.refresh(TEAM)
    async with db.transaction() as tx:
        admitted = await fence.admit(tx, installations.grant)
    directory = OwnerDirectory(passkeys, db)
    approvals = Approvals(
        store=store,
        policies=ChangeSetPolicies(db, directory),
        approvers=directory,
        delivery=inbox,
        authenticators=[passkeys.authenticator()],
        audit=audit,
    )
    key = tmp_path / "kek"
    key.write_text(os.urandom(32).hex())
    key.chmod(0o600)
    custody = Custody(LocalKeyFileProvider(key), db)
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
    containment = Containment(
        db=db,
        fence=fence,
        approvals=approvals,
        custody=custody,
        passkeys=passkeys,
        directory=directory,
        tokens=ProcessTokenCache(),
        governance=partial(producer.enqueue, hook="post-governance-hook"),
    )
    change_sets = ChangeSets(
        db,
        approvals=approvals,
        passkeys=passkeys,
        directory=directory,
        custody=custody,
        containment=containment,
        draft_limit=DraftLimit(count=2, window=timedelta(hours=1)),
        internal_destinations=InternalDestinations.DISABLED,
    )
    async with running_registry(registry_db.config.get_dsn()) as registry:
        yield World(
            db,
            passkeys,
            approvals,
            change_sets,
            directory,
            custody,
            await team_owner(registry, team_id=TEAM),
            inbox,
            fence,
            admitted,
            containment,
        )


async def enrol_owner(world: World, principal: PrincipalKey, contact: str) -> str:
    """The team owner designates ``principal`` an owner, who enrols a passkey."""
    scope = owner_scope(INSTALLATION_ID, principal.team_id, principal.principal_did)
    subject = designation_subject(scope, contact)
    prepared = await world.owner.prepare("app-role.designate", subject)
    async with world.db.transaction() as tx:
        act = await world.owner.consume(tx, prepared, subject)
        designation = await world.passkeys.designate(tx, scope=scope, contact=contact, evidence=act)
        await record_owner(tx, installation_id=INSTALLATION_ID, principal=principal)
        await assign(tx, principal, OWNER_ROLE)
    await world.passkeys.deliver(designation)
    token = world.inbox.enrolments[contact][-1]
    device = SoftAuthenticator(ORIGIN)
    await world.passkeys.complete_enrolment(
        token, device.create(await world.passkeys.enrolment_options(token))
    )
    world.devices[contact] = device
    return scope


def change_set(
    *,
    drafter: dict[str, Any],
    changes: list[dict[str, Any]],
    base_revision: int = 0,
    expires_in: timedelta = timedelta(hours=1),
) -> dict[str, Any]:
    issued = datetime.now(UTC).replace(microsecond=0)
    return {
        "v": 1,
        "type": "aweb.secrets.change",
        "change_id": f"chg_{uuid.uuid4().hex[:12]}",
        "installation_id": INSTALLATION_ID,
        "install_generation": 1,
        "team_id": TEAM,
        "drafter": drafter,
        "base_revision": base_revision,
        "changes": changes,
        "reason": "",
        "issued_at": issued.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": (issued + expires_in).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def by_member(principal: PrincipalKey) -> dict[str, Any]:
    """A team member's drafter: its principal is its did:aw when it has one, else its did:key."""
    drafter: dict[str, Any] = {
        "via": "team_auth",
        "principal": principal.principal_did,
        "member_did_key": CAROL.principal_did,
        "certificate_id": "0b4c2c1e-7f4e-4a53-9d43-2f1f0d2c6a11",
        "alias": "member",
    }
    if principal.principal_did.startswith("did:aw:"):
        drafter["did_aw"] = principal.principal_did
    return drafter


def on_console(scope: str) -> dict[str, Any]:
    return {"via": "console", "scope": scope, "subject": "console-session"}


def grant_role(principal: PrincipalKey, role: str = "secrets.role.deployers") -> dict[str, Any]:
    return {
        "kind": "role",
        "op": "create",
        "ref": role,
        "after": {"v": 1, "role": role, "principal": principal.principal_did},
    }


RELAX_FOUR_EYES = {
    "kind": "change_set_policy",
    "op": "update",
    "ref": INSTALLATION_ID,
    "after": {"v": 1, "distinct_approver": "not_required"},
}


async def draft(world: World, change: dict[str, Any], sealed=()) -> str:
    async with world.db.transaction() as tx:
        pending = await world.change_sets.draft(tx, change, sealed=sealed)
    await world.approvals.deliver(pending)
    return pending.approval.approval_id


async def decide(world: World, approval_id: str, contact: str) -> None:
    [token] = [t for a, t in world.inbox.links.get(contact, []) if a == approval_id]
    options = await world.approvals.challenge(
        approval_id, Decision.APPROVE, Assurance.PASSKEY, link_token=token
    )
    await world.approvals.decide(
        approval_id,
        Decision.APPROVE,
        Assurance.PASSKEY,
        world.devices[contact].get(dict(options)),
        link_token=token,
    )


async def confirm(world: World, change: dict[str, Any]) -> None:
    async with world.db.transaction() as tx:
        await world.change_sets.confirm(
            tx,
            change["change_id"],
            operation_id=f"apply-{change['change_id']}",
            fence=world.fence,
            admitted=world.admitted,
            governance_view=view(),
        )


async def test_a_member_draft_asks_every_current_owner(world: World) -> None:
    await enrol_owner(world, ALICE, "alice@acme.com")
    await enrol_owner(world, BOB, "bob@acme.com")
    approval_id = await draft(
        world, change_set(drafter=by_member(CAROL), changes=[grant_role(CAROL)])
    )
    assert {
        c for c, links in world.inbox.links.items() if any(a == approval_id for a, _ in links)
    } == {
        "alice@acme.com",
        "bob@acme.com",
    }


async def test_nothing_is_sent_before_the_draft_commits(world: World) -> None:
    await enrol_owner(world, ALICE, "alice@acme.com")
    change = change_set(drafter=by_member(CAROL), changes=[grant_role(CAROL)])
    async with world.db.transaction() as tx:
        await world.change_sets.draft(tx, change)
        assert world.inbox.links == {}


async def test_a_console_draft_asks_only_its_owner(world: World) -> None:
    alice = await enrol_owner(world, ALICE, "alice@acme.com")
    await enrol_owner(world, BOB, "bob@acme.com")
    approval_id = await draft(
        world, change_set(drafter=on_console(alice), changes=[grant_role(CAROL)])
    )
    assert [
        c for c, links in world.inbox.links.items() if any(a == approval_id for a, _ in links)
    ] == ["alice@acme.com"]


async def test_four_eyes_console_draft_requires_another_current_owner(world: World) -> None:
    alice = await enrol_owner(world, ALICE, "alice@acme.com")
    await enrol_owner(world, BOB, "bob@acme.com")
    async with world.db.transaction() as tx:
        await require_four_eyes(
            tx, installation_id=INSTALLATION_ID, team_id=TEAM, directory=world.directory
        )
    change = change_set(
        drafter=on_console(alice),
        changes=[grant_role(CAROL)],
        base_revision=await config_revision(world.db, INSTALLATION_ID),
    )
    approval_id = await draft(world, change)
    assert {
        contact
        for contact, links in world.inbox.links.items()
        if any(candidate == approval_id for candidate, _ in links)
    } == {"bob@acme.com"}
    assert not await has_role(world.db, CAROL, "secrets.role.deployers")
    [token] = [t for candidate, t in world.inbox.links["bob@acme.com"] if candidate == approval_id]
    options = await world.approvals.challenge(
        approval_id, Decision.APPROVE, Assurance.PASSKEY, link_token=token
    )
    with pytest.raises(ApprovalRefused):
        await world.approvals.decide(
            approval_id,
            Decision.APPROVE,
            Assurance.PASSKEY,
            world.devices["alice@acme.com"].get(dict(options)),
            link_token=token,
        )
    assert (await world.approvals.get(approval_id)).state is ApprovalState.PENDING
    await decide(world, approval_id, "bob@acme.com")
    await confirm(world, change)
    assert await has_role(world.db, CAROL, "secrets.role.deployers")
    assert (await world.approvals.get(approval_id)).state is ApprovalState.CONSUMED


async def test_four_eyes_console_draft_has_no_candidate_after_other_owner_revocation(
    world: World,
) -> None:
    alice = await enrol_owner(world, ALICE, "alice@acme.com")
    await enrol_owner(world, BOB, "bob@acme.com")
    async with world.db.transaction() as tx:
        await require_four_eyes(
            tx, installation_id=INSTALLATION_ID, team_id=TEAM, directory=world.directory
        )
        await unassign(tx, BOB, OWNER_ROLE)
    change = change_set(
        drafter=on_console(alice),
        changes=[grant_role(CAROL)],
        base_revision=await config_revision(world.db, INSTALLATION_ID),
    )
    with pytest.raises(ChangeRefused) as refused:
        await draft(world, change)
    assert refused.value.code == "no_owner_to_confirm"
    assert not await has_role(world.db, CAROL, "secrets.role.deployers")
    assert await world.db.fetch_value("SELECT count(*) FROM {{tables.change_sets}}") == 0


async def test_a_confirmed_change_set_applies_and_moves_the_revision_on(world: World) -> None:
    await enrol_owner(world, ALICE, "alice@acme.com")
    change = change_set(drafter=by_member(CAROL), changes=[grant_role(CAROL)])
    approval_id = await draft(world, change)
    await decide(world, approval_id, "alice@acme.com")
    await confirm(world, change)
    assert await has_role(world.db, CAROL, "secrets.role.deployers")
    assert await config_revision(world.db, INSTALLATION_ID) == 1
    assert (await world.approvals.get(approval_id)).state is ApprovalState.CONSUMED


async def test_an_undecided_change_set_does_not_apply(world: World) -> None:
    await enrol_owner(world, ALICE, "alice@acme.com")
    change = change_set(drafter=by_member(CAROL), changes=[grant_role(CAROL)])
    await draft(world, change)
    with pytest.raises(ChangeRefused) as refused:
        await confirm(world, change)
    assert refused.value.code == "change_not_approved"
    assert not await has_role(world.db, CAROL, "secrets.role.deployers")


async def test_a_change_set_applies_once(world: World) -> None:
    await enrol_owner(world, ALICE, "alice@acme.com")
    change = change_set(drafter=by_member(CAROL), changes=[grant_role(CAROL)])
    await decide(world, await draft(world, change), "alice@acme.com")
    await confirm(world, change)
    with pytest.raises(ChangeRefused) as refused:
        await confirm(world, change)
    assert refused.value.code == "change_not_pending"


async def test_a_change_set_drafted_before_a_narrowing_act_is_stale(world: World) -> None:
    await enrol_owner(world, ALICE, "alice@acme.com")
    change = change_set(drafter=by_member(CAROL), changes=[grant_role(CAROL)])
    approval_id = await draft(world, change)
    await decide(world, approval_id, "alice@acme.com")
    async with world.db.transaction() as tx:
        await bump_config_revision(tx, INSTALLATION_ID)  # a revoke, disable or remove
    with pytest.raises(ChangeRefused) as refused:
        await confirm(world, change)
    assert refused.value.code == "base_revision_stale"
    assert not await has_role(world.db, CAROL, "secrets.role.deployers")


async def test_a_draft_against_a_past_revision_is_refused_at_once(world: World) -> None:
    await enrol_owner(world, ALICE, "alice@acme.com")
    async with world.db.transaction() as tx:
        await bump_config_revision(tx, INSTALLATION_ID)
    with pytest.raises(ChangeRefused) as refused:
        await draft(world, change_set(drafter=by_member(CAROL), changes=[grant_role(CAROL)]))
    assert refused.value.code == "base_revision_stale"


async def test_a_member_drafts_only_so_many_change_sets_an_hour(world: World) -> None:
    await enrol_owner(world, ALICE, "alice@acme.com")
    for _ in range(2):
        await draft(world, change_set(drafter=by_member(CAROL), changes=[grant_role(CAROL)]))
    with pytest.raises(ChangeRefused) as refused:
        await draft(world, change_set(drafter=by_member(CAROL), changes=[grant_role(CAROL)]))
    assert refused.value.code == "draft_rate_limited"


async def test_the_draft_limit_is_per_member(world: World) -> None:
    await enrol_owner(world, ALICE, "alice@acme.com")
    for _ in range(2):
        await draft(world, change_set(drafter=by_member(CAROL), changes=[grant_role(CAROL)]))
    await draft(world, change_set(drafter=by_member(BOB), changes=[grant_role(BOB)]))


async def test_an_unsupported_reenable_target_is_refused_at_draft(world: World) -> None:
    await enrol_owner(world, ALICE, "alice@acme.com")
    reenable = {
        "kind": "reenable",
        "op": "enable",
        "ref": "grt_missing001",
        "after": {"v": 1, "target_kind": "grant", "target_ref": "grt_missing001"},
    }
    with pytest.raises(ChangeRefused) as refused:
        await draft(world, change_set(drafter=by_member(CAROL), changes=[reenable]))
    assert refused.value.code == "reenable_target_unsupported"


async def test_under_four_eyes_another_owner_confirms_relaxing_it(world: World) -> None:
    await enrol_owner(world, ALICE, "alice@acme.com")
    await enrol_owner(world, BOB, "bob@acme.com")
    async with world.db.transaction() as tx:
        await require_four_eyes(
            tx, installation_id=INSTALLATION_ID, team_id=TEAM, directory=world.directory
        )
    revision = await config_revision(world.db, INSTALLATION_ID)
    change = change_set(drafter=by_member(ALICE), changes=[RELAX_FOUR_EYES], base_revision=revision)
    approval_id = await draft(world, change)
    assert "alice@acme.com" not in {
        c for c, links in world.inbox.links.items() if any(a == approval_id for a, _ in links)
    }
    await decide(world, approval_id, "bob@acme.com")
    await confirm(world, change)
    assert await four_eyes(world.db, INSTALLATION_ID) == "not_required"


SECRET_ID = "sec_19ab42"
SECRET = {
    "v": 1,
    "secret_id": SECRET_ID,
    "ref": "payments-live",
    "description": "Live payments API key",
    "kind": "bearer",
    "kind_params": {},
    "sensitivity": "standard",
    "approve_only": False,
    "backend": "native",
}


async def sealed_value(world: World, contents: bytes = b"v") -> SealContext:
    from aweb_secrets.operation import CAPTURE_FIELDS
    from aweb_secrets.secret import SecretRecord

    async with world.db.transaction() as tx:
        body = await tx.fetch_value(
            "SELECT record FROM {{tables.secrets}} WHERE secret_id = $1", SECRET_ID
        )
        candidate = SecretRecord.from_after(json.loads(body) if body else SECRET)
        fields, _ = CAPTURE_FIELDS[candidate.kind]
        version = await world.custody.sealer.ingest(
            tx,
            installation_id=INSTALLATION_ID,
            team_id=TEAM,
            secret_id=SECRET_ID,
            value=encode_value(candidate.kind, dict.fromkeys(fields, contents.decode())),
            initial=candidate,
        )
    return SealContext(
        installation_id=INSTALLATION_ID, team_id=TEAM, secret_id=SECRET_ID, version=version
    )


def secret_value(version: int) -> dict[str, Any]:
    return {
        "kind": "secret_value",
        "op": "create",
        "ref": "payments-live",
        "after": {"v": 1, "secret_ref": "payments-live", "version": version},
    }


def new_secret(sealed: SealContext) -> list[dict[str, Any]]:
    """The items creating ``SECRET`` with ``sealed`` as its first value."""
    secret = {"kind": "secret", "op": "create", "ref": "payments-live", "after": SECRET}
    return [secret, secret_value(sealed.version)]


async def test_an_expired_draft_destroys_its_sealed_versions_and_its_approval(world: World) -> None:
    await enrol_owner(world, ALICE, "alice@acme.com")
    sealed = await sealed_value(world)
    change = change_set(drafter=by_member(CAROL), changes=new_secret(sealed))
    approval_id = await draft(world, change, sealed=[sealed])
    expired = await world.change_sets.expire(now=datetime.now(UTC) + timedelta(hours=2))
    assert expired == 1
    with pytest.raises(CustodyUnavailable):
        await world.custody.opener.open(sealed)
    assert (await world.approvals.get(approval_id)).state is ApprovalState.REVOKED
    with pytest.raises(ChangeRefused):
        await confirm(world, change)


async def test_a_cancelled_draft_destroys_its_sealed_versions_and_its_approval(
    world: World,
) -> None:
    await enrol_owner(world, ALICE, "alice@acme.com")
    sealed = await sealed_value(world)
    change = change_set(drafter=by_member(CAROL), changes=new_secret(sealed))
    approval_id = await draft(world, change, sealed=[sealed])
    async with world.db.transaction() as tx:
        await world.change_sets.cancel(tx, change["change_id"], cancelled_by=CAROL.principal_did)
    with pytest.raises(CustodyUnavailable):
        await world.custody.opener.open(sealed)
    assert (await world.approvals.get(approval_id)).state is ApprovalState.REVOKED


async def test_a_live_draft_keeps_its_sealed_versions(world: World) -> None:
    await enrol_owner(world, ALICE, "alice@acme.com")
    sealed = await sealed_value(world)
    await draft(world, change_set(drafter=by_member(CAROL), changes=new_secret(sealed)), [sealed])
    assert await world.change_sets.expire(now=datetime.now(UTC)) == 0
    assert (await world.custody.opener.open(sealed)).reveal() == encode_value(
        "bearer", {"value": "v"}
    )


def designate_approver(ref: str, contact: str, covers: list[str]) -> dict[str, Any]:
    return {
        "kind": "approver",
        "op": "create",
        "ref": ref,
        "after": {
            "v": 1,
            "approver_ref": ref,
            "contact": contact,
            "covers": covers,
            "principal": None,
        },
    }


async def test_a_confirmed_approver_is_designated_and_recorded(world: World) -> None:
    await enrol_owner(world, ALICE, "alice@acme.com")
    change = change_set(
        drafter=by_member(CAROL),
        changes=[designate_approver("finance", "finance@acme.com", ["sec_1", "sec_2"])],
    )
    await decide(world, await draft(world, change), "alice@acme.com")
    async with world.db.transaction() as tx:
        confirmation = await world.change_sets.confirm(
            tx,
            change["change_id"],
            operation_id="apply-1",
            fence=world.fence,
            admitted=world.admitted,
            governance_view=view(),
        )
        assert "finance@acme.com" not in world.inbox.enrolments
    await world.change_sets.deliver(confirmation)
    assert world.inbox.enrolments["finance@acme.com"]
    async with world.db.transaction() as tx:
        [record] = await approvers_for_secret(
            tx, installation_id=INSTALLATION_ID, team_id=TEAM, secret_id="sec_2"
        )
        assert (
            await approvers_for_secret(
                tx, installation_id=INSTALLATION_ID, team_id=TEAM, secret_id="sec_9"
            )
            == []
        )
    assert record.approver_ref == "finance"
    assert record.scope == approver_scope(INSTALLATION_ID, TEAM, "finance")
    assert record.change_id == change["change_id"]


async def test_an_approver_change_set_that_fails_designates_nobody(world: World) -> None:
    await enrol_owner(world, ALICE, "alice@acme.com")
    change = change_set(
        drafter=by_member(CAROL),
        changes=[designate_approver("finance", "finance@acme.com", ["sec_1"])],
    )
    await decide(world, await draft(world, change), "alice@acme.com")
    async with world.db.transaction() as tx:
        await bump_config_revision(tx, INSTALLATION_ID)
    with pytest.raises(ChangeRefused):
        await confirm(world, change)
    async with world.db.transaction() as tx:
        assert (
            await approvers_for_secret(
                tx, installation_id=INSTALLATION_ID, team_id=TEAM, secret_id="sec_1"
            )
            == []
        )
    assert "finance@acme.com" not in world.inbox.enrolments


@pytest.mark.parametrize(
    "other", [{"installation_id": "inst_other"}, {"team_id": "backend:other.com"}]
)
async def test_a_draft_takes_only_its_own_installations_sealed_values(
    world: World, other: dict[str, str]
) -> None:
    await enrol_owner(world, ALICE, "alice@acme.com")
    sealed = await sealed_value(world)
    foreign = SealContext(**{**sealed.__dict__, **other})
    with pytest.raises(ChangeRefused) as refused:
        await draft(
            world, change_set(drafter=by_member(CAROL), changes=new_secret(sealed)), [foreign]
        )
    assert refused.value.code == "sealed_value_foreign"
    assert (await world.custody.opener.open(sealed)).reveal() == encode_value(
        "bearer", {"value": "v"}
    )


async def test_a_sealed_value_belongs_to_one_draft(world: World) -> None:
    await enrol_owner(world, ALICE, "alice@acme.com")
    sealed = await sealed_value(world)
    await draft(world, change_set(drafter=by_member(CAROL), changes=new_secret(sealed)), [sealed])
    with pytest.raises(ChangeRefused) as refused:
        await draft(world, change_set(drafter=by_member(BOB), changes=new_secret(sealed)), [sealed])
    assert refused.value.code == "sealed_value_taken"


async def test_the_role_kind_never_grants_the_owner_role(world: World) -> None:
    await enrol_owner(world, ALICE, "alice@acme.com")
    with pytest.raises(ChangeRefused) as refused:
        await draft(
            world,
            change_set(drafter=by_member(CAROL), changes=[grant_role(CAROL, "secrets.owner")]),
        )
    assert refused.value.code == "role_not_grantable"


async def test_a_confirm_by_an_owner_being_revoked_waits_and_is_refused(world: World) -> None:
    await enrol_owner(world, ALICE, "alice@acme.com")
    change = change_set(drafter=by_member(CAROL), changes=[grant_role(CAROL)])
    await decide(world, await draft(world, change), "alice@acme.com")
    held = asyncio.Event()

    async def revoke_alice() -> None:
        async with world.db.transaction() as tx:
            await unassign(tx, ALICE, OWNER_ROLE)
            await held.wait()

    revoking = asyncio.create_task(revoke_alice())
    await asyncio.sleep(0.2)
    confirming = asyncio.create_task(confirm(world, change))
    await asyncio.sleep(0.2)
    held.set()
    await revoking
    with pytest.raises(ChangeRefused) as refused:
        await confirming
    assert refused.value.code == "owner_required"
    assert not await has_role(world.db, CAROL, "secrets.role.deployers")


async def test_a_second_approver_with_the_same_ref_is_refused(world: World) -> None:
    await enrol_owner(world, ALICE, "alice@acme.com")
    first = change_set(
        drafter=by_member(CAROL), changes=[designate_approver("finance", "f@acme.com", ["sec_1"])]
    )
    await decide(world, await draft(world, first), "alice@acme.com")
    await confirm(world, first)
    second = change_set(
        drafter=by_member(CAROL),
        changes=[designate_approver("finance", "f2@acme.com", ["sec_2"])],
        base_revision=1,
    )
    await decide(world, await draft(world, second), "alice@acme.com")
    with pytest.raises(ChangeRefused) as refused:
        await confirm(world, second)
    assert refused.value.code == "approver_exists"


async def test_a_refused_designation_is_a_coded_refusal(world: World) -> None:
    await enrol_owner(world, ALICE, "alice@acme.com")
    scope = approver_scope(INSTALLATION_ID, TEAM, "finance")
    subject = designation_subject(scope, "f@acme.com")
    prepared = await world.owner.prepare("app-role.designate", subject)
    async with world.db.transaction() as tx:
        act = await world.owner.consume(tx, prepared, subject)
        await world.passkeys.designate(tx, scope=scope, contact="f@acme.com", evidence=act)
    change = change_set(
        drafter=by_member(CAROL), changes=[designate_approver("finance", "f@acme.com", ["sec_1"])]
    )
    approval_id = await draft(world, change)
    await decide(world, approval_id, "alice@acme.com")
    with pytest.raises(ChangeRefused) as refused:
        await confirm(world, change)
    assert refused.value.code == "approver_designation_refused"
    assert await world.db.fetch_value("SELECT count(*) FROM {{tables.approvers}}") == 0
    assert await config_revision(world.db, INSTALLATION_ID) == 0
    assert (await world.approvals.get(approval_id)).state is ApprovalState.APPROVED


async def test_four_eyes_turned_on_after_a_draft_refuses_its_confirmation(world: World) -> None:
    alice = await enrol_owner(world, ALICE, "alice@acme.com")
    await enrol_owner(world, BOB, "bob@acme.com")
    change = change_set(drafter=on_console(alice), changes=[grant_role(CAROL)])
    approval_id = await draft(world, change)
    async with world.db.transaction() as tx:
        await require_four_eyes(
            tx, installation_id=INSTALLATION_ID, team_id=TEAM, directory=world.directory
        )
    # B2 already refuses the drafting owner's decision now; confirmation would too.
    with pytest.raises((ApprovalRefused, ChangeRefused)):
        await decide(world, approval_id, "alice@acme.com")
        await confirm(world, change)
    assert not await has_role(world.db, CAROL, "secrets.role.deployers")


async def test_relaxing_and_requiring_four_eyes_at_once_do_not_deadlock(world: World) -> None:
    await enrol_owner(world, ALICE, "alice@acme.com")
    await enrol_owner(world, BOB, "bob@acme.com")
    async with world.db.transaction() as tx:
        await require_four_eyes(
            tx, installation_id=INSTALLATION_ID, team_id=TEAM, directory=world.directory
        )
    revision = await config_revision(world.db, INSTALLATION_ID)
    change = change_set(drafter=by_member(ALICE), changes=[RELAX_FOUR_EYES], base_revision=revision)
    await decide(world, await draft(world, change), "bob@acme.com")

    async def require() -> None:
        async with world.db.transaction() as tx:
            await require_four_eyes(
                tx, installation_id=INSTALLATION_ID, team_id=TEAM, directory=world.directory
            )

    results = await asyncio.gather(confirm(world, change), require(), return_exceptions=True)
    for result in results:
        assert result is None or isinstance(result, ChangeRefused), result


def change_approver_contact(ref: str, contact: str) -> dict[str, Any]:
    return {
        "kind": "approver_contact",
        "op": "update",
        "ref": ref,
        "after": {"v": 1, "approver_ref": ref, "contact": contact},
    }


async def _with_approver(world: World) -> None:
    first = change_set(
        drafter=by_member(CAROL), changes=[designate_approver("finance", "f@acme.com", ["sec_1"])]
    )
    await decide(world, await draft(world, first), "alice@acme.com")
    await confirm(world, first)


async def _confirm_and_deliver(world: World, change: dict[str, Any]):
    async with world.db.transaction() as tx:
        confirmation = await world.change_sets.confirm(
            tx,
            change["change_id"],
            operation_id=f"apply-{change['change_id']}",
            fence=world.fence,
            admitted=world.admitted,
            governance_view=view(),
        )
        assert world.inbox.notices == {}
    await world.change_sets.deliver(confirmation)


async def test_a_confirmed_contact_change_is_scheduled_and_announced(world: World) -> None:
    await enrol_owner(world, ALICE, "alice@acme.com")
    await _with_approver(world)
    change = change_set(
        drafter=by_member(CAROL),
        changes=[change_approver_contact("finance", "f-new@acme.com")],
        base_revision=1,
    )
    await decide(world, await draft(world, change), "alice@acme.com")
    await _confirm_and_deliver(world, change)
    assert set(world.inbox.notices) == {"f@acme.com", "f-new@acme.com"}
    # Only the new contact receives the proof that makes the change count.
    assert list(world.inbox.proofs) == ["f-new@acme.com"]


async def test_a_second_contact_change_waits_for_the_first(world: World) -> None:
    await enrol_owner(world, ALICE, "alice@acme.com")
    await _with_approver(world)
    first = change_set(
        drafter=by_member(CAROL),
        changes=[change_approver_contact("finance", "f-new@acme.com")],
        base_revision=1,
    )
    await decide(world, await draft(world, first), "alice@acme.com")
    await _confirm_and_deliver(world, first)
    second = change_set(
        drafter=by_member(BOB),
        changes=[change_approver_contact("finance", "f-other@acme.com")],
        base_revision=2,
    )
    await decide(world, await draft(world, second), "alice@acme.com")
    with pytest.raises(ChangeRefused) as refused:
        await confirm(world, second)
    assert refused.value.code == "contact_change_pending"


async def test_a_contact_change_for_an_unknown_approver_is_refused(world: World) -> None:
    await enrol_owner(world, ALICE, "alice@acme.com")
    change = change_set(
        drafter=by_member(CAROL), changes=[change_approver_contact("nobody", "n@acme.com")]
    )
    await decide(world, await draft(world, change), "alice@acme.com")
    with pytest.raises(ChangeRefused) as refused:
        await confirm(world, change)
    assert refused.value.code == "approver_unknown"


@pytest.mark.parametrize("delivery", ["durable", "short_lived"])
async def test_job_definitions_refuse_unavailable_sources_or_unwired_minting(world, delivery):
    from tests.test_jobs import after as job_after

    await enrol_owner(world, ALICE, "alice@acme.com")
    # The same real confirmed-writer service can draft an implemented kind.
    await draft(world, change_set(drafter=by_member(CAROL), changes=[grant_role(CAROL)]))
    body = job_after()
    if delivery == "short_lived":
        body["credentials"][0].update(
            delivery=delivery,
            mint={"operation_id": "mint-session", "digest": "c" * 64, "params": {}},
        )
    item = {"kind": "job", "op": "create", "ref": body["job_id"], "after": body}
    with pytest.raises(ChangeRefused) as refused:
        await draft(world, change_set(drafter=by_member(CAROL), changes=[item]))
    assert refused.value.code == (
        "job_source_unknown" if delivery == "durable" else "change_kind_not_applicable"
    )
