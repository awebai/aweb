"""App-local WebAuthn approvers: designation, enrolment, assertion and recovery.

Every ceremony is real: the software authenticator answers the server's options
with real attestations and assertions, and py_webauthn verifies them.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, replace
from datetime import timedelta

import pytest
import pytest_asyncio

from aweb_naapp.hooks.owner_act_nonces import apply_owner_act_migrations
from aweb_naapp.runtime.approvals import (
    Approval,
    ApprovalRefused,
    ApprovalRevocation,
    Approvals,
    ApprovalState,
    Approver,
    Assurance,
    AuthenticationFailed,
    Decision,
    DeliveryStatus,
    DispatchOutcome,
    PgApprovalStore,
    PresentationKind,
    Purpose,
    Refusal,
)
from aweb_naapp.runtime.passkeys import (
    CONTACT_CHANGE_DELAY_FLOOR,
    MAX_OUTSTANDING_CHALLENGES,
    RECOVERY_COOLING_OFF_FLOOR,
    DesignationRefused,
    EnrolmentRefused,
    LockoutPolicy,
    Notice,
    NoticeKind,
    Passkeys,
    RelyingParty,
)
from tests.runtime.approvals.owner_acts import (
    TeamOwner,
    designation_subject,
    revocation_subject,
    team_owner,
)
from tests.runtime.approvals.soft_authenticator import SoftAuthenticator, b64url
from tests.runtime.approvals.support import SCOPE, AuditOutbox, Clock, Policies, TaskAnswers, policy
from tests.runtime.conftest import did_key

ORIGIN = "https://app.example.com"


def is_owner_scope(scope: str) -> bool:
    """In these tests, approvers designated by an owner's approval live under "approvers."."""
    return not scope.startswith("approvers.")


REQUEST = {"operation": "charge", "destination": {"host": "api.example.com"}, "executor": "broker"}


@dataclass
class Contacts:
    """Each registered contact's inbox: the only place enrolment and approval links arrive."""

    inbox: dict[str, list[str]] = field(default_factory=dict)
    by_approval: dict[str, str] = field(default_factory=dict)
    notices: dict[str, list[Notice]] = field(default_factory=dict)

    async def deliver_notice(self, contact: str, notice: Notice) -> DeliveryStatus:
        self.notices.setdefault(contact, []).append(notice)
        return DeliveryStatus.DELIVERED

    async def deliver_enrolment_link(self, approver: Approver, link_token: str) -> DeliveryStatus:
        self.inbox.setdefault(approver.contact, []).append(link_token)
        return DeliveryStatus.DELIVERED

    async def deliver_approval_link(
        self, approver: Approver, link_token: str, approval: Approval
    ) -> DeliveryStatus:
        self.inbox.setdefault(approver.contact, []).append(link_token)
        self.by_approval[approval.approval_id] = link_token
        return DeliveryStatus.DELIVERED

    def last(self, contact: str) -> str:
        return self.inbox[contact][-1]


class MappedApprovers:
    """The app's directory over B3: each passkey designation the owner linked to
    a team principal carries it, as a task presentation needs."""

    def __init__(self, passkeys: Passkeys) -> None:
        self.passkeys = passkeys
        self.principals: dict[str, str] = {}

    async def candidates(self, policy, request) -> list[Approver]:
        return [
            replace(approver, principal_did=self.principals.get(approver.subject))
            for approver in await self.passkeys.candidates(policy, request)
        ]

    async def is_current(self, scope: str, subject: str) -> bool:
        return await self.passkeys.is_current(scope, subject)


@dataclass
class PasskeyWorld:
    passkeys: Passkeys
    approvals: Approvals
    contacts: Contacts
    audit: AuditOutbox
    clock: Clock
    policies: Policies
    task_answers: TaskAnswers
    owner: TeamOwner
    approvers: MappedApprovers
    designated: set[str] = field(default_factory=set)
    delivered: list[DeliveryStatus] = field(default_factory=list)
    owner_device: SoftAuthenticator | None = None


@pytest_asyncio.fixture
async def pw(test_db_factory, registry) -> PasskeyWorld:
    db = await test_db_factory.create_db(suffix="passkeys", schema="app")
    audit = AuditOutbox(db)
    await audit.create()
    clock = Clock()
    contacts = Contacts()
    store = PgApprovalStore(db)
    await store.migrate()
    passkeys = Passkeys(
        db,
        rp=RelyingParty(origin=ORIGIN, name="Example app"),
        delivery=contacts,
        audit=audit,
        retirement=ApprovalRevocation(store, audit, clock),
        enrolment_ttl=timedelta(hours=1),
        challenge_ttl=timedelta(minutes=5),
        clock=clock,
        owner_scopes=is_owner_scope,
    )
    await passkeys.migrate()
    approvers = MappedApprovers(passkeys)
    policies = Policies(policy())
    task_answers = TaskAnswers()
    approvals = Approvals(
        store=store,
        policies=policies,
        approvers=approvers,
        delivery=contacts,
        authenticators=[passkeys.authenticator()],
        audit=audit,
        task_answers=task_answers,
        clock=clock,
    )
    owner = await team_owner(registry)
    await apply_owner_act_migrations(db)
    return PasskeyWorld(
        passkeys, approvals, contacts, audit, clock, policies, task_answers, owner, approvers
    )


async def designate(pw: PasskeyWorld, contact: str, scope: str = SCOPE, passkeys=None):
    """The owner designates, or after a lockout recovers, the scope's approver."""
    act = "app-credential.recover" if scope in pw.designated else "app-role.designate"
    pw.designated.add(scope)
    return await designate_by_act(pw, act, contact, scope, passkeys=passkeys)


async def designate_by_act(
    pw: PasskeyWorld, act: str, contact: str, scope: str = SCOPE, *, passkeys=None
):
    """Apply one signed owner act: consume it and designate in one transaction,
    then deliver after the commit."""
    passkeys = passkeys or pw.passkeys
    subject = designation_subject(scope, contact)
    prepared = await pw.owner.prepare(act, subject)
    async with passkeys.db.transaction() as tx:
        evidence = await pw.owner.consume(tx, prepared, subject)
        designation = await passkeys.designate(tx, scope=scope, contact=contact, evidence=evidence)
    pw.delivered.append(await passkeys.deliver(designation))
    return designation


async def refusal(awaitable) -> Refusal:
    with pytest.raises(ApprovalRefused) as raised:
        await awaitable
    return raised.value.reason


async def enrol(
    pw: PasskeyWorld, contact="human@example.com"
) -> tuple[Approver, SoftAuthenticator]:
    """Designate (or recover) and enrol; after a recovery, wait out the cooling-off."""
    designation = await designate(pw, contact)
    token = pw.contacts.last(contact)
    device = SoftAuthenticator(ORIGIN)
    credential = device.create(await pw.passkeys.enrolment_options(token))
    approver = await pw.passkeys.complete_enrolment(token, credential)
    if designation.effective_at > pw.clock():
        pw.clock.now = designation.effective_at
    return approver, device


async def mint(pw: PasskeyWorld, request=REQUEST) -> Approval:
    view = await pw.approvals.mint(
        request=request, policy_ref="send-charge", requested_by="agent-1"
    )
    return await pw.approvals.for_request(view.request_id)


async def ceremony(pw, approval, device, decision=Decision.APPROVE, **device_kw) -> dict:
    options = await pw.approvals.challenge(
        approval.approval_id,
        decision,
        Assurance.PASSKEY,
        link_token=pw.contacts.by_approval[approval.approval_id],
    )
    return device.get(dict(options), **device_kw)


async def decide(pw, approval, proof, decision=Decision.APPROVE) -> Approval:
    return await pw.approvals.decide(
        approval.approval_id,
        decision,
        Assurance.PASSKEY,
        proof,
        link_token=pw.contacts.by_approval[approval.approval_id],
    )


# The relying party


def test_the_relying_party_is_the_apps_own_origin():
    rp = RelyingParty(origin="https://app.example.com", name="Example app")
    assert rp.rp_id == "app.example.com"
    assert RelyingParty(origin="http://localhost:8000", name="dev").rp_id == "localhost"


@pytest.mark.parametrize(
    "origin",
    ["http://app.example.com", "https://app.example.com/approve", "app.example.com", "https://"],
)
def test_a_relying_party_needs_a_bare_secure_origin(origin):
    with pytest.raises(ValueError):
        RelyingParty(origin=origin, name="Example app")


# Designation and enrolment


async def test_designation_sends_the_enrolment_link_only_to_the_registered_contact(pw):
    designation = await designate(pw, "human@example.com")
    assert pw.delivered == [DeliveryStatus.DELIVERED]
    assert list(pw.contacts.inbox) == ["human@example.com"]
    assert designation.approver.subject_type == "app_local"
    token = pw.contacts.last("human@example.com")
    assert token not in repr(designation)
    assert token not in repr(await pw.audit.rows())
    assert "approver_designated" in await pw.audit.kinds()


async def test_an_approver_decides_nothing_before_enrolling(pw):
    await designate(pw, "human@example.com")
    assert await pw.passkeys.designated_approver(SCOPE) is None
    assert await refusal(mint(pw)) is Refusal.NO_ELIGIBLE_APPROVER


async def test_enrolment_registers_a_passkey_on_trust_on_first_use(pw):
    approver, _ = await enrol(pw)
    assert await pw.passkeys.designated_approver(SCOPE) == approver
    [enrolled] = [row for row in await pw.audit.rows() if row["kind"] == "approver_enrolled"]
    assert json.loads(enrolled["details"])["trust"] == "trust_on_first_use"
    assert enrolled["subject"] == approver.subject


async def test_an_enrolment_link_is_used_once(pw):
    await designate(pw, "human@example.com")
    token = pw.contacts.last("human@example.com")
    device = SoftAuthenticator(ORIGIN)
    await pw.passkeys.complete_enrolment(
        token, device.create(await pw.passkeys.enrolment_options(token))
    )
    with pytest.raises(EnrolmentRefused):
        await pw.passkeys.enrolment_options(token)


async def test_an_expired_enrolment_link_is_refused(pw):
    await designate(pw, "human@example.com")
    pw.clock.advance(timedelta(hours=1))
    with pytest.raises(EnrolmentRefused):
        await pw.passkeys.enrolment_options(pw.contacts.last("human@example.com"))


@pytest.mark.parametrize(
    "device_kw", [{"origin": "https://evil.example.com"}, {"user_verified": False}]
)
async def test_registration_must_come_from_the_app_origin_with_user_verification(pw, device_kw):
    await designate(pw, "human@example.com")
    token = pw.contacts.last("human@example.com")
    device = SoftAuthenticator(ORIGIN)
    options = await pw.passkeys.enrolment_options(token)
    with pytest.raises(EnrolmentRefused):
        await pw.passkeys.complete_enrolment(token, device.create(options, **device_kw))
    assert await pw.passkeys.designated_approver(SCOPE) is None
    with pytest.raises(EnrolmentRefused):
        await pw.passkeys.complete_enrolment(token, device.create(options))
    fresh = await pw.passkeys.enrolment_options(token)
    await pw.passkeys.complete_enrolment(token, device.create(fresh))


async def test_a_registration_answers_only_its_own_enrolment_challenge(pw):
    await designate(pw, "other@example.com", scope="other-scope")
    other_options = await pw.passkeys.enrolment_options(pw.contacts.last("other@example.com"))
    await designate(pw, "human@example.com")
    token = pw.contacts.last("human@example.com")
    with pytest.raises(EnrolmentRefused):
        await pw.passkeys.complete_enrolment(token, SoftAuthenticator(ORIGIN).create(other_options))


# Deciding with a passkey


async def test_a_passkey_assertion_approves_through_the_link(pw):
    approver, device = await enrol(pw)
    approval = await mint(pw)
    assert pw.contacts.by_approval[approval.approval_id] in pw.contacts.inbox[approver.contact]
    decided = await decide(pw, approval, await ceremony(pw, approval, device))
    assert decided.state is ApprovalState.APPROVED
    assert decided.decided_by.assurance is Assurance.PASSKEY
    evidence = await pw.passkeys.evidence(decided.decided_by.evidence_ref)
    assert evidence.approval_id == approval.approval_id
    assert evidence.request_sha256 == approval.request_sha256
    assert evidence.purpose == Purpose.APPROVE
    assert evidence.subject == approver.subject
    admission = await pw.approvals.admit(approval.approval_id, REQUEST, "op-1")
    assert admission.first and admission.may_send


async def test_an_assertion_for_one_approval_cannot_decide_another(pw):
    _, device = await enrol(pw)
    first, second = await mint(pw), await mint(pw, {**REQUEST, "executor": "runner"})
    proof = await ceremony(pw, first, device)
    assert await refusal(decide(pw, second, proof)) is Refusal.AUTHENTICATION_FAILED
    assert (await pw.approvals.get(second.approval_id)).state is ApprovalState.PENDING


async def test_an_assertion_for_rejecting_cannot_approve(pw):
    _, device = await enrol(pw)
    approval = await mint(pw)
    proof = await ceremony(pw, approval, device, Decision.REJECT)
    assert await refusal(decide(pw, approval, proof, Decision.APPROVE)) is (
        Refusal.AUTHENTICATION_FAILED
    )
    assert (await decide(pw, approval, await ceremony(pw, approval, device))).state is (
        ApprovalState.APPROVED
    )


async def test_an_assertion_is_not_replayable(pw):
    _, device = await enrol(pw)
    approval = await mint(pw)
    proof = await ceremony(pw, approval, device)
    forged = {
        **proof,
        "response": {
            **proof["response"],
            "signature": proof["response"]["signature"][:-4] + "AAAA",
        },
    }
    assert await refusal(decide(pw, approval, forged)) is Refusal.AUTHENTICATION_FAILED
    assert await refusal(decide(pw, approval, proof)) is Refusal.AUTHENTICATION_FAILED


@pytest.mark.parametrize(
    "device_kw", [{"origin": "https://evil.example.com"}, {"user_verified": False}]
)
async def test_an_assertion_must_come_from_the_app_origin_with_user_verification(pw, device_kw):
    _, device = await enrol(pw)
    approval = await mint(pw)
    proof = await ceremony(pw, approval, device, **device_kw)
    assert await refusal(decide(pw, approval, proof)) is Refusal.AUTHENTICATION_FAILED
    assert (await pw.approvals.get(approval.approval_id)).state is ApprovalState.PENDING


async def test_an_unenrolled_authenticator_cannot_decide(pw):
    _, _device = await enrol(pw)
    approval = await mint(pw)
    stranger = SoftAuthenticator(ORIGIN)
    stranger.create(await _foreign_registration_options(pw))
    proof = await ceremony(pw, approval, stranger)
    assert await refusal(decide(pw, approval, proof)) is Refusal.AUTHENTICATION_FAILED


async def _foreign_registration_options(pw) -> dict:
    await designate(pw, "x@example.com", scope="elsewhere")
    return dict(await pw.passkeys.enrolment_options(pw.contacts.last("x@example.com")))


async def test_a_cloned_authenticator_is_detected_by_its_counter(pw):
    _, device = await enrol(pw)
    twin = device.clone()
    first = await mint(pw)
    await decide(pw, first, await ceremony(pw, first, device))
    second = await mint(pw, {**REQUEST, "executor": "runner"})
    assert await refusal(decide(pw, second, await ceremony(pw, second, twin))) is (
        Refusal.AUTHENTICATION_FAILED
    )


async def test_an_expired_challenge_is_refused(pw):
    _, device = await enrol(pw)
    approval = await mint(pw)
    proof = await ceremony(pw, approval, device)
    pw.clock.advance(timedelta(minutes=5))
    assert await refusal(decide(pw, approval, proof)) is Refusal.AUTHENTICATION_FAILED


async def test_a_policy_change_after_the_challenge_invalidates_it(pw):
    _, device = await enrol(pw)
    approval = await mint(pw)
    proof = await ceremony(pw, approval, device)
    pw.policies.set(policy(version=2))
    assert await refusal(decide(pw, approval, proof)) is Refusal.POLICY_CHANGED


# Recovery


async def test_recovery_is_the_owner_redesignating_the_approver(pw):
    old, old_device = await enrol(pw, "human@example.com")
    pending = await mint(pw)
    new, new_device = await enrol(pw, "new-phone@example.com")
    assert new.subject != old.subject
    assert await pw.passkeys.designated_approver(SCOPE) == new
    assert "approver_redesignated" in await pw.audit.kinds()
    assert await refusal(ceremony(pw, pending, old_device)) is Refusal.LINK_UNAVAILABLE
    fresh = await mint(pw, {**REQUEST, "executor": "runner"})
    assert [c.subject for c in fresh.candidates] == [new.subject]
    assert (await decide(pw, fresh, await ceremony(pw, fresh, new_device))).state is (
        ApprovalState.APPROVED
    )


async def test_redesignation_invalidates_the_previous_enrolment_link(pw):
    await designate(pw, "human@example.com")
    stale = pw.contacts.last("human@example.com")
    await designate(pw, "human@example.com")
    with pytest.raises(EnrolmentRefused):
        await pw.passkeys.enrolment_options(stale)


async def test_recovery_revokes_the_retired_approvers_approvals(pw):
    _, old_device = await enrol(pw, "human@example.com")
    approval = await mint(pw)
    await decide(pw, approval, await ceremony(pw, approval, old_device))
    await enrol(pw, "new-phone@example.com")
    assert await refusal(pw.approvals.admit(approval.approval_id, REQUEST, "op-1")) is (
        Refusal.REVOKED
    )
    assert (await pw.approvals.get(approval.approval_id)).state is ApprovalState.REVOKED
    [revoked] = [row for row in await pw.audit.rows() if row["kind"] == "approval_revoked"]
    assert revoked["actor"] == did_key(pw.owner.team_key)
    assert json.loads(revoked["details"])["reason"] == "approver_retired"


# Owner acts


async def test_designation_needs_verified_owner_act_evidence(pw):
    async with pw.passkeys.db.transaction() as tx:
        with pytest.raises(TypeError):
            await pw.passkeys.designate(
                tx, scope=SCOPE, contact="human@example.com", evidence="owner-1"
            )


async def test_an_owner_act_binds_its_scope_and_contact(pw):
    subject = designation_subject(SCOPE, "human@example.com")
    for scope, contact in ((SCOPE, "attacker@example.com"), ("other", "human@example.com")):
        prepared = await pw.owner.prepare("app-role.designate", subject)
        with pytest.raises(DesignationRefused):
            async with pw.passkeys.db.transaction() as tx:
                act = await pw.owner.consume(tx, prepared, subject)
                await pw.passkeys.designate(tx, scope=scope, contact=contact, evidence=act)
    assert pw.contacts.inbox == {}


async def test_an_owner_act_takes_effect_once(pw):
    subject = designation_subject("first", "human@example.com")
    prepared = await pw.owner.prepare("app-role.designate", subject)
    async with pw.passkeys.db.transaction() as tx:
        act = await pw.owner.consume(tx, prepared, subject)
        await pw.passkeys.designate(tx, scope="first", contact="human@example.com", evidence=act)
    with pytest.raises(DesignationRefused):
        async with pw.passkeys.db.transaction() as tx:
            await pw.passkeys.designate(
                tx, scope="first", contact="human@example.com", evidence=act
            )


async def test_an_owner_act_does_not_outlive_its_transaction(pw):
    subject = designation_subject(SCOPE, "human@example.com")
    prepared = await pw.owner.prepare("app-role.designate", subject)

    class Abandoned(Exception):
        pass

    with pytest.raises(Abandoned):
        async with pw.passkeys.db.transaction() as tx:
            act = await pw.owner.consume(tx, prepared, subject)
            raise Abandoned
    with pytest.raises(DesignationRefused):
        async with pw.passkeys.db.transaction() as tx:
            await pw.passkeys.designate(tx, scope=SCOPE, contact="human@example.com", evidence=act)
    assert await pw.passkeys.designated_approver(SCOPE) is None


async def test_a_recovery_act_replaces_the_approver_once(pw):
    await designate(pw, "human@example.com")
    subject = designation_subject(SCOPE, "new-phone@example.com")
    prepared = await pw.owner.prepare("app-credential.recover", subject)
    async with pw.passkeys.db.transaction() as tx:
        act = await pw.owner.consume(tx, prepared, subject)
        await pw.passkeys.designate(tx, scope=SCOPE, contact="new-phone@example.com", evidence=act)
    with pytest.raises(DesignationRefused):
        async with pw.passkeys.db.transaction() as tx:
            await pw.passkeys.designate(
                tx, scope=SCOPE, contact="new-phone@example.com", evidence=act
            )


async def test_the_first_approver_is_designated_and_a_replacement_is_a_recovery(pw):
    with pytest.raises(DesignationRefused):
        await designate_by_act(pw, "app-credential.recover", "human@example.com")
    await designate_by_act(pw, "app-role.designate", "human@example.com")
    with pytest.raises(DesignationRefused):
        await designate_by_act(pw, "app-role.designate", "new@example.com")


async def test_a_revocation_act_designates_nothing(pw):
    subject = {**designation_subject(SCOPE, "human@example.com")}
    del subject["contact_sha256"]
    subject["subject_ref"] = "approver-1"
    prepared = await pw.owner.prepare("app-role.revoke", subject)
    with pytest.raises(DesignationRefused):
        async with pw.passkeys.db.transaction() as tx:
            act = await pw.owner.consume(tx, prepared, subject)
            await pw.passkeys.designate(tx, scope=SCOPE, contact="human@example.com", evidence=act)


async def test_a_designation_rolled_back_with_its_transaction_leaves_nothing(pw):
    subject = designation_subject(SCOPE, "human@example.com")
    prepared = await pw.owner.prepare("app-role.designate", subject)

    class Abandoned(Exception):
        pass

    with pytest.raises(Abandoned):
        async with pw.passkeys.db.transaction() as tx:
            act = await pw.owner.consume(tx, prepared, subject)
            await pw.passkeys.designate(tx, scope=SCOPE, contact="human@example.com", evidence=act)
            raise Abandoned
    assert pw.contacts.inbox == {}
    assert await pw.passkeys.designated_approver(SCOPE) is None
    # The act's nonce rolled back with it, so the owner can apply the same act again.
    async with pw.passkeys.db.transaction() as tx:
        act = await pw.owner.consume(tx, prepared, subject)
        designation = await pw.passkeys.designate(
            tx, scope=SCOPE, contact="human@example.com", evidence=act
        )
    assert await pw.passkeys.deliver(designation) is DeliveryStatus.DELIVERED


async def test_nothing_is_delivered_before_the_caller_delivers(pw):
    subject = designation_subject(SCOPE, "human@example.com")
    prepared = await pw.owner.prepare("app-role.designate", subject)
    async with pw.passkeys.db.transaction() as tx:
        act = await pw.owner.consume(tx, prepared, subject)
        designation = await pw.passkeys.designate(
            tx, scope=SCOPE, contact="human@example.com", evidence=act
        )
    assert pw.contacts.inbox == {}
    await pw.passkeys.deliver(designation)
    assert list(pw.contacts.inbox) == ["human@example.com"]


async def test_a_lost_enrolment_link_is_reissued_to_the_same_contact(pw):
    subject = designation_subject(SCOPE, "human@example.com")
    prepared = await pw.owner.prepare("app-role.designate", subject)
    async with pw.passkeys.db.transaction() as tx:
        act = await pw.owner.consume(tx, prepared, subject)
        lost = await pw.passkeys.designate(
            tx, scope=SCOPE, contact="human@example.com", evidence=act
        )
    async with pw.passkeys.db.transaction() as tx:
        reissued = await pw.passkeys.reissue_enrolment(tx, scope=SCOPE)
    assert "approver_enrolment_reissued" in await pw.audit.kinds()
    await pw.passkeys.deliver(reissued)
    token = pw.contacts.last("human@example.com")
    device = SoftAuthenticator(ORIGIN)
    await pw.passkeys.complete_enrolment(
        token, device.create(await pw.passkeys.enrolment_options(token))
    )
    # The lost link was revoked when the new one was issued.
    await pw.passkeys.deliver(lost)
    with pytest.raises(EnrolmentRefused):
        await pw.passkeys.enrolment_options(pw.contacts.last("human@example.com"))


async def test_an_enrolled_approver_gets_no_reissued_link(pw):
    await enrol(pw, "human@example.com")
    with pytest.raises(EnrolmentRefused):
        async with pw.passkeys.db.transaction() as tx:
            await pw.passkeys.reissue_enrolment(tx, scope=SCOPE)


async def test_a_reissue_during_recovery_tells_the_prior_contacts_again(pw):
    await enrol(pw, "human@example.com")
    await designate(pw, "new-phone@example.com")
    before = len(pw.contacts.notices["human@example.com"])
    async with pw.passkeys.db.transaction() as tx:
        reissued = await pw.passkeys.reissue_enrolment(tx, scope=SCOPE)
    await pw.passkeys.deliver(reissued)
    assert len(pw.contacts.notices["human@example.com"]) == before + 1


# Retirement


async def retire(pw: PasskeyWorld, holder: str, scope: str = SCOPE):
    """The owner revokes `holder`'s role: consume the act and retire in one
    transaction. The scope's next designation is a first one."""
    subject = revocation_subject(scope, holder)
    prepared = await pw.owner.prepare("app-role.revoke", subject)
    async with pw.passkeys.db.transaction() as tx:
        act = await pw.owner.consume(tx, prepared, subject)
        await pw.passkeys.retire(tx, scope=scope, evidence=act)
    pw.designated.discard(scope)
    return act


async def test_retiring_ends_the_designation_and_its_passkey(pw):
    approver, device = await enrol(pw, "human@example.com")
    await retire(pw, approver.subject)
    assert await pw.passkeys.designated_approver(SCOPE) is None
    assert not await pw.passkeys.is_current(SCOPE, approver.subject)
    assert await refusal(mint(pw)) is Refusal.NO_ELIGIBLE_APPROVER
    with pytest.raises(AuthenticationFailed):
        await login(pw, device)
    [retired] = [row for row in await pw.audit.rows() if row["kind"] == "approver_retired"]
    assert retired["subject"] == approver.subject
    assert retired["actor"] == did_key(pw.owner.team_key)


async def test_retiring_voids_the_approvers_live_approvals(pw):
    approver, device = await enrol(pw, "human@example.com")
    approved = await mint(pw)
    await decide(pw, approved, await ceremony(pw, approved, device))
    pending = await mint(pw, {**REQUEST, "executor": "runner"})
    await retire(pw, approver.subject)
    assert await refusal(pw.approvals.admit(approved.approval_id, REQUEST, "op-1")) is (
        Refusal.REVOKED
    )
    assert (await pw.approvals.get(pending.approval_id)).state is ApprovalState.PENDING
    assert await refusal(pw.approvals.open_link(pw.contacts.by_approval[pending.approval_id])) is (
        Refusal.LINK_UNAVAILABLE
    )


async def test_a_re_granted_owner_enrols_again_and_the_old_passkey_stays_dead(pw):
    old, old_device = await enrol(pw, "human@example.com")
    await retire(pw, old.subject)
    designation = await designate(pw, "human@example.com")
    assert designation.effective_at == pw.clock()
    assert await pw.passkeys.designated_approver(SCOPE) is None
    with pytest.raises(AuthenticationFailed):
        await pw.passkeys.login_options(SCOPE)
    token = pw.contacts.last("human@example.com")
    new_device = SoftAuthenticator(ORIGIN)
    await pw.passkeys.complete_enrolment(
        token, new_device.create(await pw.passkeys.enrolment_options(token))
    )
    approval = await mint(pw)
    assert await refusal(decide(pw, approval, await ceremony(pw, approval, old_device))) is (
        Refusal.AUTHENTICATION_FAILED
    )
    with pytest.raises(AuthenticationFailed):
        await login(pw, old_device)
    assert (await decide(pw, approval, await ceremony(pw, approval, new_device))).state is (
        ApprovalState.APPROVED
    )


async def test_retiring_during_a_recovery_ends_the_pending_approver_too(pw):
    await enrol(pw, "human@example.com")
    pending = await designate(pw, "new-phone@example.com")
    token = pw.contacts.last("new-phone@example.com")
    await retire(pw, pending.approver.subject)
    assert await pw.passkeys.recovery_pending_until(SCOPE) is None
    with pytest.raises(EnrolmentRefused):
        await pw.passkeys.enrolment_options(token)
    pw.clock.now = pending.effective_at
    assert await pw.passkeys.designated_approver(SCOPE) is None


async def test_retiring_needs_a_revocation_act_for_its_scope_in_its_transaction(pw):
    approver, _ = await enrol(pw, "human@example.com")
    designating = designation_subject(SCOPE, "other@example.com")
    prepared = await pw.owner.prepare("app-credential.recover", designating)
    with pytest.raises(DesignationRefused):
        async with pw.passkeys.db.transaction() as tx:
            act = await pw.owner.consume(tx, prepared, designating)
            await pw.passkeys.retire(tx, scope=SCOPE, evidence=act)
    elsewhere = revocation_subject("other-scope", approver.subject)
    prepared = await pw.owner.prepare("app-role.revoke", elsewhere)
    with pytest.raises(DesignationRefused):
        async with pw.passkeys.db.transaction() as tx:
            act = await pw.owner.consume(tx, prepared, elsewhere)
            await pw.passkeys.retire(tx, scope=SCOPE, evidence=act)
    revoking = revocation_subject(SCOPE, approver.subject)
    prepared = await pw.owner.prepare("app-role.revoke", revoking)
    async with pw.passkeys.db.transaction() as tx:
        stale = await pw.owner.consume(tx, prepared, revoking)
    with pytest.raises(DesignationRefused):
        async with pw.passkeys.db.transaction() as tx:
            await pw.passkeys.retire(tx, scope=SCOPE, evidence=stale)
    async with pw.passkeys.db.transaction() as tx:
        with pytest.raises(TypeError):
            await pw.passkeys.retire(tx, scope=SCOPE, evidence="owner-1")
    assert await pw.passkeys.designated_approver(SCOPE) is not None


async def test_a_revocation_act_takes_effect_once(pw):
    approver, _ = await enrol(pw, "human@example.com")
    revoking = revocation_subject(SCOPE, approver.subject)
    designating = designation_subject(SCOPE, "human@example.com")
    revoke = await pw.owner.prepare("app-role.revoke", revoking)
    regrant = await pw.owner.prepare("app-role.designate", designating)
    async with pw.passkeys.db.transaction() as tx:
        act = await pw.owner.consume(tx, revoke, revoking)
        await pw.passkeys.retire(tx, scope=SCOPE, evidence=act)
        designation = await pw.passkeys.designate(
            tx,
            scope=SCOPE,
            contact="human@example.com",
            evidence=await pw.owner.consume(tx, regrant, designating),
        )
        with pytest.raises(DesignationRefused):
            await pw.passkeys.retire(tx, scope=SCOPE, evidence=act)
    assert await pw.passkeys.is_current(SCOPE, designation.approver.subject)


async def test_retiring_a_scope_without_an_approver_is_refused(pw):
    with pytest.raises(DesignationRefused):
        await retire(pw, "approver-1")


async def test_a_revocation_act_retires_only_the_approver_it_names(pw):
    named, _ = await enrol(pw, "human@example.com")
    revoking = revocation_subject(SCOPE, named.subject)
    prepared = await pw.owner.prepare("app-role.revoke", revoking)
    successor = await designate(pw, "new-phone@example.com")
    with pytest.raises(DesignationRefused):
        async with pw.passkeys.db.transaction() as tx:
            act = await pw.owner.consume(tx, prepared, revoking)
            await pw.passkeys.retire(tx, scope=SCOPE, evidence=act)
    assert await pw.passkeys.recovery_pending_until(SCOPE) == successor.effective_at
    pw.clock.now = successor.effective_at
    assert await pw.passkeys.is_current(SCOPE, successor.approver.subject)


async def test_a_retirement_rolled_back_with_its_transaction_leaves_the_approver(pw):
    approver, device = await enrol(pw, "human@example.com")
    approval = await mint(pw)
    subject = revocation_subject(SCOPE, approver.subject)
    prepared = await pw.owner.prepare("app-role.revoke", subject)

    class Abandoned(Exception):
        pass

    with pytest.raises(Abandoned):
        async with pw.passkeys.db.transaction() as tx:
            act = await pw.owner.consume(tx, prepared, subject)
            await pw.passkeys.retire(tx, scope=SCOPE, evidence=act)
            raise Abandoned
    assert await pw.passkeys.designated_approver(SCOPE) == approver
    assert (await decide(pw, approval, await ceremony(pw, approval, device))).state is (
        ApprovalState.APPROVED
    )


# Lockout protections


async def test_recovery_freezes_approvals_for_the_cooling_off_and_tells_prior_contacts(pw):
    await enrol(pw, "human@example.com")
    started = pw.clock()
    designation = await designate(pw, "new-phone@example.com")
    assert designation.effective_at == started + timedelta(hours=72)
    assert await pw.passkeys.recovery_pending_until(SCOPE) == designation.effective_at
    assert pw.contacts.notices["human@example.com"] == [
        Notice(NoticeKind.RECOVERY_STARTED, SCOPE, designation.effective_at)
    ]
    assert "new-phone@example.com" not in pw.contacts.notices
    token = pw.contacts.last("new-phone@example.com")
    device = SoftAuthenticator(ORIGIN)
    await pw.passkeys.complete_enrolment(
        token, device.create(await pw.passkeys.enrolment_options(token))
    )
    pw.clock.advance(timedelta(hours=71))
    assert await pw.passkeys.designated_approver(SCOPE) is None
    assert await refusal(mint(pw)) is Refusal.NO_ELIGIBLE_APPROVER
    pw.clock.advance(timedelta(hours=1))
    assert await pw.passkeys.recovery_pending_until(SCOPE) is None
    approval = await mint(pw)
    assert (await decide(pw, approval, await ceremony(pw, approval, device))).state is (
        ApprovalState.APPROVED
    )


def passkeys_with(pw, **lockout):
    store = PgApprovalStore(pw.passkeys.db)
    return Passkeys(
        pw.passkeys.db,
        rp=pw.passkeys.rp,
        delivery=pw.contacts,
        audit=pw.audit,
        retirement=ApprovalRevocation(store, pw.audit, pw.clock),
        enrolment_ttl=timedelta(hours=1),
        challenge_ttl=timedelta(minutes=5),
        clock=pw.clock,
        **lockout,
    )


@pytest.mark.parametrize(
    "durations",
    [
        {"recovery_cooling_off": timedelta(0)},
        {"recovery_cooling_off": timedelta(hours=71, minutes=59)},
        {"contact_change_delay": timedelta(0)},
        {"contact_change_delay": timedelta(hours=23)},
    ],
)
def test_lockout_durations_below_the_floor_are_refused(durations):
    with pytest.raises(ValueError):
        LockoutPolicy(**durations)


def test_lockout_durations_at_or_above_the_floor_are_accepted():
    assert (
        LockoutPolicy(
            recovery_cooling_off=RECOVERY_COOLING_OFF_FLOOR,
            contact_change_delay=CONTACT_CHANGE_DELAY_FLOOR,
        )
        == LockoutPolicy()
    )
    longer = LockoutPolicy(
        recovery_cooling_off=timedelta(hours=96), contact_change_delay=timedelta(hours=48)
    )
    assert longer.recovery_cooling_off == timedelta(hours=96)


async def test_an_app_may_lengthen_the_cooling_off(pw):
    longer = passkeys_with(pw, lockout=LockoutPolicy(recovery_cooling_off=timedelta(hours=96)))
    await designate(pw, "a@example.com", scope="long", passkeys=longer)
    designation = await designate(pw, "b@example.com", scope="long", passkeys=longer)
    assert designation.effective_at == pw.clock() + timedelta(hours=96)


def test_deploy_configuration_may_raise_the_floor_and_apps_must_meet_it(pw):
    raised = LockoutPolicy(recovery_cooling_off=timedelta(hours=120))
    with pytest.raises(ValueError):
        passkeys_with(
            pw,
            lockout_floor=raised,
            lockout=LockoutPolicy(recovery_cooling_off=timedelta(hours=96)),
        )
    passkeys_with(
        pw,
        lockout_floor=raised,
        lockout=LockoutPolicy(recovery_cooling_off=timedelta(hours=120)),
    )


async def change_contact(pw, device, new_contact: str):
    options = await pw.passkeys.contact_change_options(SCOPE, new_contact)
    return await pw.passkeys.change_contact(SCOPE, new_contact, device.get(dict(options)))


async def test_a_contact_change_needs_the_approvers_passkey_and_waits_a_day(pw):
    approver, device = await enrol(pw, "human@example.com")
    effective_at = await change_contact(pw, device, "new@example.com")
    assert effective_at == pw.clock() + timedelta(hours=24)
    notice = Notice(NoticeKind.CONTACT_CHANGE_SCHEDULED, SCOPE, effective_at)
    assert pw.contacts.notices["human@example.com"] == [notice]
    assert pw.contacts.notices["new@example.com"] == [notice]
    assert (await pw.passkeys.designated_approver(SCOPE)).contact == "human@example.com"
    pw.clock.advance(timedelta(hours=24))
    assert (await pw.passkeys.designated_approver(SCOPE)).contact == "new@example.com"
    approval = await mint(pw)
    assert pw.contacts.by_approval[approval.approval_id] in pw.contacts.inbox["new@example.com"]
    assert "approver_contact_change_scheduled" in await pw.audit.kinds()


async def test_a_contact_change_proof_names_its_new_contact(pw):
    _, device = await enrol(pw, "human@example.com")
    options = await pw.passkeys.contact_change_options(SCOPE, "new@example.com")
    with pytest.raises(AuthenticationFailed):
        await pw.passkeys.change_contact(SCOPE, "attacker@example.com", device.get(dict(options)))
    stranger = SoftAuthenticator(ORIGIN)
    stranger.create(await _foreign_registration_options(pw))
    options = await pw.passkeys.contact_change_options(SCOPE, "new@example.com")
    with pytest.raises(AuthenticationFailed):
        await pw.passkeys.change_contact(SCOPE, "new@example.com", stranger.get(dict(options)))
    assert (await pw.passkeys.designated_approver(SCOPE)).contact == "human@example.com"


# Viewing and task answers with a passkey


async def test_the_request_is_shown_after_a_passkey_view_that_consumes_nothing(pw):
    _, device = await enrol(pw)
    approval = await mint(pw)
    token = pw.contacts.by_approval[approval.approval_id]
    assert (await pw.approvals.open_link(token)).request is None
    options = await pw.approvals.view_challenge(
        approval.approval_id, Assurance.PASSKEY, link_token=token
    )
    viewed = await pw.approvals.view(
        approval.approval_id, Assurance.PASSKEY, device.get(dict(options)), link_token=token
    )
    assert viewed.request == REQUEST
    assert (await decide(pw, approval, await ceremony(pw, approval, device))).state is (
        ApprovalState.APPROVED
    )


async def test_a_passkey_task_decision_needs_its_task_answer_verified(pw):
    approver, device = await enrol(pw)
    pw.approvers.principals[approver.subject] = "did:aw:human"
    view = await pw.approvals.mint(
        request=REQUEST,
        policy_ref="send-charge",
        requested_by="agent-1",
        presentation=PresentationKind.TASK,
        presentation_ref="task-1",
    )
    approval = await pw.approvals.for_request(view.request_id)

    async def task_ceremony():
        options = await pw.approvals.challenge(
            approval.approval_id,
            Decision.APPROVE,
            Assurance.PASSKEY,
            task_answer_ref="answer-1",
            subject=approver.subject,
        )
        return device.get(dict(options))

    async def task_decide(proof):
        return await pw.approvals.decide(
            approval.approval_id,
            Decision.APPROVE,
            Assurance.PASSKEY,
            proof,
            task_answer_ref="answer-1",
            subject=approver.subject,
        )

    assert await refusal(task_decide(await task_ceremony())) is Refusal.TASK_ANSWER_UNVERIFIED
    assert (await pw.approvals.get(approval.approval_id)).state is ApprovalState.PENDING
    pw.task_answers.record("answer-1", approval, Decision.APPROVE, "did:aw:someone-else")
    assert await refusal(task_decide(await task_ceremony())) is Refusal.TASK_ANSWER_UNVERIFIED
    pw.task_answers.record("answer-1", approval, Decision.APPROVE, "did:aw:human")
    decided = await task_decide(await task_ceremony())
    assert decided.state is ApprovalState.APPROVED
    assert (await pw.passkeys.evidence(decided.decided_by.evidence_ref)).task_answer_ref == (
        "answer-1"
    )


# Login


async def login(pw, device, scope=SCOPE, **device_kw):
    options = await pw.passkeys.login_options(scope)
    return await pw.passkeys.verify_login(scope, device.get(dict(options), **device_kw))


async def test_the_in_effect_approver_logs_in_with_its_passkey(pw):
    approver, device = await enrol(pw)
    session = await login(pw, device)
    assert (session.subject, session.contact) == (approver.subject, approver.contact)
    assert (await pw.passkeys.evidence(session.evidence_ref)).purpose == "login"
    [logged_in] = [row for row in await pw.audit.rows() if row["kind"] == "approver_logged_in"]
    assert logged_in["subject"] == approver.subject
    assert json.loads(logged_in["details"])["evidence_ref"] == session.evidence_ref


async def test_a_role_style_scope_logs_in_its_own_designee(pw):
    await designate(pw, "owner@example.com", scope="secrets.owner")
    token = pw.contacts.last("owner@example.com")
    device = SoftAuthenticator(ORIGIN)
    await pw.passkeys.complete_enrolment(
        token, device.create(await pw.passkeys.enrolment_options(token))
    )
    assert (await login(pw, device, scope="secrets.owner")).contact == "owner@example.com"
    with pytest.raises(AuthenticationFailed):
        await pw.passkeys.login_options(SCOPE)


async def test_login_needs_an_enrolled_in_effect_approver(pw):
    await designate(pw, "human@example.com")
    with pytest.raises(AuthenticationFailed):
        await pw.passkeys.login_options(SCOPE)


async def test_nobody_logs_in_during_a_recovery_cooling_off(pw):
    _, old_device = await enrol(pw, "human@example.com")
    await designate(pw, "new-phone@example.com")
    with pytest.raises(AuthenticationFailed):
        await pw.passkeys.login_options(SCOPE)


@pytest.mark.parametrize(
    "device_kw", [{"origin": "https://evil.example.com"}, {"user_verified": False}]
)
async def test_login_must_come_from_the_app_origin_with_user_verification(pw, device_kw):
    _, device = await enrol(pw)
    with pytest.raises(AuthenticationFailed):
        await login(pw, device, **device_kw)
    assert "approver_logged_in" not in await pw.audit.kinds()


async def test_a_login_assertion_is_single_use_and_counted(pw):
    _, device = await enrol(pw)
    twin = device.clone()
    options = await pw.passkeys.login_options(SCOPE)
    proof = device.get(dict(options))
    await pw.passkeys.verify_login(SCOPE, proof)
    with pytest.raises(AuthenticationFailed):
        await pw.passkeys.verify_login(SCOPE, proof)
    with pytest.raises(AuthenticationFailed):
        await login(pw, twin)


async def test_a_stranger_cannot_log_in(pw):
    await enrol(pw)
    stranger = SoftAuthenticator(ORIGIN)
    stranger.create(await _foreign_registration_options(pw))
    with pytest.raises(AuthenticationFailed):
        await login(pw, stranger)


async def test_a_login_proof_cannot_decide_an_approval(pw):
    _, device = await enrol(pw)
    approval = await mint(pw)
    proof = device.get(dict(await pw.passkeys.login_options(SCOPE)))
    assert await refusal(decide(pw, approval, proof)) is Refusal.AUTHENTICATION_FAILED
    assert (await pw.approvals.get(approval.approval_id)).state is ApprovalState.PENDING


async def test_a_login_answers_only_a_challenge_the_server_issued(pw):
    _, device = await enrol(pw)
    options = dict(await pw.passkeys.login_options(SCOPE))
    options["challenge"] = b64url(os.urandom(32))
    with pytest.raises(AuthenticationFailed):
        await pw.passkeys.verify_login(SCOPE, device.get(options))


async def test_an_approval_assertion_cannot_log_in(pw):
    _, device = await enrol(pw)
    approval = await mint(pw)
    proof = await ceremony(pw, approval, device)
    with pytest.raises(AuthenticationFailed):
        await pw.passkeys.verify_login(SCOPE, proof)


async def outstanding_challenges(pw, purpose: str) -> int:
    return await pw.passkeys.db.fetch_value(
        "SELECT COUNT(*) FROM {{tables.passkey_challenges}} WHERE purpose = $1", purpose
    )


async def test_unauthenticated_login_requests_cannot_grow_the_challenge_store(pw):
    _, device = await enrol(pw)
    for _ in range(MAX_OUTSTANDING_CHALLENGES * 3):
        await pw.passkeys.login_options(SCOPE)
    assert await outstanding_challenges(pw, "login") == MAX_OUTSTANDING_CHALLENGES
    assert (await login(pw, device)).subject


async def test_an_evicted_challenge_is_refused_and_the_newest_still_works(pw):
    _, device = await enrol(pw)
    oldest = dict(await pw.passkeys.login_options(SCOPE))
    for _ in range(MAX_OUTSTANDING_CHALLENGES):
        await pw.passkeys.login_options(SCOPE)
    with pytest.raises(AuthenticationFailed):
        await pw.passkeys.verify_login(SCOPE, device.get(oldest))
    assert (await login(pw, device)).subject


async def test_expired_challenges_are_removed_when_new_ones_are_issued(pw):
    await enrol(pw)
    await pw.passkeys.login_options(SCOPE)
    pw.clock.advance(timedelta(minutes=5))
    await pw.passkeys.login_options(SCOPE)
    assert await outstanding_challenges(pw, "login") == 1


# Owner approvals: an owner's decided approval designates a non-owner approver


async def decided_by_owner(pw, request=REQUEST, device=None) -> Approval:
    if device is None:
        _, device = await enrol(pw, "owner@example.com")
        pw.owner_device = device
    approval = await mint(pw, request=request)
    await decide(pw, approval, await ceremony(pw, approval, device))
    return approval


async def designate_by_approval(
    pw, approval, scopes, operation_id="designate-1", passkeys=None, request=REQUEST
):
    passkeys = passkeys or pw.passkeys
    async with passkeys.db.transaction() as tx:
        evidence = await passkeys.owner_approval(
            tx,
            pw.approvals,
            approval_id=approval.approval_id,
            request=request,
            operation_id=operation_id,
        )
        designations = [
            await passkeys.designate(tx, scope=scope, contact=contact, evidence=evidence)
            for scope, contact in scopes
        ]
    for designation in designations:
        await passkeys.deliver(designation)
    return designations


async def test_an_owner_approval_designates_non_owner_approvers(pw):
    approval = await decided_by_owner(pw)
    await designate_by_approval(
        pw,
        approval,
        [("approvers.finance", "finance@example.com"), ("approvers.ops", "ops@example.com")],
    )
    for scope, contact in (
        ("approvers.finance", "finance@example.com"),
        ("approvers.ops", "ops@example.com"),
    ):
        token = pw.contacts.last(contact)
        device = SoftAuthenticator(ORIGIN)
        await pw.passkeys.complete_enrolment(
            token, device.create(await pw.passkeys.enrolment_options(token))
        )
        assert (await pw.passkeys.designated_approver(scope)) is not None


async def test_an_owner_approval_completes_its_admitted_dispatch(pw):
    approval = await decided_by_owner(pw)
    await designate_by_approval(pw, approval, [("approvers.finance", "finance@example.com")])
    after = await pw.approvals.get(approval.approval_id)
    assert after.state is ApprovalState.CONSUMED
    assert after.dispatch_outcome is DispatchOutcome.COMPLETED


async def test_an_owner_approval_is_used_once(pw):
    approval = await decided_by_owner(pw)
    await designate_by_approval(pw, approval, [("approvers.finance", "finance@example.com")])
    with pytest.raises(DesignationRefused):
        await designate_by_approval(pw, approval, [("approvers.ops", "ops@example.com")])


async def test_an_owner_approval_does_not_outlive_its_transaction(pw):
    approval = await decided_by_owner(pw)
    async with pw.passkeys.db.transaction() as tx:
        evidence = await pw.passkeys.owner_approval(
            tx,
            pw.approvals,
            approval_id=approval.approval_id,
            request=REQUEST,
            operation_id="designate-1",
        )
    with pytest.raises(DesignationRefused):
        async with pw.passkeys.db.transaction() as tx:
            await pw.passkeys.designate(
                tx, scope="approvers.finance", contact="finance@example.com", evidence=evidence
            )


async def test_an_owner_scope_needs_an_owner_act_not_an_approval(pw):
    approval = await decided_by_owner(pw)
    with pytest.raises(DesignationRefused):
        await designate_by_approval(pw, approval, [("secrets.owner", "next-owner@example.com")])
    assert pw.contacts.inbox.get("next-owner@example.com") is None


async def test_an_owner_approval_designates_only_a_first_approver(pw):
    first = await decided_by_owner(pw)
    await designate_by_approval(pw, first, [("approvers.finance", "finance@example.com")])
    second = await decided_by_owner(pw, request={**REQUEST, "attempt": 2}, device=pw.owner_device)
    with pytest.raises(DesignationRefused):
        await designate_by_approval(
            pw,
            second,
            [("approvers.finance", "other@example.com")],
            operation_id="designate-2",
            request={**REQUEST, "attempt": 2},
        )


async def test_only_an_owner_scopes_approval_is_owner_evidence(pw):
    approval = await decided_by_owner(pw)
    nobody_owns = passkeys_with(pw, owner_scopes=lambda scope: False)
    with pytest.raises(DesignationRefused):
        await designate_by_approval(
            pw, approval, [("approvers.finance", "finance@example.com")], passkeys=nobody_owns
        )


async def test_by_default_every_scope_is_an_owner_scope(pw):
    approval = await decided_by_owner(pw)
    by_default = passkeys_with(pw)
    with pytest.raises(DesignationRefused):
        await designate_by_approval(
            pw, approval, [("approvers.finance", "finance@example.com")], passkeys=by_default
        )


async def test_an_approval_decided_by_a_non_owner_is_no_owner_evidence(pw):
    approval = await decided_by_owner(pw)
    await designate_by_approval(pw, approval, [("approvers.finance", "finance@example.com")])
    token = pw.contacts.last("finance@example.com")
    finance_device = SoftAuthenticator(ORIGIN)
    await pw.passkeys.complete_enrolment(
        token, finance_device.create(await pw.passkeys.enrolment_options(token))
    )
    pw.policies.set(policy(approver_scopes=("approvers.finance",)))
    request = {**REQUEST, "attempt": 2}
    by_finance = await mint(pw, request=request)
    await decide(pw, by_finance, await ceremony(pw, by_finance, finance_device))
    with pytest.raises(DesignationRefused):
        await designate_by_approval(
            pw,
            by_finance,
            [("approvers.ops", "ops@example.com")],
            operation_id="designate-2",
            request=request,
        )
    assert pw.contacts.inbox.get("ops@example.com") is None
