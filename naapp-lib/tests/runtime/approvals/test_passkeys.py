"""App-local WebAuthn approvers: designation, enrolment, assertion and recovery.

Every ceremony is real: the software authenticator answers the server's options
with real attestations and assertions, and py_webauthn verifies them.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import timedelta

import pytest
import pytest_asyncio

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
    PgApprovalStore,
    PresentationKind,
    Purpose,
    Refusal,
)
from aweb_naapp.runtime.passkeys import (
    DesignationRefused,
    EnrolmentRefused,
    Notice,
    NoticeKind,
    OwnerActKind,
    Passkeys,
    RelyingParty,
    contact_sha256,
)
from tests.runtime.approvals.soft_authenticator import SoftAuthenticator
from tests.runtime.approvals.support import SCOPE, AuditOutbox, Clock, Policies, TaskAnswers, policy

ORIGIN = "https://app.example.com"
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


@dataclass(frozen=True)
class OwnerAct:
    """Stands in for what the owner-act verifier returns for a verified
    `aweb.owner-act/1`; that verifier is built separately."""

    act_id: str
    kind: OwnerActKind
    signer: str
    scope: str
    contact_sha256: str


def owner_act(kind: OwnerActKind, contact: str, scope: str = SCOPE, act_id: str | None = None):
    import uuid

    return OwnerAct(
        act_id=act_id or str(uuid.uuid4()),
        kind=kind,
        signer="did:key:team-owner",
        scope=scope,
        contact_sha256=contact_sha256(contact),
    )


@dataclass
class PasskeyWorld:
    passkeys: Passkeys
    approvals: Approvals
    contacts: Contacts
    audit: AuditOutbox
    clock: Clock
    policies: Policies
    task_answers: TaskAnswers
    designated: set[str] = field(default_factory=set)


@pytest_asyncio.fixture
async def pw(test_db_factory) -> PasskeyWorld:
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
    )
    await passkeys.migrate()
    policies = Policies(policy())
    task_answers = TaskAnswers()
    approvals = Approvals(
        store=store,
        policies=policies,
        approvers=passkeys,
        delivery=contacts,
        authenticators=[passkeys.authenticator()],
        audit=audit,
        task_answers=task_answers,
        clock=clock,
    )
    return PasskeyWorld(passkeys, approvals, contacts, audit, clock, policies, task_answers)


async def designate(pw: PasskeyWorld, contact: str, scope: str = SCOPE):
    """The owner designates, or after a lockout recovers, the scope's approver."""
    kind = OwnerActKind.RECOVER if scope in pw.designated else OwnerActKind.DESIGNATE
    pw.designated.add(scope)
    return await pw.passkeys.designate(
        scope=scope, contact=contact, owner_act=owner_act(kind, contact, scope)
    )


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
    assert designation.delivery_status is DeliveryStatus.DELIVERED
    assert list(pw.contacts.inbox) == ["human@example.com"]
    assert designation.approver.subject_type == "app_local"
    token = pw.contacts.last("human@example.com")
    assert token not in repr(designation)
    assert token not in repr(await pw.audit.rows())
    assert "approver_designated" in await pw.audit.kinds()


async def test_an_approver_decides_nothing_before_enrolling(pw):
    await designate(pw, "human@example.com")
    assert await pw.passkeys.designated_approver(policy()) is None
    assert await refusal(mint(pw)) is Refusal.NO_APPROVER


async def test_enrolment_registers_a_passkey_on_trust_on_first_use(pw):
    approver, _ = await enrol(pw)
    assert await pw.passkeys.designated_approver(policy()) == approver
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
    assert await pw.passkeys.designated_approver(policy()) is None
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
    assert decided.authenticator is Assurance.PASSKEY
    evidence = await pw.passkeys.evidence(decided.auth_evidence_ref)
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
    assert await pw.passkeys.designated_approver(policy()) == new
    assert "approver_redesignated" in await pw.audit.kinds()
    assert await refusal(ceremony(pw, pending, old_device)) is Refusal.REVOKED
    fresh = await mint(pw, {**REQUEST, "executor": "runner"})
    assert fresh.approver_subject == new.subject
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
    assert revoked["actor"] == "did:key:team-owner"
    assert json.loads(revoked["details"])["reason"] == "approver_retired"


# Owner acts


async def test_designation_needs_verified_owner_act_evidence(pw):
    with pytest.raises(TypeError):
        await pw.passkeys.designate(scope=SCOPE, contact="human@example.com", owner_act="owner-1")


async def test_an_owner_act_binds_its_scope_and_contact(pw):
    act = owner_act(OwnerActKind.DESIGNATE, "human@example.com")
    with pytest.raises(DesignationRefused):
        await pw.passkeys.designate(scope=SCOPE, contact="attacker@example.com", owner_act=act)
    with pytest.raises(DesignationRefused):
        await pw.passkeys.designate(scope="other", contact="human@example.com", owner_act=act)
    assert pw.contacts.inbox == {}


async def test_an_owner_act_is_used_once(pw):
    act = owner_act(OwnerActKind.DESIGNATE, "human@example.com", scope="first")
    await pw.passkeys.designate(scope="first", contact="human@example.com", owner_act=act)
    replay = owner_act(
        OwnerActKind.DESIGNATE, "human@example.com", scope="second", act_id=act.act_id
    )
    with pytest.raises(DesignationRefused):
        await pw.passkeys.designate(scope="second", contact="human@example.com", owner_act=replay)


async def test_the_first_approver_is_designated_and_a_replacement_is_a_recovery(pw):
    with pytest.raises(DesignationRefused):
        await pw.passkeys.designate(
            scope=SCOPE,
            contact="human@example.com",
            owner_act=owner_act(OwnerActKind.RECOVER, "human@example.com"),
        )
    await pw.passkeys.designate(
        scope=SCOPE,
        contact="human@example.com",
        owner_act=owner_act(OwnerActKind.DESIGNATE, "human@example.com"),
    )
    with pytest.raises(DesignationRefused):
        await pw.passkeys.designate(
            scope=SCOPE,
            contact="new@example.com",
            owner_act=owner_act(OwnerActKind.DESIGNATE, "new@example.com"),
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
    assert await pw.passkeys.designated_approver(policy()) is None
    assert await refusal(mint(pw)) is Refusal.NO_APPROVER
    pw.clock.advance(timedelta(hours=1))
    assert await pw.passkeys.recovery_pending_until(SCOPE) is None
    approval = await mint(pw)
    assert (await decide(pw, approval, await ceremony(pw, approval, device))).state is (
        ApprovalState.APPROVED
    )


async def test_lockout_durations_are_policy_parameters(pw):
    from aweb_naapp.runtime.passkeys import LockoutPolicy

    store = PgApprovalStore(pw.passkeys.db)
    quick = Passkeys(
        pw.passkeys.db,
        rp=pw.passkeys.rp,
        delivery=pw.contacts,
        audit=pw.audit,
        retirement=ApprovalRevocation(store, pw.audit, pw.clock),
        enrolment_ttl=timedelta(hours=1),
        challenge_ttl=timedelta(minutes=5),
        lockout=LockoutPolicy(recovery_cooling_off=timedelta(hours=1)),
        clock=pw.clock,
    )
    await quick.designate(
        scope="quick",
        contact="a@example.com",
        owner_act=owner_act(OwnerActKind.DESIGNATE, "a@example.com", scope="quick"),
    )
    designation = await quick.designate(
        scope="quick",
        contact="b@example.com",
        owner_act=owner_act(OwnerActKind.RECOVER, "b@example.com", scope="quick"),
    )
    assert designation.effective_at == pw.clock() + timedelta(hours=1)


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
    assert (await pw.passkeys.designated_approver(policy())).contact == "human@example.com"
    pw.clock.advance(timedelta(hours=24))
    assert (await pw.passkeys.designated_approver(policy())).contact == "new@example.com"
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
    assert (await pw.passkeys.designated_approver(policy())).contact == "human@example.com"


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
    _, device = await enrol(pw)
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
            approval.approval_id, Decision.APPROVE, Assurance.PASSKEY, task_answer_ref="answer-1"
        )
        return device.get(dict(options))

    async def task_decide(proof):
        return await pw.approvals.decide(
            approval.approval_id,
            Decision.APPROVE,
            Assurance.PASSKEY,
            proof,
            task_answer_ref="answer-1",
        )

    assert await refusal(task_decide(await task_ceremony())) is Refusal.TASK_ANSWER_UNVERIFIED
    assert (await pw.approvals.get(approval.approval_id)).state is ApprovalState.PENDING
    pw.task_answers.record("answer-1", approval, Decision.APPROVE)
    decided = await task_decide(await task_ceremony())
    assert decided.state is ApprovalState.APPROVED
    assert (await pw.passkeys.evidence(decided.auth_evidence_ref)).task_answer_ref == "answer-1"
