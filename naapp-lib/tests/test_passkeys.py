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
from approvals_support import SCOPE, AuditOutbox, Clock, Policies, policy
from soft_authenticator import SoftAuthenticator

from aweb_naapp.runtime.approvals import (
    Approval,
    ApprovalRefused,
    Approvals,
    ApprovalState,
    Approver,
    Assurance,
    Decision,
    DeliveryStatus,
    PgApprovalStore,
    Refusal,
)
from aweb_naapp.runtime.passkeys import EnrolmentRefused, Passkeys, RelyingParty

ORIGIN = "https://app.example.com"
REQUEST = {"operation": "charge", "destination": {"host": "api.example.com"}, "executor": "broker"}


@dataclass
class Contacts:
    """Each registered contact's inbox: the only place enrolment and approval links arrive."""

    inbox: dict[str, list[str]] = field(default_factory=dict)
    by_approval: dict[str, str] = field(default_factory=dict)

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


@dataclass
class PasskeyWorld:
    passkeys: Passkeys
    approvals: Approvals
    contacts: Contacts
    audit: AuditOutbox
    clock: Clock
    policies: Policies


@pytest_asyncio.fixture
async def pw(test_db_factory) -> PasskeyWorld:
    db = await test_db_factory.create_db(suffix="passkeys", schema="app")
    audit = AuditOutbox(db)
    await audit.create()
    clock = Clock()
    contacts = Contacts()
    passkeys = Passkeys(
        db,
        rp=RelyingParty(origin=ORIGIN, name="Example app"),
        delivery=contacts,
        audit=audit,
        enrolment_ttl=timedelta(hours=1),
        challenge_ttl=timedelta(minutes=5),
        clock=clock,
    )
    await passkeys.migrate()
    store = PgApprovalStore(db)
    await store.migrate()
    policies = Policies(policy())
    approvals = Approvals(
        store=store,
        policies=policies,
        approvers=passkeys,
        delivery=contacts,
        authenticators=[passkeys.authenticator()],
        audit=audit,
        clock=clock,
    )
    return PasskeyWorld(passkeys, approvals, contacts, audit, clock, policies)


async def refusal(awaitable) -> Refusal:
    with pytest.raises(ApprovalRefused) as raised:
        await awaitable
    return raised.value.reason


async def enrol(
    pw: PasskeyWorld, contact="human@example.com"
) -> tuple[Approver, SoftAuthenticator]:
    await pw.passkeys.designate(scope=SCOPE, contact=contact, designated_by="owner-1")
    token = pw.contacts.last(contact)
    device = SoftAuthenticator(ORIGIN)
    credential = device.create(await pw.passkeys.enrolment_options(token))
    return await pw.passkeys.complete_enrolment(token, credential), device


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
    designation = await pw.passkeys.designate(
        scope=SCOPE, contact="human@example.com", designated_by="owner-1"
    )
    assert designation.delivery_status is DeliveryStatus.DELIVERED
    assert list(pw.contacts.inbox) == ["human@example.com"]
    assert designation.approver.subject_type == "app_local"
    token = pw.contacts.last("human@example.com")
    assert token not in repr(designation)
    assert token not in repr(await pw.audit.rows())
    assert "approver_designated" in await pw.audit.kinds()


async def test_an_approver_decides_nothing_before_enrolling(pw):
    await pw.passkeys.designate(scope=SCOPE, contact="human@example.com", designated_by="owner-1")
    assert await pw.passkeys.designated_approver(policy()) is None
    assert await refusal(mint(pw)) is Refusal.NO_APPROVER


async def test_enrolment_registers_a_passkey_on_trust_on_first_use(pw):
    approver, _ = await enrol(pw)
    assert await pw.passkeys.designated_approver(policy()) == approver
    [enrolled] = [row for row in await pw.audit.rows() if row["kind"] == "approver_enrolled"]
    assert json.loads(enrolled["details"])["trust"] == "trust_on_first_use"
    assert enrolled["subject"] == approver.subject


async def test_an_enrolment_link_is_used_once(pw):
    await pw.passkeys.designate(scope=SCOPE, contact="human@example.com", designated_by="owner-1")
    token = pw.contacts.last("human@example.com")
    device = SoftAuthenticator(ORIGIN)
    await pw.passkeys.complete_enrolment(
        token, device.create(await pw.passkeys.enrolment_options(token))
    )
    with pytest.raises(EnrolmentRefused):
        await pw.passkeys.enrolment_options(token)


async def test_an_expired_enrolment_link_is_refused(pw):
    await pw.passkeys.designate(scope=SCOPE, contact="human@example.com", designated_by="owner-1")
    pw.clock.advance(timedelta(hours=1))
    with pytest.raises(EnrolmentRefused):
        await pw.passkeys.enrolment_options(pw.contacts.last("human@example.com"))


@pytest.mark.parametrize(
    "device_kw", [{"origin": "https://evil.example.com"}, {"user_verified": False}]
)
async def test_registration_must_come_from_the_app_origin_with_user_verification(pw, device_kw):
    await pw.passkeys.designate(scope=SCOPE, contact="human@example.com", designated_by="owner-1")
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
    await pw.passkeys.designate(scope="other-scope", contact="other@example.com", designated_by="o")
    other_options = await pw.passkeys.enrolment_options(pw.contacts.last("other@example.com"))
    await pw.passkeys.designate(scope=SCOPE, contact="human@example.com", designated_by="owner-1")
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
    assert evidence.decision is Decision.APPROVE
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
    await pw.passkeys.designate(scope="elsewhere", contact="x@example.com", designated_by="o")
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
    assert await refusal(ceremony(pw, pending, old_device)) is Refusal.APPROVER_RETIRED
    fresh = await mint(pw, {**REQUEST, "executor": "runner"})
    assert fresh.approver_subject == new.subject
    assert (await decide(pw, fresh, await ceremony(pw, fresh, new_device))).state is (
        ApprovalState.APPROVED
    )


async def test_redesignation_invalidates_the_previous_enrolment_link(pw):
    await pw.passkeys.designate(scope=SCOPE, contact="human@example.com", designated_by="owner-1")
    stale = pw.contacts.last("human@example.com")
    await pw.passkeys.designate(scope=SCOPE, contact="human@example.com", designated_by="owner-1")
    with pytest.raises(EnrolmentRefused):
        await pw.passkeys.enrolment_options(stale)


async def test_approvals_given_by_a_retired_approver_are_void(pw):
    _, old_device = await enrol(pw, "human@example.com")
    approval = await mint(pw)
    await decide(pw, approval, await ceremony(pw, approval, old_device))
    await enrol(pw, "new-phone@example.com")
    assert await refusal(pw.approvals.admit(approval.approval_id, REQUEST, "op-1")) is (
        Refusal.APPROVER_RETIRED
    )
    assert (await pw.approvals.get(approval.approval_id)).state is ApprovalState.APPROVED
