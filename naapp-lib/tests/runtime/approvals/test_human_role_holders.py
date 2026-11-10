# ruff: noqa: F811 -- pw is the imported real passkey composition fixture.
"""B3's human-role holder writers (owner-act-delivery.md, Effects): designate,
replace and revoke, each applied in the transaction that consumed its signed
owner act, on real PostgreSQL. The holder's credential is bound by the act and
logs in with real WebAuthn assertions; no enrolment link exists."""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass
from typing import Any

import cbor2
import pytest
from aweb_naapp_testing.owner_acts import (
    APP_ID,
    INSTALLATION_ID,
    TEAM_ID,
    TeamOwner,
    designation_subject,
)
from aweb_naapp_testing.webauthn import SoftAuthenticator, SoftCredential, b64url
from cryptography.hazmat.primitives.asymmetric import ec

from aweb_naapp.hooks.owner_act import HUMAN_ROLE_ACTS, HumanCredential
from aweb_naapp.roles import (
    apply_roles_migrations,
    begin_holding,
    hold_holding,
    holding_scope,
    read_holding,
)
from aweb_naapp.runtime.approvals import AuthenticationFailed, DeliveryStatus, Refusal
from aweb_naapp.runtime.human_roles import HumanRoleHoldings
from aweb_naapp.runtime.installation import AdmittedInstallation
from aweb_naapp.runtime.passkeys import (
    ContactChangeRefused,
    DesignationRefused,
    EnrolmentRefused,
    NoticeKind,
    contact_sha256,
)
from tests.runtime.approvals.support import SCOPE as CONTACT_SCOPE
from tests.runtime.approvals.support import policy
from tests.runtime.approvals.test_passkeys import (
    ORIGIN,
    REQUEST,
    PasskeyWorld,
    designate_by_act,
    pw,  # noqa: F401
    refusal,
)

ROLE = "example.reader"
PRINCIPAL = "did:aw:2Wq7mXn4kP9rT1vY5zA8bC3dE6"
OTHER_PRINCIPAL = "did:aw:3Xr8nYo5mQ1sU2wZ6aB9cD4eF7"
RP_ID = "app.example.com"
NOTICE = "reader@example.com"
CERTIFICATE = b'{"certificate_id":"cert-1"}'
RENEWED = b'{"certificate_id":"cert-2"}'
SCOPE = holding_scope(INSTALLATION_ID, TEAM_ID, ROLE, PRINCIPAL)
KEY = dict(installation_id=INSTALLATION_ID, team_id=TEAM_ID, role=ROLE, principal=PRINCIPAL)
INSTALLATION = AdmittedInstallation(
    team_id=TEAM_ID, app_id=APP_ID, installation_id=INSTALLATION_ID, generation=1
)


@dataclass
class Holder:
    """A member's authenticator and the credential an act binds from it."""

    device: SoftAuthenticator
    body: dict[str, str]

    @property
    def credential(self) -> HumanCredential:
        return HumanCredential.parse(self.body)


def holder(rp_id: str = RP_ID, *, cose: bytes | None = None) -> Holder:
    soft = SoftCredential(
        os.urandom(32), ec.generate_private_key(ec.SECP256R1()), rp_id, os.urandom(16)
    )
    device = SoftAuthenticator(ORIGIN)
    device.credentials[soft.credential_id] = soft
    body = {
        "credential_id": b64url(soft.credential_id),
        "public_key": b64url(cose if cose is not None else soft.cose_public_key()),
        "rp_id": rp_id,
    }
    return Holder(device, body)


def owner(pw: PasskeyWorld) -> TeamOwner:
    return pw.owner.for_acts(HUMAN_ROLE_ACTS)


def holding_subject(
    credential: dict[str, str] | None, notice: str | None = None, principal: str = PRINCIPAL
) -> dict[str, Any]:
    subject: dict[str, Any] = {
        "app_id": APP_ID,
        "installation_id": INSTALLATION_ID,
        "role": ROLE,
        "principal": principal,
    }
    if credential is not None:
        subject["credential_sha256"] = HumanCredential.parse(credential).sha256
    if notice is not None:
        subject["notice_contact_sha256"] = contact_sha256(notice)
    return subject


async def migrated(pw: PasskeyWorld) -> PasskeyWorld:
    await apply_roles_migrations(pw.passkeys.db)
    return pw


async def designate(
    pw: PasskeyWorld,
    member: Holder,
    *,
    notice: str | None = None,
    signed: dict[str, str] | None = None,
    act: str = "human-role.designate",
):
    """Consume a signed act and apply it in one transaction."""
    subject = holding_subject(signed or member.body, notice)
    signer = owner(pw)
    prepared = await signer.prepare(act, subject)
    async with pw.passkeys.db.transaction() as tx:
        verified = await signer.consume(tx, prepared, subject)
        operation = (
            pw.passkeys.designate_holder
            if act == "human-role.designate"
            else pw.passkeys.replace_holder_credential
        )
        return await operation(
            tx,
            act=verified,
            credential=member.credential,
            certificate=CERTIFICATE if act == "human-role.designate" else RENEWED,
            notice_contact=notice,
        )


async def replace(pw: PasskeyWorld, member: Holder, *, notice: str | None = None):
    return await designate(pw, member, notice=notice, act="human-credential.replace")


async def revoke(pw: PasskeyWorld, tx=None) -> None:
    subject = holding_subject(None)
    signer = owner(pw)
    prepared = await signer.prepare("human-role.revoke", subject)
    if tx is not None:
        verified = await signer.consume(tx, prepared, subject)
        await pw.passkeys.revoke_holder(tx, act=verified)
        return
    async with pw.passkeys.db.transaction() as tx:
        verified = await signer.consume(tx, prepared, subject)
        await pw.passkeys.revoke_holder(tx, act=verified)


async def log_in(pw: PasskeyWorld, member: Holder, **device_kw):
    options = await pw.passkeys.login_options(SCOPE)
    return await pw.passkeys.verify_login(SCOPE, member.device.get(options, **device_kw))


async def holding(pw: PasskeyWorld):
    store = HumanRoleHoldings(roles=frozenset({ROLE}), passkeys=pw.passkeys)
    async with pw.passkeys.db.transaction() as tx:
        return await store.read_holding(
            tx, installation=INSTALLATION, role=ROLE, principal=PRINCIPAL
        )


async def stored_holding(pw: PasskeyWorld):
    async with pw.passkeys.db.transaction() as tx:
        return await read_holding(tx, **KEY)


# Designate


async def test_a_designated_holder_logs_in_with_the_bound_credential(pw: PasskeyWorld):
    await migrated(pw)
    member = holder()
    designation = await designate(pw, member)
    assert designation.effective_at == pw.clock()
    found = await holding(pw)
    assert found is not None
    assert (found.b3_scope, found.subject, found.certificate) == (
        SCOPE,
        designation.approver.subject,
        CERTIFICATE,
    )
    login = await log_in(pw, member)
    assert login.subject == designation.approver.subject
    assert login.contact is None


async def test_a_designation_sends_no_enrolment_link(pw: PasskeyWorld):
    await migrated(pw)
    designation = await designate(pw, holder(), notice=NOTICE)
    assert await pw.passkeys.deliver(designation) == DeliveryStatus.NOT_REQUIRED
    assert pw.contacts.inbox == {} and pw.contacts.notices == {}


async def test_a_designated_holder_keeps_its_notice_contact(pw: PasskeyWorld):
    await migrated(pw)
    member = holder()
    await designate(pw, member, notice=NOTICE)
    assert (await log_in(pw, member)).contact == NOTICE


async def test_a_designation_must_be_applied_in_the_transaction_that_consumed_its_act(
    pw: PasskeyWorld,
):
    await migrated(pw)
    member = holder()
    subject = holding_subject(member.body)
    signer = owner(pw)
    prepared = await signer.prepare("human-role.designate", subject)
    async with pw.passkeys.db.transaction() as tx:
        verified = await signer.consume(tx, prepared, subject)
    async with pw.passkeys.db.transaction() as tx:
        with pytest.raises(DesignationRefused):
            await pw.passkeys.designate_holder(
                tx,
                act=verified,
                credential=member.credential,
                certificate=CERTIFICATE,
                notice_contact=None,
            )
    assert await stored_holding(pw) is None


async def test_only_a_designate_act_designates_a_holder(pw: PasskeyWorld):
    await migrated(pw)
    with pytest.raises(DesignationRefused):
        await designate(pw, holder(), act="human-credential.replace")
    assert await stored_holding(pw) is None


@pytest.mark.parametrize(
    "fault", ["other-credential", "private-key", "foreign-rp", "aweb-rp", "notice-mismatch"]
)
async def test_a_designation_refuses_a_credential_or_contact_the_act_does_not_bind(
    pw: PasskeyWorld, fault: str
):
    await migrated(pw)
    member = holder()
    signed = None
    if fault == "other-credential":
        signed = holder().body
    elif fault == "private-key":
        key = cbor2.loads(next(iter(member.device.credentials.values())).cose_public_key())
        key[-4] = os.urandom(32)
        member = holder(cose=cbor2.dumps(key))
    elif fault == "foreign-rp":
        member = holder("logs.example.com")
    elif fault == "aweb-rp":
        member = holder("aweb:")
    if fault == "notice-mismatch":
        subject = holding_subject(member.body, NOTICE)
        signer = owner(pw)
        prepared = await signer.prepare("human-role.designate", subject)
        async with pw.passkeys.db.transaction() as tx:
            verified = await signer.consume(tx, prepared, subject)
            with pytest.raises(DesignationRefused):
                await pw.passkeys.designate_holder(
                    tx,
                    act=verified,
                    credential=member.credential,
                    certificate=CERTIFICATE,
                    notice_contact="someone-else@example.com",
                )
    else:
        with pytest.raises(DesignationRefused):
            await designate(pw, member, signed=signed)
    assert await stored_holding(pw) is None


async def test_a_held_role_is_not_designated_again(pw: PasskeyWorld):
    await migrated(pw)
    first = holder()
    await designate(pw, first)
    with pytest.raises(DesignationRefused):
        await designate(pw, holder())
    assert (await log_in(pw, first)).subject == (await holding(pw)).subject


async def test_of_two_concurrent_designations_one_holds_and_the_other_rolls_back(
    pw: PasskeyWorld,
):
    await migrated(pw)
    results = await asyncio.gather(
        designate(pw, holder()), designate(pw, holder()), return_exceptions=True
    )
    refused = [r for r in results if isinstance(r, DesignationRefused)]
    held = [r for r in results if not isinstance(r, BaseException)]
    assert len(refused) == 1 and len(held) == 1
    assert (await holding(pw)).subject == held[0].approver.subject


async def test_a_holder_scope_takes_no_contact_designation_or_enrolment_link(pw: PasskeyWorld):
    await migrated(pw)
    await designate(pw, holder(), notice=NOTICE)
    subject = designation_subject(SCOPE, NOTICE)
    for act in ("app-role.designate", "app-credential.recover"):
        prepared = await pw.owner.prepare(act, subject)
        async with pw.passkeys.db.transaction() as tx:
            verified = await pw.owner.consume(tx, prepared, subject)
            with pytest.raises(DesignationRefused):
                await pw.passkeys.designate(tx, scope=SCOPE, contact=NOTICE, evidence=verified)
    async with pw.passkeys.db.transaction() as tx:
        with pytest.raises(EnrolmentRefused):
            await pw.passkeys.reissue_enrolment(tx, scope=SCOPE)


async def test_a_holder_without_a_notice_contact_cannot_gain_one(pw: PasskeyWorld):
    await migrated(pw)
    member = holder()
    await designate(pw, member)
    options = await pw.passkeys.contact_change_options(SCOPE, NOTICE)
    with pytest.raises(ContactChangeRefused):
        await pw.passkeys.change_contact(SCOPE, NOTICE, member.device.get(options))


async def test_a_holder_assertion_from_another_origin_is_refused(pw: PasskeyWorld):
    await migrated(pw)
    member = holder()
    await designate(pw, member)
    with pytest.raises(AuthenticationFailed):
        await log_in(pw, member, origin="https://logs.example.com")


# Replace


async def test_a_replacement_keeps_the_holding_and_changes_its_subject(pw: PasskeyWorld):
    await migrated(pw)
    first = holder()
    designated = await designate(pw, first, notice=NOTICE)
    before = await stored_holding(pw)
    second = holder()
    replaced = await replace(pw, second, notice=NOTICE)
    after = await stored_holding(pw)
    assert after.held_since == before.held_since
    assert after.certificate == RENEWED
    assert replaced.approver.subject != designated.approver.subject
    assert replaced.notices == ((NOTICE, replaced.notices[0][1]),)
    assert replaced.notices[0][1].kind == NoticeKind.RECOVERY_STARTED
    assert (await holding(pw)).subject is None
    with pytest.raises(AuthenticationFailed):
        await log_in(pw, first)
    pw.clock.now = replaced.effective_at
    assert (await holding(pw)).subject == replaced.approver.subject
    assert (await log_in(pw, second)).subject == replaced.approver.subject


async def test_nothing_held_is_replaced_or_revoked(pw: PasskeyWorld):
    await migrated(pw)
    with pytest.raises(DesignationRefused):
        await replace(pw, holder())
    with pytest.raises(DesignationRefused):
        await revoke(pw)
    assert await stored_holding(pw) is None


# Revoke


async def test_a_revoked_holding_ends_with_its_credential(pw: PasskeyWorld):
    await migrated(pw)
    member = holder()
    await designate(pw, member)
    await revoke(pw)
    assert await holding(pw) is None
    with pytest.raises(AuthenticationFailed):
        await log_in(pw, member)


async def test_ending_a_holding_that_never_had_an_approver_is_audited(pw: PasskeyWorld):
    await migrated(pw)
    async with pw.passkeys.db.transaction() as tx:
        await begin_holding(tx, **KEY, certificate=None)
    await revoke(pw)
    assert await stored_holding(pw) is None
    [ended] = [row for row in await pw.audit.rows() if row["kind"] == "approver_retired"]
    details = json.loads(ended["details"])
    assert (details["scope"], details["principal"], details["owner_act_kind"]) == (
        SCOPE,
        PRINCIPAL,
        "human-role.revoke",
    )


async def test_a_revoked_role_is_held_again_as_a_new_holding(pw: PasskeyWorld):
    await migrated(pw)
    await designate(pw, holder())
    first = await stored_holding(pw)
    await revoke(pw)
    again = holder()
    await designate(pw, again)
    second = await stored_holding(pw)
    assert second.held_since > first.held_since
    assert (await log_in(pw, again)).subject == (await holding(pw)).subject


async def test_revoking_and_designating_in_one_transaction_is_a_new_holding(pw: PasskeyWorld):
    await migrated(pw)
    await designate(pw, holder())
    first = await stored_holding(pw)
    again = holder()
    subject = holding_subject(again.body)
    signer = owner(pw)
    prepared = await signer.prepare("human-role.designate", subject)
    async with pw.passkeys.db.transaction() as tx:
        await revoke(pw, tx)
        verified = await signer.consume(tx, prepared, subject)
        await pw.passkeys.designate_holder(
            tx, act=verified, credential=again.credential, certificate=RENEWED, notice_contact=None
        )
    second = await stored_holding(pw)
    assert second.held_since != first.held_since
    assert second.certificate == RENEWED
    assert (await log_in(pw, again)).subject == (await holding(pw)).subject


# A reader's hold


@pytest.mark.parametrize("write", ["replace", "revoke"])
async def test_a_held_holding_blocks_replace_and_revoke_until_the_reader_commits(
    pw: PasskeyWorld, write: str
):
    await migrated(pw)
    await designate(pw, holder())
    started: asyncio.Future[int] = asyncio.get_running_loop().create_future()
    db = pw.passkeys.db

    async def writer() -> None:
        signer = owner(pw)
        member = holder()
        act = "human-credential.replace" if write == "replace" else "human-role.revoke"
        subject = holding_subject(member.body if write == "replace" else None)
        prepared = await signer.prepare(act, subject)
        async with db.transaction() as tx:
            started.set_result(await tx.fetch_value("SELECT pg_backend_pid()"))
            verified = await signer.consume(tx, prepared, subject)
            if write == "replace":
                await pw.passkeys.replace_holder_credential(
                    tx,
                    act=verified,
                    credential=member.credential,
                    certificate=RENEWED,
                    notice_contact=None,
                )
            else:
                await pw.passkeys.revoke_holder(tx, act=verified)

    writing = None
    try:
        async with db.transaction() as tx:
            assert await hold_holding(tx, **KEY) is not None
            reader = await tx.fetch_value("SELECT pg_backend_pid()")
            writing = asyncio.create_task(writer())
            pid = await asyncio.wait_for(started, 5)
            async with asyncio.timeout(5):
                while reader not in await db.fetch_value("SELECT pg_blocking_pids($1)", pid):
                    assert not writing.done(), "the writer changed a held holding"
                    await asyncio.sleep(0.01)
        await asyncio.wait_for(writing, 5)
    finally:
        if writing is not None and not writing.done():
            writing.cancel()
            await asyncio.gather(writing, return_exceptions=True)


# The holder as an approver


async def test_a_holder_is_its_principals_approver_in_the_directory(pw: PasskeyWorld):
    await migrated(pw)
    designation = await designate(pw, holder(), notice=NOTICE)
    approver = await pw.passkeys.designated_approver(SCOPE)
    assert approver is not None
    assert (approver.subject, approver.principal_did, approver.contact) == (
        designation.approver.subject,
        PRINCIPAL,
        NOTICE,
    )


@pytest.mark.parametrize("requester", [PRINCIPAL, OTHER_PRINCIPAL])
async def test_a_holder_never_approves_its_own_principals_request(pw: PasskeyWorld, requester: str):
    await migrated(pw)
    designation = await designate(pw, holder(), notice=NOTICE)
    pw.policies.set(policy(approver_scopes=(SCOPE,)))
    minting = pw.approvals.mint(request=REQUEST, policy_ref="send-charge", requested_by=requester)
    if requester == PRINCIPAL:
        assert await refusal(minting) is Refusal.NO_ELIGIBLE_APPROVER
        return
    view = await minting
    approval = await pw.approvals.for_request(view.request_id)
    [candidate] = approval.candidates
    assert (candidate.subject, candidate.principal_did) == (
        designation.approver.subject,
        PRINCIPAL,
    )


# A contact approver whose scope became a holding (16.43's backfill)


async def backfilled(pw: PasskeyWorld) -> None:
    """What 16.43's backfill writes for an existing contact approver: the
    holding record of its scope, and the principal on every approver row of
    that scope, in one transaction."""
    async with pw.passkeys.db.transaction() as tx:
        await begin_holding(tx, **KEY, certificate=None)
        await tx.execute(
            "UPDATE {{tables.passkey_approvers}} SET principal = $2 WHERE scope = $1",
            SCOPE,
            PRINCIPAL,
        )


async def test_a_backfilled_contact_approver_keeps_its_credential_and_leaves_the_contact_paths(
    pw: PasskeyWorld,
):
    await migrated(pw)
    designation = await designate_by_act(pw, "app-role.designate", NOTICE, SCOPE)
    device = SoftAuthenticator(ORIGIN)
    token = pw.contacts.last(NOTICE)
    await pw.passkeys.complete_enrolment(
        token, device.create(await pw.passkeys.enrolment_options(token))
    )
    await backfilled(pw)
    for act in ("app-role.designate", "app-credential.recover"):
        with pytest.raises(DesignationRefused):
            await designate_by_act(pw, act, NOTICE, SCOPE)
    options = await pw.passkeys.login_options(SCOPE)
    login = await pw.passkeys.verify_login(SCOPE, device.get(options))
    assert login.subject == designation.approver.subject
    assert (await holding(pw)).subject == designation.approver.subject


async def test_a_backfilled_scope_gets_no_enrolment_link_while_a_contact_scope_does(
    pw: PasskeyWorld,
):
    await migrated(pw)
    await designate_by_act(pw, "app-role.designate", NOTICE, SCOPE)
    await designate_by_act(pw, "app-role.designate", NOTICE, CONTACT_SCOPE)
    await backfilled(pw)
    async with pw.passkeys.db.transaction() as tx:
        with pytest.raises(EnrolmentRefused):
            await pw.passkeys.reissue_enrolment(tx, scope=SCOPE)
    async with pw.passkeys.db.transaction() as tx:
        assert (await pw.passkeys.reissue_enrolment(tx, scope=CONTACT_SCOPE)).link_token
