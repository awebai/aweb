"""App-authorized containment on real B3 keys and B2 decisions."""
# ruff: noqa: F811 -- pw is the imported real passkey composition fixture.

from __future__ import annotations

import os

import pytest
from aweb_naapp_testing.webauthn import SoftAuthenticator, b64url

from aweb_naapp.runtime.approvals import AuthenticationFailed, Decision, Refusal
from aweb_naapp.runtime.passkeys import EnrolmentRefused, RetirementRefused, verify_registration
from tests.runtime.approvals.support import SCOPE
from tests.runtime.approvals.test_passkeys import (
    ORIGIN,
    REQUEST,
    ceremony,
    decide,
    designate,
    enrol,
    login,
    mint,
    pw,  # noqa: F401
    refusal,
)


async def second_passkey(pw, subject):
    """Seed a second genuinely verified credential; B3 supports multiple stored
    keys, while its enrolment-link API currently registers one per link."""
    device = SoftAuthenticator(ORIGIN)
    challenge = os.urandom(32)
    credential = verify_registration(
        device.create(
            {
                "rp": {"id": pw.passkeys.rp.rp_id},
                "user": {"id": b64url(subject.encode())},
                "challenge": b64url(challenge),
            }
        ),
        challenge=challenge,
        rp=pw.passkeys.rp,
    )
    await pw.passkeys.db.execute(
        "INSERT INTO {{tables.passkey_credentials}} "
        "(credential_id,subject,public_key,sign_count,created_at) VALUES ($1,$2,$3,$4,$5)",
        credential.credential_id,
        subject,
        credential.public_key,
        credential.sign_count,
        pw.clock(),
    )
    return device


async def contain(pw, subject, *, device=None, protect=None, scope=SCOPE):
    async with pw.passkeys.db.transaction() as tx:
        kwargs = dict(scope=scope, subject=subject, authorized_by="team-owner", protect=protect)
        if device is None:
            await pw.passkeys.retire_in(tx, **kwargs)
        else:
            await pw.passkeys.revoke_passkey_in(
                tx, credential_id=next(iter(device.credentials)), **kwargs
            )


@pytest.mark.parametrize("one_key", [False, True])
async def test_team_containment_without_a_ceremony_voids_decisions_and_ends_the_last_key(
    pw, one_key
):  # noqa: F811
    approver, device = await enrol(pw)
    approved = await mint(pw)
    await decide(pw, approved, await ceremony(pw, approved, device))
    pending = await mint(pw, {**REQUEST, "executor": "runner"})
    before_acts = await pw.passkeys.db.fetch_value(
        "SELECT count(*) FROM {{tables.passkey_owner_acts}}"
    )
    await contain(pw, approver.subject, device=device if one_key else None)
    assert await pw.passkeys.designated_approver(SCOPE) is None
    with pytest.raises(AuthenticationFailed):
        await login(pw, device)
    assert (
        await refusal(pw.approvals.admit(approved.approval_id, REQUEST, "dispatch"))
        is Refusal.REVOKED
    )
    assert (
        await refusal(pw.approvals.open_link(pw.contacts.by_approval[pending.approval_id]))
        is Refusal.LINK_UNAVAILABLE
    )
    assert (
        await pw.passkeys.db.fetch_value("SELECT count(*) FROM {{tables.passkey_owner_acts}}")
        == before_acts
    )
    retired = [r for r in await pw.audit.rows() if r["kind"] == "approver_retired"]
    assert [(r["subject"], r["actor"]) for r in retired] == [(approver.subject, "team-owner")]


async def test_losing_one_passkey_preserves_the_other_key_and_the_designation(pw):  # noqa: F811
    approver, lost = await enrol(pw)
    kept = await second_passkey(pw, approver.subject)
    approved = await mint(pw)
    await decide(pw, approved, await ceremony(pw, approved, lost))
    pending = await mint(pw, {**REQUEST, "executor": "runner"})
    await contain(pw, approver.subject, device=lost)
    assert await pw.passkeys.designated_approver(SCOPE) == approver
    with pytest.raises(AuthenticationFailed):
        await login(pw, lost)
    assert (await login(pw, kept)).subject == approver.subject
    assert (
        await refusal(pw.approvals.admit(approved.approval_id, REQUEST, "dispatch"))
        is Refusal.REVOKED
    )
    assert (
        await refusal(pw.approvals.open_link(pw.contacts.by_approval[pending.approval_id]))
        is Refusal.LINK_UNAVAILABLE
    )
    fresh = await mint(pw, {**REQUEST, "operation": "fresh"})
    await decide(pw, fresh, await ceremony(pw, fresh, kept, decision=Decision.APPROVE))
    assert (
        await pw.approvals.admit(fresh.approval_id, {**REQUEST, "operation": "fresh"}, "fresh")
    ).may_send
    assert len([r for r in await pw.audit.rows() if r["kind"] == "approver_passkey_revoked"]) == 1
    assert not [r for r in await pw.audit.rows() if r["kind"] == "approver_retired"]


@pytest.mark.parametrize("single_key", [False, True])
@pytest.mark.parametrize("has_sibling", [False, True])
async def test_team_retirement_protection_runs_before_writes_and_can_refuse(
    pw, single_key, has_sibling
):
    approver, device = await enrol(pw)
    if has_sibling:
        await second_passkey(pw, approver.subject)
    approval = await mint(pw)
    before = await pw.audit.rows()

    async def protect(tx, scope, subject):
        assert (scope, subject) == (SCOPE, approver.subject)
        assert await tx.fetch_value(
            "SELECT superseded_at IS NULL FROM {{tables.passkey_approvers}} WHERE subject=$1",
            subject,
        )
        assert await tx.fetch_value(
            "SELECT count(*) FROM {{tables.passkey_credentials}} WHERE subject=$1 AND revoked_at IS NULL",
            subject,
        ) == (2 if has_sibling else 1)
        raise RetirementRefused("last_owner_protected")

    with pytest.raises(RetirementRefused) as refused:
        await contain(pw, approver.subject, device=device if single_key else None, protect=protect)
    assert refused.value.reason == "last_owner_protected"
    assert await pw.audit.rows() == before
    assert (await login(pw, device)).subject == approver.subject
    await decide(pw, approval, await ceremony(pw, approval, device))


@pytest.mark.parametrize("mode", ["full", "last_key", "one_of_two"])
async def test_team_containment_rolls_back_with_the_caller_transaction(pw, mode):
    approver, device = await enrol(pw)
    if mode == "one_of_two":
        await second_passkey(pw, approver.subject)
    approved = await mint(pw)
    await decide(pw, approved, await ceremony(pw, approved, device))
    before = await pw.audit.rows()
    with pytest.raises(RuntimeError):
        async with pw.passkeys.db.transaction() as tx:
            kwargs = dict(scope=SCOPE, subject=approver.subject, authorized_by="team-owner")
            if mode != "full":
                await pw.passkeys.revoke_passkey_in(
                    tx, credential_id=next(iter(device.credentials)), **kwargs
                )
            else:
                await pw.passkeys.retire_in(tx, **kwargs)
            raise RuntimeError("rollback")
    assert await pw.audit.rows() == before
    assert (await login(pw, device)).subject == approver.subject
    assert (await pw.approvals.admit(approved.approval_id, REQUEST, "dispatch")).may_send


@pytest.mark.parametrize("single_key", [False, True])
async def test_team_retirement_cannot_retarget_a_recovered_scope(pw, single_key):  # noqa: F811
    old, device = await enrol(pw)
    successor = await designate(pw, "replacement@example.com")
    with pytest.raises(RetirementRefused):
        await contain(pw, old.subject, device=device if single_key else None)
    assert await pw.passkeys.recovery_pending_until(SCOPE) == successor.effective_at


async def test_a_credential_cannot_be_revoked_under_another_subject_or_scope(pw):  # noqa: F811
    approver, device = await enrol(pw)
    for subject, scope in [(approver.subject, "other-scope"), ("other-subject", SCOPE)]:
        with pytest.raises(RetirementRefused):
            await contain(pw, subject, device=device, scope=scope)
    assert (await login(pw, device)).subject == approver.subject


async def test_a_foreign_credential_cannot_be_revoked_under_the_current_holder(pw):
    approver, device = await enrol(pw)
    other = await designate(pw, "other@example.com", scope="approvers.other")
    token = pw.contacts.last("other@example.com")
    foreign = SoftAuthenticator(ORIGIN)
    await pw.passkeys.complete_enrolment(
        token, foreign.create(await pw.passkeys.enrolment_options(token))
    )
    with pytest.raises(RetirementRefused) as refused:
        await contain(pw, approver.subject, device=foreign)
    assert refused.value.reason == "credential_not_found"
    assert (await login(pw, device)).subject == approver.subject
    assert (await login(pw, foreign, scope="approvers.other")).subject == other.approver.subject


async def test_team_retirement_ends_pending_recovery_and_its_unused_enrolment(pw):
    await enrol(pw)
    successor = await designate(pw, "replacement@example.com")
    token = pw.contacts.last("replacement@example.com")
    await contain(pw, successor.approver.subject)
    assert await pw.passkeys.recovery_pending_until(SCOPE) is None
    with pytest.raises(EnrolmentRefused):
        await pw.passkeys.enrolment_options(token)
