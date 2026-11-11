"""Q1 credential maintenance: an in-effect approver adds a passkey, or replaces
one it selects, with a passkey it already holds, at once. The new credential
registers with user verification first; a current credential's assertion then
approves that exact credential and operation. Recovery without a working
passkey stays the owner's, after its cooling-off. Every ceremony is real
WebAuthn on real PostgreSQL."""

from __future__ import annotations

import asyncio
import shutil
from collections.abc import Awaitable
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

import pytest
import pytest_asyncio
from aweb_naapp_testing.webauthn import SoftAuthenticator, SoftCredential, b64url
from cryptography.hazmat.primitives.asymmetric import ec
from pgdbm import AsyncMigrationManager

from aweb_naapp.roles import apply_roles_migrations, is_holding_scope
from aweb_naapp.runtime.approvals import (
    ApprovalRefused,
    ApprovalRevocation,
    ApprovalState,
    AuthenticationFailed,
    DeliveryStatus,
    PgApprovalStore,
    Refusal,
)
from aweb_naapp.runtime.installation import AdmittedInstallation
from aweb_naapp.runtime.passkeys import (
    CredentialChangeRefused,
    CredentialChangeState,
    CredentialPolicy,
    NoticeKind,
    PasskeyInstallationContext,
    Passkeys,
    RelyingParty,
    prepare_retirement,
)
from aweb_naapp.runtime.passkeys.service import MIGRATION_MODULE, MIGRATIONS
from tests.runtime.approvals import test_human_role_holders as holders
from tests.runtime.approvals.support import SCOPE, AuditOutbox, Clock
from tests.runtime.approvals.test_passkeys import (
    ORIGIN,
    REQUEST,
    Contacts,
    PasskeyWorld,
    ceremony,
    decide,
    designate,
    enrol,
    login,
    mint,
    passkey_world,
)

CONTACT = "human@example.com"
FIVE_MINUTES = timedelta(minutes=5)
WAIT = 10  # Seconds any test waits for a task or a lock before failing.
# The installation the passkey world's proof context resolves every scope to.
INSTALLATION = AdmittedInstallation(
    team_id="team", app_id="fixture", installation_id="installation", generation=1
)
CALLER_LOCK = 0x46360000  # Stands in for the caller's F6 lock.
ROLE_HOLD = 0x524F4C45  # Stands in for the caller's actor and target role holds.
SESSION_HOLD = 0x53340000  # Stands in for the caller's S4 hold.


@pytest_asyncio.fixture
async def pw(test_db_factory, registry) -> PasskeyWorld:
    """The passkey world of an app that also keeps human-role holdings, with a
    receipts table the caller writes in the effect transaction."""
    world = await passkey_world(test_db_factory, registry, holding_scopes=is_holding_scope)
    await apply_roles_migrations(world.passkeys.db)
    await world.passkeys.db.execute(
        "CREATE TABLE {{tables.credential_receipts}} (challenge TEXT PRIMARY KEY, "
        "credential_id BYTEA NOT NULL, operation TEXT NOT NULL, txid BIGINT NOT NULL)"
    )
    return world


def credential_of(device: SoftAuthenticator) -> bytes:
    [credential_id] = device.credentials
    return credential_id


@dataclass
class Prepared:
    """A registered new credential and the assertion options approving it."""

    new_device: SoftAuthenticator
    options: dict


async def prepare(
    passkeys: Passkeys,
    *,
    replace: bytes | None = None,
    scope: str = SCOPE,
) -> Prepared:
    new_device = SoftAuthenticator(ORIGIN)
    registration = new_device.create(dict(await passkeys.credential_registration_options(scope)))
    options = await passkeys.credential_change_options(scope, registration, replace=replace)
    return Prepared(new_device, dict(options))


async def rotate(pw: PasskeyWorld, device, *, replace: bytes | None = None, **change_kw):
    change_kw.setdefault("fence", Fence(pw.passkeys))
    prepared = await prepare(pw.passkeys, replace=replace)
    change = await pw.passkeys.change_credential(SCOPE, device.get(prepared.options), **change_kw)
    return change, prepared.new_device


async def active_credentials(pw: PasskeyWorld, subject: str) -> set[bytes]:
    rows = await pw.passkeys.db.fetch_all(
        "SELECT credential_id FROM {{tables.passkey_credentials}} "
        "WHERE subject = $1 AND revoked_at IS NULL",
        subject,
    )
    return {row["credential_id"] for row in rows}


async def credential_count(pw: PasskeyWorld) -> int:
    return await pw.passkeys.db.fetch_value("SELECT count(*) FROM {{tables.passkey_credentials}}")


async def receipts(pw: PasskeyWorld) -> list[dict[str, Any]]:
    return await pw.passkeys.db.fetch_all("SELECT * FROM {{tables.credential_receipts}}")


async def receipt(tx, change) -> None:
    """The caller's receipt, written through the effect transaction."""
    await tx.execute(
        "INSERT INTO {{tables.credential_receipts}} (challenge, credential_id, operation, txid) "
        "VALUES ($1, $2, $3, txid_current())",
        change.challenge,
        change.credential_id,
        change.operation,
    )


async def refusal_of(awaitable: Awaitable) -> Refusal:
    with pytest.raises(ApprovalRefused) as raised:
        await awaitable
    return raised.value.reason


def world_with(pw: PasskeyWorld, **options) -> Passkeys:
    """Another Passkeys over the same database, configured with `options`."""
    store = PgApprovalStore(pw.passkeys.db)
    options.setdefault("challenge_ttl", FIVE_MINUTES)
    return Passkeys(
        pw.passkeys.db,
        rp=pw.passkeys.rp,
        delivery=pw.contacts,
        audit=pw.audit,
        retirement=ApprovalRevocation(store, pw.audit, pw.clock),
        enrolment_ttl=timedelta(hours=1),
        clock=pw.clock,
        proof_context=pw.passkeys._proof_context,
        holding_scopes=is_holding_scope,
        **options,
    )


async def lock_waiters(pw: PasskeyWorld) -> int:
    return await pw.passkeys.db.fetch_value(
        "SELECT count(*) FROM pg_stat_activity "
        "WHERE datname = current_database() AND wait_event_type = 'Lock'"
    )


async def until_waiting(pw: PasskeyWorld, waiters: int = 1) -> None:
    """Return once `waiters` sessions are observed waiting on a lock."""

    async def observe() -> None:
        while await lock_waiters(pw) < waiters:
            await asyncio.sleep(0.02)

    await asyncio.wait_for(observe(), WAIT)


async def settle(*tasks: asyncio.Task | None) -> None:
    """Cancel whatever is still running, so a failing test cannot hang the suite."""
    running = [task for task in tasks if task is not None]
    for task in running:
        if not task.done():
            task.cancel()
    await asyncio.gather(*running, return_exceptions=True)


@dataclass
class Fence:
    """A caller's credential-change fence in the contracted order: its own
    lock (F6), the retirement gate, its role holds, then B3's write-locked
    preparation, then S4. It hands B3's handle back, records its calls, and can
    wait for its racers, hold or refuse."""

    passkeys: Passkeys
    scope: str = SCOPE
    calls: list[str] = field(default_factory=list)
    refuse: str | None = None
    arrive: asyncio.Barrier | None = None
    hold: asyncio.Event | None = None
    holding: asyncio.Event = field(default_factory=asyncio.Event)
    hand_back: bool = True

    async def prepare(self, tx):
        self.calls.append("prepare")
        if self.arrive is not None:
            await asyncio.wait_for(self.arrive.wait(), WAIT)
        await tx.execute("SELECT pg_advisory_xact_lock($1::bigint)", CALLER_LOCK)
        await prepare_retirement(tx, installation=INSTALLATION)
        await tx.execute("SELECT pg_advisory_xact_lock($1::bigint)", ROLE_HOLD)
        prepared = await self.passkeys.prepare_credential_change(tx, scope=self.scope)
        await tx.execute("SELECT pg_advisory_xact_lock($1::bigint)", SESSION_HOLD)
        if self.refuse == "prepare":
            raise CredentialChangeRefused("completion_authority_unavailable")
        return prepared if self.hand_back else None

    async def check(self, tx) -> None:
        self.calls.append("check")
        if self.hold is not None:
            self.holding.set()
            await asyncio.wait_for(self.hold.wait(), WAIT)
        if self.refuse == "check":
            raise CredentialChangeRefused("completion_authority_unavailable")


async def two_credentials(pw: PasskeyWorld):
    """An enrolled approver holding two credentials on separate authenticators."""
    approver, first = await enrol(pw, CONTACT)
    _, second = await rotate(pw, first)
    pw.contacts.notices.clear()
    return approver, first, second


async def race(*calls: Awaitable) -> list[Any]:
    tasks = [asyncio.ensure_future(call) for call in calls]
    try:
        return await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), WAIT)
    finally:
        await settle(*tasks)


# Add


async def test_an_approver_adds_a_passkey_with_one_it_holds(pw):
    approver, device = await enrol(pw, CONTACT)
    change, new_device = await rotate(pw, device)
    assert change.operation == "add"
    assert change.retired_credential_id is None
    assert await active_credentials(pw, approver.subject) == {
        credential_of(device),
        credential_of(new_device),
    }
    assert (await login(pw, new_device)).subject == approver.subject
    assert (await login(pw, device)).subject == approver.subject
    assert "approver_passkey_added" in await pw.audit.kinds()


async def test_an_add_tells_the_contact_which_passkey_and_voids_nothing(pw):
    _, device = await enrol(pw, CONTACT)
    approved = await mint(pw)
    await decide(pw, approved, await ceremony(pw, approved, device))
    change, new_device = await rotate(pw, device)
    [notice] = pw.contacts.notices[CONTACT]
    assert notice.kind is NoticeKind.CREDENTIAL_ADDED
    assert notice.credential_ids == (b64url(credential_of(new_device)),)
    assert change.delivery is DeliveryStatus.DELIVERED
    assert (await pw.approvals.get(approved.approval_id)).state is ApprovalState.APPROVED


# Replace


async def test_a_replace_retires_only_the_selected_passkey(pw):
    approver, device, second = await two_credentials(pw)
    change, third = await rotate(pw, device, replace=credential_of(second))
    assert change.operation == "replace"
    assert change.retired_credential_id == credential_of(second)
    assert await active_credentials(pw, approver.subject) == {
        credential_of(device),
        credential_of(third),
    }
    with pytest.raises(AuthenticationFailed):
        await login(pw, second)
    [notice] = pw.contacts.notices[CONTACT]
    assert notice.kind is NoticeKind.CREDENTIAL_REPLACED
    assert notice.credential_ids == (b64url(credential_of(third)), b64url(credential_of(second)))
    assert "approver_passkey_replaced" in await pw.audit.kinds()


async def test_a_passkey_can_replace_itself(pw):
    approver, device = await enrol(pw, CONTACT)
    _, new_device = await rotate(pw, device, replace=credential_of(device))
    assert await active_credentials(pw, approver.subject) == {credential_of(new_device)}
    assert (await login(pw, new_device)).subject == approver.subject


async def test_a_replace_ends_the_retired_passkeys_sessions_only(pw):
    _, device, second = await two_credentials(pw)
    kept = await login(pw, device)
    ended = await login(pw, second)
    await rotate(pw, device, replace=credential_of(second))
    assert await pw.passkeys.login_evidence_is_current(SCOPE, kept.subject, kept.evidence_ref)
    assert not await pw.passkeys.login_evidence_is_current(SCOPE, ended.subject, ended.evidence_ref)


async def test_a_replace_voids_the_holders_live_approvals(pw):
    """Re-approval cost: a replace voids every live approval the holder
    decided, not only those its retired passkey decided."""
    _, device, second = await two_credentials(pw)
    approved = await mint(pw)
    await decide(pw, approved, await ceremony(pw, approved, device))
    await rotate(pw, device, replace=credential_of(second))
    assert await refusal_of(pw.approvals.admit(approved.approval_id, REQUEST, "op-1")) is (
        Refusal.REVOKED
    )


# Who may approve the change


async def test_the_new_passkey_cannot_approve_its_own_change(pw):
    await enrol(pw, CONTACT)
    prepared = await prepare(pw.passkeys)
    before = await credential_count(pw)
    with pytest.raises(AuthenticationFailed):
        await pw.passkeys.change_credential(SCOPE, prepared.new_device.get(prepared.options))
    assert await credential_count(pw) == before


async def test_another_holdings_passkey_on_the_same_authenticator_cannot_approve(pw):
    await enrol(pw, CONTACT)
    await designate(pw, "other@example.com", scope="other.scope")
    token = pw.contacts.last("other@example.com")
    foreign = SoftAuthenticator(ORIGIN)
    await pw.passkeys.complete_enrolment(
        token, foreign.create(await pw.passkeys.enrolment_options(token))
    )
    prepared = await prepare(pw.passkeys)
    before = await credential_count(pw)
    with pytest.raises(AuthenticationFailed):
        await pw.passkeys.change_credential(SCOPE, foreign.get(prepared.options))
    assert await credential_count(pw) == before


async def test_a_revoked_passkey_cannot_approve(pw):
    approver, _, second = await two_credentials(pw)
    prepared = await prepare(pw.passkeys)
    async with pw.passkeys.db.transaction() as tx:
        await pw.passkeys.revoke_passkey_in(
            tx,
            scope=SCOPE,
            subject=approver.subject,
            credential_id=credential_of(second),
            authorized_by="owner",
        )
    before = await credential_count(pw)
    with pytest.raises(AuthenticationFailed):
        await pw.passkeys.change_credential(SCOPE, second.get(prepared.options))
    assert await credential_count(pw) == before


async def test_both_ceremonies_need_user_verification(pw):
    _, device = await enrol(pw, CONTACT)
    new_device = SoftAuthenticator(ORIGIN)
    unverified = new_device.create(
        dict(await pw.passkeys.credential_registration_options(SCOPE)), user_verified=False
    )
    with pytest.raises(CredentialChangeRefused):
        await pw.passkeys.credential_change_options(SCOPE, unverified)
    prepared = await prepare(pw.passkeys)
    before = await credential_count(pw)
    with pytest.raises(AuthenticationFailed):
        await pw.passkeys.change_credential(
            SCOPE, device.get(prepared.options, user_verified=False)
        )
    assert await credential_count(pw) == before


async def test_an_assertion_approves_one_change_only(pw):
    _, device = await enrol(pw, CONTACT)
    prepared = await prepare(pw.passkeys)
    assertion = device.get(prepared.options)
    await pw.passkeys.change_credential(SCOPE, assertion)
    count = await credential_count(pw)
    with pytest.raises(AuthenticationFailed):
        await pw.passkeys.change_credential(SCOPE, assertion)
    assert await credential_count(pw) == count


async def test_a_change_approved_in_one_scope_does_not_apply_in_another(pw):
    _, device = await enrol(pw, CONTACT)
    await designate(pw, "other@example.com", scope="other.scope")
    prepared = await prepare(pw.passkeys)
    before = await credential_count(pw)
    with pytest.raises((AuthenticationFailed, CredentialChangeRefused)):
        await pw.passkeys.change_credential("other.scope", device.get(prepared.options))
    assert await credential_count(pw) == before


async def test_another_ceremonys_assertion_cannot_effect_a_change(pw):
    _, device = await enrol(pw, CONTACT)
    login_assertion = device.get(dict(await pw.passkeys.login_options(SCOPE)))
    before = await credential_count(pw)
    with pytest.raises(AuthenticationFailed):
        await pw.passkeys.change_credential(SCOPE, login_assertion)
    assert await credential_count(pw) == before


async def test_a_registration_is_bound_into_one_change_only(pw):
    await enrol(pw, CONTACT)
    new_device = SoftAuthenticator(ORIGIN)
    registration = new_device.create(dict(await pw.passkeys.credential_registration_options(SCOPE)))
    await pw.passkeys.credential_change_options(SCOPE, registration)
    with pytest.raises(CredentialChangeRefused):
        await pw.passkeys.credential_change_options(SCOPE, registration)


async def test_a_registered_credential_cannot_be_added_again(pw):
    """A valid registration of a credential B3 already holds, from an
    authenticator that ignores excludeCredentials."""
    _, device = await enrol(pw, CONTACT)
    _, new_device = await rotate(pw, device)
    existing: SoftCredential = new_device.credentials[credential_of(new_device)]
    again = new_device.create(
        dict(await pw.passkeys.credential_registration_options(SCOPE)), credential=existing
    )
    with pytest.raises(CredentialChangeRefused) as refused:
        await pw.passkeys.credential_change_options(SCOPE, again)
    assert refused.value.reason == "credential_registered"


async def test_a_malformed_registration_is_refused(pw):
    await enrol(pw, CONTACT)
    new_device = SoftAuthenticator(ORIGIN)
    registration = new_device.create(dict(await pw.passkeys.credential_registration_options(SCOPE)))
    registration["response"] = {"clientDataJSON": registration["response"]["clientDataJSON"]}
    with pytest.raises(CredentialChangeRefused):
        await pw.passkeys.credential_change_options(SCOPE, registration)


async def test_replace_names_one_of_the_approvers_active_passkeys(pw):
    await enrol(pw, CONTACT)
    new_device = SoftAuthenticator(ORIGIN)
    registration = new_device.create(dict(await pw.passkeys.credential_registration_options(SCOPE)))
    with pytest.raises(CredentialChangeRefused) as refused:
        await pw.passkeys.credential_change_options(SCOPE, registration, replace=b"\x00" * 16)
    assert refused.value.reason == "not_active_credential"


async def test_nobody_maintains_credentials_during_a_recovery_cooling_off(pw):
    await enrol(pw, CONTACT)
    await designate(pw, "new@example.com")
    with pytest.raises(CredentialChangeRefused) as refused:
        await pw.passkeys.credential_registration_options(SCOPE)
    assert refused.value.reason == "not_in_effect"


async def test_an_approver_with_no_passkey_enrols_instead(pw):
    await designate(pw, CONTACT)
    with pytest.raises(CredentialChangeRefused) as refused:
        await pw.passkeys.credential_registration_options(SCOPE)
    assert refused.value.reason == "no_active_credential"


# Between options and effect


async def test_a_recovery_between_options_and_effect_refuses_the_change(pw):
    _, device = await enrol(pw, CONTACT)
    prepared = await prepare(pw.passkeys)
    assertion = device.get(prepared.options)
    await designate(pw, "new@example.com")
    count = await credential_count(pw)
    with pytest.raises((AuthenticationFailed, CredentialChangeRefused)):
        await pw.passkeys.change_credential(SCOPE, assertion, fence=Fence(pw.passkeys))
    assert await credential_count(pw) == count


async def test_a_retire_target_revoked_meanwhile_refuses_the_replace(pw):
    approver, device, second = await two_credentials(pw)
    prepared = await prepare(pw.passkeys, replace=credential_of(second))
    async with pw.passkeys.db.transaction() as tx:
        await pw.passkeys.revoke_passkey_in(
            tx,
            scope=SCOPE,
            subject=approver.subject,
            credential_id=credential_of(second),
            authorized_by="owner",
        )
    count = await credential_count(pw)
    with pytest.raises(CredentialChangeRefused) as refused:
        await pw.passkeys.change_credential(
            SCOPE, device.get(prepared.options), fence=Fence(pw.passkeys)
        )
    assert refused.value.reason == "stale_binding"
    assert await credential_count(pw) == count


async def test_an_expired_approval_of_the_change_is_refused(pw):
    _, device = await enrol(pw, CONTACT)
    prepared = await prepare(pw.passkeys)
    assertion = device.get(prepared.options)
    pw.clock.advance(FIVE_MINUTES)
    count = await credential_count(pw)
    with pytest.raises((AuthenticationFailed, CredentialChangeRefused)):
        await pw.passkeys.change_credential(SCOPE, assertion)
    assert await credential_count(pw) == count


async def test_an_expired_registration_refuses_a_fresh_approval(pw):
    """The registration's own deadline holds even when the assertion
    approving it is still fresh."""
    _, device = await enrol(pw, CONTACT)
    new_device = SoftAuthenticator(ORIGIN)
    registration_options = dict(await pw.passkeys.credential_registration_options(SCOPE))
    pw.clock.advance(timedelta(minutes=4))
    registration = new_device.create(registration_options)
    options = dict(await pw.passkeys.credential_change_options(SCOPE, registration))
    assertion = device.get(options)
    pw.clock.advance(timedelta(minutes=2))
    count = await credential_count(pw)
    with pytest.raises(CredentialChangeRefused) as refused:
        await pw.passkeys.change_credential(SCOPE, assertion)
    assert refused.value.reason == "expired"
    assert await credential_count(pw) == count


async def test_the_change_stays_within_five_minutes_whatever_the_challenge_ttl(pw):
    passkeys = world_with(pw, challenge_ttl=timedelta(minutes=30))
    _, device = await enrol(pw, CONTACT)
    prepared = await prepare(passkeys)
    assertion = device.get(prepared.options)
    pw.clock.advance(FIVE_MINUTES)
    count = await credential_count(pw)
    with pytest.raises((AuthenticationFailed, CredentialChangeRefused)):
        await passkeys.change_credential(SCOPE, assertion)
    assert await credential_count(pw) == count


async def test_a_deadline_passed_while_waiting_at_the_fence_refuses_the_effect(pw):
    _, device = await enrol(pw, CONTACT)
    prepared = await prepare(pw.passkeys)
    fence = Fence(pw.passkeys, hold=asyncio.Event())
    count = await credential_count(pw)
    change = asyncio.create_task(
        pw.passkeys.change_credential(
            SCOPE, device.get(prepared.options), fence=fence, receipt=receipt
        )
    )
    try:
        await asyncio.wait_for(fence.holding.wait(), WAIT)
        pw.clock.advance(FIVE_MINUTES)
        fence.hold.set()
        with pytest.raises(CredentialChangeRefused) as refused:
            await asyncio.wait_for(change, WAIT)
        assert refused.value.reason == "expired"
    finally:
        await settle(change)
    assert await credential_count(pw) == count
    assert await receipts(pw) == []


async def test_a_deadline_passed_while_waiting_for_a_lock_refuses_the_effect(pw):
    """The caller's own lock, which only the effect's fence takes, is held
    elsewhere while the deadline passes; the effect then refuses."""
    approver, device = await enrol(pw, CONTACT)
    prepared = await prepare(pw.passkeys)
    count = await credential_count(pw)
    change = None
    try:
        async with pw.passkeys.db.transaction() as blocker:
            await blocker.execute("SELECT pg_advisory_xact_lock($1::bigint)", CALLER_LOCK)
            change = asyncio.create_task(
                pw.passkeys.change_credential(
                    SCOPE, device.get(prepared.options), fence=Fence(pw.passkeys)
                )
            )
            await until_waiting(pw)
            pw.clock.advance(FIVE_MINUTES)
        with pytest.raises(CredentialChangeRefused) as refused:
            await asyncio.wait_for(change, WAIT)
        assert refused.value.reason == "expired"
    finally:
        await settle(change)
    assert await credential_count(pw) == count


# Notice contact


async def test_a_pending_contact_change_is_neither_told_nor_touched(pw):
    approver, device = await enrol(pw, CONTACT)
    options = await pw.passkeys.contact_change_options(SCOPE, "attacker@example.com")
    effective_at = await pw.passkeys.change_contact(
        SCOPE, "attacker@example.com", device.get(dict(options))
    )
    pw.contacts.notices.clear()
    await rotate(pw, device)
    assert list(pw.contacts.notices) == [CONTACT]
    pending = await pw.passkeys.db.fetch_one(
        "SELECT pending_contact, pending_contact_at FROM {{tables.passkey_approvers}} "
        "WHERE subject = $1",
        approver.subject,
    )
    assert (pending["pending_contact"], pending["pending_contact_at"]) == (
        "attacker@example.com",
        effective_at,
    )


async def test_the_notice_goes_to_the_contact_in_effect_at_the_effect(pw):
    """A contact change that takes effect between the options and the
    effect: the notice goes to the contact then in effect, not the one in
    effect when the options were issued."""
    _, device = await enrol(pw, CONTACT)
    options = await pw.passkeys.contact_change_options(SCOPE, "new@example.com")
    await pw.passkeys.change_contact(SCOPE, "new@example.com", device.get(dict(options)))
    await pw.passkeys.prove_contact(pw.contacts.proofs["new@example.com"][-1])
    pw.clock.advance(timedelta(hours=24) - timedelta(minutes=1))
    pw.contacts.notices.clear()
    prepared = await prepare(pw.passkeys)
    assertion = device.get(prepared.options)
    pw.clock.advance(timedelta(minutes=2))
    await pw.passkeys.change_credential(SCOPE, assertion)
    assert list(pw.contacts.notices) == ["new@example.com"]


async def test_a_failed_notice_leaves_the_change_committed(pw):
    approver, device = await enrol(pw, CONTACT)

    async def fail(contact, notice) -> DeliveryStatus:
        return DeliveryStatus.FAILED

    pw.contacts.deliver_notice = fail
    change, new_device = await rotate(pw, device, receipt=receipt)
    assert change.delivery is DeliveryStatus.FAILED
    assert credential_of(new_device) in await active_credentials(pw, approver.subject)
    [stored] = await receipts(pw)
    assert stored["credential_id"] == change.credential_id
    status = await pw.passkeys.credential_change_status(SCOPE, change.challenge)
    assert status.state is CredentialChangeState.COMMITTED


# Human-role holders


async def test_a_holder_with_a_notice_contact_maintains_its_bound_credentials(pw):
    member = holders.holder()
    await holders.designate(pw, member, notice=holders.NOTICE)
    prepared = await prepare(pw.passkeys, scope=holders.SCOPE)
    change = await pw.passkeys.change_credential(
        holders.SCOPE,
        member.device.get(prepared.options),
        fence=Fence(pw.passkeys, scope=holders.SCOPE),
    )
    [notice] = pw.contacts.notices[holders.NOTICE]
    assert notice.kind is NoticeKind.CREDENTIAL_ADDED
    bound = await pw.passkeys.db.fetch_value(
        "SELECT rp_id FROM {{tables.passkey_credentials}} WHERE credential_id = $1",
        change.credential_id,
    )
    assert bound == holders.RP_ID
    options = await pw.passkeys.login_options(holders.SCOPE)
    session = await pw.passkeys.verify_login(holders.SCOPE, prepared.new_device.get(options))
    assert session.subject == change.subject


async def test_a_holder_without_a_notice_contact_rotates_only_through_the_owner(pw):
    member = holders.holder()
    await holders.designate(pw, member)
    before = await pw.passkeys.db.fetch_value("SELECT count(*) FROM {{tables.passkey_challenges}}")
    with pytest.raises(CredentialChangeRefused) as refused:
        await pw.passkeys.credential_registration_options(holders.SCOPE)
    assert refused.value.reason == "no_notice_contact"
    after = await pw.passkeys.db.fetch_value("SELECT count(*) FROM {{tables.passkey_challenges}}")
    assert after == before
    await holders.replace(pw, holders.holder())


async def test_a_holder_whose_only_contact_is_pending_has_none(pw):
    member = holders.holder()
    await holders.designate(pw, member)
    await pw.passkeys.db.execute(
        "UPDATE {{tables.passkey_approvers}} SET pending_contact = $2, pending_contact_at = $3, "
        "pending_contact_proven_at = $4 WHERE scope = $1 AND superseded_at IS NULL",
        holders.SCOPE,
        holders.NOTICE,
        pw.clock() + timedelta(hours=24),
        pw.clock(),
    )
    with pytest.raises(CredentialChangeRefused) as refused:
        await pw.passkeys.credential_registration_options(holders.SCOPE)
    assert refused.value.reason == "no_notice_contact"


async def test_a_notice_contact_gone_by_the_effect_refuses_it(pw):
    member = holders.holder()
    await holders.designate(pw, member, notice=holders.NOTICE)
    prepared = await prepare(pw.passkeys, scope=holders.SCOPE)
    await pw.passkeys.db.execute(
        "UPDATE {{tables.passkey_approvers}} SET contact = NULL "
        "WHERE scope = $1 AND superseded_at IS NULL",
        holders.SCOPE,
    )
    before = await credential_count(pw)
    with pytest.raises(CredentialChangeRefused) as refused:
        await pw.passkeys.change_credential(
            holders.SCOPE,
            member.device.get(prepared.options),
            fence=Fence(pw.passkeys, scope=holders.SCOPE),
            receipt=receipt,
        )
    assert refused.value.reason == "no_notice_contact"
    assert await credential_count(pw) == before
    assert await receipts(pw) == []


async def test_a_credential_bound_to_another_relying_party_cannot_approve(pw):
    member = holders.holder()
    await holders.designate(pw, member, notice=holders.NOTICE)
    prepared = await prepare(pw.passkeys, scope=holders.SCOPE)
    await pw.passkeys.db.execute(
        "UPDATE {{tables.passkey_credentials}} SET rp_id = 'elsewhere.example.com' "
        "WHERE credential_id = $1",
        credential_of(member.device),
    )
    before = await credential_count(pw)
    with pytest.raises((AuthenticationFailed, CredentialChangeRefused)):
        await pw.passkeys.change_credential(
            holders.SCOPE,
            member.device.get(prepared.options),
            fence=Fence(pw.passkeys, scope=holders.SCOPE),
        )
    assert await credential_count(pw) == before


# Fence and receipt


async def test_the_fence_brackets_the_effect_and_its_receipt(pw):
    _, device = await enrol(pw, CONTACT)
    fence = Fence(pw.passkeys)
    change, _ = await rotate(pw, device, fence=fence, receipt=receipt)
    assert fence.calls == ["prepare", "check"]
    [stored] = await receipts(pw)
    assert (stored["challenge"], stored["credential_id"], stored["operation"]) == (
        change.challenge,
        change.credential_id,
        "add",
    )


@pytest.mark.parametrize("refuse", ["prepare", "check"])
async def test_a_refused_replace_changes_nothing(pw, refuse):
    approver, device, second = await two_credentials(pw)
    session = await login(pw, second)
    pending = await mint(pw)
    await decide(pw, pending, await ceremony(pw, pending, device))
    kinds = await pw.audit.kinds()
    before = await active_credentials(pw, approver.subject)
    prepared = await prepare(pw.passkeys, replace=credential_of(second))
    with pytest.raises(CredentialChangeRefused):
        await pw.passkeys.change_credential(
            SCOPE,
            device.get(prepared.options),
            fence=Fence(pw.passkeys, refuse=refuse),
            receipt=receipt,
        )
    assert await active_credentials(pw, approver.subject) == before
    assert await receipts(pw) == []
    assert "approver_passkey_replaced" not in (await pw.audit.kinds())[len(kinds) :]
    assert pw.contacts.notices.get(CONTACT, []) == []
    assert await pw.passkeys.login_evidence_is_current(SCOPE, session.subject, session.evidence_ref)
    assert (await pw.approvals.admit(pending.approval_id, REQUEST, "op-1")).first


async def test_a_fence_must_hand_back_b3s_own_preparation(pw):
    approver, device, second = await two_credentials(pw)
    before = await active_credentials(pw, approver.subject)
    prepared = await prepare(pw.passkeys, replace=credential_of(second))
    with pytest.raises(ValueError):
        await pw.passkeys.change_credential(
            SCOPE, device.get(prepared.options), fence=Fence(pw.passkeys, hand_back=False)
        )
    assert await active_credentials(pw, approver.subject) == before


async def test_a_handle_from_another_transaction_is_refused(pw):
    approver, device = await enrol(pw, CONTACT)
    async with pw.passkeys.db.transaction() as other:
        stale = await pw.passkeys.prepare_credential_change(other, scope=SCOPE)

    class Stale(Fence):
        async def prepare(self, tx):
            await super().prepare(tx)
            return stale

    before = await active_credentials(pw, approver.subject)
    prepared = await prepare(pw.passkeys)
    with pytest.raises(ValueError):
        await pw.passkeys.change_credential(
            SCOPE, device.get(prepared.options), fence=Stale(pw.passkeys)
        )
    assert await active_credentials(pw, approver.subject) == before


async def test_a_change_waits_behind_a_session_holding_the_approver(pw):
    """A console session prepares B3 FOR SHARE; the change waits for it,
    without deadlock, and then commits."""
    approver, device = await enrol(pw, CONTACT)
    prepared = await prepare(pw.passkeys)
    assertion = device.get(prepared.options)
    change = None
    try:
        async with pw.passkeys.db.transaction() as session:
            await pw.passkeys.prepare_current_approvers(session, [(SCOPE, approver.subject)])
            change = asyncio.create_task(
                pw.passkeys.change_credential(SCOPE, assertion, fence=Fence(pw.passkeys))
            )
            await until_waiting(pw)
            assert not change.done()
        await asyncio.wait_for(change, WAIT)
    finally:
        await settle(change)
    assert credential_of(prepared.new_device) in await active_credentials(pw, approver.subject)


# Cap


async def test_the_default_cap_is_five(pw):
    approver, device = await enrol(pw, CONTACT)
    for _ in range(4):
        await rotate(pw, device)
    assert len(await active_credentials(pw, approver.subject)) == 5
    with pytest.raises(CredentialChangeRefused) as refused:
        await prepare(pw.passkeys)
    assert refused.value.reason == "cap_reached"


async def test_at_a_cap_of_one_a_replace_works_and_an_add_refuses(pw):
    single = world_with(pw, credentials=CredentialPolicy(max_active=1))
    approver, device = await enrol(pw, CONTACT)
    with pytest.raises(CredentialChangeRefused) as refused:
        await prepare(single)
    assert refused.value.reason == "cap_reached"
    replaced = await prepare(single, replace=credential_of(device))
    await single.change_credential(SCOPE, device.get(replaced.options), fence=Fence(single))
    assert await active_credentials(pw, approver.subject) == {credential_of(replaced.new_device)}


async def test_a_lowered_cap_keeps_every_credential_and_refuses_adds(pw):
    approver, device = await enrol(pw, CONTACT)
    await rotate(pw, device)
    _, third = await rotate(pw, device)
    lowered = world_with(pw, credentials=CredentialPolicy(max_active=1))
    assert len(await active_credentials(pw, approver.subject)) == 3
    with pytest.raises(CredentialChangeRefused) as refused:
        await prepare(lowered)
    assert refused.value.reason == "cap_reached"
    replaced = await prepare(lowered, replace=credential_of(third))
    await lowered.change_credential(SCOPE, device.get(replaced.options), fence=Fence(lowered))
    assert len(await active_credentials(pw, approver.subject)) == 3


@pytest.mark.parametrize("max_active", [0, -1])
def test_a_cap_is_at_least_one(max_active):
    with pytest.raises(ValueError):
        CredentialPolicy(max_active=max_active)


def test_a_cap_above_the_deployment_ceiling_is_refused(pw):
    with pytest.raises(ValueError):
        world_with(
            pw,
            credentials=CredentialPolicy(max_active=6),
            credentials_ceiling=CredentialPolicy(max_active=5),
        )
    world_with(
        pw,
        credentials=CredentialPolicy(max_active=6),
        credentials_ceiling=CredentialPolicy(max_active=8),
    )


# Races


async def test_concurrent_adds_to_the_last_free_place_admit_one(pw):
    passkeys = world_with(pw, credentials=CredentialPolicy(max_active=3))
    approver, first, second = await two_credentials(pw)
    one, other = await prepare(passkeys), await prepare(passkeys)
    arrive = asyncio.Barrier(2)
    results = await race(
        passkeys.change_credential(
            SCOPE, first.get(one.options), fence=Fence(passkeys, arrive=arrive)
        ),
        passkeys.change_credential(
            SCOPE, second.get(other.options), fence=Fence(passkeys, arrive=arrive)
        ),
    )
    committed = [r for r in results if not isinstance(r, BaseException)]
    refused = [r for r in results if isinstance(r, BaseException)]
    assert len(committed) == 1
    assert len(refused) == 1 and isinstance(refused[0], CredentialChangeRefused)
    assert refused[0].reason == "cap_reached"
    assert len(await active_credentials(pw, approver.subject)) == 3


async def test_concurrent_replaces_of_one_passkey_admit_one(pw):
    approver, first, second = await two_credentials(pw)
    _, target = await rotate(pw, first)
    one = await prepare(pw.passkeys, replace=credential_of(target))
    other = await prepare(pw.passkeys, replace=credential_of(target))
    arrive = asyncio.Barrier(2)
    results = await race(
        pw.passkeys.change_credential(
            SCOPE, first.get(one.options), fence=Fence(pw.passkeys, arrive=arrive)
        ),
        pw.passkeys.change_credential(
            SCOPE, second.get(other.options), fence=Fence(pw.passkeys, arrive=arrive)
        ),
    )
    committed = [r for r in results if not isinstance(r, BaseException)]
    refused = [r for r in results if isinstance(r, BaseException)]
    assert len(committed) == 1
    assert len(refused) == 1 and isinstance(refused[0], CredentialChangeRefused)
    assert refused[0].reason == "stale_binding"
    active = await active_credentials(pw, approver.subject)
    assert credential_of(target) not in active and len(active) == 3


async def test_a_replace_racing_an_approvals_admission_has_one_order(pw):
    _, device, second = await two_credentials(pw)
    approved = await mint(pw)
    await decide(pw, approved, await ceremony(pw, approved, device))
    prepared = await prepare(pw.passkeys, replace=credential_of(second))
    replaced, admitted = await race(
        pw.passkeys.change_credential(
            SCOPE, device.get(prepared.options), fence=Fence(pw.passkeys)
        ),
        pw.approvals.admit(approved.approval_id, REQUEST, "op-1"),
    )
    assert replaced.operation == "replace"
    if isinstance(admitted, BaseException):
        # The void came first: the admission is refused as revoked.
        assert isinstance(admitted, ApprovalRefused) and admitted.reason is Refusal.REVOKED
    else:
        # The admission came first and stands.
        assert admitted.first


async def test_a_recovery_waits_for_a_change_in_flight_and_then_retires_it(pw):
    approver, device = await enrol(pw, CONTACT)
    prepared = await prepare(pw.passkeys)
    fence = Fence(pw.passkeys, hold=asyncio.Event())
    change = asyncio.create_task(
        pw.passkeys.change_credential(SCOPE, device.get(prepared.options), fence=fence)
    )
    recovery = None
    try:
        await asyncio.wait_for(fence.holding.wait(), WAIT)
        recovery = asyncio.create_task(designate(pw, "new@example.com"))
        await until_waiting(pw)
        fence.hold.set()
        committed = await asyncio.wait_for(change, WAIT)
        await asyncio.wait_for(recovery, WAIT)
    finally:
        await settle(change, recovery)
    status = await pw.passkeys.credential_change_status(SCOPE, committed.challenge)
    assert status.state is CredentialChangeState.COMMITTED
    assert await active_credentials(pw, approver.subject) == set()


@pytest.mark.parametrize("contact_act", ["change", "cancel"])
async def test_a_contact_act_waits_for_a_change_in_flight(pw, contact_act):
    _, device = await enrol(pw, CONTACT)
    if contact_act == "cancel":
        options = await pw.passkeys.contact_change_options(SCOPE, "new@example.com")
        await pw.passkeys.change_contact(SCOPE, "new@example.com", device.get(dict(options)))
        contact_options = await pw.passkeys.contact_cancel_options(SCOPE)
    else:
        contact_options = await pw.passkeys.contact_change_options(SCOPE, "other@example.com")
    contact_assertion = device.get(dict(contact_options))
    prepared = await prepare(pw.passkeys)
    fence = Fence(pw.passkeys, hold=asyncio.Event())
    pw.contacts.notices.clear()
    change = asyncio.create_task(
        pw.passkeys.change_credential(SCOPE, device.get(prepared.options), fence=fence)
    )
    contact = None
    try:
        await asyncio.wait_for(fence.holding.wait(), WAIT)
        contact = asyncio.create_task(
            pw.passkeys.change_contact(SCOPE, "other@example.com", contact_assertion)
            if contact_act == "change"
            else pw.passkeys.cancel_pending_contact(SCOPE, contact_assertion)
        )
        await until_waiting(pw)
        fence.hold.set()
        await asyncio.wait_for(change, WAIT)
        await asyncio.wait_for(contact, WAIT)
    finally:
        await settle(change, contact)
    told = [
        address
        for address, notices in pw.contacts.notices.items()
        for notice in notices
        if notice.kind is NoticeKind.CREDENTIAL_ADDED
    ]
    assert told == [CONTACT]


# Outcome after a lost response


async def test_a_committed_change_is_found_by_its_challenge_even_once_retired(pw):
    _, device = await enrol(pw, CONTACT)
    change, new_device = await rotate(pw, device)
    status = await pw.passkeys.credential_change_status(SCOPE, change.challenge)
    assert status.state is CredentialChangeState.COMMITTED
    assert status.change.credential_id == change.credential_id
    await rotate(pw, device, replace=credential_of(new_device))
    status = await pw.passkeys.credential_change_status(SCOPE, change.challenge)
    assert status.state is CredentialChangeState.COMMITTED


async def test_an_uncommitted_change_is_pending_until_its_deadline(pw):
    _, device = await enrol(pw, CONTACT)
    prepared = await prepare(pw.passkeys)
    with pytest.raises(CredentialChangeRefused):
        await pw.passkeys.change_credential(
            SCOPE, device.get(prepared.options), fence=Fence(pw.passkeys, refuse="prepare")
        )
    challenge = prepared.options["challenge"]
    status = await pw.passkeys.credential_change_status(SCOPE, challenge)
    assert status.state is CredentialChangeState.PENDING
    pw.clock.advance(FIVE_MINUTES)
    status = await pw.passkeys.credential_change_status(SCOPE, challenge)
    assert status.state is CredentialChangeState.SPENT_UNCOMMITTED


async def test_a_status_read_waits_for_a_change_in_flight(pw):
    _, device = await enrol(pw, CONTACT)
    prepared = await prepare(pw.passkeys)
    fence = Fence(pw.passkeys, hold=asyncio.Event())
    change = asyncio.create_task(
        pw.passkeys.change_credential(SCOPE, device.get(prepared.options), fence=fence)
    )
    status = None
    try:
        await asyncio.wait_for(fence.holding.wait(), WAIT)
        status = asyncio.create_task(
            pw.passkeys.credential_change_status(SCOPE, prepared.options["challenge"])
        )
        await until_waiting(pw)
        assert not status.done()
        fence.hold.set()
        await asyncio.wait_for(change, WAIT)
        read = await asyncio.wait_for(status, WAIT)
    finally:
        await settle(change, status)
    assert read.state is CredentialChangeState.COMMITTED


async def test_an_unknown_challenge_is_not_found(pw):
    await enrol(pw, CONTACT)
    status = await pw.passkeys.credential_change_status(SCOPE, "AAAA")
    assert status.state is CredentialChangeState.NOT_FOUND


# Unchanged


async def test_recovery_without_a_working_passkey_still_waits_out_the_cooling_off(pw):
    await enrol(pw, CONTACT)
    designation = await designate(pw, "new@example.com")
    assert designation.effective_at == pw.clock() + timedelta(hours=72)


# Upgrade


async def test_an_installation_populated_before_the_upgrade_keeps_working(
    test_db_factory, tmp_path
):
    """A credential enrolled before credential maintenance existed stays
    usable after the upgrade, and can then be maintained."""
    earlier = tmp_path / "migrations"
    earlier.mkdir()
    for migration in sorted(MIGRATIONS.glob("*.sql")):
        if migration.name < "005":
            shutil.copy(migration, earlier / migration.name)
    db = await test_db_factory.create_db(suffix="upgrade", schema="app")
    await AsyncMigrationManager(
        db, migrations_path=str(earlier), module_name=MIGRATION_MODULE
    ).apply_pending_migrations()
    clock = Clock()
    rp = RelyingParty(origin=ORIGIN, name="Example app")
    device = SoftAuthenticator(ORIGIN)
    enrolled = SoftCredential(
        b"\x01" * 32, ec.generate_private_key(ec.SECP256R1()), rp.rp_id, b"approver-1"
    )
    device.credentials[enrolled.credential_id] = enrolled
    await db.execute(
        "INSERT INTO {{tables.passkey_approvers}} (subject, scope, contact, designated_by, "
        "designated_at, effective_at) VALUES ('approver-1', $1, $2, 'owner', $3, $3)",
        SCOPE,
        CONTACT,
        clock(),
    )
    await db.execute(
        "INSERT INTO {{tables.passkey_credentials}} (credential_id, subject, public_key, "
        "sign_count, created_at) VALUES ($1, 'approver-1', $2, 0, $3)",
        enrolled.credential_id,
        enrolled.cose_public_key(),
        clock(),
    )
    audit = AuditOutbox(db)
    await audit.create()
    store = PgApprovalStore(db)
    await store.migrate()

    async def context(scope, *, tx):
        return PasskeyInstallationContext("fixture", "team", "installation", 1)

    passkeys = Passkeys(
        db,
        rp=rp,
        delivery=Contacts(),
        audit=audit,
        retirement=ApprovalRevocation(store, audit, clock),
        enrolment_ttl=timedelta(hours=1),
        challenge_ttl=FIVE_MINUTES,
        clock=clock,
        proof_context=context,
    )
    await passkeys.migrate()
    session = await passkeys.verify_login(
        SCOPE, device.get(dict(await passkeys.login_options(SCOPE)))
    )
    assert session.subject == "approver-1"
    prepared = await prepare(passkeys)
    change = await passkeys.change_credential(SCOPE, device.get(prepared.options))
    assert change.operation == "add"
