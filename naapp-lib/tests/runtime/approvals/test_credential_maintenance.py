"""Q1 credential maintenance: an in-effect approver adds a passkey, or replaces
one it selects, with a passkey it already holds, at once. The new credential
registers with user verification first; a current credential's assertion then
approves that exact credential and operation. Recovery without a working
passkey stays the owner's, after its cooling-off. Every ceremony is real
WebAuthn on real PostgreSQL."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import timedelta

import pytest
import pytest_asyncio
from aweb_naapp_testing.webauthn import SoftAuthenticator

from aweb_naapp.roles import apply_roles_migrations, is_holding_scope
from aweb_naapp.runtime.approvals import (
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
    Passkeys,
    prepare_retirement,
)
from tests.runtime.approvals import test_human_role_holders as holders
from tests.runtime.approvals.support import SCOPE
from tests.runtime.approvals.test_passkeys import (
    ORIGIN,
    REQUEST,
    PasskeyWorld,
    ceremony,
    decide,
    designate,
    enrol,
    login,
    mint,
    passkey_world,
    refusal,
)

CONTACT = "human@example.com"
# The installation the passkey world's proof context resolves every scope to.
INSTALLATION = AdmittedInstallation(
    team_id="team", app_id="fixture", installation_id="installation", generation=1
)
CALLER_LOCK = 0x46360000  # Stands in for the caller's F6 lock.
FIVE_MINUTES = timedelta(minutes=5)


@pytest_asyncio.fixture
async def pw(test_db_factory, registry) -> PasskeyWorld:
    """The passkey world of an app that also keeps human-role holdings."""
    world = await passkey_world(test_db_factory, registry, holding_scopes=is_holding_scope)
    await apply_roles_migrations(world.passkeys.db)
    return world


def credential_of(device: SoftAuthenticator) -> bytes:
    [credential_id] = device.credentials
    return credential_id


def only(device: SoftAuthenticator, credential_id: bytes) -> SoftAuthenticator:
    """An authenticator holding just one of `device`'s credentials."""
    single = SoftAuthenticator(ORIGIN)
    single.credentials[credential_id] = device.credentials[credential_id]
    return single


@dataclass
class Prepared:
    """A registered new credential and the assertion options approving it."""

    new_device: SoftAuthenticator
    options: dict
    replace: bytes | None


async def prepare(
    passkeys: Passkeys, *, replace: bytes | None = None, scope: str = SCOPE
) -> Prepared:
    new_device = SoftAuthenticator(ORIGIN)
    registration = new_device.create(dict(await passkeys.credential_registration_options(scope)))
    options = await passkeys.credential_change_options(scope, registration, replace=replace)
    return Prepared(new_device, dict(options), replace)


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
        **options,
    )


ROLE_HOLD = 0x524F4C45  # Stands in for the caller's actor and target role holds.
SESSION_HOLD = 0x53340000  # Stands in for the caller's S4 hold.


@dataclass
class Fence:
    """A caller's credential-change fence in the contracted order: its own
    lock (F6), the retirement gate, its role holds, then B3's write-locked
    preparation, then S4. It hands B3's handle back, records its calls, and
    can hold or refuse."""

    passkeys: Passkeys
    calls: list[str] = field(default_factory=list)
    refuse: str | None = None
    hold: asyncio.Event | None = None
    holding: asyncio.Event = field(default_factory=asyncio.Event)
    hand_back: bool = True

    async def prepare(self, tx):
        self.calls.append("prepare")
        await tx.execute("SELECT pg_advisory_xact_lock($1::bigint)", CALLER_LOCK)
        await prepare_retirement(tx, installation=INSTALLATION)
        await tx.execute("SELECT pg_advisory_xact_lock($1::bigint)", ROLE_HOLD)
        prepared = await self.passkeys.prepare_credential_change(tx, scope=SCOPE)
        await tx.execute("SELECT pg_advisory_xact_lock($1::bigint)", SESSION_HOLD)
        if self.refuse == "prepare":
            raise CredentialChangeRefused("completion_authority_unavailable")
        return prepared if self.hand_back else None

    async def check(self, tx) -> None:
        self.calls.append("check")
        if self.hold is not None:
            self.holding.set()
            await self.hold.wait()
        if self.refuse == "check":
            raise CredentialChangeRefused("completion_authority_unavailable")


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


async def test_an_add_tells_the_contact_and_voids_nothing(pw):
    _, device = await enrol(pw, CONTACT)
    approved = await mint(pw)
    await decide(pw, approved, await ceremony(pw, approved, device))
    change, new_device = await rotate(pw, device)
    [notice] = pw.contacts.notices[CONTACT]
    assert notice.kind is NoticeKind.CREDENTIAL_ADDED
    assert change.delivery is DeliveryStatus.DELIVERED
    assert (await pw.approvals.get(approved.approval_id)).state is ApprovalState.APPROVED


# Replace


async def test_a_replace_retires_only_the_selected_passkey(pw):
    approver, device = await enrol(pw, CONTACT)
    _, second = await rotate(pw, device)
    change, third = await rotate(pw, device, replace=credential_of(second))
    assert change.operation == "replace"
    assert change.retired_credential_id == credential_of(second)
    assert await active_credentials(pw, approver.subject) == {
        credential_of(device),
        credential_of(third),
    }
    with pytest.raises(AuthenticationFailed):
        await login(pw, second)
    [_, notice] = pw.contacts.notices[CONTACT]
    assert notice.kind is NoticeKind.CREDENTIAL_REPLACED
    assert "approver_passkey_replaced" in await pw.audit.kinds()


async def test_a_passkey_can_replace_itself(pw):
    approver, device = await enrol(pw, CONTACT)
    _, new_device = await rotate(pw, device, replace=credential_of(device))
    assert await active_credentials(pw, approver.subject) == {credential_of(new_device)}
    assert (await login(pw, new_device)).subject == approver.subject


async def test_a_replace_ends_the_retired_passkeys_sessions_only(pw):
    _, device = await enrol(pw, CONTACT)
    _, second = await rotate(pw, device)
    kept = await login(pw, device)
    ended = await login(pw, second)
    await rotate(pw, device, replace=credential_of(second))
    assert await pw.passkeys.login_evidence_is_current(SCOPE, kept.subject, kept.evidence_ref)
    assert not await pw.passkeys.login_evidence_is_current(SCOPE, ended.subject, ended.evidence_ref)


async def test_a_replace_voids_the_holders_live_approvals(pw):
    """Re-approval cost: a replace voids every live approval the holder
    decided, not only those its retired passkey decided."""
    _, device = await enrol(pw, CONTACT)
    approved = await mint(pw)
    await decide(pw, approved, await ceremony(pw, approved, device))
    _, second = await rotate(pw, device)
    await rotate(pw, device, replace=credential_of(second))
    assert await refusal(pw.approvals.admit(approved.approval_id, REQUEST, "op-1")) is (
        Refusal.REVOKED
    )


# Who may approve the change


async def test_the_new_passkey_cannot_approve_its_own_change(pw):
    approver, device = await enrol(pw, CONTACT)
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


async def test_an_assertion_approves_one_change_only(pw):
    _, device = await enrol(pw, CONTACT)
    prepared = await prepare(pw.passkeys)
    assertion = device.get(prepared.options)
    await pw.passkeys.change_credential(SCOPE, assertion)
    count = await credential_count(pw)
    with pytest.raises(AuthenticationFailed):
        await pw.passkeys.change_credential(SCOPE, assertion)
    assert await credential_count(pw) == count


async def test_a_registration_is_bound_into_one_change_only(pw):
    _, device = await enrol(pw, CONTACT)
    new_device = SoftAuthenticator(ORIGIN)
    registration = new_device.create(dict(await pw.passkeys.credential_registration_options(SCOPE)))
    await pw.passkeys.credential_change_options(SCOPE, registration)
    with pytest.raises(CredentialChangeRefused):
        await pw.passkeys.credential_change_options(SCOPE, registration)


async def test_a_registered_credential_cannot_be_added_again(pw):
    _, device = await enrol(pw, CONTACT)
    new_device = SoftAuthenticator(ORIGIN)
    first = new_device.create(dict(await pw.passkeys.credential_registration_options(SCOPE)))
    options = await pw.passkeys.credential_change_options(SCOPE, first)
    await pw.passkeys.change_credential(SCOPE, device.get(dict(options)))
    again = SoftAuthenticator(ORIGIN)
    again.credentials = dict(new_device.credentials)
    replay = again.create(dict(await pw.passkeys.credential_registration_options(SCOPE)))
    replay["id"] = first["id"]
    replay["rawId"] = first["rawId"]
    with pytest.raises(CredentialChangeRefused):
        await pw.passkeys.credential_change_options(SCOPE, replay)


async def test_replace_names_one_of_the_approvers_active_passkeys(pw):
    _, device = await enrol(pw, CONTACT)
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
        await pw.passkeys.change_credential(SCOPE, assertion)
    assert await credential_count(pw) == count


async def test_a_retire_target_revoked_meanwhile_refuses_the_replace(pw):
    approver, device = await enrol(pw, CONTACT)
    _, second = await rotate(pw, device)
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


async def test_the_change_stays_within_five_minutes_whatever_the_challenge_ttl(pw):
    passkeys = world_with(pw, challenge_ttl=timedelta(minutes=30))
    _, device = await enrol(pw, CONTACT)
    prepared = await prepare(passkeys)
    assertion = device.get(prepared.options)
    pw.clock.advance(FIVE_MINUTES)
    with pytest.raises((AuthenticationFailed, CredentialChangeRefused)):
        await passkeys.change_credential(SCOPE, assertion)


async def test_a_deadline_passed_while_waiting_for_the_effect_refuses_it(pw):
    approver, device = await enrol(pw, CONTACT)
    prepared = await prepare(pw.passkeys)
    assertion = device.get(prepared.options)
    fence = Fence(pw.passkeys, hold=asyncio.Event())
    count = await credential_count(pw)
    change = asyncio.create_task(pw.passkeys.change_credential(SCOPE, assertion, fence=fence))
    await fence.holding.wait()
    pw.clock.advance(FIVE_MINUTES)
    fence.hold.set()
    with pytest.raises(CredentialChangeRefused) as refused:
        await change
    assert refused.value.reason == "expired"
    assert await credential_count(pw) == count


# Fence and receipt


async def test_a_fence_must_hand_back_b3s_own_preparation(pw):
    approver, device = await enrol(pw, CONTACT)
    _, second = await rotate(pw, device)
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
    async with pw.passkeys.db.transaction() as session:
        await pw.passkeys.prepare_current_approvers(session, [(SCOPE, approver.subject)])
        change = asyncio.create_task(
            pw.passkeys.change_credential(SCOPE, assertion, fence=Fence(pw.passkeys))
        )
        await asyncio.sleep(0.2)
        assert not change.done()
    await asyncio.wait_for(change, timeout=10)
    assert credential_of(prepared.new_device) in await active_credentials(pw, approver.subject)


async def test_a_replace_racing_an_approvals_admission_has_one_order(pw):
    _, device = await enrol(pw, CONTACT)
    approved = await mint(pw)
    await decide(pw, approved, await ceremony(pw, approved, device))
    _, second = await rotate(pw, device)
    prepared = await prepare(pw.passkeys, replace=credential_of(second))
    replaced, admitted = await asyncio.gather(
        pw.passkeys.change_credential(
            SCOPE, device.get(prepared.options), fence=Fence(pw.passkeys)
        ),
        pw.approvals.admit(approved.approval_id, REQUEST, "op-1"),
        return_exceptions=True,
    )
    assert not isinstance(replaced, BaseException)
    # Either the admission came first and stands, or the void came first and it is refused.
    if isinstance(admitted, BaseException):
        assert await refusal(pw.approvals.admit(approved.approval_id, REQUEST, "op-2")) is (
            Refusal.REVOKED
        )
    else:
        assert admitted.first


async def test_the_fence_brackets_the_effect_and_its_refusal_rolls_back(pw):
    approver, device = await enrol(pw, CONTACT)
    for refuse in ("prepare", "check"):
        prepared = await prepare(pw.passkeys)
        fence = Fence(pw.passkeys, refuse=refuse)
        count = await credential_count(pw)
        with pytest.raises(CredentialChangeRefused):
            await pw.passkeys.change_credential(SCOPE, device.get(prepared.options), fence=fence)
        assert await credential_count(pw) == count
        assert pw.contacts.notices.get(CONTACT, []) == []
    fence = Fence(pw.passkeys)
    await rotate(pw, device, fence=fence)
    assert fence.calls == ["prepare", "check"]


async def test_the_receipt_is_written_with_the_effect(pw):
    _, device = await enrol(pw, CONTACT)
    received = []

    async def receipt(tx, change) -> None:
        received.append((await tx.fetch_value("SELECT txid_current()"), change))

    fence = Fence(pw.passkeys, refuse="check")
    prepared = await prepare(pw.passkeys)
    with pytest.raises(CredentialChangeRefused):
        await pw.passkeys.change_credential(
            SCOPE, device.get(prepared.options), fence=fence, receipt=receipt
        )
    change, _ = await rotate(pw, device, receipt=receipt)
    assert [entry[1] for entry in received][-1] == change


# Notices


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


async def test_a_failed_notice_leaves_the_change_committed(pw):
    approver, device = await enrol(pw, CONTACT)

    async def fail(contact, notice) -> DeliveryStatus:
        return DeliveryStatus.FAILED

    pw.contacts.deliver_notice = fail
    change, new_device = await rotate(pw, device)
    assert change.delivery is DeliveryStatus.FAILED
    assert credential_of(new_device) in await active_credentials(pw, approver.subject)


async def test_a_holder_without_a_notice_contact_rotates_only_through_the_owner(pw):
    world = pw
    member = holders.holder()
    await holders.designate(world, member)
    before = await world.passkeys.db.fetch_value(
        "SELECT count(*) FROM {{tables.passkey_challenges}}"
    )
    with pytest.raises(CredentialChangeRefused) as refused:
        await world.passkeys.credential_registration_options(holders.SCOPE)
    assert refused.value.reason == "no_notice_contact"
    assert (
        await world.passkeys.db.fetch_value("SELECT count(*) FROM {{tables.passkey_challenges}}")
        == before
    )


# Cap


async def test_a_full_set_refuses_an_add_and_allows_a_replace(pw):
    passkeys = world_with(pw, credentials=CredentialPolicy(max_active=2))
    approver, device = await enrol(pw, CONTACT)
    prepared = await prepare(passkeys)
    await passkeys.change_credential(SCOPE, device.get(prepared.options))
    with pytest.raises(CredentialChangeRefused) as refused:
        await prepare(passkeys)
    assert refused.value.reason == "cap_reached"
    second = credential_of(prepared.new_device)
    replaced = await prepare(passkeys, replace=second)
    await passkeys.change_credential(SCOPE, device.get(replaced.options), fence=Fence(passkeys))
    assert len(await active_credentials(pw, approver.subject)) == 2


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


async def test_concurrent_adds_to_the_last_free_place_admit_one(pw):
    passkeys = world_with(pw, credentials=CredentialPolicy(max_active=2))
    approver, device = await enrol(pw, CONTACT)
    first, second = await prepare(passkeys), await prepare(passkeys)
    results = await asyncio.gather(
        passkeys.change_credential(SCOPE, device.get(first.options), fence=Fence(passkeys)),
        passkeys.change_credential(SCOPE, device.get(second.options), fence=Fence(passkeys)),
        return_exceptions=True,
    )
    refused = [r for r in results if isinstance(r, CredentialChangeRefused)]
    assert len(refused) == 1 and refused[0].reason == "cap_reached"
    assert len(await active_credentials(pw, approver.subject)) == 2


async def test_concurrent_replaces_of_one_passkey_admit_one(pw):
    approver, device = await enrol(pw, CONTACT)
    _, second = await rotate(pw, device)
    first = await prepare(pw.passkeys, replace=credential_of(second))
    other = await prepare(pw.passkeys, replace=credential_of(second))
    results = await asyncio.gather(
        pw.passkeys.change_credential(SCOPE, device.get(first.options), fence=Fence(pw.passkeys)),
        pw.passkeys.change_credential(SCOPE, device.get(other.options), fence=Fence(pw.passkeys)),
        return_exceptions=True,
    )
    refused = [r for r in results if isinstance(r, CredentialChangeRefused)]
    assert len(refused) == 1 and refused[0].reason == "stale_binding"
    assert len(await active_credentials(pw, approver.subject)) == 2


# Outcome after a lost response


async def test_a_committed_change_is_found_by_its_challenge(pw):
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
    assertion = device.get(prepared.options)
    with pytest.raises(CredentialChangeRefused):
        await pw.passkeys.change_credential(
            SCOPE, assertion, fence=Fence(pw.passkeys, refuse="prepare")
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
    await fence.holding.wait()
    status = asyncio.create_task(
        pw.passkeys.credential_change_status(SCOPE, prepared.options["challenge"])
    )
    await asyncio.sleep(0.2)
    assert not status.done()
    fence.hold.set()
    await change
    assert (await status).state is CredentialChangeState.COMMITTED


async def test_an_unknown_challenge_is_not_found(pw):
    await enrol(pw, CONTACT)
    status = await pw.passkeys.credential_change_status(SCOPE, "AAAA")
    assert status.state is CredentialChangeState.NOT_FOUND


# Unchanged


async def test_recovery_without_a_working_passkey_still_waits_out_the_cooling_off(pw):
    await enrol(pw, CONTACT)
    designation = await designate(pw, "new@example.com")
    assert designation.effective_at == pw.clock() + timedelta(hours=72)
