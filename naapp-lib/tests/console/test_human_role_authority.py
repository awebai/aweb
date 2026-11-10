# ruff: noqa: F811 -- pw is the imported real passkey composition fixture.
"""The console handoff's authority over a human-role holding
(human-role-holders.md, Reading a holding; handoff_authority.HandoffAuthority),
on the shared holding store, B3 and the installation fence, on real PostgreSQL
with real owner acts.

A public scope selects a holding and proves nothing. Projection reads the
current holding; the hold takes the fence, then the holding, then B3, and
compares the holding's version and credential with what was projected, so a
revocation or replacement in between refuses rather than retargets.
"""

from __future__ import annotations

import asyncio
import dataclasses
import time
from types import SimpleNamespace

import pytest
from asyncpg.exceptions import LockNotAvailableError
from aweb_naapp_testing.owner_acts import APP_ID, INSTALLATION_ID, TEAM_ID
from fastapi import HTTPException

from aweb_naapp.console.handoff_authority import PublicScope
from aweb_naapp.console.human_role_authority import HumanRoleHandoffAuthority
from aweb_naapp.runtime.authorization import Grant, GrantUnavailable
from aweb_naapp.runtime.clock import seconds_to_ns
from aweb_naapp.runtime.human_roles import HumanRoleHoldings
from aweb_naapp.runtime.installation import (
    InstallationFence,
    InstallationRefused,
    apply_installation_migrations,
)
from tests.runtime.approvals.test_human_role_holders import (
    CERTIFICATE,
    OTHER_PRINCIPAL,
    PRINCIPAL,
    ROLE,
    SCOPE,
    PasskeyWorld,
    designate,
    holder,
    owner,
    pw,  # noqa: F401
    replace,
    revoke,
)

PUBLIC = PublicScope(installation_id=INSTALLATION_ID, role=ROLE, principal=PRINCIPAL)
OTHER_ROLE = "example.auditor"


class Installations:
    """The app's installation in TEAM_ID as the team server reports it: active
    unless ``state`` says otherwise, and unreachable while ``unreachable``."""

    def __init__(self) -> None:
        self.state = "active"
        self.unreachable = False
        self.grant = Grant(
            team_id=TEAM_ID,
            installation_id=INSTALLATION_ID,
            generation=1,
            scopes=frozenset(),
            fresh_until=time.monotonic_ns() + seconds_to_ns(55),
        )

    async def grant_for(self, team_id, certificate_id=None):
        return self.grant if team_id == TEAM_ID else None

    async def status_for(self, team_id):
        if self.unreachable:
            raise GrantUnavailable()
        if team_id != TEAM_ID:
            return None
        return SimpleNamespace(
            team_id=TEAM_ID,
            app_id=APP_ID,
            state=self.state,
            installation_id=INSTALLATION_ID,
            generation=1,
            granted_scopes=self.grant.scopes,
            fresh_until=self.grant.fresh_until,
        )


async def authority_for(
    pw: PasskeyWorld,
    role: str = ROLE,
    *,
    declared: frozenset[str] = frozenset({ROLE}),
    installations: Installations | None = None,
) -> HumanRoleHandoffAuthority:
    db = pw.passkeys.db
    await apply_installation_migrations(db)
    fence = InstallationFence(db, app_id=APP_ID, grants=installations or Installations())
    await fence.refresh(TEAM_ID)
    return HumanRoleHandoffAuthority(
        role=role,
        holdings=HumanRoleHoldings(roles=declared, passkeys=pw.passkeys),
        fence=fence,
        passkeys=pw.passkeys,
    )


async def designate_other_role(pw: PasskeyWorld):
    """The owner names PRINCIPAL as holder of OTHER_ROLE too, with its own
    credential."""
    member = holder()
    subject = {
        "app_id": APP_ID,
        "installation_id": INSTALLATION_ID,
        "role": OTHER_ROLE,
        "principal": PRINCIPAL,
        "credential_sha256": member.credential.sha256,
    }
    signer = owner(pw)
    prepared = await signer.prepare("human-role.designate", subject)
    async with pw.passkeys.db.transaction() as tx:
        verified = await signer.consume(tx, prepared, subject)
        return await pw.passkeys.designate_holder(
            tx,
            act=verified,
            credential=member.credential,
            certificate=CERTIFICATE,
            notice_contact=None,
        )


def refusal(raised: pytest.ExceptionInfo[HTTPException]) -> tuple[int, str]:
    return raised.value.status_code, raised.value.detail


# Projection


async def test_a_credential_target_names_the_holdings_scope_and_grants_nothing(pw: PasskeyWorld):
    authority = await authority_for(pw)
    target = await authority.credential_target(PUBLIC)
    assert (target.b3_scope, target.team_id, target.admitted.installation_id) == (
        SCOPE,
        TEAM_ID,
        INSTALLATION_ID,
    )
    with pytest.raises(HTTPException) as refused:
        await authority.session_target(PUBLIC)
    assert refusal(refused) == (403, "role_not_held")


@pytest.mark.parametrize(
    "scope",
    [
        PublicScope(INSTALLATION_ID, "example.other", PRINCIPAL),
        PublicScope(INSTALLATION_ID, ROLE, "alice"),
        PublicScope("6f9619ff-8b86-4011-b42d-00c04fc964ff", ROLE, PRINCIPAL),
        PublicScope("", ROLE, PRINCIPAL),
        SimpleNamespace(installation_id=INSTALLATION_ID, role=ROLE),
    ],
    ids=["undeclared role", "not a did:aw", "another installation", "no installation", "partial"],
)
async def test_a_public_scope_selects_nothing_but_its_own_holding(pw: PasskeyWorld, scope):
    authority = await authority_for(pw)
    await designate(pw, holder())
    with pytest.raises(HTTPException) as refused:
        await authority.credential_target(scope)
    assert refusal(refused) == (403, "role_not_held")


async def test_a_session_target_is_the_current_holder_and_its_credential(pw: PasskeyWorld):
    authority = await authority_for(pw)
    designation = await designate(pw, holder())
    target = await authority.session_target(PUBLIC)
    assert (target.b3_scope, target.subject) == (SCOPE, designation.approver.subject)
    assert target.public_scope.principal == PRINCIPAL


async def test_a_holder_whose_credential_is_being_replaced_must_sign_in_again(pw: PasskeyWorld):
    authority = await authority_for(pw)
    await designate(pw, holder())
    await replace(pw, holder())
    with pytest.raises(HTTPException) as refused:
        await authority.session_target(PUBLIC)
    assert refusal(refused) == (401, "console_session_required")


async def test_another_principal_s_scope_reads_another_holding(pw: PasskeyWorld):
    authority = await authority_for(pw)
    await designate(pw, holder())
    with pytest.raises(HTTPException) as refused:
        await authority.session_target(PublicScope(INSTALLATION_ID, ROLE, OTHER_PRINCIPAL))
    assert refusal(refused) == (403, "role_not_held")


# Hold and check


async def test_a_hold_returns_the_complete_union_for_downstream_reuse(pw: PasskeyWorld):
    authority = await authority_for(pw)
    designation = await designate(pw, holder())
    target = await authority.session_target(PUBLIC)
    pair = (SCOPE, designation.approver.subject)
    async with pw.passkeys.db.transaction() as tx:
        held = await authority.hold_session_target(tx, target, approver_pairs=[pair, pair])
        assert held.target is target
        assert tuple(held.approver_pairs) == (pair,)
        assert await authority.check_session_target(tx, held)
        again = await authority.hold_session_target(tx, held, approver_pairs=[pair])
        assert again is held


async def test_the_union_must_include_the_targets_own_pair(pw: PasskeyWorld):
    authority = await authority_for(pw)
    await designate(pw, holder())
    target = await authority.session_target(PUBLIC)
    for pairs in ([], [("other.scope", "someone")], "not pairs"):
        async with pw.passkeys.db.transaction() as tx:
            with pytest.raises(HTTPException) as refused:
                await authority.hold_session_target(tx, target, approver_pairs=pairs)
        assert refusal(refused) == (403, "role_not_held"), pairs


async def test_a_revocation_between_projection_and_hold_refuses(pw: PasskeyWorld):
    authority = await authority_for(pw)
    designation = await designate(pw, holder())
    target = await authority.session_target(PUBLIC)
    await revoke(pw)
    async with pw.passkeys.db.transaction() as tx:
        with pytest.raises(HTTPException) as refused:
            await authority.hold_session_target(
                tx, target, approver_pairs=[(SCOPE, designation.approver.subject)]
            )
    assert refusal(refused) == (403, "role_not_held")


async def test_a_holding_held_again_does_not_heal_an_earlier_target(pw: PasskeyWorld):
    authority = await authority_for(pw)
    member = holder()
    first = await designate(pw, member)
    target = await authority.session_target(PUBLIC)
    await revoke(pw)
    await designate(pw, holder())
    async with pw.passkeys.db.transaction() as tx:
        with pytest.raises(HTTPException) as refused:
            await authority.hold_session_target(
                tx, target, approver_pairs=[(SCOPE, first.approver.subject)]
            )
    assert refusal(refused) == (403, "role_not_held")


async def test_a_replacement_between_projection_and_hold_requires_signing_in_again(
    pw: PasskeyWorld,
):
    authority = await authority_for(pw)
    designation = await designate(pw, holder())
    target = await authority.session_target(PUBLIC)
    await replace(pw, holder())
    async with pw.passkeys.db.transaction() as tx:
        with pytest.raises(HTTPException) as refused:
            await authority.hold_session_target(
                tx, target, approver_pairs=[(SCOPE, designation.approver.subject)]
            )
    assert refusal(refused) == (401, "console_session_required")


async def test_only_the_returned_handle_checks_and_only_in_its_own_transaction(
    pw: PasskeyWorld,
):
    authority = await authority_for(pw)
    designation = await designate(pw, holder())
    target = await authority.session_target(PUBLIC)
    pair = (SCOPE, designation.approver.subject)
    async with pw.passkeys.db.transaction() as tx:
        held = await authority.hold_session_target(tx, target, approver_pairs=[pair])
        copied = dataclasses.replace(held)
        assert not await authority.check_session_target(tx, copied)
        async with pw.passkeys.db.transaction() as other:
            assert not await authority.check_session_target(other, held)
        assert await authority.check_session_target(tx, held)


async def test_a_hold_serializes_a_revocation_until_the_holder_s_transaction_ends(
    pw: PasskeyWorld,
):
    authority = await authority_for(pw)
    designation = await designate(pw, holder())
    target = await authority.session_target(PUBLIC)
    pair = (SCOPE, designation.approver.subject)
    writer: list[int] = []

    async def revoking_writer() -> None:
        async with pw.passkeys.db.transaction() as wtx:
            writer.append(await wtx.fetch_value("SELECT pg_backend_pid()"))
            await revoke(pw, wtx)

    revoking: asyncio.Task[None] | None = None
    try:
        async with pw.passkeys.db.transaction() as tx:
            held = await authority.hold_session_target(tx, target, approver_pairs=[pair])
            holding_pid = await tx.fetch_value("SELECT pg_backend_pid()")
            revoking = asyncio.create_task(revoking_writer())
            # The writer's own backend waits on this transaction's hold.
            try:
                async with asyncio.timeout(10):
                    while not (
                        writer
                        and await tx.fetch_value(
                            "SELECT $1 = ANY(pg_blocking_pids($2))", holding_pid, writer[0]
                        )
                    ):
                        await asyncio.sleep(0.02)
            except TimeoutError:
                pytest.fail("the revocation never waited on the hold")
            assert not revoking.done()
            assert await authority.check_session_target(tx, held)
        await asyncio.wait_for(revoking, 10)
    finally:
        if revoking is not None and not revoking.done():
            revoking.cancel()
            await asyncio.gather(revoking, return_exceptions=True)
    with pytest.raises(HTTPException) as refused:
        await authority.session_target(PUBLIC)
    assert refusal(refused) == (403, "role_not_held")


async def test_a_target_projected_for_another_role_is_never_held(pw: PasskeyWorld):
    """One store declaring two roles: a real target of the other role's
    authority, with its own pair, is refused, not held under this role."""
    declared = frozenset({ROLE, OTHER_ROLE})
    reader = await authority_for(pw, ROLE, declared=declared)
    auditor = await authority_for(pw, OTHER_ROLE, declared=declared)
    await designate(pw, holder())
    await designate_other_role(pw)
    theirs = await auditor.session_target(PublicScope(INSTALLATION_ID, OTHER_ROLE, PRINCIPAL))
    async with pw.passkeys.db.transaction() as tx:
        with pytest.raises(HTTPException) as refused:
            await reader.hold_session_target(
                tx, theirs, approver_pairs=[(theirs.b3_scope, theirs.subject)]
            )
    assert refusal(refused) == (403, "role_not_held")


async def test_a_target_whose_selector_names_another_installation_is_never_held(
    pw: PasskeyWorld,
):
    authority = await authority_for(pw)
    designation = await designate(pw, holder())
    target = await authority.session_target(PUBLIC)
    moved = dataclasses.replace(
        target,
        public_scope=PublicScope("6f9619ff-8b86-4011-b42d-00c04fc964ff", ROLE, PRINCIPAL),
    )
    async with pw.passkeys.db.transaction() as tx:
        with pytest.raises(HTTPException) as refused:
            await authority.hold_session_target(
                tx, moved, approver_pairs=[(SCOPE, designation.approver.subject)]
            )
    assert refusal(refused) == (403, "role_not_held")


async def test_a_hold_locks_the_holding_itself_not_only_its_credential(pw: PasskeyWorld):
    """While the prepared authority is retained, the holding's assignment and
    record cannot be locked for writing, whatever B3 holds."""
    authority = await authority_for(pw)
    designation = await designate(pw, holder())
    target = await authority.session_target(PUBLIC)
    pair = (SCOPE, designation.approver.subject)
    assignment = (
        "SELECT 1 FROM {{tables.role_assignments}}"
        " WHERE team_id = $1 AND role = $2 AND principal_did = $3 FOR UPDATE NOWAIT"
    )
    record = "SELECT 1 FROM {{tables.role_holdings}} WHERE b3_scope = $1 FOR UPDATE NOWAIT"
    async with pw.passkeys.db.transaction() as tx:
        await authority.hold_session_target(tx, target, approver_pairs=[pair])
        async with pw.passkeys.db.transaction() as probe:
            with pytest.raises(LockNotAvailableError):
                await probe.fetch_value(assignment, TEAM_ID, ROLE, PRINCIPAL)
        async with pw.passkeys.db.transaction() as probe:
            with pytest.raises(LockNotAvailableError):
                await probe.fetch_value(record, SCOPE)
    async with pw.passkeys.db.transaction() as probe:
        assert await probe.fetch_value(assignment, TEAM_ID, ROLE, PRINCIPAL) == 1


async def test_an_inactive_installation_holds_nothing(pw: PasskeyWorld):
    installations = Installations()
    authority = await authority_for(pw, installations=installations)
    await designate(pw, holder())
    installations.state = "inactive"
    with pytest.raises(HTTPException) as refused:
        await authority.session_target(PUBLIC)
    assert refusal(refused) == (403, "role_not_held")


async def test_an_unreachable_installation_authority_is_not_a_lost_holding(pw: PasskeyWorld):
    installations = Installations()
    authority = await authority_for(pw, installations=installations)
    await designate(pw, holder())
    installations.unreachable = True
    with pytest.raises(InstallationRefused) as refused:
        await authority.session_target(PUBLIC)
    assert (refused.value.status, refused.value.code) == (503, "authority_unavailable")
