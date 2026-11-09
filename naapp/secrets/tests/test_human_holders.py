"""Existing-records owner projection, not certificate or session authentication.

The shared handoff API is still structural. These tests use real owner acts,
B3 enrolment and PostgreSQL, and retain authority only in the caller's tx.
"""

import asyncio
from dataclasses import dataclass, replace

import pytest
from aweb_naapp.roles import assign, unassign
from aweb_naapp.runtime.installation import InstallationRefused
from aweb_naapp_testing.owner_acts import INSTALLATION_ID
from fastapi import HTTPException
from pgdbm.core import TransactionManager

from aweb_secrets.console import OwnerConsole
from aweb_secrets.installation_lookup import InstallationLookup
from aweb_secrets.owners import OWNER_ROLE, owner_scope
from tests.test_owner_bootstrap import ALICE, BOB, TEAM, _apply, _enrol
from tests.test_owner_bootstrap import world as world


@dataclass(frozen=True)
class PublicScope:
    installation_id: str = INSTALLATION_ID
    role: str = OWNER_ROLE
    principal: str = ALICE.principal_did


def authority(w):
    # Use the production lookup rather than the bootstrap fixture's ID-only shortcut.
    from aweb_secrets.human_holders import OwnerHoldingAuthority

    return OwnerHoldingAuthority(
        console=OwnerConsole(
            db=w.db,
            passkeys=w.passkeys,
            directory=w.directory,
            fence=w.console.fence,
            verifier=w.owner.verifier,
            installation=InstallationLookup(w.console.fence),
            credential_audit=w.credential_audit,
        )
    )


@pytest.fixture
async def enrolled(world):
    await _apply(world, "app-role.designate", ALICE, "alice@example.com")
    await _enrol(world, "alice@example.com")
    return world


async def test_registration_target_grants_no_holding(world):
    service = authority(world)
    target = await service.credential_target(PublicScope())
    assert target.team_id == TEAM
    assert target.b3_scope == owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did)
    with pytest.raises(HTTPException) as refused:
        await service.session_target(PublicScope())
    assert (refused.value.status_code, refused.value.detail) == (403, "owner_required")
    assert not await world.directory.owner_of(world.db, target.b3_scope)


async def test_projection_uses_the_exact_existing_owner_and_b3_subject(enrolled):
    service = authority(enrolled)
    target = await service.session_target(PublicScope())
    scope = owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did)
    approver = await enrolled.passkeys.designated_approver(scope)
    assert approver is not None
    assert (target.team_id, target.b3_scope, target.subject) == (TEAM, scope, approver.subject)
    assert target.public_scope.installation_id == INSTALLATION_ID
    assert target.public_scope.role == OWNER_ROLE
    assert target.public_scope.principal == ALICE.principal_did
    assert target.admitted == enrolled.admitted


@pytest.mark.parametrize(
    "public_scope",
    [
        PublicScope(role="logs.reader"),
        PublicScope(principal=BOB.principal_did),
        PublicScope(installation_id="6f9619ff-8b86-4011-b42d-00c04fc964ff"),
    ],
    ids=["wrong-role", "another-principal", "another-installation"],
)
async def test_public_scope_cannot_select_another_holding(enrolled, public_scope):
    with pytest.raises(HTTPException) as refused:
        await authority(enrolled).session_target(public_scope)
    assert (refused.value.status_code, refused.value.detail) == (403, "owner_required")


async def test_unenrolled_designation_is_not_a_session_target(world):
    await _apply(world, "app-role.designate", ALICE, "alice@example.com")
    with pytest.raises(HTTPException) as refused:
        await authority(world).session_target(PublicScope())
    assert refused.value.detail == "owner_required"


async def test_withdrawal_between_projection_and_hold_refuses(enrolled):
    service = authority(enrolled)
    target = await service.session_target(PublicScope())
    async with enrolled.db.transaction() as tx:
        await unassign(tx, ALICE, OWNER_ROLE)
    async with enrolled.db.transaction() as tx:
        with pytest.raises(HTTPException) as refused:
            await service.hold_session_target(tx, target)
    assert refused.value.detail == "owner_required"


async def test_role_reassignment_does_not_heal_an_outstanding_target(enrolled):
    service = authority(enrolled)
    target = await service.session_target(PublicScope())
    async with enrolled.db.transaction() as tx:
        await unassign(tx, ALICE, OWNER_ROLE)
        await assign(tx, ALICE, OWNER_ROLE)
    async with enrolled.db.transaction() as tx:
        with pytest.raises(HTTPException):
            await service.hold_session_target(tx, target)
    fresh = await service.session_target(PublicScope())
    async with enrolled.db.transaction() as tx:
        held = await service.hold_session_target(tx, fresh)
        assert await service.check_session_target(tx, held)


async def test_generation_change_refuses_the_original_target(enrolled):
    service = authority(enrolled)
    target = await service.session_target(PublicScope())
    await enrolled.db.execute("UPDATE {{tables.installation_fences}} SET generation=generation+1")
    async with enrolled.db.transaction() as tx:
        with pytest.raises(InstallationRefused):
            await service.hold_session_target(tx, target)


async def test_recovery_does_not_retarget_the_original_subject(enrolled):
    service = authority(enrolled)
    target = await service.session_target(PublicScope())
    await _apply(enrolled, "app-credential.recover", ALICE, "alice-new@example.com")
    assert await enrolled.passkeys.recovery_pending_until(target.b3_scope) is not None
    with pytest.raises(HTTPException):
        await service.session_target(PublicScope())
    async with enrolled.db.transaction() as tx:
        with pytest.raises(HTTPException):
            await service.hold_session_target(tx, target)


async def test_a_supplied_subject_cannot_rebind_the_projection(enrolled):
    service = authority(enrolled)
    target = await service.session_target(PublicScope())
    async with enrolled.db.transaction() as tx:
        with pytest.raises(HTTPException):
            await service.hold_session_target(tx, replace(target, subject="another-subject"))


async def test_preparation_reuses_the_callers_existing_b3_union(enrolled):
    service = authority(enrolled)
    target = await service.session_target(PublicScope())
    async with enrolled.db.transaction() as tx:
        await enrolled.console.fence.check(tx, target.admitted)
        from aweb_naapp.roles import hold_role

        assert await hold_role(tx, ALICE, OWNER_ROLE)
        union = await enrolled.passkeys.prepare_current_approvers(
            tx, [(target.b3_scope, target.subject)]
        )
        held = await service.hold_session_target(tx, target, approvers=union)
        assert await service.check_session_target(tx, held)


async def test_late_check_observes_local_withdrawal_without_rearming(enrolled):
    service = authority(enrolled)
    target = await service.session_target(PublicScope())
    async with enrolled.db.transaction() as tx:
        held = await service.hold_session_target(tx, target)
        assert await service.check_session_target(tx, held)
        await unassign(tx, ALICE, OWNER_ROLE)
        assert not await service.check_session_target(tx, held)


async def test_late_check_samples_the_fence_deadline_after_a_wait(enrolled):
    service = authority(enrolled)
    target = await service.session_target(PublicScope())
    async with enrolled.db.transaction() as tx:
        held = await service.hold_session_target(tx, target)
        await tx.execute(
            "UPDATE {{tables.installation_fences}}"
            " SET fresh_until=clock_timestamp()+interval '30 milliseconds'"
        )
        await asyncio.sleep(0.05)
        assert not await service.check_session_target(tx, held)


async def test_projection_and_holds_write_no_authority_or_login_records(enrolled):
    tables = (
        "owner_principals",
        "role_assignments",
        "passkey_approvers",
        "passkey_credentials",
        "passkey_assertions",
    )

    async def fingerprints():
        return [
            await enrolled.db.fetch_value(
                "SELECT md5(coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),"
                "'[]'::jsonb)::text) FROM {{tables." + table + "}} r"
            )
            for table in tables
        ]

    before = await fingerprints()
    service = authority(enrolled)
    target = await service.session_target(PublicScope())
    async with enrolled.db.transaction() as tx:
        held = await service.hold_session_target(tx, target)
        assert await service.check_session_target(tx, held)
    assert await fingerprints() == before


async def test_prepared_authority_does_not_survive_savepoint_rollback(enrolled):
    service = authority(enrolled)
    target = await service.session_target(PublicScope())
    async with enrolled.db.transaction() as tx:
        await tx.execute("SAVEPOINT holding")
        held = await service.hold_session_target(tx, target)
        await tx.execute("ROLLBACK TO SAVEPOINT holding")
        async with asyncio.timeout(0.5):
            assert not await service.check_session_target(tx, held)


async def test_prepared_authority_cannot_be_borrowed_by_another_tx_wrapper(enrolled):
    service = authority(enrolled)
    target = await service.session_target(PublicScope())
    async with enrolled.db.transaction() as tx:
        held = await service.hold_session_target(tx, target)
        borrowed = TransactionManager(tx.connection, enrolled.db)
        assert not await service.check_session_target(borrowed, held)
        assert await service.check_session_target(tx, held)


async def test_hold_serializes_withdrawal_without_locking_another_owner(enrolled):
    await _apply(enrolled, "app-role.designate", BOB, "bob@example.com")
    await _enrol(enrolled, "bob@example.com")
    service = authority(enrolled)
    target = await service.session_target(PublicScope())
    writer_pid = asyncio.get_running_loop().create_future()

    async def withdraw(principal, *, report_pid=False):
        async with enrolled.db.transaction() as tx:
            if report_pid:
                writer_pid.set_result(await tx.fetch_value("SELECT pg_backend_pid()"))
            await unassign(tx, principal, OWNER_ROLE)

    writer = None
    try:
        async with enrolled.db.transaction() as tx:
            held = await service.hold_session_target(tx, target)
            holder_pid = await tx.fetch_value("SELECT pg_backend_pid()")
            writer = asyncio.create_task(withdraw(ALICE, report_pid=True))
            async with asyncio.timeout(2):
                blocked_pid = await writer_pid
                while holder_pid not in await tx.fetch_value(
                    "SELECT pg_blocking_pids($1)", blocked_pid
                ):
                    await asyncio.sleep(0.01)
            async with asyncio.timeout(1):
                await withdraw(BOB)
                assert await service.check_session_target(tx, held)
            assert not writer.done()
        async with asyncio.timeout(1):
            await writer
        with pytest.raises(HTTPException):
            await service.session_target(PublicScope())
    finally:
        if writer is not None:
            writer.cancel()
            await asyncio.gather(writer, return_exceptions=True)
