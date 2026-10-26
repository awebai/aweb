"""The settlement caller holds actual OWNER, B3 LOGIN and exact S4 authority."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from aweb_naapp.console import COOKIE_NAME, apply_console_migrations
from aweb_naapp.roles import unassign
from aweb_naapp.runtime.installation import InstallationRefused
from fastapi import HTTPException, Request

from aweb_secrets.console import OwnerConsole
from aweb_secrets.console_reconciliation.authority import ConsoleReconciliationFence
from aweb_secrets.owners import OWNER_ROLE
from tests.test_change_sets import ALICE, enrol_owner
from tests.test_change_sets import world as world


async def caller(w):
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    await apply_console_migrations(w.db)

    async def installation(installation_id, *, team_id=None):
        if installation_id != w.admitted.installation_id:
            raise LookupError(installation_id)
        return w.admitted

    console = OwnerConsole(
        db=w.db,
        passkeys=w.passkeys,
        directory=w.directory,
        fence=w.fence,
        verifier=w.owner.verifier,
        installation=installation,
    )
    options = await w.passkeys.login_options(scope)
    logged = await w.passkeys.verify_login(scope, w.devices["alice@acme.com"].get(dict(options)))
    issued = await console.sessions.open(
        subject=logged.subject, scope=scope, evidence_ref=logged.evidence_ref
    )
    current = await console.sessions.current(
        Request(
            {
                "type": "http",
                "method": "POST",
                "path": "/reconciliation",
                "headers": [
                    (b"cookie", (COOKIE_NAME + "=" + issued.token).encode()),
                    (b"x-csrf-token", issued.csrf_token.encode()),
                ],
            }
        )
    )
    return console, current


async def relations(tx):
    return {
        (row["relation"], row["mode"])
        for row in await tx.fetch_all(
            "SELECT relation,mode FROM pg_locks WHERE pid=pg_backend_pid()"
            " AND locktype='relation' AND granted"
        )
    }


async def test_one_shared_handle_is_reused_and_final_check_takes_no_new_relation_locks(world):
    console, current = await caller(world)
    fence = ConsoleReconciliationFence(console=console, current=current, scope=world.admitted)
    async with world.db.transaction() as tx:
        handle = await fence.prepare(tx)
        before = await relations(tx)
        assert await fence.prepare(tx) is handle
        await fence.check(tx)
        assert await relations(tx) == before
        assert await world.passkeys.check_current_approver(
            tx, handle, scope=current.scope, subject=current.subject
        )
        assert await tx.fetch_value("SELECT count(*) FROM {{tables.approvals}}") == 0
    # Postcommit presentation uses a newly prepared handle, never this cache.
    async with world.db.transaction() as tx:
        with pytest.raises(HTTPException):
            await fence.prepare(tx)
        fresh = ConsoleReconciliationFence(console=console, current=current, scope=world.admitted)
        assert await fresh.prepare(tx) is not handle


@pytest.mark.parametrize("field", ["subject", "evidence_ref", "token_sha256", "expires_at"])
async def test_preparation_binds_the_exact_persisted_session(world, field):
    console, current = await caller(world)
    changed = {
        "subject": "another-subject",
        "evidence_ref": "another-login",
        "token_sha256": b"x" * 32,
        "expires_at": current.expires_at + timedelta(seconds=1),
    }
    fence = ConsoleReconciliationFence(
        console=console, current=replace(current, **{field: changed[field]}), scope=world.admitted
    )
    with pytest.raises(HTTPException) as refused:
        async with world.db.transaction() as tx:
            await fence.prepare(tx)
    assert refused.value.status_code == 401


@pytest.mark.parametrize("revoked", ["owner", "login", "session"])
async def test_authority_lost_after_request_authentication_refuses_preparation(world, revoked):
    console, current = await caller(world)
    if revoked == "owner":
        async with world.db.transaction() as tx:
            await unassign(tx, ALICE, OWNER_ROLE)
    elif revoked == "login":
        await world.db.execute(
            "UPDATE {{tables.passkey_credentials}} SET revoked_at=clock_timestamp()"
            " WHERE credential_id=(SELECT credential_id FROM {{tables.passkey_assertions}}"
            " WHERE evidence_ref=$1)",
            current.evidence_ref,
        )
    else:
        await world.db.execute(
            "UPDATE {{tables.console_sessions}} SET closed_at=clock_timestamp()"
            " WHERE token_sha256=$1",
            current.token_sha256,
        )
    fence = ConsoleReconciliationFence(console=console, current=current, scope=world.admitted)
    with pytest.raises(HTTPException) as refused:
        async with world.db.transaction() as tx:
            await fence.prepare(tx)
    assert refused.value.status_code == (403 if revoked == "owner" else 401)


async def test_rolled_back_preparation_cannot_reacquire_authority_from_its_cache(world):
    console, current = await caller(world)
    fence = ConsoleReconciliationFence(console=console, current=current, scope=world.admitted)
    async with world.db.transaction() as tx:
        with pytest.raises(RuntimeError, match="rollback preparation"):
            async with tx.transaction():
                await fence.prepare(tx)
                raise RuntimeError("rollback preparation")
        with pytest.raises(HTTPException) as refused:
            await fence.prepare(tx)
        assert refused.value.status_code == 401


async def test_final_check_reads_live_f6_and_persisted_s4_after_preparation(world):
    console, current = await caller(world)
    async with world.db.transaction() as tx:
        fence = ConsoleReconciliationFence(console=console, current=current, scope=world.admitted)
        await fence.prepare(tx)
        await tx.execute(
            "UPDATE {{tables.installation_fences}}"
            " SET fresh_until=clock_timestamp()-interval '1 second'"
        )
        with pytest.raises(InstallationRefused):
            await fence.check(tx)
    await world.fence.refresh(ALICE.team_id)
    async with world.db.transaction() as tx:
        fence = ConsoleReconciliationFence(console=console, current=current, scope=world.admitted)
        await fence.prepare(tx)
        await tx.execute(
            "UPDATE {{tables.console_sessions}} SET expires_at=$2 WHERE token_sha256=$1",
            current.token_sha256,
            datetime.now(UTC) - timedelta(seconds=1),
        )
        with pytest.raises(HTTPException) as refused:
            await fence.check(tx)
        assert refused.value.status_code == 401
