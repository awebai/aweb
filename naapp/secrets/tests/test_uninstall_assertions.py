"""Retirement drains real B3 writers before removing their restricted material."""

import asyncio
import secrets

import pytest
from aweb_naapp.runtime.passkeys import ProofContextUnavailable

from aweb_secrets.owners import owner_scope
from tests.test_change_sets import ALICE
from tests.test_change_sets import world as world
from tests.test_uninstall_cleanup import staged


async def test_uninstall_drains_a_real_assertion_before_deleting_its_children(world):
    fence, authority = await staged(world)
    scope = owner_scope(world.admitted.installation_id, world.admitted.team_id, ALICE.principal_did)
    proof = world.devices["alice@acme.com"].get(await world.passkeys.login_options(scope))
    gate = secrets.randbelow(2**30) + 1
    await world.db.execute(
        "CREATE FUNCTION {{tables.pause_retirement_counter}}() RETURNS TRIGGER LANGUAGE plpgsql AS $$"
        f" BEGIN PERFORM pg_advisory_xact_lock({gate}::bigint); RETURN NEW; END; $$"
    )
    await world.db.execute(
        "CREATE TRIGGER pause_retirement_counter AFTER UPDATE OF sign_count"
        " ON {{tables.passkey_credentials}} FOR EACH ROW"
        " EXECUTE FUNCTION {{tables.pause_retirement_counter}}()"
    )
    retiring = asyncio.get_running_loop().create_future()
    actual_retire = fence.on_retire
    assert actual_retire is not None

    async def traced_retire(tx, team_id):
        # Instrument the real callback's connection, retaining its full body.
        if not retiring.done():
            retiring.set_result(await tx.fetch_value("SELECT pg_backend_pid()"))
        await actual_retire(tx, team_id)

    fence.on_retire = traced_retire
    verifier, retirement = None, None
    try:
        async with world.db.transaction() as barrier:
            await barrier.execute("SELECT pg_advisory_xact_lock($1::bigint)", gate)
            verifier = asyncio.create_task(world.passkeys.verify_login(scope, proof))
            async with asyncio.timeout(5):
                while not (
                    verifier_pid := await world.db.fetch_value(
                        "SELECT pid FROM pg_locks WHERE locktype='advisory'"
                        " AND classid=0 AND objid=$1 AND NOT granted",
                        gate,
                    )
                ):
                    if verifier.done():
                        await verifier
                        pytest.fail("verifier did not reach the counter barrier")
                    await asyncio.sleep(0.01)
            authority.state = "uninstalled"
            retirement = asyncio.create_task(fence.refresh(world.admitted.team_id))
            retirement_pid = await asyncio.wait_for(retiring, 5)
            async with asyncio.timeout(5):
                while verifier_pid not in await world.db.fetch_value(
                    "SELECT pg_blocking_pids($1)", retirement_pid
                ):
                    if retirement.done():
                        await retirement
                        pytest.fail("retirement did not drain the live assertion")
                    await asyncio.sleep(0.01)
            # The old order reached credential DELETE with its parent held.
            # Retirement must instead wait before child deletion/credential DML.
            assert not await world.db.fetch_value(
                "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1"
                " AND mode='RowExclusiveLock' AND relation="
                " (SELECT tableoid FROM {{tables.passkey_credentials}} LIMIT 1))",
                retirement_pid,
            )
        await asyncio.wait_for(asyncio.gather(verifier, retirement), 5)
        assert (
            await world.db.fetch_value("SELECT count(*) FROM {{tables.passkey_credentials}}") == 0
        )
        assert await world.db.fetch_value("SELECT count(*) FROM {{tables.passkey_assertions}}") == 0
        assert await world.db.fetch_value("SELECT count(*) FROM {{tables.passkey_proofs}}") == 0
    finally:
        for task in (retirement, verifier):
            if task is not None and not task.done():
                task.cancel()
        await asyncio.gather(
            *(task for task in (retirement, verifier) if task is not None), return_exceptions=True
        )


async def test_challenge_checked_before_uninstall_cannot_publish_after_it(world):
    fence, authority = await staged(world)
    scope = owner_scope(world.admitted.installation_id, world.admitted.team_id, ALICE.principal_did)
    checked, resume = asyncio.Event(), asyncio.Event()
    original_context = world.passkeys._proof_context

    async def paused_context(scope, *, tx):
        # Pause only after the real persisted-scope/F6 resolver ran.
        context = await original_context(scope, tx=tx)
        checked.set()
        await resume.wait()
        return context

    world.passkeys._proof_context = paused_context
    request = asyncio.create_task(world.passkeys.login_options(scope))
    try:
        await asyncio.wait_for(checked.wait(), 5)
        authority.state = "uninstalled"
        await asyncio.wait_for(fence.refresh(world.admitted.team_id), 5)
        resume.set()
        with pytest.raises(ProofContextUnavailable):
            await asyncio.wait_for(request, 5)
        assert await world.db.fetch_value("SELECT count(*) FROM {{tables.passkey_challenges}}") == 0
    finally:
        world.passkeys._proof_context = original_context
        resume.set()
        if not request.done():
            request.cancel()
        await asyncio.gather(request, return_exceptions=True)
