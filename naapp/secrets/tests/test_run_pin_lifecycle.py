"""Real native assignment/result and transactional pin destruction paths."""

import asyncio
import json
import secrets
from datetime import timedelta

import pytest

from aweb_secrets import records, run_pin_store
from aweb_secrets.custody import SealContext, encode_value
from tests.test_run_dispatch_service import report, setup
from tests.test_use_approvals import SECRET, TEAM
from tests.test_use_approvals import uses as uses
from tests.test_use_approvals import world as world


async def stored_result(context, dispatch_ref):
    await context.service.result(
        dispatch_ref,
        context.signed(f"/runner/v1/dispatches/{dispatch_ref}/result", report(context.credential)),
    )
    return await context.service.submit(job=context.job.job_id, submission=context.submission)


@pytest.mark.parametrize("effect", ["rotate", "destroy", "disable", "installation"])
async def test_value_narrowing_disposes_pins_before_any_report_and_withholds(uses, effect):
    context = await setup(uses)
    _, _, wire = await context.assigned()
    db, custody, scope = uses.world.db, uses.world.custody, uses.world.admitted
    pinned = SealContext(scope.installation_id, TEAM, SECRET["secret_id"], 1)
    assert await db.fetch_value("SELECT count(*) FROM {{tables.run_redaction_pins}}") == 1
    other = other_wire = other_dispatch = None
    if effect != "installation":
        other = await setup(uses, variant="unrelated")
        _, _, other_wire = await other.assigned()
        other_dispatch = await db.fetch_value(
            "SELECT dispatch_id FROM {{tables.run_contexts}} WHERE dispatch_ref=$1",
            other_wire["assignment"]["dispatch_id"],
        )
    async with db.transaction() as tx:
        if effect != "installation":
            await run_pin_store.prepare_secrets(
                tx,
                installation_id=scope.installation_id,
                team_id=TEAM,
                secret_ids=[pinned.secret_id],
            )
        if effect == "rotate":
            new = await custody.sealer.ingest(
                tx,
                installation_id=scope.installation_id,
                team_id=TEAM,
                secret_id=pinned.secret_id,
                value=encode_value("bearer", {"value": secrets.token_urlsafe(32)}),
            )
            await records.set_active_version(tx, scope.installation_id, TEAM, pinned.secret_id, new)
            await custody.destroy(tx, pinned)
        elif effect == "destroy":
            await custody.destroy(tx, pinned)
        elif effect == "disable":
            await custody.disable(
                tx, installation_id=scope.installation_id, team_id=TEAM, secret_id=pinned.secret_id
            )
        else:
            from aweb_secrets.containment import disable_installation

            await disable_installation(
                tx,
                context.arguments["approvals"],
                custody,
                installation_id=scope.installation_id,
                team_id=TEAM,
                revoked_by="owner-fixture",
            )
        assert (
            await tx.fetch_value(
                "SELECT count(*) FROM {{tables.run_redaction_pins}} WHERE secret_id=$1",
                pinned.secret_id,
            )
            == 0
        )
        if other_dispatch is not None:
            assert (
                await tx.fetch_value(
                    "SELECT count(*) FROM {{tables.run_redaction_pins}} WHERE dispatch_id=$1",
                    other_dispatch,
                )
                == 1
            )
    receipt = await stored_result(context, wire["assignment"]["dispatch_id"])
    assert receipt.body["state"] == "result_withheld"
    assert receipt.body["result"]["body"] is None
    assert receipt.body["result"]["exit_code"] == 0
    if other is not None:
        unrelated = await stored_result(other, other_wire["assignment"]["dispatch_id"])
        assert unrelated.body["state"] == "completed"
        assert unrelated.body["result"]["redaction_count"] > 0
        if other.credential in str(unrelated.body):
            raise AssertionError("unrelated dispatch lost original-value redaction")


async def test_disposal_during_native_reopen_withholds_the_original_result(uses):
    context = await setup(uses)
    _, _, wire = await context.assigned()
    db, scope = uses.world.db, uses.world.admitted
    dispatch_id = await db.fetch_value("SELECT dispatch_id FROM {{tables.run_redaction_pins}}")
    opened, resume = asyncio.Event(), asyncio.Event()
    actual = context.arguments["opener"].open

    async def pause_after_real_open(sealed_context):
        plaintext = await actual(sealed_context)
        opened.set()
        await resume.wait()
        return plaintext

    # Pause the real opener after actual native unsealing. No value is supplied
    # by this scheduling wrapper, and all final state is production state.
    context.arguments["opener"].open = pause_after_real_open
    pending = asyncio.create_task(stored_result(context, wire["assignment"]["dispatch_id"]))
    try:
        await asyncio.wait_for(opened.wait(), 5)
        async with db.transaction() as tx:
            # Exercise the real lifecycle sink while the original native
            # value remains readable. This isolates pin liveness from the
            # independent destroy/disabled-value checks above.
            await run_pin_store.prepare_dispatches(tx, [dispatch_id])
            await run_pin_store.discard_dispatch(
                tx,
                installation_id=scope.installation_id,
                team_id=TEAM,
                dispatch_id=dispatch_id,
            )
        resume.set()
        receipt = await asyncio.wait_for(pending, 5)
        assert receipt.body["state"] == "result_withheld"
        assert receipt.body["result"]["body"] is None
    finally:
        context.arguments["opener"].open = actual
        resume.set()
        if not pending.done():
            pending.cancel()
        await asyncio.gather(pending, return_exceptions=True)


@pytest.mark.parametrize("wait_stage", ["dispatch", "outbox", "pin_disposal"])
async def test_original_database_deadline_expiring_during_a_wait_withholds(uses, wait_stage):
    context = await setup(uses, job_timeout_s=1)
    context.arguments["assignment_ttl"] = timedelta(seconds=2)
    context.arguments["sweep_margin"] = timedelta(milliseconds=100)
    _, _, wire = await context.assigned()
    db = uses.world.db
    deadline = await db.fetch_value("SELECT deadline FROM {{tables.run_redaction_pins}}")
    assert deadline > await db.fetch_value("SELECT clock_timestamp()")
    pending = None
    try:
        async with db.transaction() as barrier:
            blocker = await barrier.fetch_value("SELECT pg_backend_pid()")
            if wait_stage == "dispatch":
                await barrier.fetch_one("SELECT dispatch_id FROM {{tables.dispatches}} FOR UPDATE")
            elif wait_stage == "pin_disposal":
                # RowShare from the liveness SELECT FOR UPDATE is allowed;
                # RowExclusive from our final DELETE must actually wait.
                await barrier.execute("LOCK TABLE {{tables.run_redaction_pins}} IN SHARE MODE")
            else:
                # This blocks the actual outcome producer after output was
                # tentatively rendered, exercising the savepoint rollback.
                await barrier.execute("LOCK TABLE {{tables.outbox_events}} IN SHARE MODE")
            pending = asyncio.create_task(stored_result(context, wire["assignment"]["dispatch_id"]))
            async with asyncio.timeout(5):
                while not await db.fetch_value(
                    "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))",
                    blocker,
                ):
                    if pending.done():
                        await pending
                        pytest.fail("result did not reach the real database wait")
                    await asyncio.sleep(0.01)
            remaining = (
                deadline - await barrier.fetch_value("SELECT clock_timestamp()")
            ).total_seconds()
            await barrier.execute("SELECT pg_sleep($1::double precision)", max(0, remaining) + 0.1)
        receipt = await asyncio.wait_for(pending, 5)
        assert receipt.body["state"] == "result_withheld"
        assert receipt.body["result"]["body"] is None
        assert receipt.body["result"]["exit_code"] == 0
        assert await db.fetch_value("SELECT sweep_after FROM {{tables.dispatches}}") == deadline
        assert await db.fetch_value("SELECT count(*) FROM {{tables.run_redaction_pins}}") == 0
        observations = await db.fetch_all(
            "SELECT result FROM {{tables.dispatch_observations}} WHERE kind='outcome'"
        )
        assert len(observations) == 1
        stored = json.loads(observations[0]["result"])
        assert stored["state"] == "result_withheld"
        assert stored["result"]["body"] is None

    finally:
        if pending is not None:
            if not pending.done():
                pending.cancel()
            await asyncio.gather(pending, return_exceptions=True)


@pytest.mark.parametrize("isolation", ["REPEATABLE READ", "SERIALIZABLE"])
async def test_pin_disposal_refuses_a_stale_snapshot_without_switching_it(uses, isolation):
    context = await setup(uses)
    await context.assigned()
    db, scope = uses.world.db, uses.world.admitted
    async with db.transaction() as tx:
        await tx.execute(f"SET TRANSACTION ISOLATION LEVEL {isolation}")
        assert await tx.fetch_value("SELECT count(*) FROM {{tables.run_redaction_pins}}") == 1
        with pytest.raises(ValueError):
            await run_pin_store.discard_installation(
                tx, installation_id=scope.installation_id, team_id=TEAM
            )
        assert await tx.fetch_value("SHOW transaction_isolation") == isolation.lower()
        assert await tx.fetch_value("SELECT count(*) FROM {{tables.run_redaction_pins}}") == 1


async def test_failed_destruction_rolls_back_pin_disposal_with_the_value(uses):
    context = await setup(uses)
    _, _, wire = await context.assigned()
    db, scope = uses.world.db, uses.world.admitted

    class RollBack(Exception):
        pass

    with pytest.raises(RollBack):
        async with db.transaction() as tx:
            await run_pin_store.prepare_secrets(
                tx,
                installation_id=scope.installation_id,
                team_id=TEAM,
                secret_ids=[SECRET["secret_id"]],
            )
            await uses.world.custody.destroy(
                tx, SealContext(scope.installation_id, TEAM, SECRET["secret_id"], 1)
            )
            assert await tx.fetch_value("SELECT count(*) FROM {{tables.run_redaction_pins}}") == 0
            raise RollBack
    assert await db.fetch_value("SELECT count(*) FROM {{tables.run_redaction_pins}}") == 1
    receipt = await stored_result(context, wire["assignment"]["dispatch_id"])
    assert receipt.body["state"] == "completed"
    assert receipt.body["result"]["redaction_count"] > 0
    if context.credential in str(receipt.body):
        raise AssertionError("rolled-back destruction lost original-value redaction")


async def test_confirmed_uninstall_disposes_assignment_keys_in_its_retirement_transaction(uses):
    from aweb_secrets.app import installation_fence
    from tests.test_reinstall import TeamServer, _grant

    context = await setup(uses)
    await context.assigned()
    db, scope = uses.world.db, uses.world.admitted
    authority = TeamServer()
    authority.grant = _grant(scope.installation_id, scope.generation, scope.team_id)
    authority.state = "uninstalled"
    fence = installation_fence(db, app_id="secrets", grants=authority)
    await fence.refresh(TEAM)
    assert await db.fetch_value("SELECT count(*) FROM {{tables.run_redaction_pins}}") == 0
    assert await db.fetch_value("SELECT count(*) FROM {{tables.sealed_versions}}") == 0
    destroyed = await db.fetch_value(
        "SELECT destroyed FROM {{tables.installation_retirement_events}}"
    )
    assert json.loads(destroyed)["run_redaction_pins"] == 1


@pytest.mark.parametrize("terminal", ["sweep", "deregister"])
async def test_terminal_run_settlement_disposes_original_assignment_keys(uses, terminal):
    context = await setup(uses)
    await context.assigned()
    db, scope = uses.world.db, uses.world.admitted
    assert await db.fetch_value("SELECT count(*) FROM {{tables.run_redaction_pins}}") == 1
    if terminal == "sweep":
        await db.execute(
            "UPDATE {{tables.dispatches}} SET sweep_after=clock_timestamp()-interval '1 second'"
        )
        assert await context.service.sweep() == 1
    else:
        async with db.transaction() as tx:
            await context.arguments["fence"].admit(tx, context.submission.authorization.grant)
            assert await context.service.deregister_runner(
                tx,
                scope.installation_id,
                context.runner.runner_id,
                now=uses.clock(),
                revoked_by="owner-fixture",
            )
    assert await db.fetch_value("SELECT count(*) FROM {{tables.run_redaction_pins}}") == 0


async def test_reopen_budget_does_not_restart_after_a_delayed_real_preflight(uses):
    context = await setup(uses, job_timeout_s=1)
    context.arguments["assignment_ttl"] = timedelta(seconds=2)
    context.arguments["sweep_margin"] = timedelta(milliseconds=100)
    _, _, wire = await context.assigned()
    db, loop = uses.world.db, asyncio.get_running_loop()
    timing = await db.fetch_one(
        "SELECT deadline,clock_timestamp() AS now FROM {{tables.run_redaction_pins}}"
    )
    # Taking the monotonic sample after this response is an upper bound for
    # the true original deadline, sufficient to detect any restarted interval.
    latest_end = loop.time() + (timing["deadline"] - timing["now"]).total_seconds()
    fence, opener = context.arguments["fence"], context.arguments["opener"]
    actual_check, actual_open = fence.check, opener.open
    delayed = False
    opened, finished = [], []

    async def delayed_real_check(tx, admitted):
        nonlocal delayed
        await actual_check(tx, admitted)
        if not delayed:
            delayed = True
            remaining = (
                timing["deadline"] - await tx.fetch_value("SELECT clock_timestamp()")
            ).total_seconds()
            await tx.execute("SELECT pg_sleep($1::double precision)", max(0, remaining) * 0.6)

    async def bounded_real_open(sealed_context):
        value = await actual_open(sealed_context)
        opened.append(loop.time())
        try:
            await asyncio.sleep(6)
            return value
        finally:
            finished.append(loop.time())

    fence.check, opener.open = delayed_real_check, bounded_real_open
    try:
        receipt = await asyncio.wait_for(
            stored_result(context, wire["assignment"]["dispatch_id"]), 8
        )
        assert len(opened) == len(finished) == 1
        assert finished[0] <= latest_end + 0.25
        assert receipt.body["state"] == "result_withheld"
        assert receipt.body["result"]["body"] is None
    finally:
        fence.check, opener.open = actual_check, actual_open


async def test_ordinary_grant_revocation_disposes_only_its_original_assignment(uses):
    from aweb_secrets.revisions import config_revision
    from tests.test_containment_service import act, service

    original = await setup(uses)
    _, _, first_wire = await original.assigned()
    other = await setup(uses, variant="independent", reuse_source=original)
    _, _, other_wire = await other.assigned()
    db, scope = uses.world.db, uses.world.admitted
    first_id = await db.fetch_value(
        "SELECT dispatch_id FROM {{tables.run_contexts}} WHERE dispatch_ref=$1",
        first_wire["assignment"]["dispatch_id"],
    )
    other_id = await db.fetch_value(
        "SELECT dispatch_id FROM {{tables.run_contexts}} WHERE dispatch_ref=$1",
        other_wire["assignment"]["dispatch_id"],
    )
    before = await config_revision(db, scope.installation_id)
    await act(await service(uses), uses, "revoke-grant", "grt_durable001", "revoke-root-run")
    assert await config_revision(db, scope.installation_id) == before + 1
    assert (
        await db.fetch_value(
            "SELECT count(*) FROM {{tables.run_redaction_pins}} WHERE dispatch_id=$1", first_id
        )
        == 0
    )
    assert (
        await db.fetch_value(
            "SELECT count(*) FROM {{tables.run_redaction_pins}} WHERE dispatch_id=$1", other_id
        )
        == 1
    )
    assert await db.fetch_value("SELECT count(*) FROM {{tables.sealed_versions}}") == 1
    dispatch_ref = first_wire["assignment"]["dispatch_id"]
    assert (
        await original.service.result(
            dispatch_ref,
            original.signed(
                f"/runner/v1/dispatches/{dispatch_ref}/result", report(original.credential)
            ),
        )
    ).status == 204
    stored = json.loads(
        await db.fetch_value(
            "SELECT result FROM {{tables.dispatches}} WHERE dispatch_id=$1", first_id
        )
    )
    assert stored["state"] == "result_withheld"
    assert stored["result"]["body"] is None
    # Current grant revocation still denies requester reads; do not restore it
    # to inspect the receipt. The unrelated grant on the SAME value still works.
    denied = await original.service.submit(job=original.job.job_id, submission=original.submission)
    assert denied.status == 404
    unrelated = await stored_result(other, other_wire["assignment"]["dispatch_id"])
    assert unrelated.body["state"] == "completed"
    assert unrelated.body["result"]["redaction_count"] > 0
