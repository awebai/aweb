"""Real reciprocal retirements finish without deadlock or losing every owner.

A database trigger pauses each effect after its own actor preparation, before
retiring the other owner. Its shared advisory barrier does not serialize the
released effects. Observe actual lock graphs and terminal database outcomes;
an observation timeout is never evidence that the retirement gate works.
"""

import asyncio
import json
import secrets
from dataclasses import replace

import asyncpg
import httpx
import pytest
from aweb_naapp.console import COOKIE_NAME
from aweb_naapp.runtime.team_auth import AWIDTeamCache, authenticate_request
from aweb_naapp_testing import REGISTRY_URL, SERVICE_TOKEN
from fastapi import FastAPI, HTTPException, Request

from aweb_secrets.containment import ContainmentRefused
from aweb_secrets.owners import OWNER_ROLE
from tests.test_change_sets import Installations
from tests.test_handoff_sessions import API
from tests.test_handoff_sessions import journey as journey
from tests.test_handoff_sessions import world as world
from tests.test_key_bound_owner_effects import containment_service
from tests.test_production_handoffs import bound_console, current_session


async def other_owner(journey):
    member, scope, device = await journey.enrol_owner("other-owner")
    return replace(journey, member=member, scope=scope, device=device)


async def session(holder, kind):
    if kind == "signed":
        key, issued = await holder.open()
        return await current_session(holder, key, issued)
    # Genuine B3 verification and an actual S4 cookie row, rather than a
    # constructed ConsoleSession. Ceremony-only H2 composition is separate.
    w = holder.world
    target = await holder.factory.authority.session_target(holder.scope)
    logged = await w.passkeys.verify_login(
        target.b3_scope,
        holder.device.get(await w.passkeys.login_options(target.b3_scope)),
    )
    console = bound_console(holder)
    issued = await console.sessions.open(
        subject=logged.subject, scope=target.b3_scope, evidence_ref=logged.evidence_ref
    )
    return await console.sessions.current(
        Request(
            {
                "type": "http",
                "method": "GET",
                "path": "/session",
                "headers": [(b"cookie", (COOKIE_NAME + "=" + issued.token).encode())],
            }
        )
    )


async def wait_for_blocked(db, blocker, tasks):
    async with asyncio.timeout(5):
        while True:
            waiting = await db.fetch_value(
                "SELECT count(*) FROM pg_stat_activity"
                " WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid))",
                blocker,
            )
            if waiting == len(tasks):
                return
            if any(task.done() for task in tasks):
                pytest.fail("retirement completed before the controlled authority wait")
            await asyncio.sleep(0.01)


async def finish(tasks):
    for task in tasks:
        if not task.done():
            task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


async def actor_is_free(db, statement, *args):
    try:
        async with db.transaction() as probe:
            assert await probe.fetch_value(statement, *args) is not None
    except asyncpg.LockNotAvailableError:
        pytest.fail("a retirement waiter retained actor authority before its entry gate")


async def lock_snapshot(db, pids=None):
    # Catalog identities and SQL placeholders only; no certificates or tokens.
    states = await db.fetch_all(
        "SELECT pid,wait_event_type,wait_event,pg_blocking_pids(pid) AS blockers,"
        "left(query,250) AS query FROM pg_stat_activity"
        " WHERE datname=current_database() AND pid<>pg_backend_pid()"
        " AND ($1::int[] IS NULL OR pid=ANY($1)) ORDER BY pid",
        pids,
    )
    locks = await db.fetch_all(
        "SELECT pid,locktype,mode,granted,relation::regclass::text AS relation,"
        "page,tuple,transactionid::text,classid::bigint,objid::bigint,objsubid"
        " FROM pg_locks WHERE database=(SELECT oid FROM pg_database"
        " WHERE datname=current_database()) OR locktype='transactionid'",
    )
    selected = {row["pid"] for row in states}
    return {
        "states": [dict(row) for row in states],
        "locks": [
            dict(row)
            for row in locks
            if row["pid"] in selected
            and (
                row["locktype"] != "relation"
                or any(
                    table in (row["relation"] or "")
                    for table in ("passkey_approvers", "passkey_credentials", "console_sessions")
                )
            )
        ],
    }


async def barrier_waiters(tx, key):
    return [
        row["pid"]
        for row in await tx.fetch_all(
            "SELECT pid FROM pg_locks WHERE locktype='advisory'"
            " AND database=(SELECT oid FROM pg_database WHERE datname=current_database())"
            " AND classid=$1::oid AND objid=$2::oid AND objsubid=1"
            " AND mode='ShareLock' AND NOT granted ORDER BY pid",
            key >> 32,
            key & 0xFFFFFFFF,
        )
    ]


def same_retirement_gate(snapshot, first, second):
    # Compare actual catalog lock identities: no copied key derivation or
    # inference that a blocking PID names the resource being waited on.
    held = {
        (row["classid"], row["objid"])
        for row in snapshot["locks"]
        if row["pid"] == first
        and row["locktype"] == "advisory"
        and row["objsubid"] == 2
        and row["mode"] == "ExclusiveLock"
        and row["granted"]
    }
    return any(
        row["pid"] == second
        and row["locktype"] == "advisory"
        and row["objsubid"] == 2
        and row["mode"] == "ExclusiveLock"
        and not row["granted"]
        and (row["classid"], row["objid"]) in held
        for row in snapshot["locks"]
    )


async def wait_for_effects(tx, key, blocker_pid, tasks, *, first=False):
    try:
        async with asyncio.timeout(5):
            while True:
                await tx.execute("SELECT pg_stat_clear_snapshot()")
                entered = await barrier_waiters(tx, key)
                snapshot = await lock_snapshot(tx)
                reached = {blocker_pid}
                while True:
                    connected = {
                        row["pid"]
                        for row in snapshot["states"]
                        if reached.intersection(row["blockers"])
                    }
                    if connected.issubset(reached):
                        break
                    reached.update(connected)
                pids = sorted(reached - {blocker_pid})
                if first and len(entered) == 1:
                    return snapshot, entered, pids, "first actor prepared"
                if len(pids) == 2:
                    if set(entered) == set(pids):
                        return snapshot, entered, pids, "both at shared test barrier"
                    if len(entered) == 1:
                        other = next(pid for pid in pids if pid != entered[0])
                        if same_retirement_gate(snapshot, entered[0], other):
                            return (
                                snapshot,
                                entered,
                                pids,
                                "one at barrier; other at retirement gate",
                            )
                if any(task.done() for task in tasks):
                    raise RuntimeError(
                        "retirement ended before its SQL barrier: " + json.dumps(snapshot)
                    )
                await asyncio.sleep(0.01)
    except TimeoutError:
        raise RuntimeError(
            "reciprocal setup did not reach its SQL barrier: " + json.dumps(await lock_snapshot(tx))
        ) from None


@pytest.mark.parametrize("kind", ["signed", "cookie"])
async def test_reciprocal_owner_retirements_leave_one_current_owner(journey, tmp_path, kind):
    second = await other_owner(journey)
    a, b = await session(journey, kind), await session(second, kind)
    w = journey.world
    service = await containment_service(journey, tmp_path)
    barrier = secrets.randbits(63)
    tasks = []
    evidence = {}
    try:
        # Scheduling instrumentation on exactly the two real claim keys. It
        # does not replace application authority, effects or the audit recorder.
        await w.db.execute(
            "CREATE FUNCTION {{tables.pause_reciprocal_retirement}}() RETURNS trigger"
            " LANGUAGE plpgsql AS $$ BEGIN"
            " IF NEW.key[3] IN ('reciprocal-0','reciprocal-1') THEN"
            f" PERFORM pg_advisory_xact_lock_shared({barrier}::bigint);"
            " END IF; RETURN NEW; END $$"
        )
        await w.db.execute(
            "CREATE TRIGGER pause_reciprocal_retirement BEFORE INSERT"
            " ON {{tables.idempotency_keys}} FOR EACH ROW"
            " EXECUTE FUNCTION {{tables.pause_reciprocal_retirement}}()"
        )
        async with w.db.transaction() as observer:
            # No F6 or target row is held: after release the effects can reach
            # the real deadlock or last-owner outcome instead of being parked.
            await observer.execute("SELECT pg_advisory_xact_lock($1::bigint)", barrier)
            pid = await observer.fetch_value("SELECT pg_backend_pid()")
            for index, (actor, target) in enumerate(((a, b), (b, a))):
                tasks.append(
                    asyncio.create_task(
                        service.by_console(
                            admitted=w.admitted,
                            session=actor,
                            request_id=f"reciprocal-{index}",
                            action="revoke-approver",
                            target=target.scope,
                        )
                    )
                )
                if len(tasks) == 1:
                    await wait_for_effects(observer, barrier, pid, tasks, first=True)
            before, entered, pids, state = await wait_for_effects(observer, barrier, pid, tasks)
            evidence.update(before_release=before, at_shared_barrier=entered, state=state)
        # Shared waiters may both proceed after the observer commits. With the
        # product gate intact the second instead waits before its actor holds.
        async with asyncio.timeout(10):
            while not all(task.done() for task in tasks):
                snapshot = await lock_snapshot(w.db, pids)
                if any(row["blockers"] for row in snapshot["states"]):
                    evidence["after_release"] = snapshot
                await asyncio.sleep(0.01)
            outcomes = await asyncio.gather(*tasks, return_exceptions=True)
        deadlocks = [
            {"sqlstate": value.sqlstate, "detail": value.detail}
            for value in outcomes
            if isinstance(value, asyncpg.DeadlockDetectedError)
        ]
        remaining = sum([await w.passkeys.can_log_in(s.scope, s.subject) for s in (a, b)])
        committed = sum(not isinstance(value, BaseException) for value in outcomes)
        evidence.update(
            deadlocks=deadlocks,
            remaining_owners=remaining,
            committed=committed,
            outcomes=[
                type(value).__name__ if isinstance(value, BaseException) else "committed"
                for value in outcomes
            ],
        )
        # A sensitive control fails on the observed defect, never on a missed
        # wait: actual PostgreSQL40P01/detail, or both commits with no owner left.
        assert not deadlocks, "reciprocal retirement deadlock: " + json.dumps(evidence)
        assert not (committed == 2 and remaining == 0), (
            "reciprocal retirements both committed with no owner: " + json.dumps(evidence)
        )
        assert committed == 1, evidence
        refused = next(value for value in outcomes if isinstance(value, BaseException))
        assert isinstance(refused, (ContainmentRefused, HTTPException)), evidence
        assert getattr(refused, "status", getattr(refused, "status_code", None)) == 401
        assert remaining == 1
    finally:
        await finish(tasks)
        await w.db.execute(
            "DROP TRIGGER IF EXISTS pause_reciprocal_retirement ON {{tables.idempotency_keys}}"
        )
        await w.db.execute("DROP FUNCTION IF EXISTS {{tables.pause_reciprocal_retirement}}()")


async def test_team_auth_retirement_waits_before_holding_its_owner_role(journey, tmp_path):
    from aweb_naapp.runtime.passkeys import prepare_retirement

    second = await other_owner(journey)
    w = journey.world
    target = await second.factory.authority.session_target(second.scope)
    service = await containment_service(journey, tmp_path)
    cache = AWIDTeamCache(
        registry_url=REGISTRY_URL,
        ttl_seconds=60,
        service_token=SERVICE_TOKEN,
        transport=w.registry.transport,
    )
    grant = Installations(team_id=w.admitted.team_id, app_id=w.admitted.app_id).grant
    app = FastAPI()

    @app.post("/retire")
    async def retire(request: Request):
        principal = await authenticate_request(request, public_origin=API, team_cache=cache)
        await service.by_member(
            grant=grant,
            principal=principal,
            request_id="member-retirement",
            action="revoke-approver",
            target=target.b3_scope,
        )
        return {"retired": True}

    tasks = []
    try:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url=API) as client:
            async with w.db.transaction() as blocker:
                # This observer does not authorize an effect or take F6. It
                # must allow by_member to acquire exclusive F6 before waiting.
                await prepare_retirement(blocker, installation=w.admitted)
                await blocker.fetch_value(
                    "SELECT subject FROM {{tables.passkey_approvers}}"
                    " WHERE subject=$1 FOR NO KEY UPDATE",
                    target.subject,
                )
                pid = await blocker.fetch_value("SELECT pg_backend_pid()")
                tasks.append(
                    asyncio.create_task(
                        client.post(
                            "/retire",
                            content=b"{}",
                            headers=journey.member.headers(
                                aud=API, method="POST", path="/retire", body=b"{}"
                            ),
                        )
                    )
                )
                await wait_for_blocked(w.db, pid, tasks)
                await actor_is_free(
                    w.db,
                    "SELECT principal_did FROM {{tables.role_assignments}}"
                    " WHERE team_id=$1 AND principal_did=$2 AND role=$3 FOR UPDATE NOWAIT",
                    w.admitted.team_id,
                    journey.scope.principal,
                    OWNER_ROLE,
                )
            response = await asyncio.wait_for(tasks[0], 10)
            assert response.status_code == 200, response.text
            assert not await w.passkeys.can_log_in(target.b3_scope, target.subject)
    finally:
        await finish(tasks)
