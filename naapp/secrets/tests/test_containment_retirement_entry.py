"""Real reciprocal owners wait before retaining any later authority.

The blocker holds the new entry gate AND a target B3 row. Thus old code still
reaches an observed PostgreSQL wait, but retains its actor authority there.
The NOWAIT actor probe distinguishes that reverse order from the entry gate;
pg_blocking_pids alone is deliberately not treated as a lock-resource proof.
"""

import asyncio
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


@pytest.mark.parametrize("kind", ["signed", "cookie"])
async def test_reciprocal_owner_retirements_wait_without_actor_b3_holds(journey, tmp_path, kind):
    from aweb_naapp.runtime.passkeys import prepare_retirement

    second = await other_owner(journey)
    a, b = await session(journey, kind), await session(second, kind)
    w = journey.world
    service = await containment_service(journey, tmp_path)
    tasks = []
    try:
        async with w.db.transaction() as blocker:
            await w.console.fence.check(blocker, w.admitted)
            await prepare_retirement(blocker, installation=w.admitted)
            await blocker.fetch_value(
                "SELECT subject FROM {{tables.passkey_approvers}}"
                " WHERE subject=$1 FOR NO KEY UPDATE",
                b.subject,
            )
            pid = await blocker.fetch_value("SELECT pg_backend_pid()")
            for actor, target in ((a, b), (b, a)):
                tasks.append(
                    asyncio.create_task(
                        service.by_console(
                            admitted=w.admitted,
                            session=actor,
                            request_id="reciprocal-" + actor.subject,
                            action="revoke-approver",
                            target=target.scope,
                        )
                    )
                )
            await wait_for_blocked(w.db, pid, tasks)
            await actor_is_free(
                w.db,
                "SELECT subject FROM {{tables.passkey_approvers}}"
                " WHERE subject=$1 FOR UPDATE NOWAIT",
                a.subject,
            )
        outcomes = await asyncio.wait_for(asyncio.gather(*tasks, return_exceptions=True), 10)
        assert sum(not isinstance(value, BaseException) for value in outcomes) == 1, outcomes
        refused = next(value for value in outcomes if isinstance(value, BaseException))
        assert isinstance(refused, (ContainmentRefused, HTTPException)), outcomes
        assert getattr(refused, "status", getattr(refused, "status_code", None)) == 401
        assert sum([await w.passkeys.can_log_in(s.scope, s.subject) for s in (a, b)]) == 1
    finally:
        await finish(tasks)


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
