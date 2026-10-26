"""Human token ingress over real S4/B3/F6/native custody, never the agent API."""

import asyncio
import os
from contextlib import asynccontextmanager

import httpx
import pytest
from aweb_naapp.console import apply_console_migrations
from aweb_naapp.roles import unassign
from aweb_naapp.runtime.origins import split_origins
from aweb_naapp_testing.owner_acts import INSTALLATION_ID
from fastapi import FastAPI

from aweb_secrets.console import OwnerConsole, owner_console_router
from aweb_secrets.console_ui import console_ui_router
from aweb_secrets.console_values import ConsoleValues, console_values_router
from aweb_secrets.custody import CustodyUnavailable, SealContext, decode_value
from aweb_secrets.owners import OWNER_ROLE
from tests.test_change_sets import ALICE, ORIGIN, TEAM, enrol_owner
from tests.test_change_sets import world as _world
from tests.test_console import API, login
from tests.test_use_approvals import uses as _uses

world = _world
uses = _uses
PATH = f"/installations/{INSTALLATION_ID}/backend-credentials/onepassword/versions"


@asynccontextmanager
async def clients(w, *, lookup_ready=None, resume=None):
    await apply_console_migrations(w.db)

    async def installation(installation_id, *, team_id: str | None = None):
        if installation_id != INSTALLATION_ID:
            raise LookupError(installation_id)
        if lookup_ready is not None:
            lookup_ready.set()
            await resume.wait()
        return w.admitted

    console = OwnerConsole(
        db=w.db,
        passkeys=w.passkeys,
        credential_audit=w.credential_audit,
        directory=w.directory,
        fence=w.fence,
        verifier=w.owner.verifier,
        installation=installation,
    )
    human_app = FastAPI()
    human_app.include_router(owner_console_router(console))
    human_app.include_router(console_ui_router(sessions=console.sessions))
    human_app.include_router(
        console_values_router(ConsoleValues(console=console, custody=w.custody))
    )
    app = split_origins(FastAPI(), human_app, agent_origin=API, human_origin=ORIGIN)
    async with (
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN) as human,
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=API) as agent,
    ):
        yield human, agent


def no_value(response, value):
    if value in response.text:
        raise AssertionError("submitted value appeared in response")


async def test_owner_token_ingress_is_sealed_scoped_inert_and_never_echoed(world):
    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    value = os.urandom(24).hex()
    async with clients(w) as (human, agent):
        logged = await login(w, human, scope)
        response = await human.post(
            PATH, json={"value": value}, headers={"X-CSRF-Token": logged.json()["csrf_token"]}
        )
        assert response.status_code == 201
        assert response.json() == {
            "v": 1,
            "backend": "onepassword",
            "credential_id": "bkc_onepassword",
            "version": 1,
        }
        assert response.headers["cache-control"] == "no-store"
        no_value(response, value)
        assert (await agent.post(PATH, json={"value": value})).status_code == 404
    context = SealContext(INSTALLATION_ID, TEAM, "bkc_onepassword", 1)
    opened = await w.custody.backend_credential_preview.open(context)
    if decode_value("bearer", opened.plaintext.reveal())["value"] != value:
        raise AssertionError("sealed token differs from entered token")
    with pytest.raises(CustodyUnavailable):
        await w.custody.backend_credential_opener.open(context)
    with pytest.raises(CustodyUnavailable):
        await w.custody.opener.open(context)
    assert (
        await w.db.fetch_value("SELECT active_version FROM {{tables.onepassword_credentials}}")
        is None
    )
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.secrets}}") == 0
    for row in await w.db.fetch_all("SELECT * FROM {{tables.sealed_versions}}"):
        if value in str(dict(row)):
            raise AssertionError("entered token present as plaintext in custody")


async def test_ingress_requires_login_and_this_tabs_csrf_before_any_allocation(world):
    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    value = os.urandom(24).hex()
    async with clients(w) as (human, _):
        assert (await human.post(PATH, json={"value": value})).status_code == 401
        await login(w, human, scope)
        response = await human.post(PATH, json={"value": value})
        assert response.status_code == 403
        assert response.json() == {"detail": "csrf_token_required"}
        no_value(response, value)
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.custody_secrets}}") == 0


@pytest.mark.parametrize(
    "body",
    [{"value": ""}, {"value": {}}, {"value": 1}, {}, {"value": "x", "team_id": "another-team"}],
)
async def test_invalid_ingress_body_is_constant_and_allocates_nothing(world, body):
    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    async with clients(w) as (human, _):
        logged = await login(w, human, scope)
        response = await human.post(
            PATH, json=body, headers={"X-CSRF-Token": logged.json()["csrf_token"]}
        )
        assert response.status_code == 400
        assert response.json() == {"detail": "request_invalid"}
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.custody_secrets}}") == 0


async def test_ingress_json_and_scope_fail_without_reflecting_submitted_bytes(world):
    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    value = os.urandom(24).hex()
    async with clients(w) as (human, _):
        logged = await login(w, human, scope)
        headers = {"X-CSRF-Token": logged.json()["csrf_token"]}
        response = await human.post(
            PATH, content=value, headers={**headers, "Content-Type": "text/plain"}
        )
        assert response.status_code == 415
        no_value(response, value)
        response = await human.post(
            PATH, content=value, headers={**headers, "Content-Type": "application/json"}
        )
        assert response.status_code == 400
        no_value(response, value)
        response = await human.post(
            PATH.replace(INSTALLATION_ID, "another-installation"),
            json={"value": value},
            headers=headers,
        )
        assert response.status_code == 403
        no_value(response, value)
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.custody_secrets}}") == 0


async def test_owner_role_revoked_during_lookup_cannot_enter_a_token(world):
    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    ready, resume = asyncio.Event(), asyncio.Event()
    async with clients(w, lookup_ready=ready, resume=resume) as (human, _):
        logged = await login(w, human, scope)
        task = asyncio.create_task(
            human.post(
                PATH,
                json={"value": os.urandom(24).hex()},
                headers={"X-CSRF-Token": logged.json()["csrf_token"]},
            )
        )
        try:
            await asyncio.wait_for(ready.wait(), 5)
            async with w.db.transaction() as tx:
                await unassign(tx, ALICE, OWNER_ROLE)
            resume.set()
            response = await asyncio.wait_for(task, 5)
            assert response.status_code == 403
            assert response.json() == {"detail": "owner_required"}
        finally:
            resume.set()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.custody_secrets}}") == 0


@pytest.mark.parametrize(
    "failure,status,code",
    [("stale", 503, "authority_unavailable"), ("generation", 409, "generation_superseded")],
)
async def test_ingress_preserves_f6_status_and_allocates_nothing(world, failure, status, code):
    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    value = os.urandom(24).hex()
    async with clients(w) as (human, _):
        logged = await login(w, human, scope)
        async with w.db.transaction() as tx:
            if failure == "stale":
                await tx.execute(
                    "UPDATE {{tables.installation_fences}} SET fresh_until=clock_timestamp()-interval '1 second' WHERE installation_id=$1",
                    INSTALLATION_ID,
                )
            else:
                await tx.execute(
                    "UPDATE {{tables.installation_fences}} SET generation=generation+1 WHERE installation_id=$1",
                    INSTALLATION_ID,
                )
        response = await human.post(
            PATH, json={"value": value}, headers={"X-CSRF-Token": logged.json()["csrf_token"]}
        )
        assert response.status_code == status
        assert response.json() == {"detail": code}
        no_value(response, value)
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.custody_secrets}}") == 0


async def test_login_evidence_retired_during_lookup_cannot_stage_a_token(world):
    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    holder = await w.passkeys.designated_approver(scope)
    ready, resume = asyncio.Event(), asyncio.Event()
    async with clients(w, lookup_ready=ready, resume=resume) as (human, _):
        logged = await login(w, human, scope)
        task = asyncio.create_task(
            human.post(
                PATH,
                json={"value": os.urandom(24).hex()},
                headers={"X-CSRF-Token": logged.json()["csrf_token"]},
            )
        )
        try:
            await asyncio.wait_for(ready.wait(), 5)
            async with w.db.transaction() as tx:
                await w.passkeys.retire_in(
                    tx, scope=scope, subject=holder.subject, authorized_by="owner"
                )
            resume.set()
            response = await asyncio.wait_for(task, 5)
            assert response.status_code == 401
            assert "Max-Age=0" in response.headers["set-cookie"]
            assert await w.db.fetch_value(
                "SELECT closed_at IS NOT NULL FROM {{tables.console_sessions}}"
            )
        finally:
            resume.set()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.custody_secrets}}") == 0


async def test_current_approver_session_has_no_backend_credential_ingress_authority(uses):
    from tests.test_use_approvals import designate

    w = uses.world
    await designate(uses, "finance", "finance@acme.com")
    from aweb_secrets.owners import approver_scope

    scope = approver_scope(INSTALLATION_ID, TEAM, "finance")
    async with clients(w) as (human, _):
        options = await human.post("/login/options", json={"scope": scope})
        assert options.status_code == 200
        logged = await human.post(
            "/login",
            json={
                "scope": scope,
                "assertion": w.devices["finance@acme.com"].get(options.json()),
            },
        )
        assert logged.status_code == 200
        response = await human.post(
            PATH,
            json={"value": os.urandom(24).hex()},
            headers={"X-CSRF-Token": logged.json()["csrf_token"]},
        )
        assert response.status_code == 403
        assert response.json() == {"detail": "owner_required"}
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.custody_secrets}}") == 0


async def test_owner_role_revocation_waits_for_the_real_ingress_transaction(world):
    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    async with clients(w) as (human, _):
        logged = await login(w, human, scope)
        headers = {"X-CSRF-Token": logged.json()["csrf_token"]}
        assert (
            await human.post(PATH, json={"value": os.urandom(24).hex()}, headers=headers)
        ).status_code == 201
        posting = revoking = None
        started = asyncio.get_running_loop().create_future()

        async def revoke():
            async with w.db.transaction() as tx:
                started.set_result(await tx.fetch_value("SELECT pg_backend_pid()"))
                await unassign(tx, ALICE, OWNER_ROLE)

        try:
            async with w.db.transaction() as gate:
                gate_pid = await gate.fetch_value("SELECT pg_backend_pid()")
                await gate.fetch_value(
                    "SELECT credential_id FROM {{tables.onepassword_credentials}} WHERE installation_id=$1 AND team_id=$2 FOR UPDATE",
                    INSTALLATION_ID,
                    TEAM,
                )
                posting = asyncio.create_task(
                    human.post(PATH, json={"value": os.urandom(24).hex()}, headers=headers)
                )
                async with asyncio.timeout(5):
                    while not (
                        ingress_pid := await w.db.fetch_value(
                            "SELECT pid FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)) LIMIT 1",
                            gate_pid,
                        )
                    ):
                        if posting.done():
                            await posting
                            pytest.fail("ingress did not reach its private parent lock")
                        await asyncio.sleep(0.01)
                revoking = asyncio.create_task(revoke())
                revoker_pid = await asyncio.wait_for(started, 5)
                assert ingress_pid != revoker_pid and gate_pid != ingress_pid
                async with asyncio.timeout(5):
                    while ingress_pid not in await w.db.fetch_value(
                        "SELECT pg_blocking_pids($1)", revoker_pid
                    ):
                        if revoking.done():
                            await revoking
                            pytest.fail("role revocation committed before authorized ingress")
                        await asyncio.sleep(0.01)
            response, _ = await asyncio.wait_for(asyncio.gather(posting, revoking), 10)
            assert response.status_code == 201 and response.json()["version"] == 2
            assert (
                await human.post(PATH, json={"value": os.urandom(24).hex()}, headers=headers)
            ).status_code == 401
        finally:
            tasks = [t for t in (posting, revoking) if t is not None]
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
    assert (
        await w.db.fetch_value("SELECT active_version FROM {{tables.onepassword_credentials}}")
        is None
    )
    assert await w.db.fetch_value("SELECT last_version FROM {{tables.custody_secrets}}") == 2


async def test_expired_f6_after_wait_rolls_back_the_new_token_version(world):
    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    async with clients(w) as (human, _):
        logged = await login(w, human, scope)
        headers = {"X-CSRF-Token": logged.json()["csrf_token"]}
        assert (
            await human.post(PATH, json={"value": os.urandom(24).hex()}, headers=headers)
        ).status_code == 201
        await w.db.execute(
            "UPDATE {{tables.installation_fences}} SET fresh_until=clock_timestamp()+interval '2 seconds' WHERE installation_id=$1",
            INSTALLATION_ID,
        )
        posting = None
        try:
            async with w.db.transaction() as gate:
                gate_pid = await gate.fetch_value("SELECT pg_backend_pid()")
                await gate.fetch_value(
                    "SELECT credential_id FROM {{tables.onepassword_credentials}} WHERE installation_id=$1 AND team_id=$2 FOR UPDATE",
                    INSTALLATION_ID,
                    TEAM,
                )
                posting = asyncio.create_task(
                    human.post(PATH, json={"value": os.urandom(24).hex()}, headers=headers)
                )
                async with asyncio.timeout(5):
                    while not await w.db.fetch_value(
                        "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))",
                        gate_pid,
                    ):
                        if posting.done():
                            await posting
                            pytest.fail("ingress did not reach its private parent wait")
                        await asyncio.sleep(0.01)
                    while await w.db.fetch_value(
                        "SELECT fresh_until>clock_timestamp() FROM {{tables.installation_fences}} WHERE installation_id=$1",
                        INSTALLATION_ID,
                    ):
                        await asyncio.sleep(0.02)
            response = await asyncio.wait_for(posting, 5)
            assert response.status_code == 503
            assert response.json() == {"detail": "authority_unavailable"}
        finally:
            if posting is not None and not posting.done():
                posting.cancel()
            if posting is not None:
                await asyncio.gather(posting, return_exceptions=True)
    assert await w.db.fetch_value("SELECT last_version FROM {{tables.custody_secrets}}") == 1
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.sealed_versions}}") == 1
    assert (
        await w.db.fetch_value("SELECT active_version FROM {{tables.onepassword_credentials}}")
        is None
    )
