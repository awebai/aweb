"""Owner reference ingress on real PG, passkeys and native custody.

SDK Item projection supplies data to the final persistence phase; it does not
stand in for an SDK client. Successful external vault access remains HO6 proof.
"""

import asyncio
import os
from contextlib import asynccontextmanager
from dataclasses import replace

import httpx
import pytest
from aweb_naapp.console import apply_console_migrations
from aweb_naapp.roles import unassign
from aweb_naapp.runtime.installation import InstallationRefused
from aweb_naapp.runtime.origins import split_origins
from aweb_naapp_testing.owner_acts import INSTALLATION_ID
from fastapi import FastAPI, HTTPException, Request

from aweb_secrets import records
from aweb_secrets.console import OwnerConsole, owner_console_router
from aweb_secrets.console_values import ConsoleValues, console_values_router
from aweb_secrets.custody import CustodyUnavailable, SealContext, encode_value
from aweb_secrets.custody.onepassword import project_item
from aweb_secrets.owners import OWNER_ROLE
from tests.custody.test_onepassword import field, reference, sdk_item
from tests.custody.test_onepassword_staging import candidate
from tests.test_change_sets import ALICE, ORIGIN, TEAM, enrol_owner
from tests.test_change_sets import world as _world
from tests.test_console import API, login
from tests.test_use_approvals import uses as _uses

world = _world
uses = _uses
PATH = f"/installations/{INSTALLATION_ID}/onepassword/references"


@asynccontextmanager
async def console_clients(w):
    await apply_console_migrations(w.db)

    async def installation(installation_id, *, team_id: str | None = None):
        if installation_id != INSTALLATION_ID:
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
    values = ConsoleValues(console=console, custody=w.custody)
    human_app = FastAPI()
    human_app.include_router(owner_console_router(console))
    human_app.include_router(console_values_router(values))
    app = split_origins(FastAPI(), human_app, agent_origin=API, human_origin=ORIGIN)
    async with (
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN) as human,
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=API) as agent,
    ):
        yield values, human, agent


def body(**changes):
    return {
        "secret": candidate().after,
        "reference": reference().as_config(),
        "credential_version": 1,
        **changes,
    }


async def signed_in(w, values, human, scope):
    logged = await login(w, human, scope)
    assert logged.status_code == 200
    headers = {"X-CSRF-Token": logged.json()["csrf_token"]}
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "headers": [
                (b"cookie", f"__Host-console={human.cookies.get('__Host-console')}".encode()),
                (b"x-csrf-token", headers["X-CSRF-Token"].encode()),
            ],
        }
    )
    return await values.console.sessions.current(request), headers


async def token(w, values, current):
    return await values.stage_backend_credential(
        current,
        installation_id=INSTALLATION_ID,
        value=encode_value("bearer", {"value": os.urandom(24).hex()}),
    )


async def test_reference_route_requires_owner_session_csrf_and_human_origin(world):
    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    async with console_clients(w) as (values, human, agent):
        assert (await agent.post(PATH, json=body())).status_code == 404
        assert (await human.post(PATH, json=body())).status_code == 401
        await signed_in(w, values, human, scope)
        assert (await human.post(PATH, json=body())).status_code == 403
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.onepassword_versions}}") == 0


@pytest.mark.parametrize(
    "changes",
    [
        {"credential_version": True},
        {"credential_version": 0},
        {"credential_version": "1"},
        {"reference": {"vault_id": "invalid"}},
        {"secret": {"value": "not-a-record"}},
        {"secret": candidate(backend="native").after},
        {"team_id": "other-team"},
    ],
)
async def test_invalid_reference_request_allocates_nothing_and_does_not_echo(world, changes):
    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    async with console_clients(w) as (values, human, _):
        _, headers = await signed_in(w, values, human, scope)
        response = await human.post(PATH, json=body(**changes), headers=headers)
        assert response.status_code == 400
        assert response.json() == {"detail": "request_invalid"}
        assert response.headers["cache-control"] == "no-store"
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.custody_secrets}}") == 0


async def test_missing_scoped_token_refuses_before_sdk_without_exposing_selectors(world):
    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    async with console_clients(w) as (values, human, _):
        _, headers = await signed_in(w, values, human, scope)
        response = await human.post(PATH, json=body(), headers=headers)
        assert response.status_code == 503
        assert response.json() == {"detail": "custody_unavailable"}
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.onepassword_versions}}") == 0


@pytest.mark.parametrize("changed", ["installation", "stale", "generation"])
async def test_preflight_fences_refuse_before_sdk(world, changed):
    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    async with console_clients(w) as (values, human, _):
        _, headers = await signed_in(w, values, human, scope)
        path = PATH
        if changed == "installation":
            path = PATH.replace(INSTALLATION_ID, "other-installation")
            status, code = 403, "owner_required"
        else:
            async with w.db.transaction() as tx:
                if changed == "stale":
                    await tx.execute(
                        "UPDATE {{tables.installation_fences}} SET fresh_until=clock_timestamp()-interval '1 second'"
                    )
                    status, code = 503, "authority_unavailable"
                else:
                    await tx.execute(
                        "UPDATE {{tables.installation_fences}} SET generation=generation+1"
                    )
                    status, code = 409, "generation_superseded"
        response = await human.post(path, json=body(), headers=headers)
        assert response.status_code == status
        assert response.json() == {"detail": code}
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.onepassword_versions}}") == 0


async def test_current_approver_has_no_reference_ingress_authority(uses):
    from aweb_secrets.owners import approver_scope
    from tests.test_use_approvals import designate

    w = uses.world
    await designate(uses, "finance", "finance@acme.com")
    scope = approver_scope(INSTALLATION_ID, TEAM, "finance")
    async with console_clients(w) as (_, human, _):
        options = await human.post("/login/options", json={"scope": scope})
        assert options.status_code == 200
        logged = await human.post(
            "/login",
            json={"scope": scope, "assertion": w.devices["finance@acme.com"].get(options.json())},
        )
        assert logged.status_code == 200
        response = await human.post(
            PATH, json=body(), headers={"X-CSRF-Token": logged.json()["csrf_token"]}
        )
        assert response.status_code == 403
        assert response.json() == {"detail": "owner_required"}
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.onepassword_versions}}") == 0


async def test_observed_reference_is_staged_inert_with_no_item_value(world):
    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    value = os.urandom(24).hex()
    async with console_clients(w) as (values, human, _):
        current, _ = await signed_in(w, values, human, scope)
        credential = await token(w, values, current)
        observed = project_item(
            reference(), sdk_item([field("credential", value)]), credential_context=credential
        )
        staged = await values._stage_observed_reference(
            current, admitted=w.admitted, initial=candidate(), observed=observed
        )
    assert staged.after["credential_version"] == credential.version
    assert staged.after["item_version"] == 7
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.secrets}}") == 0
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.onepassword_versions}}") == 1
    with pytest.raises(CustodyUnavailable):
        await w.custody.opener.open(staged.context)
    for row in await w.db.fetch_all("SELECT * FROM {{tables.onepassword_versions}}"):
        if value in str(dict(row)):
            raise AssertionError("observed value entered persistent metadata")


@pytest.mark.parametrize("changed", ["role", "login", "logout", "token", "kind", "team"])
async def test_authority_changed_after_observation_refuses_without_allocating(world, changed):
    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    async with console_clients(w) as (values, human, _):
        current, _ = await signed_in(w, values, human, scope)
        credential = await token(w, values, current)
        observed = project_item(
            reference(),
            sdk_item([field("credential", os.urandom(24).hex())]),
            credential_context=credential,
        )
        async with w.db.transaction() as tx:
            if changed == "role":
                await unassign(tx, ALICE, OWNER_ROLE)
            elif changed == "login":
                await w.passkeys.retire_in(
                    tx, scope=scope, subject=current.subject, authorized_by="owner"
                )
            elif changed == "token":
                await w.custody.destroy(tx, credential)
            elif changed == "kind":
                await records.create_secret(tx, INSTALLATION_ID, TEAM, candidate(kind="basic"))
        if changed == "logout":
            await values.console.sessions.close(current)
        if changed == "team":
            observed = replace(
                observed,
                credential_context=SealContext(
                    INSTALLATION_ID, "other-team", credential.secret_id, 1
                ),
            )
        expected = HTTPException if changed in {"role", "login", "logout"} else CustodyUnavailable
        with pytest.raises(expected) as refused:
            await values._stage_observed_reference(
                current, admitted=w.admitted, initial=candidate(), observed=observed
            )
        if changed in {"role", "login", "logout"}:
            assert refused.value.status_code == (403 if changed == "role" else 401)
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.onepassword_versions}}") == 0


async def test_reference_staging_rolls_back_if_parent_wait_outlasts_f6(world):
    w = world
    scope = await enrol_owner(w, ALICE, "alice@acme.com")
    async with console_clients(w) as (values, human, _):
        current, _ = await signed_in(w, values, human, scope)
        credential = await token(w, values, current)
        observed = project_item(
            reference(),
            sdk_item([field("credential", os.urandom(24).hex())]),
            credential_context=credential,
        )
        async with w.db.transaction() as tx:
            await records.create_secret(tx, INSTALLATION_ID, TEAM, candidate())
            await tx.execute(
                "UPDATE {{tables.installation_fences}} SET fresh_until=clock_timestamp()+interval '2 seconds'"
            )
        staging = None
        try:
            async with w.db.transaction() as gate:
                pid = await gate.fetch_value("SELECT pg_backend_pid()")
                await gate.fetch_one(
                    "SELECT secret_id FROM {{tables.secrets}} WHERE secret_id=$1 FOR UPDATE",
                    candidate().secret_id,
                )
                staging = asyncio.create_task(
                    values._stage_observed_reference(
                        current, admitted=w.admitted, initial=candidate(), observed=observed
                    )
                )
                async with asyncio.timeout(5):
                    while not await gate.fetch_value(
                        "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))",
                        pid,
                    ):
                        if staging.done():
                            await staging
                            pytest.fail("reference staging did not wait for its parent")
                await gate.execute("SELECT pg_sleep(2)")
            with pytest.raises(InstallationRefused):
                await asyncio.wait_for(staging, 5)
        finally:
            if staging is not None:
                if not staging.done():
                    staging.cancel()
                await asyncio.gather(staging, return_exceptions=True)
    assert await w.db.fetch_value("SELECT count(*) FROM {{tables.onepassword_versions}}") == 0
    assert (
        await w.db.fetch_value(
            "SELECT count(*) FROM {{tables.custody_secrets}} WHERE secret_id=$1",
            candidate().secret_id,
        )
        == 0
    )
