"""Owner HTTP ceremonies use the real S4, B3 and PostgreSQL paths."""

import json
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
import pytest
from aweb_naapp.console import apply_console_migrations
from aweb_naapp.roles import unassign
from aweb_naapp.runtime.origins import split_origins
from fastapi import FastAPI

from aweb_secrets.console import OwnerConsole, owner_console_router
from aweb_secrets.owners import OWNER_ROLE
from tests.test_change_sets import ALICE, ORIGIN, World, enrol_owner
from tests.test_change_sets import world as _world

world = _world
API = "https://api.secrets.example.com"


@asynccontextmanager
async def clients(world: World) -> AsyncIterator[tuple[httpx.AsyncClient, httpx.AsyncClient]]:
    await apply_console_migrations(world.db)

    async def installation(installation_id: str, *, team_id: str):
        # The real admitted F6 record this fixture already stored.
        row = await world.db.fetch_one(
            "SELECT installation_id, team_id FROM {{tables.installation_fences}}"
            " WHERE installation_id = $1 AND state = 'active'",
            installation_id,
        )
        if row is None:
            raise LookupError(installation_id)
        async with world.db.transaction() as tx:
            await world.fence.check(tx, world.admitted)
        return world.admitted

    services = OwnerConsole(
        db=world.db,
        passkeys=world.passkeys,
        credential_audit=world.credential_audit,
        directory=world.directory,
        fence=world.fence,
        installation=installation,
    )
    console = FastAPI()
    console.include_router(owner_console_router(services))
    app = split_origins(FastAPI(), console, agent_origin=API, human_origin=ORIGIN)
    async with (
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN) as human,
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=API) as agent,
    ):
        yield human, agent


async def login(world: World, human: httpx.AsyncClient, scope: str) -> httpx.Response:
    options = await human.post("/login/options", json={"scope": scope})
    assert options.status_code == 200
    return await human.post(
        "/login",
        json={"scope": scope, "assertion": world.devices["alice@acme.com"].get(options.json())},
    )


async def test_an_owner_logs_in_with_a_passkey_and_a_revoked_role_ends_the_session(world: World):
    scope = await enrol_owner(world, ALICE, "alice@acme.com")
    async with clients(world) as (human, agent):
        assert (await human.get("/session")).status_code == 401
        response = await login(world, human, scope)
        assert response.status_code == 200
        assert response.json()["csrf_token"]
        assert (await human.get("/session")).json()["scope"] == scope
        assert (await agent.get("/session")).status_code == 404
        async with world.db.transaction() as tx:
            await unassign(tx, ALICE, OWNER_ROLE)
        assert (await human.get("/session")).status_code == 401
        assert (await human.post("/login/options", json={"scope": scope})).status_code == 401


async def test_bodiless_console_logout_requires_csrf_and_ends_the_session(world: World):
    scope = await enrol_owner(world, ALICE, "alice@acme.com")
    async with clients(world) as (human, _):
        response = await login(world, human, scope)
        assert (await human.post("/logout")).status_code == 403
        assert (
            await human.post("/logout", headers={"X-CSRF-Token": response.json()["csrf_token"]})
        ).status_code == 200
        assert (await human.get("/session")).status_code == 401


async def test_team_auth_never_reaches_the_console_routes(world: World):
    async with clients(world) as (human, _):
        for path in (
            "/login/options",
            "/enrolment/options",
        ):
            response = await human.post(path, json={}, headers={"X-AWEB-Signature": "invalid"})
            assert response.status_code == 403


async def test_console_ceremony_errors_do_not_echo_input(world: World):
    canary = os.urandom(24).hex()
    async with clients(world) as (human, _):
        for path in ("/enrolment", "/enrolment/options", "/contact-proof"):
            response = await human.post(path, json={"unexpected": canary})
            assert response.status_code == 400
            assert canary not in response.text


async def test_unknown_contact_proof_is_refused(world: World):
    async with clients(world) as (human, _):
        token = os.urandom(24).hex()
        response = await human.post("/contact-proof", json={"proof_token": token})
        assert response.status_code == 403
        assert token not in response.text


@pytest.mark.parametrize("kind", ["token", "credential"])
async def test_custom_ceremony_errors_do_not_reflect_malformed_fields(world: World, kind: str):
    canary = os.urandom(24).hex()
    body = (
        {"link_token": {"unexpected": canary}}
        if kind == "token"
        else {"link_token": canary, "credential": [canary]}
    )
    path = "/enrolment/options" if kind == "token" else "/enrolment"
    async with clients(world) as (human, _):
        response = await human.post(path, json=body)
        assert response.status_code == 400
        assert canary not in response.text


@pytest.mark.parametrize("content_type", [None, "text/plain", "application/x-www-form-urlencoded"])
async def test_console_ceremonies_require_json_without_echoing_the_body(world: World, content_type):
    canary = os.urandom(24).hex()
    headers = {} if content_type is None else {"Content-Type": content_type}
    bodies = {
        "/enrolment/options": {"link_token": canary},
        "/enrolment": {"link_token": canary, "credential": {}},
        "/contact-proof": {"proof_token": canary},
    }
    async with clients(world) as (human, _):
        for path, body in bodies.items():
            response = await human.post(path, content=json.dumps(body), headers=headers)
            assert response.status_code == 415, path
            assert response.json() == {"detail": "json_required"}
            assert canary not in response.text
    for table in ("owner_act_nonces", "role_assignments", "owner_principals"):
        assert not await world.db.fetch_value("SELECT count(*) FROM {{tables." + table + "}}")
    assert world.inbox.enrolments == {}


async def test_json_content_type_parameters_are_allowed(world: World):
    scope = await enrol_owner(world, ALICE, "alice@acme.com")
    async with clients(world) as (human, _):
        response = await human.post(
            "/login/options",
            content=json.dumps({"scope": scope}),
            headers={"Content-Type": "application/json; charset=utf-8"},
        )
        assert response.status_code == 200
        response = await human.post(
            "/contact-proof",
            content=json.dumps({"proof_token": os.urandom(24).hex()}),
            headers={"Content-Type": "application/json; charset=utf-8"},
        )
        assert response.status_code == 403
        assert response.json() == {"detail": "contact_proof_refused"}
