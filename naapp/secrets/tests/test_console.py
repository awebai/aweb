"""Owner HTTP ceremonies use the real S4, B3 and PostgreSQL paths.

Authored during Juan's execution pause; run after explicit resume.
"""

import asyncio
import base64
import hashlib
import json
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
import pytest
from aweb_naapp.console import apply_console_migrations
from aweb_naapp.roles import unassign
from aweb_naapp.runtime.origins import split_origins
from aweb_naapp_testing.owner_acts import INSTALLATION_ID
from aweb_naapp_testing.webauthn import SoftAuthenticator
from fastapi import FastAPI

from aweb_secrets.change_policy import require_four_eyes
from aweb_secrets.console import OwnerConsole, owner_console_router
from aweb_secrets.owners import OWNER_ROLE, owner_scope
from tests.test_change_sets import ALICE, BOB, CAROL, ORIGIN, TEAM, World, enrol_owner
from tests.test_change_sets import world as _world

world = _world
API = "https://api.secrets.example.com"


@asynccontextmanager
async def clients(
    world: World,
    *,
    lookup_ready: asyncio.Event | None = None,
    continue_lookup: asyncio.Event | None = None,
) -> AsyncIterator[tuple[httpx.AsyncClient, httpx.AsyncClient]]:
    await apply_console_migrations(world.db)

    async def installation(installation_id: str):
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
        if lookup_ready is not None:
            lookup_ready.set()
            assert continue_lookup is not None
            await continue_lookup.wait()
        return world.admitted

    services = OwnerConsole(
        db=world.db,
        passkeys=world.passkeys,
        directory=world.directory,
        fence=world.fence,
        verifier=world.owner.verifier,
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


async def test_owner_bootstrap_uses_the_installations_team_and_never_returns_the_link(world: World):
    contact = "alice@acme.com"
    scope = owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did)
    subject = {
        "app_id": world.admitted.app_id,
        "installation_id": INSTALLATION_ID,
        "role": scope,
        "contact_sha256": hashlib.sha256(contact.encode()).hexdigest(),
    }
    signing, signature = world.owner.sign("app-role.designate", subject)
    body = {
        "signing": base64.b64encode(signing).decode(),
        "signature": signature,
        "team_id": TEAM,
        "principal": ALICE.principal_did,
        "contact": contact,
    }
    path = f"/installations/{INSTALLATION_ID}/owner-acts"
    async with clients(world) as (human, agent):
        assert (
            await human.post(path, json={**body, "team_id": "other:example.com"})
        ).status_code == 403
        assert (await agent.post(path, json=body)).status_code == 404
        response = await human.post(path, json=body)
        assert response.status_code == 200
        assert response.json()["scope"] == scope
        token = world.inbox.enrolments[contact][-1]
        assert token not in response.text
        assert (await human.post(path, json=body)).status_code == 403
        options = await human.post("/enrolment/options", json={"link_token": token})
        assert options.status_code == 200
        device = SoftAuthenticator(ORIGIN)
        credential = device.create(options.json())
        enrolled = await human.post(
            "/enrolment", json={"link_token": token, "credential": credential}
        )
        assert enrolled.status_code == 200
        assert token not in enrolled.text
        world.devices[contact] = device
        assert (await login(world, human, scope)).status_code == 200
        assert (
            await human.post("/enrolment/options", json={"link_token": token})
        ).status_code == 403


async def test_team_auth_never_reaches_the_console_routes(world: World):
    async with clients(world) as (human, _):
        for path in (
            "/login/options",
            "/enrolment/options",
            f"/installations/{INSTALLATION_ID}/owner-acts",
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


@pytest.mark.parametrize("owners", [2, 3])
async def test_recovery_counts_the_recovering_owner_out_of_four_eyes(world: World, owners: int):
    alice = await enrol_owner(world, ALICE, "alice@acme.com")
    await enrol_owner(world, BOB, "bob@acme.com")
    if owners == 3:
        await enrol_owner(world, CAROL, "carol@acme.com")
    async with world.db.transaction() as tx:
        await require_four_eyes(
            tx, installation_id=INSTALLATION_ID, team_id=TEAM, directory=world.directory
        )
    contact = "alice-new@acme.com"
    subject = {
        "app_id": world.admitted.app_id,
        "installation_id": INSTALLATION_ID,
        "role": alice,
        "contact_sha256": hashlib.sha256(contact.encode()).hexdigest(),
    }
    signing, signature = world.owner.sign("app-credential.recover", subject)
    body = {
        "signing": base64.b64encode(signing).decode(),
        "signature": signature,
        "team_id": TEAM,
        "principal": ALICE.principal_did,
        "contact": contact,
    }
    async with clients(world) as (human, _):
        response = await human.post(f"/installations/{INSTALLATION_ID}/owner-acts", json=body)
        assert response.status_code == (403 if owners == 2 else 200)
        if owners == 2:
            assert response.json() == {"detail": "four_eyes_needs_two_owners"}
            assert await world.passkeys.login_options(alice)
        else:
            assert world.inbox.notices["alice@acme.com"]


async def test_a_non_controller_signature_cannot_bootstrap_an_owner(world: World):
    from nacl.signing import SigningKey

    scope = owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did)
    contact = "alice@acme.com"
    subject = {
        "app_id": world.admitted.app_id,
        "installation_id": INSTALLATION_ID,
        "role": scope,
        "contact_sha256": hashlib.sha256(contact.encode()).hexdigest(),
    }
    signing, _ = world.owner.sign("app-role.designate", subject)
    signature = base64.b64encode(SigningKey.generate().sign(signing).signature).decode().rstrip("=")
    async with clients(world) as (human, _):
        response = await human.post(
            f"/installations/{INSTALLATION_ID}/owner-acts",
            json={
                "signing": base64.b64encode(signing).decode(),
                "signature": signature,
                "team_id": TEAM,
                "principal": ALICE.principal_did,
                "contact": contact,
            },
        )
        assert response.status_code == 403
        assert not world.inbox.enrolments


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


@pytest.mark.parametrize(
    ("failure", "status", "code"),
    [
        ("stale", 503, "authority_unavailable"),
        ("superseded", 409, "generation_superseded"),
    ],
)
@pytest.mark.parametrize("stage", ["lookup", "transaction"])
async def test_owner_acts_preserve_typed_fence_refusals(world: World, failure, status, code, stage):
    contact = "alice@acme.com"
    scope = owner_scope(INSTALLATION_ID, TEAM, ALICE.principal_did)
    subject = {
        "app_id": world.admitted.app_id,
        "installation_id": INSTALLATION_ID,
        "role": scope,
        "contact_sha256": hashlib.sha256(contact.encode()).hexdigest(),
    }
    signing, signature = world.owner.sign("app-role.designate", subject)
    body = {
        "signing": base64.b64encode(signing).decode(),
        "signature": signature,
        "team_id": TEAM,
        "principal": ALICE.principal_did,
        "contact": contact,
    }
    path = f"/installations/{INSTALLATION_ID}/owner-acts"
    lookup_ready = asyncio.Event()
    continue_lookup = asyncio.Event()

    async def invalidate():
        if failure == "stale":
            await world.db.execute(
                "UPDATE {{tables.installation_fences}}"
                " SET fresh_until = clock_timestamp() - interval '1 second'"
                " WHERE installation_id = $1",
                INSTALLATION_ID,
            )
        else:
            await world.db.execute(
                "UPDATE {{tables.installation_fences}}"
                " SET generation = generation + 1 WHERE installation_id = $1",
                INSTALLATION_ID,
            )

    gates = (
        {"lookup_ready": lookup_ready, "continue_lookup": continue_lookup}
        if stage == "transaction"
        else {}
    )
    task = None
    async with clients(world, **gates) as (human, _):
        try:
            if stage == "lookup":
                await invalidate()
                response = await human.post(path, json=body)
            else:
                task = asyncio.create_task(human.post(path, json=body))
                await asyncio.wait_for(lookup_ready.wait(), 5)
                await invalidate()
                continue_lookup.set()
                response = await asyncio.wait_for(task, 5)
            assert response.status_code == status
            assert response.json()["detail"] == code
            for table in (
                "role_assignments",
                "owner_principals",
                "passkey_approvers",
                "owner_act_nonces",
            ):
                assert (
                    await world.db.fetch_value(f"SELECT count(*) FROM {{{{tables.{table}}}}}") == 0
                )
            assert not world.inbox.enrolments
            assert not world.inbox.notices
        finally:
            continue_lookup.set()
            if task is not None and not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("content_type", [None, "text/plain", "application/x-www-form-urlencoded"])
async def test_console_ceremonies_require_json_without_echoing_the_body(world: World, content_type):
    canary = os.urandom(24).hex()
    headers = {} if content_type is None else {"Content-Type": content_type}
    bodies = {
        "/enrolment/options": {"link_token": canary},
        "/enrolment": {"link_token": canary, "credential": {}},
        "/contact-proof": {"proof_token": canary},
        f"/installations/{INSTALLATION_ID}/owner-acts": {"signing": canary},
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
