"""The narrow link-bound routes on the human origin: POST-only, no-store,
no-referrer, not cross-origin, pinned Host/Origin, and no console session."""

from __future__ import annotations

from datetime import timedelta

import httpx
import pytest
import pytest_asyncio
from fastapi import FastAPI

from aweb_naapp.console import (
    ClientIdentity,
    ConsoleSessions,
    LoginLimiter,
    apply_console_migrations,
)
from aweb_naapp.runtime.protected_signer.http import ProtectedOperationsHTTP
from tests.runtime.approvals.test_passkeys import Contacts
from tests.runtime.test_protected_signer import CONTACT, ORIGIN, SCOPE
from tests.runtime.test_protected_signer_link import mailing_signer

pytest_plugins = ("tests.runtime.test_protected_signer",)


@pytest_asyncio.fixture
async def link_http(world):
    await apply_console_migrations(world.passkeys.db)
    contacts = Contacts()
    signer = mailing_signer(world, contacts)

    async def nobody(*args, **kwargs):
        raise AssertionError("no requester route is used here")

    async def admitted_scope(scope):
        return scope == SCOPE

    mount = ProtectedOperationsHTTP(
        signer, request_origin=ORIGIN, requester=nobody, reader=nobody,
        limiter=LoginLimiter(world.passkeys.db, client_identity=ClientIdentity(), limit=50,
            window=timedelta(minutes=1), clock=world.clock),
        human_sessions=ConsoleSessions(world.passkeys.db, passkeys=world.passkeys, scopes=admitted_scope),
        human_csrf_key="protected-human-csrf",
    )
    app = FastAPI()
    app.include_router(mount.human_router())
    prepared = await signer.prepare(world.operation, requester=world.requester)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN) as client:
        yield world, client, prepared, contacts.last(CONTACT)


BROWSER = {"Origin": ORIGIN}


async def sessions(world):
    return await world.passkeys.db.fetch_value("SELECT count(*) FROM {{tables.console_sessions}}")


def private(response):
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert "access-control-allow-origin" not in response.headers


async def test_the_link_reveals_by_post_only_and_opens_no_session(link_http):
    world, client, prepared, token = link_http
    path = f"/handoff/{prepared.handoff_id}/link"
    assert (await client.get(path)).status_code == 405
    assert (await client.get(path + "?token=" + token)).status_code == 405
    response = await client.post(path, json={"token": token}, headers=BROWSER)
    assert response.status_code == 200, response.text
    private(response)
    body = response.json()
    assert body["mode"] == "governance-link"
    assert body["operation_id"] == prepared.operation_id and body["digest"] == prepared.digest
    assert body["payload"]["request"] == prepared.payload and body["state"] == "pending"
    assert body["expires_at"] == prepared.expires_at
    assert token not in response.text
    assert await sessions(world) == 0


async def test_one_touch_over_http_approves(link_http):
    world, client, prepared, token = link_http
    path = f"/handoff/{prepared.handoff_id}/link"
    options = await client.post(path + "/options", json={"token": token, "decision": "approve"}, headers=BROWSER)
    assert options.status_code == 200, options.text
    private(options)
    decided = await client.post(path + "/decide", json={"token": token, "decision": "approve",
        "assertion": world.device.get(options.json())}, headers=BROWSER)
    assert decided.status_code == 200, decided.text
    private(decided)
    assert decided.json()["state"] == "committed"
    assert await sessions(world) == 0


async def test_one_touch_over_http_denies(link_http):
    world, client, prepared, token = link_http
    path = f"/handoff/{prepared.handoff_id}/link"
    options = await client.post(path + "/options", json={"token": token, "decision": "reject"}, headers=BROWSER)
    decided = await client.post(path + "/decide", json={"token": token, "decision": "reject",
        "assertion": world.device.get(options.json())}, headers=BROWSER)
    assert decided.status_code == 200, decided.text
    assert decided.json() == {"state": "refused", "code": "human_refused"}


@pytest.mark.parametrize("case", ["origin", "no-origin", "host", "token", "extra", "decision", "console-header"])
async def test_the_link_routes_refuse_anything_but_the_exact_request(link_http, case):
    world, client, prepared, token = link_http
    path = f"/handoff/{prepared.handoff_id}/link"
    body, headers, url = {"token": token}, dict(BROWSER), path
    if case == "origin":
        headers["Origin"] = "https://elsewhere.example"
    elif case == "no-origin":
        headers = {}
    elif case == "host":
        url = "https://elsewhere.example" + path
    elif case == "token":
        body = {"token": token[:-2] + "xx"}
    elif case == "extra":
        body = {"token": token, "scope": SCOPE}
    elif case == "decision":
        url, body = path + "/options", {"token": token, "decision": "maybe"}
    elif case == "console-header":
        headers["X-Console-Token"] = "anything"
    response = await client.post(url, json=body, headers=headers)
    assert response.status_code in (400, 401, 403), (case, response.status_code, response.text)
    private(response)
    assert prepared.digest not in response.text
    assert (await world.signer.receipt(prepared.operation_id, reader=world.reader)).state == "pending"
