"""The shared B3 credential endpoints, mounted by an app that is not secrets:
a designated holder enrols through its link, and every refusal is fixed,
console-headed and never echoes what was sent."""

from __future__ import annotations

import json
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
import pytest
from aweb_naapp_testing.webauthn import SoftAuthenticator
from fastapi import FastAPI

from aweb_naapp.console import CONSOLE_HEADERS, credential_router
from tests.runtime.credential_audit.support import (
    CONTACT,
    ORIGIN,
    World,
    bind,
    designate,
    events,
)

ROUTES = {
    "/enrolment/options": {"link_token": "token"},
    "/enrolment": {"link_token": "token", "credential": {}},
    "/contact-proof": {"proof_token": "token"},
}


@asynccontextmanager
async def console(world: World, prefix: str = "") -> AsyncIterator[httpx.AsyncClient]:
    app = FastAPI()
    app.include_router(
        credential_router(passkeys=world.passkeys, recorder=world.recorder, prefix=prefix)
    )
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN) as client:
        yield client


def console_headed(response: httpx.Response) -> bool:
    return all(response.headers.get(name) == value for name, value in CONSOLE_HEADERS.items())


async def test_a_designated_holder_enrols_through_its_link(world: World):
    scope = await bind(world)
    await designate(world, scope)
    token = world.inbox.enrolments[CONTACT][-1]
    device = SoftAuthenticator(ORIGIN)
    async with console(world, "/console") as client:
        options = await client.post("/console/enrolment/options", json={"link_token": token})
        assert options.status_code == 200
        assert console_headed(options)
        enrolled = await client.post(
            "/console/enrolment",
            json={"link_token": token, "credential": device.create(options.json())},
        )
        assert enrolled.status_code == 200
        assert enrolled.json() == {"scope": scope}
        assert token not in enrolled.text
        assert "set-cookie" not in enrolled.headers
        again = await client.post("/console/enrolment/options", json={"link_token": token})
        assert (again.status_code, again.json()) == (403, {"detail": "enrolment_refused"})
    assert [fields["payload"]["act"] for _, fields in await events(world)] == [
        "role.designated",
        "credential.enrolled",
    ]


async def test_unknown_tokens_are_refused_without_echoing_them(world: World):
    canary = os.urandom(24).hex()
    async with console(world) as client:
        refusals = {
            "/enrolment/options": ({"link_token": canary}, "enrolment_refused"),
            "/enrolment": ({"link_token": canary, "credential": {}}, "enrolment_refused"),
            "/contact-proof": ({"proof_token": canary}, "contact_proof_refused"),
        }
        for path, (body, code) in refusals.items():
            response = await client.post(path, json=body)
            assert (response.status_code, response.json()) == (403, {"detail": code}), path
            assert canary not in response.text
            assert console_headed(response)


@pytest.mark.parametrize("content_type", [None, "text/plain", "application/x-www-form-urlencoded"])
async def test_the_endpoints_take_only_json(world: World, content_type):
    headers = {} if content_type is None else {"Content-Type": content_type}
    async with console(world) as client:
        for path, body in ROUTES.items():
            response = await client.post(path, content=json.dumps(body), headers=headers)
            assert (response.status_code, response.json()) == (415, {"detail": "json_required"})
            assert console_headed(response)


async def test_the_endpoints_take_exactly_their_fields(world: World):
    canary = os.urandom(24).hex()
    async with console(world) as client:
        for path, body in ROUTES.items():
            for wrong in ({**body, "unexpected": canary}, {"unexpected": canary}, [canary]):
                response = await client.post(path, json=wrong)
                assert (response.status_code, response.json()) == (
                    400,
                    {"detail": "request_invalid"},
                ), path
                assert canary not in response.text
                assert console_headed(response)
        response = await client.post("/enrolment", json={"link_token": canary, "credential": []})
        assert (response.status_code, response.json()) == (400, {"detail": "request_invalid"})
