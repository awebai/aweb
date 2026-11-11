"""A session start by the holder's direct-child agent (handoff-wire 1a).

The router admits a signer other than scope.principal only for a session start
and only when the requester check names exactly that principal as the signer's
direct parent. Every other case stays scope_not_signer. The requester check
itself is tested against real AWID chains in test_handoff_requester.py.
"""

import json
import time
from datetime import timedelta

import httpx
import pytest
from aweb_naapp_testing import REGISTRY_URL, SERVICE_TOKEN, Member
from fastapi import FastAPI, Request

from aweb_naapp.console import ClientIdentity, LoginLimiter
from aweb_naapp.console.handoff_requester import RequesterEvidence
from aweb_naapp.console.handoff_store import HandoffStore, handoff_start_router
from aweb_naapp.runtime.origins import split_origins
from aweb_naapp.runtime.team_auth import AWIDTeamCache, authenticate_request
from tests.console.test_handoff_store import ORIGIN, handoff_db, start_body

__all__ = ["handoff_db"]

API = "https://api.example"
HOLDER = "did:aw:2Zf4Lq8m3VYb9nKc5RjTs7Hd"


@pytest.fixture
async def requester_app(handoff_db, registry):
    member = Member(team_id="people:example.com")
    member.extra_cert_fields = {"member_did_aw": await registry.register_did(member.member_key)}
    await registry.add_team(member.team_id, member.team_did_key)
    await registry.add_certificate(member.certificate())
    cache = AWIDTeamCache(
        registry_url=REGISTRY_URL, ttl_seconds=60, service_token=SERVICE_TOKEN,
        transport=registry.transport,
    )
    seen = {"parent": HOLDER, "starts": []}

    async def principal(request: Request):
        return await authenticate_request(request, public_origin=API, team_cache=cache)

    async def parent(request, signer):
        if seen["parent"] is None:
            return None
        return RequesterEvidence(seen["parent"], time.monotonic_ns() + 60_000_000_000)

    async def session_start(start, signer, request, *, requester=None):
        seen["starts"].append((start, signer))
        seen["requester"] = requester
        return {"handoff_id": "h1", "expires_at": "2026-11-11T12:10:00Z"}

    api = FastAPI()
    api.include_router(
        handoff_start_router(
            store=HandoffStore(handoff_db),
            principal=principal,
            limiter=LoginLimiter(handoff_db, client_identity=ClientIdentity(), limit=50, window=timedelta(minutes=1)),
            session_start=session_start,
            requester_parent=parent,
        )
    )
    return split_origins(api, FastAPI(), agent_origin=API, human_origin=ORIGIN), member, seen


async def post(app, member, body):
    raw = json.dumps(body, separators=(",", ":")).encode()
    headers = {"Content-Type": "application/json", **member.headers(aud=API, method="POST", path="/handoffs", body=raw)}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=API) as client:
        return await client.post("/handoffs", content=raw, headers=headers)


def session_body_for(holder: str) -> dict:
    body = start_body(purpose="session")
    body["scope"]["principal"] = holder
    return body


async def test_the_holders_direct_child_starts_a_session_for_it(requester_app):
    app, member, seen = requester_app
    response = await post(app, member, session_body_for(HOLDER))
    assert response.status_code == 201, response.text
    (start, signer), = seen["starts"]
    assert start.scope.principal == HOLDER and signer.did_aw == member.extra_cert_fields["member_did_aw"]
    # The requester's original evidence deadline travels to the start's effect.
    assert seen["requester"].parent == HOLDER


async def test_a_signer_whose_parent_is_another_human_is_refused(requester_app):
    app, member, seen = requester_app
    seen["parent"] = "did:aw:3Zf4Lq8m3VYb9nKc5RjTs7Hd"
    response = await post(app, member, session_body_for(HOLDER))
    assert response.status_code == 403 and response.json() == {"detail": "scope_not_signer"}
    assert seen["starts"] == []


async def test_a_signer_with_no_qualifying_chain_is_refused(requester_app):
    app, member, seen = requester_app
    seen["parent"] = None
    response = await post(app, member, session_body_for(HOLDER))
    assert response.status_code == 403 and response.json() == {"detail": "scope_not_signer"}


async def test_a_child_cannot_start_a_credential_handoff_for_its_parent(requester_app):
    app, member, seen = requester_app
    body = start_body(purpose="credential")
    body["scope"]["principal"] = HOLDER
    response = await post(app, member, body)
    assert response.status_code == 403 and response.json() == {"detail": "scope_not_signer"}
    assert seen["starts"] == []


async def test_a_holder_certificate_in_the_body_is_invalid(requester_app):
    app, member, _ = requester_app
    body = session_body_for(HOLDER)
    body["holder_certificate"] = "eyJ9"
    response = await post(app, member, body)
    assert response.status_code == 400 and response.json() == {"detail": "handoff_invalid"}


def user_code_body(holder: str) -> dict:
    body = session_body_for(holder)
    body.update(**{"return": "user_code"}, client_hostname="laptop.local")
    del body["redirect_uri"]
    return body


async def test_a_direct_child_cannot_use_the_user_code_fallback(requester_app):
    # Loopback only for a start the holder did not sign, refused before any
    # handoff exists and independent of the fallback (contract 584d76c9c).
    app, member, seen = requester_app
    response = await post(app, member, user_code_body(HOLDER))
    assert response.status_code == 400 and response.json() == {"detail": "handoff_invalid"}
    assert seen["starts"] == []


async def test_the_holders_own_user_code_start_follows_the_fallback_rule(requester_app):
    # No fallback is enabled in the shared factory, so the holder gets 409.
    app, member, seen = requester_app
    response = await post(app, member, user_code_body(member.extra_cert_fields["member_did_aw"]))
    assert response.status_code == 409 and response.json() == {"detail": "fallback_unavailable"}
    assert seen["starts"] == []
