"""The pinned API start admits the actual signer, never an anonymous scope."""

import json
from datetime import timedelta

import httpx
import pytest
from aweb_naapp_testing import REGISTRY_URL, SERVICE_TOKEN, Member
from awid.did import stable_id_from_did_key
from fastapi import FastAPI, Request

from aweb_naapp.console import ClientIdentity, LoginLimiter
from aweb_naapp.console.handoff_store import HandoffStore, handoff_start_router
from aweb_naapp.runtime.origins import split_origins
from aweb_naapp.runtime.team_auth import AWIDTeamCache, authenticate_request
from tests.console.test_handoff_store import ORIGIN, handoff_db, start_body

__all__ = ["handoff_db"]

API = "https://api.example"


@pytest.fixture
async def signed_start(handoff_db, registry, request):
    member = Member(team_id="people:example.com")
    member.extra_cert_fields = {"member_did_aw": await registry.register_did(member.member_key)}
    await registry.add_team(member.team_id, member.team_did_key)
    await registry.add_certificate(member.certificate())
    cache = AWIDTeamCache(
        registry_url=REGISTRY_URL,
        ttl_seconds=60,
        service_token=SERVICE_TOKEN,
        transport=registry.transport,
    )

    async def principal(request: Request):
        return await authenticate_request(request, public_origin=API, team_cache=cache)

    api = FastAPI()
    api.include_router(
        handoff_start_router(
            store=HandoffStore(handoff_db),
            principal=principal,
            limiter=LoginLimiter(
                handoff_db,
                client_identity=ClientIdentity(),
                limit=getattr(request, "param", 20),
                window=timedelta(minutes=1),
            ),
        )
    )
    app = split_origins(api, FastAPI(), agent_origin=API, human_origin=ORIGIN)
    body = start_body(purpose="credential")
    body["scope"]["principal"] = member.extra_cert_fields["member_did_aw"]
    return app, member, body


async def post_start(app, member, body, *, signed=True, origin=API):
    raw = json.dumps(body, separators=(",", ":")).encode()
    headers = {"Content-Type": "application/json"}
    if signed:
        headers.update(member.headers(aud=API, method="POST", path="/handoffs", body=raw))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=origin) as client:
        return await client.post("/handoffs", content=raw, headers=headers)


async def test_unsigned_api_start_has_no_handoff_effect(signed_start, handoff_db):
    app, member, body = signed_start
    response = await post_start(app, member, body, signed=False)
    assert response.status_code == 401
    assert await handoff_db.fetch_value("SELECT count(*) FROM {{tables.console_handoffs}}") == 0


async def test_registered_signer_starts_only_its_own_scope(signed_start, handoff_db):
    app, member, body = signed_start
    response = await post_start(app, member, body)
    assert response.status_code == 201
    assert set(response.json()) == {"handoff_id", "expires_at"}
    assert await handoff_db.fetch_value("SELECT count(*) FROM {{tables.console_handoffs}}") == 1
    assert await handoff_db.fetch_value("SELECT count(*) FROM {{tables.console_sessions}}") == 0


async def test_signer_cannot_select_another_principal(signed_start, handoff_db):
    app, member, body = signed_start
    body["scope"]["principal"] = stable_id_from_did_key(Member(team_id=member.team_id).did_key)
    response = await post_start(app, member, body)
    assert response.status_code == 403
    assert response.json() == {"detail": "scope_not_signer"}
    assert await handoff_db.fetch_value("SELECT count(*) FROM {{tables.console_handoffs}}") == 0


async def test_human_origin_still_refuses_team_auth_before_routing(signed_start, handoff_db):
    app, member, body = signed_start
    response = await post_start(app, member, body, origin=ORIGIN)
    assert response.status_code == 403
    assert response.json()["code"] == "team_auth_refused"
    assert await handoff_db.fetch_value("SELECT count(*) FROM {{tables.console_handoffs}}") == 0


async def test_unsupported_session_fallback_is_final(signed_start, handoff_db):
    app, member, body = signed_start
    body.update(purpose="session", **{"return": "user_code"}, client_hostname="owned-client")
    del body["redirect_uri"]
    response = await post_start(app, member, body)
    assert response.status_code == 409
    assert response.json() == {"detail": "fallback_unavailable"}
    assert await handoff_db.fetch_value("SELECT count(*) FROM {{tables.console_handoffs}}") == 0


@pytest.mark.parametrize("signed_start", [1], indirect=True)
async def test_creation_throttle_keeps_its_typed_wire_refusal(signed_start, handoff_db):
    app, member, body = signed_start
    assert (await post_start(app, member, body)).status_code == 201
    response = await post_start(app, member, body)
    assert response.status_code == 429
    assert response.json() == {"detail": "handoff_rate_limited"}
    assert "Retry-After" in response.headers
    assert await handoff_db.fetch_value("SELECT count(*) FROM {{tables.console_handoffs}}") == 1
