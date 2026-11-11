"""The production origins mount shared handoffs without creating authority."""

import hashlib
import json
import secrets
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from aweb_naapp.roles import PrincipalKey, has_role
from aweb_naapp_testing import Member, did_key
from aweb_naapp_testing.webauthn import SoftAuthenticator
from fastapi import FastAPI
from nacl.signing import SigningKey

from aweb_secrets.console import OwnerConsole, owner_console_router
from aweb_secrets.owners import OWNER_ROLE
from tests.test_handoff_sessions import journey as journey
from tests.test_handoff_sessions import signed_request
from tests.test_handoff_sessions import world as world
from tests.test_production_bootstrap import root as root
from tests.test_production_bootstrap import signed_in_owner


@pytest.fixture
async def registered_member(root, registry):
    # Reuse the actual installed production root and its owner bootstrap.
    # Credential collection grants this second certified member no holding.
    await signed_in_owner(root)
    _, _, _, owner, _, _, _, _ = root
    member = Member(
        team_id=owner.team_id,
        team_key=owner.team_key,
        certificate_id="handoff-member",
    )
    principal = await registry.register_did(member.member_key)
    member.extra_cert_fields = {"member_did_aw": principal}
    await registry.add_certificate(member.certificate())
    return member, principal


def start_request(root, member, principal, *, purpose="credential"):
    _, _, settings, _, installed, _, _, _ = root
    key = SigningKey.generate()
    verifier = secrets.token_urlsafe(32)
    body = json.dumps(
        {
            "v": 1,
            "purpose": purpose,
            "client_key": did_key(key),
            "return": "loopback",
            "redirect_uri": "http://127.0.0.1:54321/callback",
            "verifier_sha256": hashlib.sha256(verifier.encode()).hexdigest(),
            "scope": {
                "installation_id": installed["installation_id"],
                "role": OWNER_ROLE,
                "principal": principal,
            },
        }
    ).encode()
    headers = {
        "Content-Type": "application/json",
        **member.headers(aud=settings.public_origin, method="POST", path="/handoffs", body=body),
    }
    return key, verifier, body, headers


async def test_production_credential_handoff_uses_both_origins_and_grants_no_holding(
    root, registered_member
):
    service, client, settings, _, _, _, _, _ = root
    member, principal = registered_member
    db = service.runtime.db()
    before = [
        await db.fetch_value("SELECT count(*) FROM " + table)
        for table in ("role_assignments", "passkey_credentials", "console_sessions")
    ]
    key, verifier, body, headers = start_request(root, member, principal)
    started = await client.post(settings.public_origin + "/handoffs", content=body, headers=headers)
    assert started.status_code == 201
    assert sum(route.path == "/handoffs" for route in service.api_app.routes) == 1
    handoff = started.json()["handoff_id"]
    prefix = f"/handoff/{handoff}/credential"
    human = settings.console_origin
    assert (await client.get(settings.public_origin + prefix)).status_code == 404
    state = await client.get(human + prefix)
    assert state.status_code == 200
    browser = {"Origin": human, "X-CSRF-Token": state.json()["csrf_token"]}
    options = await client.post(human + prefix + "/options", json={}, headers=browser)
    assert options.status_code == 200
    device = SoftAuthenticator(human)
    complete = await client.post(
        human + prefix + "/complete",
        json={"credential": device.create(options.json())},
        headers=browser,
    )
    assert complete.status_code == 200
    code = parse_qs(urlsplit(complete.json()["redirect_uri"]).query)["code"][0]
    path = f"/handoffs/{handoff}/result"
    raw = json.dumps({"v": 1, "code": code, "verifier": verifier}).encode()
    result_headers = signed_request(key, human, "POST", path, raw, session_id=handoff)
    result = await client.post(human + path, content=raw, headers=result_headers)
    assert result.status_code == 200
    assert result.json()["purpose"] == "credential"
    assert set(result.json()["credential"]) == {"credential_id", "public_key", "rp_id"}
    assert (await client.post(human + path, content=raw, headers=result_headers)).status_code == 403
    assert not await has_role(db, PrincipalKey(member.team_id, principal), OWNER_ROLE)
    assert [
        await db.fetch_value("SELECT count(*) FROM " + table)
        for table in ("role_assignments", "passkey_credentials", "console_sessions")
    ] == before


async def test_production_session_start_refuses_a_certified_member_without_the_holding(
    root, registered_member
):
    _, client, settings, _, _, _, _, _ = root
    member, principal = registered_member
    _, _, body, headers = start_request(root, member, principal, purpose="session")
    response = await client.post(
        settings.public_origin + "/handoffs", content=body, headers=headers
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "role_not_held"


async def test_production_human_origin_refuses_team_auth_and_partial_signed_cookie_fallback(
    root, registered_member
):
    _, client, settings, _, _, _, _, _ = root
    member, principal = registered_member
    _, _, body, headers = start_request(root, member, principal)
    response = await client.post(
        settings.console_origin + "/handoffs", content=body, headers=headers
    )
    assert response.status_code == 403
    assert response.json()["detail"] == "team_auth_refused"
    assert (await client.get(settings.console_origin + "/activity")).status_code == 200
    response = await client.get(
        settings.console_origin + "/activity", headers={"X-Console-Key": member.did_key}
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "console_session_required"


async def test_owner_console_s4_uses_the_shared_verified_session_once(journey):
    # This is the shared native component fixture, not a supported root bootstrap.
    original = journey.world.console
    console = OwnerConsole(
        db=original.db,
        passkeys=original.passkeys,
        directory=original.directory,
        fence=original.fence,
        verifier=original.verifier,
        installation=original.installation,
        credential_audit=original.credential_audit,
        key_bound=journey.factory.current,
    )
    app = FastAPI()
    app.include_router(owner_console_router(console))
    key, issued = await journey.open()
    raw = b"{}"
    headers = signed_request(
        key,
        journey.device.origin,
        "POST",
        "/logout",
        raw,
        session_id=issued["session_id"],
        csrf=issued["csrf_token"],
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app), base_url=journey.device.origin
    ) as client:
        assert (await client.post("/logout", content=raw, headers=headers)).status_code == 200
        assert (await client.post("/logout", content=raw, headers=headers)).status_code == 401
