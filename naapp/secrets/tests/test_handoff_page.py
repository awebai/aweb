"""The shared human router's page, real holding/B3 services and Chromium.

Reuse the existing component journey; this is not the H-lab root journey.
The browser executes the shipped script and a real WebAuthn authenticator.
"""

import asyncio
import base64
import hashlib
import json
import secrets
import socket
from dataclasses import asdict
from urllib.parse import parse_qs
from uuid import uuid4

import httpx
import pytest
import uvicorn
from aweb_naapp.console import CONSOLE_HEADERS
from aweb_naapp.runtime.origins import split_origins
from aweb_naapp.runtime.passkeys import RelyingParty
from aweb_naapp_testing import did_key
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from nacl.signing import SigningKey
from playwright.async_api import expect

from tests.test_console_ui_browser import browser as browser
from tests.test_handoff_sessions import API, signed_request
from tests.test_handoff_sessions import journey as journey
from tests.test_handoff_sessions import world as world


async def start(
    journey, purpose, redirect_uri="http://127.0.0.1:54321/callback", member=None, scope=None
):
    member, scope = member or journey.member, scope or journey.scope
    key, verifier = SigningKey.generate(), secrets.token_urlsafe(32)
    raw = json.dumps(
        {
            "v": 1,
            "purpose": purpose,
            "client_key": did_key(key),
            "return": "loopback",
            "redirect_uri": redirect_uri,
            "verifier_sha256": hashlib.sha256(verifier.encode()).hexdigest(),
            "scope": asdict(scope),
        }
    ).encode()
    response = await journey.client.post(
        API + "/handoffs",
        content=raw,
        headers={
            "Content-Type": "application/json",
            **member.headers(aud=API, method="POST", path="/handoffs", body=raw),
        },
    )
    assert response.status_code == 201
    return response.json()["handoff_id"], key, verifier


@pytest.mark.parametrize("purpose", ["credential", "session"])
async def test_factory_human_router_serves_the_page_and_assets_without_completing(journey, purpose):
    handoff, _, _ = await start(journey, purpose)
    response = await journey.client.get("/handoff/" + handoff)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert all(response.headers[name] == value for name, value in CONSOLE_HEADERS.items())
    assert 'data-purpose="' + purpose + '"' in response.text
    for path, mime in (
        ("/handoff-assets/handoff.js", "text/javascript"),
        ("/handoff-assets/handoff.css", "text/css"),
    ):
        asset = await journey.client.get(path)
        assert asset.status_code == 200
        assert asset.headers["content-type"].startswith(mime)
    row = await journey.world.db.fetch_one(
        "SELECT challenge,browser_sha256,completed_at,code_sha256 FROM {{tables.console_handoffs}} "
        "WHERE handoff_id=$1::uuid",
        handoff,
    )
    assert all(value is None for value in row.values())
    assert (
        await journey.world.db.fetch_value("SELECT count(*) FROM {{tables.console_sessions}}") == 0
    )


@pytest.mark.parametrize("fault", ["malformed", "unknown", "expired", "completed"])
async def test_page_refuses_invalid_or_ended_handoffs_without_reflecting_inputs(journey, fault):
    handoff, _, _ = await start(journey, "credential")
    if fault == "malformed":
        handoff = "not-a-handoff"
    elif fault == "unknown":
        handoff = str(uuid4())
    else:
        column = "expires_at" if fault == "expired" else "completed_at"
        await journey.world.db.execute(
            "UPDATE {{tables.console_handoffs}} SET " + column + "=clock_timestamp() "
            "WHERE handoff_id=$1::uuid",
            handoff,
        )
    response = await journey.client.get("/handoff/" + handoff)
    assert (response.status_code, response.json()) == (403, {"detail": "handoff_refused"})
    assert all(response.headers[name] == value for name, value in CONSOLE_HEADERS.items())


@pytest.fixture
async def page_service(journey):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    origin, callback_origin = f"http://localhost:{port}", f"http://127.0.0.1:{port}"
    journey.world.passkeys.rp = RelyingParty(origin=origin, name="Secrets")
    member, scope, device = await journey.enrol_owner("browser")
    human, loopback = FastAPI(), FastAPI()
    human.include_router(journey.factory.human_router())
    callback = asyncio.get_running_loop().create_future()

    @loopback.get("/callback")
    async def complete(request: Request):
        assert not callback.done()
        callback.set_result(parse_qs(request.url.query))
        return HTMLResponse(
            "<!doctype html><html lang=en><title>Complete</title><p>Return to your terminal.</p></html>"
        )

    app = split_origins(loopback, human, agent_origin=callback_origin, human_origin=origin)
    server = uvicorn.Server(
        uvicorn.Config(app, log_level="warning", access_log=False, lifespan="off")
    )
    task = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        async with asyncio.timeout(10):
            while not server.started:
                if task.done():
                    await task
                    raise RuntimeError("handoff server stopped before startup")
                await asyncio.sleep(0.01)
        yield origin, callback_origin, callback, member, scope, device
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, 10)
        sock.close()


@pytest.mark.parametrize(
    "purpose,width", [(p, w) for p in ("credential", "session") for w in (375, 1440)]
)
async def test_browser_uses_its_passkey_and_returns_only_after_the_purposes_ceremony(
    journey,
    browser,
    page_service,
    tmp_path,
    purpose,
    width,
):
    await browser_flow(journey, browser, page_service, tmp_path, purpose, width, user_verified=True)


@pytest.mark.parametrize("purpose", ["credential", "session"])
async def test_browser_without_user_verification_never_completes_or_calls_back(
    journey,
    browser,
    page_service,
    tmp_path,
    purpose,
):
    await browser_flow(journey, browser, page_service, tmp_path, purpose, 375, user_verified=False)


async def browser_flow(journey, browser, service, tmp_path, purpose, width, *, user_verified):
    origin, callback_origin, callback, member, scope, device = service
    handoff, key, verifier = await start(
        journey, purpose, callback_origin + "/callback", member, scope
    )
    async with await browser.new_context(viewport={"width": width, "height": 900}) as context:
        page = await context.new_page()
        cdp = await context.new_cdp_session(page)
        await cdp.send("WebAuthn.enable")
        authenticator = (
            await cdp.send(
                "WebAuthn.addVirtualAuthenticator",
                {
                    "options": {
                        "protocol": "ctap2",
                        "transport": "internal",
                        "hasResidentKey": True,
                        "hasUserVerification": True,
                        "isUserVerified": user_verified,
                        "automaticPresenceSimulation": True,
                    }
                },
            )
        )["authenticatorId"]
        if purpose == "session":
            # Import the genuinely enrolled software device into Chromium's
            # virtual authenticator. No browser API or verifier is replaced.
            credential = next(iter(device.credentials.values()))
            await cdp.send(
                "WebAuthn.addCredential",
                {
                    "authenticatorId": authenticator,
                    "credential": {
                        "credentialId": base64.b64encode(credential.credential_id).decode(),
                        "isResidentCredential": True,
                        "rpId": credential.rp_id,
                        "privateKey": base64.b64encode(
                            credential.key.private_bytes(
                                Encoding.DER,
                                PrivateFormat.PKCS8,
                                NoEncryption(),
                            )
                        ).decode(),
                        "userHandle": base64.b64encode(credential.user_handle).decode(),
                        "signCount": credential.sign_count,
                    },
                },
            )
        errors = []
        page.on("pageerror", lambda error: errors.append(error.name))
        response = await page.goto(origin + "/handoff/" + handoff)
        assert response.status == 200
        action = page.get_by_role(
            "button",
            name="Create passkey" if purpose == "credential" else "Sign in with passkey",
            exact=True,
        )
        await expect(action).to_be_enabled()
        assert await page.locator("#handoff-principal").text_content() == scope.principal
        assert await page.locator("#handoff-role").text_content() == scope.role
        assert await page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        await page.screenshot(path=tmp_path / f"handoff-{purpose}-{width}.png", full_page=True)
        assert not callback.done()
        await action.focus()
        assert await action.evaluate("element => element === document.activeElement")
        await page.keyboard.press("Enter")
        if not user_verified:
            await page.wait_for_function(
                "['refused', 'ready'].includes(document.body.dataset.handoffState)"
            )
            assert not callback.done()
            row = await journey.world.db.fetch_one(
                "SELECT completed_at,code_sha256 FROM {{tables.console_handoffs}} WHERE handoff_id=$1::uuid",
                handoff,
            )
            assert row["completed_at"] is row["code_sha256"] is None
            await expect(page.get_by_role("button", name="Allow", exact=True)).to_be_hidden()
            assert errors == []
            await page.screenshot(path=tmp_path / f"handoff-refused-{purpose}.png", full_page=True)
            return
        if purpose == "session":
            allow = page.get_by_role("button", name="Allow", exact=True)
            await expect(allow).to_be_visible()
            assert not callback.done()
            row = await journey.world.db.fetch_one(
                "SELECT login_evidence_ref,completed_at FROM {{tables.console_handoffs}} WHERE handoff_id=$1::uuid",
                handoff,
            )
            assert row["login_evidence_ref"] and row["completed_at"] is None
            await page.screenshot(path=tmp_path / f"handoff-allow-{width}.png", full_page=True)
            await allow.click()
        async with asyncio.timeout(10):
            result = await callback
        assert set(result) == {"handoff_id", "code"} and result["handoff_id"] == [handoff]
        assert errors == []
    path = "/handoffs/" + handoff + "/result"
    raw = json.dumps({"v": 1, "code": result["code"][0], "verifier": verifier}).encode()
    # The page never collects the result: only aw's retained key/verifier can.
    async with httpx.AsyncClient(base_url=origin) as client:
        response = await client.post(
            path,
            content=raw,
            headers=signed_request(
                key,
                origin,
                "POST",
                path,
                raw,
                session_id=handoff,
            ),
        )
    assert response.status_code == 200
    assert response.json()["purpose"] == purpose
    count = await journey.world.db.fetch_value("SELECT count(*) FROM {{tables.console_sessions}}")
    assert count == (1 if purpose == "session" else 0)
