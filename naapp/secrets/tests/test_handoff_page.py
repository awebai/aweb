"""The shared human router's page, real holding/B3 services and Chromium.

Reuse the existing component journey; this is not the H-lab root journey.
The browser executes the shipped script and a real WebAuthn authenticator.
"""

import asyncio
import base64
import hashlib
import json
import re
import secrets
import socket
from dataclasses import asdict
from datetime import timedelta
from urllib.parse import parse_qs
from uuid import uuid4

import httpx
import pytest
import uvicorn
from aweb_naapp.console import CONSOLE_HEADERS, ClientIdentity, LoginLimiter
from aweb_naapp.console.handoff_sessions import ConsoleHandoffs
from aweb_naapp.runtime.origins import split_origins
from aweb_naapp.runtime.passkeys import RelyingParty
from aweb_naapp_testing import did_key
from aweb_naapp_testing.browser_capture import capture_enabled_control
from awid.id_certificates import encode_id_chain_header
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from nacl.signing import SigningKey
from playwright.async_api import expect

from tests.test_console_ui_browser import browser as browser
from tests.test_handoff_direct_child import REQUESTER, certify_agent
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


@pytest.mark.parametrize("fault", ["malformed", "unknown", "expired", "completed", "released"])
async def test_page_refuses_invalid_or_ended_handoffs_without_reflecting_inputs(journey, fault):
    handoff, _, _ = await start(journey, "credential")
    if fault == "malformed":
        handoff = "not-a-handoff"
    elif fault == "unknown":
        handoff = str(uuid4())
    else:
        column = {"expired": "expires_at", "completed": "completed_at", "released": "released_at"}[
            fault
        ]
        await journey.world.db.execute(
            "UPDATE {{tables.console_handoffs}} SET " + column + "=clock_timestamp() "
            "WHERE handoff_id=$1::uuid",
            handoff,
        )
    response = await journey.client.get("/handoff/" + handoff)
    assert response.status_code == 403
    assert response.headers["content-type"].startswith("text/html")
    assert "<main" in response.text and "<h1" in response.text
    assert 'role="status"' in response.text
    assert handoff not in response.text
    assert "<script" not in response.text and "<button" not in response.text
    assert all(response.headers[name] == value for name, value in CONSOLE_HEADERS.items())


def limited_factory(original):
    return ConsoleHandoffs(
        db=original.db,
        passkeys=original.passkeys,
        authority=original.authority,
        principal=original.principal,
        human_member=original.human_member,
        limiter=LoginLimiter(
            original.db, client_identity=ClientIdentity(), limit=1, window=timedelta(minutes=1)
        ),
    )


async def test_throttled_page_is_html_with_retry_after_and_ceremony_refusal_stays_json(journey):
    handoff, _, _ = await start(journey, "credential")
    factory = limited_factory(journey.factory)
    human = FastAPI()
    human.include_router(factory.human_router())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=human, client=("192.0.2.123", 9000)),
        base_url=factory.passkeys.rp.origin,
    ) as client:
        path = "/handoff/" + handoff
        assert (await client.get(path)).status_code == 200
        response = await client.get(path)
        assert response.status_code == 429
        assert response.headers["content-type"].startswith("text/html")
        assert 0 < int(response.headers["Retry-After"]) <= 60
        assert all(response.headers[name] == value for name, value in CONSOLE_HEADERS.items())
        assert 'role="status"' in response.text and "<h1" in response.text
        assert handoff not in response.text
        assert "<script" not in response.text and "<button" not in response.text
        ceremony = await client.get(path + "/credential")
        assert (ceremony.status_code, ceremony.json()) == (429, {"detail": "handoff_rate_limited"})
        assert int(ceremony.headers["Retry-After"]) > 0


@pytest.fixture
async def page_service(journey, request, console_listener, console_tls):
    # The holder act's audience and credential must share the real HTTPS RP.
    # aw's callback remains plain HTTP loopback on its own listener.
    origin = console_listener.origin
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as callback_socket:
        callback_socket.bind(("127.0.0.1", 0))
        callback_origin = f"http://127.0.0.1:{callback_socket.getsockname()[1]}"
        journey.world.passkeys.rp = RelyingParty(origin=origin, name="Secrets")
        member, scope, device = await journey.enrol_owner("browser")
        human, loopback = FastAPI(), FastAPI()
        factory = (
            limited_factory(journey.factory)
            if getattr(request, "param", False)
            else journey.factory
        )
        human.include_router(factory.human_router())
        callback = asyncio.get_running_loop().create_future()

        @loopback.get("/callback")
        async def complete(request: Request):
            assert not callback.done()
            callback.set_result(parse_qs(request.url.query))
            return HTMLResponse(
                "<!doctype html><html lang=en><title>Complete</title><p>Return to your terminal.</p></html>"
            )

        app = split_origins(loopback, human, agent_origin=callback_origin, human_origin=origin)
        servers = [
            (
                uvicorn.Server(
                    uvicorn.Config(
                        app,
                        log_level="warning",
                        access_log=False,
                        lifespan="off",
                        ssl_certfile=str(console_tls.cert_file),
                        ssl_keyfile=str(console_tls.key_file),
                    )
                ),
                console_listener.socket,
            ),
            (
                uvicorn.Server(
                    uvicorn.Config(
                        app,
                        log_level="warning",
                        access_log=False,
                        lifespan="off",
                    )
                ),
                callback_socket,
            ),
        ]
        tasks = []
        try:
            for server, sock in servers:
                tasks.append(asyncio.create_task(server.serve(sockets=[sock])))
            async with asyncio.timeout(10):
                for (server, _), task in zip(servers, tasks, strict=True):
                    while not server.started:
                        if task.done():
                            await task
                            raise RuntimeError("handoff server stopped before startup")
                        await asyncio.sleep(0.01)
            yield origin, callback_origin, callback, member, scope, device
        finally:
            for server, _ in servers:
                server.should_exit = True
            if tasks:
                await asyncio.wait_for(asyncio.gather(*tasks), 10)


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


@pytest.mark.parametrize("width", [375, 1440])
@pytest.mark.parametrize(
    "page_service,expected_status", [(False, 403), (True, 429)], indirect=["page_service"]
)
async def test_unavailable_link_renders_recovery_without_starting_a_ceremony(
    browser,
    page_service,
    tmp_path,
    width,
    expected_status,
):
    origin, _, callback, _, _, _ = page_service
    async with await browser.new_context(
        viewport={"width": width, "height": 900},
        ignore_https_errors=True,
    ) as context:
        page = await context.new_page()
        requests = []
        page.on("request", lambda request: requests.append(request.url))
        response = await page.goto(origin + "/handoff/not-a-handoff")
        assert response.status == 403
        # One more navigation makes the small real shared limiter return429;
        # ordinary capacity remains403. Both are inert HTML browser pages.
        response = await page.reload()
        assert response.status == expected_status
        await expect(page.get_by_role("heading", level=1)).to_be_visible()
        await expect(page.get_by_role("status")).to_be_visible()
        assert await page.get_by_role("button").count() == 0
        assert not [
            url for url in requests if url.endswith(("/options", "/credential", "/session"))
        ]
        assert not callback.done()
        assert await page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        await page.screenshot(
            path=tmp_path / f"handoff-unavailable-{response.status}-{width}.png", full_page=True
        )


async def browser_flow(journey, browser, service, tmp_path, purpose, width, *, user_verified):
    origin, callback_origin, callback, member, scope, device = service
    handoff, key, verifier = await start(
        journey, purpose, callback_origin + "/callback", member, scope
    )
    async with await browser.new_context(
        viewport={"width": width, "height": 900},
        ignore_https_errors=True,
    ) as context:
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
        await capture_enabled_control(page, action, tmp_path / f"handoff-{purpose}-{width}.png")
        assert not callback.done()
        await action.focus()
        assert await action.evaluate("element => element === document.activeElement")
        await page.keyboard.press("Enter")
        if not user_verified:
            await expect(page.locator("body")).to_have_attribute(
                "data-handoff-state", re.compile(r"^(refused|ready)$")
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
            await expect(page.locator("#handoff-allow-title")).to_be_focused()
            await capture_enabled_control(page, allow, tmp_path / f"handoff-allow-{width}.png")
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


async def requester_start(journey, member, scope, laptop, chain, redirect_uri):
    """A session start that ``laptop``, the holder's direct-child agent, signs."""
    key, verifier = SigningKey.generate(), secrets.token_urlsafe(32)
    raw = json.dumps(
        {
            "v": 1,
            "purpose": "session",
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
            "X-AWID-ID-Chain": encode_id_chain_header(
                {"v": 1, "type": "aweb.id-chain", "certificates": chain}
            ),
            **laptop.headers(aud=API, method="POST", path="/handoffs", body=raw),
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["handoff_id"]


@pytest.mark.parametrize("width", [375, 1440])
@pytest.mark.parametrize("requester", ["valid", "none", "malformed"])
@pytest.mark.parametrize("journey", [REQUESTER], indirect=True)
async def test_the_requesting_agent_is_shown_apart_from_the_identity_or_the_page_fails_closed(
    journey, browser, page_service, tmp_path, requester, width
):
    origin, callback_origin, callback, member, scope, _ = page_service
    laptop, chain = await certify_agent(journey, member, [member.id_certificate], "laptop")
    if requester == "none":
        handoff, _, _ = await start(
            journey, "session", callback_origin + "/callback", member, scope
        )
    else:
        handoff = await requester_start(
            journey, member, scope, laptop, chain, callback_origin + "/callback"
        )
    async with await browser.new_context(
        viewport={"width": width, "height": 900},
        ignore_https_errors=True,
    ) as context:
        page = await context.new_page()
        if requester == "malformed":
            original = []

            async def malformed(route):
                # The service's real, admitted state, with a requester the page cannot show.
                response = await route.fetch()
                state = await response.json()
                original.append((response.status, state.get("requester", {}).get("id")))
                state["requester"] = {"id": "", "key_fingerprint": 7}
                await route.fulfill(response=response, json=state)

            await page.route(f"**/handoff/{handoff}/session", malformed)
        response = await page.goto(origin + "/handoff/" + handoff)
        assert response.status == 200
        await expect(page.locator("body")).to_have_attribute(
            "data-handoff-state", re.compile(r"^(refused|ready)$")
        )
        label, value = page.locator("#handoff-requester-label"), page.locator("#handoff-requester")
        action = page.locator("#handoff-action")
        if requester == "valid":
            await expect(label).to_be_visible()
            await expect(value).to_be_visible()
            shown = await value.text_content()
            assert laptop.extra_cert_fields["member_did_aw"] in shown and " · key " in shown
            # The identity being signed in stays the holder's, not the agent's.
            assert await page.locator("#handoff-principal").text_content() == scope.principal
            await expect(action).to_be_enabled()
        elif requester == "none":
            await expect(label).to_be_hidden()
            await expect(value).to_be_hidden()
            await expect(action).to_be_enabled()
        else:
            # Only the requester changed: the service admitted this laptop's start.
            assert original == [(200, laptop.extra_cert_fields["member_did_aw"])]
            assert await page.evaluate("document.body.dataset.handoffState") == "refused"
            await expect(page.locator("#handoff-scope")).to_be_hidden()
            await expect(action).to_be_disabled()
        assert await page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        capture = tmp_path / f"handoff-requester-{requester}-{width}.png"
        if requester == "malformed":
            await page.screenshot(path=capture, full_page=True)
        else:
            await capture_enabled_control(page, action, capture)
        assert not callback.done()
