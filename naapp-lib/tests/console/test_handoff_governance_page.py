"""Fresh-tab governance: actual LOGIN, B2/B3, PostgreSQL and Chromium UV."""

import asyncio
import base64
import json
import re
import socket
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from urllib.parse import parse_qs

import pytest
import uvicorn
from aweb_naapp_testing.browser_capture import capture_enabled_control
from aweb_naapp_testing.network import make_certificates
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from playwright.async_api import async_playwright, expect

from aweb_naapp.console import (
    ClientIdentity,
    ConsoleSessions,
    LoginLimiter,
    apply_console_migrations,
    console_login_router,
)
from aweb_naapp.console.handoff_page import handoff_page_router
from aweb_naapp.console.handoff_store import HandoffStore
from aweb_naapp.runtime.passkeys import RelyingParty
from aweb_naapp.runtime.protected_signer.http import ProtectedOperationsHTTP
from tests.runtime.test_protected_signer import SCOPE
from tests.runtime.test_protected_signer import world as world

CSRF_KEY = "aweb.protected.console.csrf"


@pytest.fixture
async def governance_service(world, tmp_path, request):
    w = world
    w.clock.now = datetime.now(UTC)
    tls = make_certificates(tmp_path, ["signer.example.com"], ["127.0.0.1"])
    with socket.socket() as human_socket, socket.socket() as callback_socket:
        human_socket.bind(("127.0.0.1", 0))
        callback_socket.bind(("127.0.0.1", 0))
        origin = f"https://signer.example.com:{human_socket.getsockname()[1]}"
        callback_origin = f"http://127.0.0.1:{callback_socket.getsockname()[1]}"
        # The enrolled credential's RP stays signer.example.com; only the
        # browser server's ephemeral port is added to the verifier's origin.
        w.passkeys.rp = RelyingParty(origin, "Protected signer")
        await apply_console_migrations(w.passkeys.db)

        async def scopes(scope):
            return scope == SCOPE

        async def refuse_request_actor(*args):
            # This component mounts only the human origin. No request-side
            # credential can manufacture an actor here.
            raise HTTPException(403, "scope_refused")

        sessions = ConsoleSessions(w.passkeys.db, passkeys=w.passkeys, scopes=scopes)
        limiter = LoginLimiter(
            w.passkeys.db,
            client_identity=ClientIdentity(),
            limit=100,
            window=timedelta(minutes=1),
        )
        mount = ProtectedOperationsHTTP(
            w.signer,
            request_origin="https://request.example.com",
            requester=refuse_request_actor,
            reader=refuse_request_actor,
            limiter=limiter,
            human_sessions=sessions,
            human_csrf_key=CSRF_KEY,
        )
        human, loopback = FastAPI(), FastAPI()
        human.include_router(
            handoff_page_router(
                store=HandoffStore(w.passkeys.db), limiter=limiter, protected_operations=mount
            )
        )
        human.include_router(mount.human_router())
        human.include_router(console_login_router(sessions=sessions, limiter=limiter))
        callback = asyncio.get_running_loop().create_future()

        @loopback.get("/callback")
        async def complete(request: Request):
            assert not callback.done()
            callback.set_result(parse_qs(request.url.query))
            return HTMLResponse("<!doctype html><html lang=en><title>Complete</title></html>")

        operation = replace(
            w.operation,
            redirect_uri=callback_origin + "/callback" if getattr(request, "param", True) else None,
        )
        prepared = await w.signer.prepare(operation, requester=w.requester)
        servers = [
            (
                uvicorn.Server(
                    uvicorn.Config(
                        human,
                        log_level="warning",
                        access_log=False,
                        lifespan="off",
                        ssl_certfile=str(tls.cert_file),
                        ssl_keyfile=str(tls.key_file),
                    )
                ),
                human_socket,
            ),
            (
                uvicorn.Server(
                    uvicorn.Config(loopback, log_level="warning", access_log=False, lifespan="off")
                ),
                callback_socket,
            ),
        ]
        tasks = []
        try:
            tasks = [asyncio.create_task(server.serve(sockets=[sock])) for server, sock in servers]
            async with asyncio.timeout(10):
                for (server, _), task in zip(servers, tasks, strict=True):
                    while not server.started:
                        if task.done():
                            await task
                            raise RuntimeError("governance server stopped before startup")
                        await asyncio.sleep(0.01)
            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch(
                    args=[
                        "--host-resolver-rules=MAP signer.example.com 127.0.0.1",
                        "--no-proxy-server",
                    ]
                )
                try:
                    yield SimpleNamespace(
                        world=w,
                        origin=origin,
                        prepared=prepared,
                        callback=callback,
                        browser=browser,
                    )
                finally:
                    await browser.close()
        finally:
            for server, _ in servers:
                server.should_exit = True
            if tasks:
                await asyncio.wait_for(asyncio.gather(*tasks), 10)


async def authenticator(context, page):
    cdp = await context.new_cdp_session(page)
    await cdp.send("WebAuthn.enable")
    device = await cdp.send(
        "WebAuthn.addVirtualAuthenticator",
        {
            "options": {
                "protocol": "ctap2",
                "transport": "internal",
                "hasResidentKey": True,
                "hasUserVerification": True,
                "isUserVerified": True,
                "automaticPresenceSimulation": True,
            }
        },
    )
    return cdp, device["authenticatorId"]


async def open_page(service, width):
    context = await service.browser.new_context(
        ignore_https_errors=True, viewport={"width": width, "height": 900}
    )
    page = await context.new_page()
    cdp, device = await authenticator(context, page)
    credential = next(iter(service.world.device.credentials.values()))
    await cdp.send(
        "WebAuthn.addCredential",
        {
            "authenticatorId": device,
            "credential": {
                "credentialId": base64.b64encode(credential.credential_id).decode(),
                "isResidentCredential": True,
                "rpId": credential.rp_id,
                "privateKey": base64.b64encode(
                    credential.key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
                ).decode(),
                "userHandle": base64.b64encode(credential.user_handle).decode(),
                "signCount": credential.sign_count,
            },
        },
    )
    return context, page, cdp, device


@pytest.mark.parametrize("width", [375, 1440])
async def test_fresh_tab_logs_in_then_approves_the_frozen_act_with_two_real_uv_gestures(
    governance_service, width, tmp_path
):
    s = governance_service
    context, page, _, _ = await open_page(s, width)
    async with context:
        assert await context.cookies() == []
        posts = []
        page.on("request", lambda r: posts.append(r.url) if r.method == "POST" else None)
        assert (await page.goto(s.origin + "/handoff/" + s.prepared.handoff_id)).status == 200
        assert await page.evaluate("sessionStorage.length") == 0
        action = page.locator("#handoff-action")
        await expect(action).to_be_enabled()
        assert not s.callback.done()
        assert await page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        await capture_enabled_control(page, action, tmp_path / f"governance-login-{width}.png")
        await action.click()
        await expect(page.locator("#handoff-digest")).to_have_text(s.prepared.digest)
        await expect(page.locator("#handoff-fingerprint")).to_have_text(
            " ".join(s.prepared.digest[i : i + 4] for i in range(0, 16, 4))
        )
        await expect(page.locator("#handoff-act")).to_have_text("human-role.revoke")
        await expect(page.locator("#handoff-target")).to_contain_text(s.world.operation.principal)
        await expect(page.locator("#handoff-governance-title")).to_be_focused()
        assert page.url == s.origin + "/handoff/" + s.prepared.handoff_id
        assert await page.evaluate("key => !!sessionStorage.getItem(key)", CSRF_KEY)
        assert not any(url.endswith("/execute") for url in posts)
        assert not s.callback.done()
        assert await page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        await capture_enabled_control(page, action, tmp_path / f"governance-ready-{width}.png")
        summary = page.get_by_text("View the frozen operation", exact=True)
        await summary.click()
        await expect(page.locator("#handoff-payload")).to_be_visible()
        assert await page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        await capture_enabled_control(page, action, tmp_path / f"governance-expanded-{width}.png")
        await summary.click()
        await action.click()
        async with asyncio.timeout(10):
            assert await s.callback == {"handoff_id": [s.prepared.handoff_id]}
        assert [url.removeprefix(s.origin) for url in posts] == [
            "/login/options",
            "/login",
            f"/handoff/{s.prepared.handoff_id}/governance/options",
            f"/handoff/{s.prepared.handoff_id}/governance/execute",
        ]
        assert (
            await s.world.signer.receipt(s.prepared.operation_id, reader=s.world.reader)
        ).state == "committed"


@pytest.mark.parametrize("stage", ["login", "approval"])
async def test_non_uv_never_executes_or_calls_back(governance_service, stage):
    s = governance_service
    context, page, cdp, device = await open_page(s, 375)
    async with context:
        await page.goto(s.origin + "/handoff/" + s.prepared.handoff_id)
        action = page.locator("#handoff-action")
        if stage == "approval":
            await action.click()
            await expect(page.locator("#handoff-digest")).to_have_text(s.prepared.digest)
        await cdp.send(
            "WebAuthn.setUserVerified", {"authenticatorId": device, "isUserVerified": False}
        )
        await action.click()
        await expect(page.locator("body")).to_have_attribute(
            "data-handoff-state", re.compile(r"^(refused|ready)$")
        )
        assert not s.callback.done()
        assert (
            await s.world.signer.receipt(s.prepared.operation_id, reader=s.world.reader)
        ).state != "committed"


@pytest.mark.parametrize("width", [375, 1440])
async def test_current_authority_refusal_never_executes_or_calls_back(
    governance_service, width, tmp_path
):
    s = governance_service
    context, page, _, _ = await open_page(s, width)
    async with context:
        await page.goto(s.origin + "/handoff/" + s.prepared.handoff_id)
        await page.locator("#handoff-action").click()
        await expect(page.locator("#handoff-digest")).to_have_text(s.prepared.digest)
        await s.world.passkeys.db.execute("UPDATE {{tables.signer_authority}} SET active=false")
        await page.locator("#handoff-action").click()
        await expect(page.locator("body")).to_have_attribute("data-handoff-state", "refused")
        assert await page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        await page.screenshot(path=tmp_path / f"governance-refused-{width}.png", full_page=True)
        assert not s.callback.done()
        assert (
            await s.world.passkeys.db.fetch_value(
                "SELECT result FROM {{tables.protected_signer_operations}} WHERE operation_id=$1",
                s.prepared.operation_id,
            )
            is None
        )


@pytest.mark.parametrize(
    "fault", ["digest", "handoff", "payload", "consistent_target", "valid_digest"]
)
async def test_malformed_real_authenticated_state_disables_approval(governance_service, fault):
    s = governance_service
    context, page, _, _ = await open_page(s, 375)
    async with context:
        observed, executes = [], []
        page.on(
            "request",
            lambda r: (
                executes.append(r.url)
                if r.method == "POST" and r.url.endswith("/governance/execute")
                else None
            ),
        )

        async def corrupt(route):
            response = await route.fetch()
            state = await response.json()
            observed.append((response.status, state.get("digest")))
            if fault == "digest":
                state["digest"] = "not-a-digest"
            elif fault == "handoff":
                state["handoff_id"] = s.prepared.operation_id
            elif fault == "consistent_target":
                state["payload"]["request"]["subject"]["role"] = "changed.owner"
                state["payload"]["request"]["artifact"]["subject"]["role"] = "changed.owner"
            elif fault == "valid_digest":
                state["digest"] = ("0" if state["digest"][0] != "0" else "1") + state["digest"][1:]
            else:
                state["payload"]["request"]["subject"] = None
            await route.fulfill(response=response, body=json.dumps(state))

        await page.route("**/handoff/*/governance", corrupt)
        await page.goto(s.origin + "/handoff/" + s.prepared.handoff_id)
        await page.locator("#handoff-action").click()
        await expect(page.locator("body")).to_have_attribute("data-handoff-state", "refused")
        assert observed == [(200, s.prepared.digest)]
        await expect(page.locator("#handoff-action")).to_be_disabled()
        await expect(page.locator("#handoff-scope")).to_be_hidden()
        assert executes == []
        assert not s.callback.done()


@pytest.mark.parametrize("width", [375, 1440])
@pytest.mark.parametrize("response_fault", ["code", "drop"])
async def test_committed_operation_with_damaged_or_lost_response_is_unconfirmed(
    governance_service, width, response_fault, tmp_path
):
    s = governance_service
    context, page, _, _ = await open_page(s, width)
    async with context:
        observed, executes = [], []
        page.on(
            "request",
            lambda r: (
                executes.append(r.url)
                if r.method == "POST" and r.url.endswith("/governance/execute")
                else None
            ),
        )

        async def corrupt(route):
            response = await route.fetch()
            result = await response.json()
            observed.append((response.status, result.get("state")))
            if response_fault == "drop":
                # Execute really committed; only its reply to the browser is lost.
                await route.abort("failed")
            else:
                result["redirect_uri"] += "&code=unexpected"
                await route.fulfill(response=response, body=json.dumps(result))

        await page.route("**/handoff/*/governance/execute", corrupt)
        await page.goto(s.origin + "/handoff/" + s.prepared.handoff_id)
        await page.locator("#handoff-action").click()
        await expect(page.locator("#handoff-digest")).to_have_text(s.prepared.digest)
        await page.locator("#handoff-action").click()
        await expect(page.locator("body")).to_have_attribute("data-handoff-state", "unconfirmed")
        assert observed == [(200, "committed")]
        await expect(page.locator("#handoff-action")).to_be_disabled()
        await expect(page.get_by_role("status")).to_contain_text("cannot confirm")
        await expect(page.get_by_role("status")).to_contain_text(
            "Check the existing receipt in your terminal before retrying."
        )
        assert not s.callback.done()
        # The effect committed before its browser reply was damaged. Refusing
        # navigation must never replay it; aw can recover its receipt.
        assert (
            await s.world.signer.receipt(s.prepared.operation_id, reader=s.world.reader)
        ).state == "committed"
        assert (await s.world.audit.kinds()).count("protected_operation_signed") == 1
        assert executes == [s.origin + f"/handoff/{s.prepared.handoff_id}/governance/execute"]
        assert await page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        await page.screenshot(
            path=tmp_path / f"governance-uncertain-{response_fault}-{width}.png", full_page=True
        )


@pytest.mark.parametrize("governance_service", [False], indirect=True)
@pytest.mark.parametrize("width", [375, 1440])
async def test_unconfigured_callback_completes_in_place_with_a_real_receipt(
    governance_service, width, tmp_path
):
    s = governance_service
    context, page, _, _ = await open_page(s, width)
    async with context:
        await page.goto(s.origin + "/handoff/" + s.prepared.handoff_id)
        await page.locator("#handoff-action").click()
        await expect(page.locator("#handoff-digest")).to_have_text(s.prepared.digest)
        await page.locator("#handoff-action").click()
        await expect(page.locator("body")).to_have_attribute("data-handoff-state", "complete")
        assert page.url == s.origin + "/handoff/" + s.prepared.handoff_id
        assert not s.callback.done()
        assert (
            await s.world.signer.receipt(s.prepared.operation_id, reader=s.world.reader)
        ).state == "committed"
        assert await page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        await page.screenshot(path=tmp_path / f"governance-complete-{width}.png", full_page=True)
