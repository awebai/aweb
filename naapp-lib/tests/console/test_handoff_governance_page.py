"""Fresh-tab governance: actual LOGIN, B2/B3, PostgreSQL and Chromium UV."""

import asyncio
import base64
import json
import os
import re
import socket
from contextlib import asynccontextmanager
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
from tests.runtime.protected_signer_support import SCOPE
from tests.runtime.protected_signer_support import world as world

CSRF_KEY = "aweb.protected.console.csrf"


def governance_browser_options():
    args = ["--host-resolver-rules=MAP signer.example.com 127.0.0.1"]
    if proxy := os.environ.get("HTTPS_PROXY"):
        # Route.fetch runs in Playwright's driver, outside Chromium's resolver
        # map. An explicit proxy reaches both request paths; the native guard
        # forwards this exact RP host to loopback without public DNS.
        return {
            "args": args,
            "proxy": {"server": proxy, "bypass": "localhost,127.0.0.1,[::1]"},
        }
    # The isolated runner has an exact hosts entry for driver DNS and no
    # external route. Keep direct routing when no native guard was selected.
    return {"args": [*args, "--no-proxy-server"]}


def test_governance_browser_selects_the_native_guard_for_browser_and_route_fetch(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:43210")
    options = governance_browser_options()
    assert options["proxy"]["server"] == "http://127.0.0.1:43210"
    assert "signer.example.com" not in options["proxy"]["bypass"]
    assert "--no-proxy-server" not in options["args"]
    assert "--host-resolver-rules=MAP signer.example.com 127.0.0.1" in options["args"]


def test_governance_browser_keeps_direct_routing_inside_the_isolated_runner(monkeypatch):
    monkeypatch.delenv("HTTPS_PROXY", raising=False)
    options = governance_browser_options()
    assert "proxy" not in options
    assert "--no-proxy-server" in options["args"]
    assert "--host-resolver-rules=MAP signer.example.com 127.0.0.1" in options["args"]


@pytest.fixture
async def governance_service(world, tmp_path, request):
    async with governance_server(world, tmp_path, redirect=getattr(request, "param", True)) as service:
        yield service


@asynccontextmanager
async def governance_server(world, tmp_path, *, redirect=True, signer=None):
    """The human origin over real TLS in Chromium, for ``signer`` (by default
    the world's own) with one prepared operation."""
    w = world
    signer = w.signer if signer is None else signer
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
            signer,
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
            redirect_uri=callback_origin + "/callback" if redirect else None,
        )
        prepared = await signer.prepare(operation, requester=w.requester)
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
                browser = await playwright.chromium.launch(**governance_browser_options())
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


async def open_page(service, width, **context_options):
    context = await service.browser.new_context(
        ignore_https_errors=True, viewport={"width": width, "height": 900}, **context_options
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
        await expect(page.locator("#handoff-title")).to_have_text(
            f"Remove {s.world.operation.principal} as example.owner of example?"
        )
        await expect(page.locator("#handoff-technical")).to_contain_text(
            f"Principal{s.world.operation.principal}"
        )
        await expect(page.locator("#handoff-title")).to_be_focused()
        await expect(page.locator("body")).to_have_attribute("data-handoff-state", "ready")
        await expect(action).to_have_text("Approve")
        assert page.url == s.origin + "/handoff/" + s.prepared.handoff_id
        assert await page.evaluate("key => !!sessionStorage.getItem(key)", CSRF_KEY)
        assert not any(url.endswith("/execute") for url in posts)
        assert not s.callback.done()
        assert await page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        await capture_enabled_control(page, action, tmp_path / f"governance-ready-{width}.png")
        # The full digest and frozen operation are one step away, in
        # Technical details (Juan 2026-11-13, via coordinator).
        await page.get_by_text("Technical details", exact=True).click()
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
async def test_cancelled_login_or_non_uv_approval_never_executes_or_calls_back(
    governance_service, stage, tmp_path
):
    s = governance_service
    context, page, cdp, device = await open_page(s, 375)
    async with context:
        posts, responses = [], []
        page.on("request", lambda r: posts.append(r.url) if r.method == "POST" else None)
        page.on(
            "response",
            lambda r: (
                responses.append((r.url.removeprefix(s.origin), r.status))
                if r.request.method == "POST"
                else None
            ),
        )
        await page.goto(s.origin + "/handoff/" + s.prepared.handoff_id)
        action = page.locator("#handoff-action")
        timeouts = []

        async def short_client_timeout(route):
            response = await route.fetch()
            options = await response.json()
            assert response.status == 200 and options["userVerification"] == "required"
            timeouts.append(options.get("timeout"))
            # Only a browser hint changes. The real server's challenge,
            # required UV, RP and nonce/freshness policy remain intact.
            options["timeout"] = 1000
            await route.fulfill(response=response, body=json.dumps(options))

        if stage == "login":
            await cdp.send(
                "WebAuthn.setAutomaticPresenceSimulation",
                {"authenticatorId": device, "enabled": False},
            )
            await page.route("**/login/options", short_client_timeout)
        if stage == "approval":
            await action.click()
            await expect(page.locator("#handoff-digest")).to_have_text(s.prepared.digest)
            await cdp.send(
                "WebAuthn.setUserVerified", {"authenticatorId": device, "isUserVerified": False}
            )
        started = asyncio.get_running_loop().time()
        try:
            await action.click()
            await expect(page.locator("body")).to_have_attribute(
                "data-handoff-state",
                "login-required" if stage == "login" else re.compile(r"^(refused|ready)$"),
                timeout=120_000 if stage == "login" else 5000,
            )
        finally:
            if stage == "login":
                await page.unroute("**/login/options", short_client_timeout)
            # Each case owns a fresh context/authenticator; closing it also
            # resets presence, timeout hints and credentials for the next case.
        if stage == "login":
            elapsed = asyncio.get_running_loop().time() - started
            # This unchanged production status is set only by the
            # NotAllowedError branch. Exception identity is inferred from
            # that exercised branch, not captured by a CDP exception event.
            status_text = "The passkey prompt was cancelled. You can try again."
            await expect(page.locator("#handoff-status")).to_have_text(status_text)
            assert len(timeouts) == 1
            assert responses == [("/login/options", 200)]
            assert [url.removeprefix(s.origin) for url in posts] == ["/login/options"]
            assert elapsed >= 0.9  # Supports the timeout input, not the sole proof.
            await expect(action).to_be_enabled()
            await expect(action).to_have_text("Sign in with passkey")
            await expect(page.locator("#handoff-governance")).to_be_hidden()
            for field in ("act", "digest", "fingerprint"):
                await expect(page.locator(f"#handoff-{field}")).to_be_empty()
            await expect(
                page.get_by_role("button", name="Approve")
            ).to_be_hidden()
            assert not any("/governance/" in url for url in posts)
            (tmp_path / "governance-cancel-375.json").write_text(
                json.dumps(
                    {
                        "exception_name_inferred": "NotAllowedError",
                        "exception_identity_source": "exercised production status branch",
                        "status_text": status_text,
                        "http": responses,
                        "client_timeout_ms": 1000,
                        "elapsed_seconds": elapsed,
                        "state": await page.locator("body").get_attribute("data-handoff-state"),
                    },
                    indent=2,
                )
                + "\n"
            )
            await page.screenshot(path=tmp_path / "governance-cancel-375.png", full_page=True)
        assert not s.callback.done()
        assert (
            await s.world.signer.receipt(s.prepared.operation_id, reader=s.world.reader)
        ).state != "committed"
        assert "protected_operation_signed" not in await s.world.audit.kinds()


async def test_login_401_cannot_expose_approval_or_send_governance_requests(governance_service):
    s = governance_service
    context, page, _, _ = await open_page(s, 375)
    async with context:
        options, login_statuses, posts = [], [], []
        page.on("request", lambda r: posts.append(r.url) if r.method == "POST" else None)

        async def retain_options(route):
            response = await route.fetch()
            assert response.status == 200
            options.append(await response.json())
            await route.fulfill(response=response)

        async def without_uv(route):
            # Same enrolled holder and real challenge/signature, but no UV.
            # The actual LOGIN service decides; no refusal response is faked.
            body = route.request.post_data_json
            body["assertion"] = s.world.device.get(
                options[-1], origin=s.origin, user_verified=False
            )
            response = await route.fetch(post_data=json.dumps(body))
            login_statuses.append(response.status)
            await route.fulfill(response=response)

        await page.route("**/login/options", retain_options)
        await page.route("**/login", without_uv)
        await page.goto(s.origin + "/handoff/" + s.prepared.handoff_id)
        await page.locator("#handoff-action").click()
        await expect(page.locator("body")).to_have_attribute("data-handoff-state", "refused")
        assert login_statuses == [401]
        assert [url.removeprefix(s.origin) for url in posts] == ["/login/options", "/login"]
        await expect(page.locator("#handoff-action")).to_be_disabled()
        await expect(page.locator("#handoff-governance")).to_be_hidden()
        for field in ("act", "digest", "fingerprint"):
            await expect(page.locator(f"#handoff-{field}")).to_be_empty()
        assert not s.callback.done()
        assert (
            await s.world.signer.receipt(s.prepared.operation_id, reader=s.world.reader)
        ).state != "committed"
        assert "protected_operation_signed" not in await s.world.audit.kinds()


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
        await expect(page.get_by_role("status")).to_contain_text("could not confirm")
        await expect(page.get_by_role("status")).to_contain_text(
            "Your owner page shows the outcome under History."
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
