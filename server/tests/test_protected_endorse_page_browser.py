"""A real root-agent endorsement on the approval page, in Chromium.

The server's own composed signer prepares the endorsement (admission policy,
registry, retained effect); the human origin is served over real TLS and the
approver signs in and approves with their enrolled passkey through a virtual
authenticator. What the page says comes from the operation definition.
"""

import asyncio
import base64
import re
import socket
from contextlib import asynccontextmanager
from datetime import timedelta
from types import SimpleNamespace

import pytest
import uvicorn
from aweb_naapp_testing.network import make_certificates
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from fastapi import FastAPI, HTTPException
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
from tests.test_independent_protected_signer import TEAM
from tests.test_protected_admission_native import admissions as admissions  # noqa: F401
from tests.test_protected_admission_native import prepare, root_operation

pytest_plugins = ("tests.test_independent_protected_signer",)

CSRF_KEY = "aweb.protected.console.csrf"
HOST = "human.customer.example"


@asynccontextmanager
async def endorse_page(a, tmp_path, *, headless=True):
    """The human origin, over TLS, for the server's composed human signer,
    with one prepared root endorsement."""
    tls = make_certificates(tmp_path, [HOST], ["127.0.0.1"])
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        origin = f"https://{HOST}:{listener.getsockname()[1]}"
        # The enrolled credential's RP stays the host; only this server's
        # ephemeral port joins the verifier's origin.
        a.human.passkeys.rp = RelyingParty(origin, "Protected signing")
        db = a.human.db
        await apply_console_migrations(db)
        scope = a.actor.b3_scope

        async def scopes(candidate):
            return candidate == scope

        async def refuse(*args):
            raise HTTPException(403, "scope_refused")

        sessions = ConsoleSessions(db, passkeys=a.human.passkeys, scopes=scopes)
        limiter = LoginLimiter(db, client_identity=ClientIdentity(), limit=100, window=timedelta(minutes=1))
        mount = ProtectedOperationsHTTP(a.human.signer, request_origin=a.w.request_origin, requester=refuse,
            reader=refuse, limiter=limiter, human_sessions=sessions, human_csrf_key=CSRF_KEY)
        human = FastAPI()
        human.include_router(handoff_page_router(store=HandoffStore(db), limiter=limiter, protected_operations=mount))
        human.include_router(mount.human_router())
        human.include_router(console_login_router(sessions=sessions, limiter=limiter))
        operation = root_operation(a)
        response = await prepare(a, operation)
        assert response.status_code == 200, response.text
        server = uvicorn.Server(uvicorn.Config(human, log_level="warning", access_log=False, lifespan="off", ws="none",
            ssl_certfile=str(tls.cert_file), ssl_keyfile=str(tls.key_file)))
        task = asyncio.create_task(server.serve(sockets=[listener]))
        try:
            async with asyncio.timeout(10):
                while not server.started:
                    if task.done():
                        await task
                        raise RuntimeError("human origin stopped before startup")
                    await asyncio.sleep(0.01)
            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch(headless=headless,
                    args=[f"--host-resolver-rules=MAP {HOST} 127.0.0.1", "--no-proxy-server"])
                try:
                    yield SimpleNamespace(origin=origin, operation=operation, prepared=response.json(), browser=browser)
                finally:
                    await browser.close()
        finally:
            server.should_exit = True
            await asyncio.wait_for(task, 10)


async def open_with_passkey(a, browser, width):
    context = await browser.new_context(ignore_https_errors=True, viewport={"width": width, "height": 900})
    page = await context.new_page()
    cdp = await context.new_cdp_session(page)
    await cdp.send("WebAuthn.enable")
    device = (await cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {
        "protocol": "ctap2", "transport": "internal", "hasResidentKey": True, "hasUserVerification": True,
        "isUserVerified": True, "automaticPresenceSimulation": True}}))["authenticatorId"]
    credential = next(iter(a.device.credentials.values()))
    await cdp.send("WebAuthn.addCredential", {"authenticatorId": device, "credential": {
        "credentialId": base64.b64encode(credential.credential_id).decode(),
        "isResidentCredential": True,
        "rpId": credential.rp_id,
        "privateKey": base64.b64encode(
            credential.key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())).decode(),
        "userHandle": base64.b64encode(credential.user_handle).decode(),
        "signCount": credential.sign_count,
    }})
    return context, page


@pytest.mark.asyncio
@pytest.mark.parametrize("width", [375, 1440])
async def test_a_root_endorsement_asks_in_plain_words_and_approves_with_the_passkey(admissions, tmp_path, width):
    a = admissions
    async with endorse_page(a, tmp_path) as s:
        context, page = await open_with_passkey(a, s.browser, width)
        async with context:
            await page.goto(s.origin + "/handoff/" + s.prepared["handoff_id"])
            action = page.locator("#handoff-action")
            await expect(action).to_have_text("Sign in with passkey")
            await action.click()
            await expect(action).to_have_text("Approve")
            team = TEAM.partition(":")[0]
            question = f"Make oats-root your root agent for {team}?"
            await expect(page.locator("#handoff-title")).to_have_text(question)
            assert await page.title() == question
            request = s.prepared["payload"]["request"]
            # The frozen responsibility statement first, then the one limit
            # line; no claim twice.
            bounds = a.policy["bounds"]
            # The limits are part of what it does, in the list the person reads.
            await expect(page.locator("#handoff-consequences li")).to_have_text([
                request["responsibility_statement"],
                f"It can add agents only to {team}: at most {bounds['max_active']} at a time, "
                f"and at most {bounds['max_per_window']} per hour.",
            ])
            await expect(page.locator("#handoff-names dt")).to_have_text(["Root agent", "Teams"])
            await expect(page.locator("#handoff-names dd")).to_have_text(["oats-root", team])
            # The root asks for itself: it is named, not shown as its DID.
            # When it was asked: the moment the request was prepared.
            await expect(page.locator("#handoff-requested")).to_have_text(re.compile(r"^oats-root, asked .+$"))
            assert "did:aw" not in await page.locator("#handoff-facts").inner_text()
            assert "limits" not in await page.locator("#handoff-status").inner_text()
            # The name rows and the facts below them are visibly two groups.
            gap = await page.evaluate(
                "document.querySelector('#handoff-facts').getBoundingClientRect().top"
                " - document.querySelector('#handoff-names').getBoundingClientRect().bottom")
            assert gap >= 8
            body = await page.locator("main").inner_text()
            assert TEAM not in body.split("Technical details")[0]
            assert "endorse" not in body.lower().split("technical details")[0]
            assert await page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            await page.screenshot(path=tmp_path / f"endorse-ready-{width}.png", full_page=True)
            await action.click()
            await expect(page.locator("#handoff-title")).to_have_text("Approved")
            await expect(page.locator("#handoff-governance-title")).to_have_text("What was asked")
            receipt = await a.human.signer.receipt(s.operation.operation_id, reader=a.actor)
            assert receipt.state == "committed"
