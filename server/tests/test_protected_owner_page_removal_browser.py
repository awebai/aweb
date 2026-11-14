"""The owner page's Remove…, end to end in Chromium.

Sign in with the owner's passkey, press Remove for a member on the owner page
(same-origin CSRF prepare of an owner-approved removal), approve that exact
act with the passkey on its page, and the membership is revoked with a stored
receipt. The human origin is the real owner page, handoff page, owner-session
route and console login over TLS; no root or requester grant is active.
"""

import asyncio
import socket
from contextlib import asynccontextmanager
from datetime import timedelta
from types import SimpleNamespace
from urllib.parse import quote

import pytest
import uvicorn
from aweb_naapp_testing.network import make_certificates
from fastapi import FastAPI
from playwright.async_api import async_playwright, expect

from aweb_naapp.console import ClientIdentity, LoginLimiter, apply_console_migrations, console_login_router
from aweb_naapp.console.handoff_page import handoff_page_router
from aweb_naapp.console.handoff_store import HandoffStore
from aweb_naapp.runtime.passkeys import RelyingParty
from tests.test_independent_protected_signer import DOMAIN, did
from tests.test_protected_admission_native import admissions as admissions  # noqa: F401
from tests.test_protected_boundary_retention_native import activate
from tests.test_protected_endorse_page_browser import HOST, open_with_passkey
from tests.test_protected_owner_initiation_native import independent_reader
from tests.test_protected_owner_removal_native import revoked

pytest_plugins = ("tests.test_independent_protected_signer",)

CSRF_KEY = "aweb.protected.console.csrf"


@asynccontextmanager
async def owner_origin(a, tmp_path):
    """The team owner's human origin: owner page, approval page, owner-session
    route and passkey login, served over TLS."""
    from aweb.protected_signing.owner import owner_router

    c = a.w.app
    await activate(a, tmp_path)
    await apply_console_migrations(c.db)
    tls = make_certificates(tmp_path, [HOST], ["127.0.0.1"])
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        origin = f"https://{HOST}:{listener.getsockname()[1]}"
        c.passkeys.rp = RelyingParty(origin, "Protected signing")
        sessions = c.protected_sessions()
        limiter = LoginLimiter(c.db, client_identity=ClientIdentity(), limit=100, window=timedelta(minutes=1))
        mount = c.operations_http(limiter=limiter, human_sessions=sessions, human_csrf_key=CSRF_KEY)
        human = FastAPI()
        human.include_router(owner_router(c, sessions=sessions, csrf_key=CSRF_KEY))
        human.include_router(handoff_page_router(store=HandoffStore(c.db), limiter=limiter, protected_operations=mount))
        human.include_router(mount.human_router())
        human.include_router(console_login_router(sessions=sessions, limiter=limiter))
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
                browser = await playwright.chromium.launch(
                    args=[f"--host-resolver-rules=MAP {HOST} 127.0.0.1", "--no-proxy-server"])
                try:
                    yield origin, browser
                finally:
                    await browser.close()
        finally:
            server.should_exit = True
            await asyncio.wait_for(task, 10)


@pytest.mark.asyncio
@pytest.mark.parametrize("width", [375, 1440])
@pytest.mark.parametrize("lost_answer", [False, True])
async def test_the_owner_removes_a_member_from_the_owner_page_with_one_exact_passkey_approval(
    admissions, tmp_path, width, lost_answer, monkeypatch
):
    a = admissions
    rows = await a.w.registry.list_team_certificates_fresh(DOMAIN, "engineering", active_only=True)
    root = next(row for row in rows if row.member_did_key == did(a.w.root))
    certificate = {"certificate_id": root.certificate_id}
    async with independent_reader(a), owner_origin(a, tmp_path) as (origin, browser):
        from aweb_naapp.runtime.protected_signer import SignerRefused

        custody = a.w.app.authority.custody
        deliver, deliveries = custody.deliver_retained, []

        async def release(operation, retained):
            deliveries.append(retained.fields())
            await deliver(operation, retained)
            if lost_answer:
                raise SignerRefused("receipt_unavailable")  # Lose only the already applied answer.

        monkeypatch.setattr(custody, "deliver_retained", release)
        # No root or requester grant: the owner's own session starts it.
        await a.w.db.execute("UPDATE {{tables.protected_requester_bindings}} SET active=false")
        # The team owner's enrolled passkey.
        context, page = await open_with_passkey(SimpleNamespace(device=a.w.device), browser, width)
        async with context:
            posts = []
            page.on("request", lambda r: posts.append(r.url.removeprefix(origin)) if r.method == "POST" else None)
            await page.goto(origin + "/login?scope=" + quote(a.w.human.b3_scope, safe=""))
            await page.locator("#login button").click()
            await page.wait_for_url(origin + "/")
            remove = page.locator(f'[data-remove-certificate="{root.certificate_id}"]')
            await expect(remove).to_have_text(f"Remove {root.alias}…")
            assert await page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            await page.screenshot(path=tmp_path / f"owner-remove-{width}.png", full_page=True)
            await remove.click()
            await page.wait_for_url(origin + "/handoff/*")
            approve = page.locator("#handoff-action")
            await expect(approve).to_have_text("Approve")
            await expect(page.locator("#handoff-title")).to_have_text(f"Remove {root.alias} from engineering?")
            await expect(page.locator("#handoff-names dt")).to_contain_text(["Kind"])
            assert not await revoked(a, certificate)
            retained_page = page.url
            await approve.click()
            if lost_answer:
                await expect(page.locator("#handoff-status")).to_contain_text("could not confirm")
                assert await revoked(a, certificate)
                await page.goto(origin + "/")
                await expect(page.locator(f'[data-remove-certificate="{root.certificate_id}"]')).to_have_count(0)
                recovery = page.get_by_role("link", name="Check this request", exact=True)
                await expect(recovery).to_have_attribute("href", retained_page.removeprefix(origin))
                await recovery.click()
                await page.wait_for_url(retained_page)
            await expect(page.locator("#handoff-title")).to_have_text("Approved")
            assert await revoked(a, certificate)
            assert len(deliveries) == 1
            # Opening the same request again shows its outcome, not a refusal.
            await page.reload()
            await expect(page.locator("#handoff-title")).to_have_text("Approved")
            await expect(page.locator("#handoff-action")).to_be_hidden()
            # Prepare from the page, then the exact act's options and execute.
            assert [p for p in posts if p.startswith("/governance") or "/governance/" in p] == [
                "/governance/operations",
                *[p for p in posts if p.endswith("/governance/options")],
                *[p for p in posts if p.endswith("/governance/execute")],
            ]
            assert len([p for p in posts if p == "/governance/operations"]) == 1
            assert len([p for p in posts if p.endswith("/governance/execute")]) == 1
