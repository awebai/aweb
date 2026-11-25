"""The ordinary app page serves a stored session or credential handoff."""

import asyncio
import socket
from datetime import timedelta

import httpx
import pytest
import uvicorn
from aweb_naapp_testing.network import make_certificates
from fastapi import FastAPI, Request
from playwright.async_api import async_playwright, expect

from aweb_naapp.console import ClientIdentity, LoginLimiter
from aweb_naapp.console.handoff_page import handoff_page_router
from aweb_naapp.console.handoff_store import HandoffStore, parse_start
from tests.console.test_handoff_credential import app as credential_app
from tests.console.test_handoff_store import ORIGIN, handoff_db, start_body

__all__ = ["handoff_db"]


@pytest.mark.parametrize(
    "purpose,title", [("session", "Sign in with a passkey"), ("credential", "Create a passkey")]
)
async def test_app_handoff_page_keeps_the_stored_purpose_and_grants_nothing(
    handoff_db, purpose, title
):
    store = HandoffStore(handoff_db)
    created = await store.create(
        parse_start(start_body(purpose=purpose)), team_id="people:example.com"
    )
    app = FastAPI()
    app.include_router(
        handoff_page_router(
            store=store,
            limiter=LoginLimiter(
                handoff_db,
                client_identity=ClientIdentity(),
                limit=30,
                window=timedelta(minutes=1),
            ),
        )
    )
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN) as client:
        page = await client.get(f"/handoff/{created['handoff_id']}")
        assert page.status_code == 200
        assert f"<title>{title}</title>" in page.text
        assert f'data-purpose="{purpose}"' in page.text
        assert f'data-handoff-id="{created["handoff_id"]}"' in page.text
        assert (await client.get("/handoff-assets/handoff.js")).status_code == 200
        assert (await client.get("/handoff-assets/handoff.css")).status_code == 200
    row = await handoff_db.fetch_one(
        "SELECT completed_at, released_at FROM {{tables.console_handoffs}} WHERE handoff_id=$1::uuid",
        created["handoff_id"],
    )
    assert row["completed_at"] is None and row["released_at"] is None
    assert await handoff_db.fetch_value("SELECT COUNT(*) FROM {{tables.console_sessions}}") == 0


async def test_app_credential_page_completes_real_webauthn_and_returns_to_the_terminal(
    handoff_db, tmp_path
):
    sockets = []
    for _ in range(2):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        sockets.append(listener)
    origin = f"https://localhost:{sockets[0].getsockname()[1]}"
    redirect = f"http://127.0.0.1:{sockets[1].getsockname()[1]}/callback"
    store = HandoffStore(handoff_db)
    created = await store.create(
        parse_start(start_body(purpose="credential", redirect_uri=redirect)),
        team_id="people:example.com",
    )
    app = credential_app(handoff_db, origin)
    app.include_router(
        handoff_page_router(
            store=store,
            limiter=LoginLimiter(
                handoff_db,
                client_identity=ClientIdentity(),
                limit=30,
                window=timedelta(minutes=1),
            ),
        )
    )
    callback = FastAPI()
    returned = []

    @callback.get("/callback")
    async def terminal(request: Request):
        returned.append(dict(request.query_params))
        return {"returned": True}

    tls = make_certificates(tmp_path, ["localhost"], ["127.0.0.1"])
    servers = [
        uvicorn.Server(
            uvicorn.Config(
                app,
                lifespan="off",
                log_level="error",
                ws="none",
                ssl_certfile=str(tls.cert_file),
                ssl_keyfile=str(tls.key_file),
            )
        ),
        uvicorn.Server(uvicorn.Config(callback, lifespan="off", log_level="error", ws="none")),
    ]
    tasks = [
        asyncio.create_task(server.serve(sockets=[listener]))
        for server, listener in zip(servers, sockets, strict=True)
    ]
    try:
        async with asyncio.timeout(10):
            while not all(server.started for server in servers):
                assert all(not task.done() for task in tasks)
                await asyncio.sleep(0.01)
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(args=["--no-proxy-server"])
            try:
                context = await browser.new_context(ignore_https_errors=True)
                page = await context.new_page()
                errors = []
                page.on("pageerror", lambda error: errors.append(str(error)))
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
                await page.goto(f"{origin}/handoff/{created['handoff_id']}")
                await expect(page.locator("body")).to_have_attribute("data-handoff-state", "ready")
                await page.locator("#handoff-action").click()
                await page.wait_for_url(redirect + "?**")
                assert returned[0]["handoff_id"] == created["handoff_id"]
                assert len(returned[0]["code"]) == 43
                credentials = await cdp.send(
                    "WebAuthn.getCredentials",
                    {
                        "authenticatorId": device["authenticatorId"],
                    },
                )
                assert len(credentials["credentials"]) == 1
                assert errors == []
            finally:
                await browser.close()
        row = await handoff_db.fetch_one(
            "SELECT completed_at, credential FROM {{tables.console_handoffs}} WHERE handoff_id=$1::uuid",
            created["handoff_id"],
        )
        assert row["completed_at"] is not None and row["credential"] is not None
        assert await handoff_db.fetch_value("SELECT COUNT(*) FROM {{tables.console_sessions}}") == 0
    finally:
        for server in servers:
            server.should_exit = True
        await asyncio.wait_for(asyncio.gather(*tasks), 10)
        for listener in sockets:
            listener.close()
