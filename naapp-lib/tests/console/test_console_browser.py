"""Console passkey login in a real browser, with Chromium's virtual authenticator.

The service runs on a real socket, split into its agent and human origins. A
console page loads its script from its own origin under the console CSP; the
script enrols a passkey and logs in through ``navigator.credentials``, which
Chromium answers with a CDP WebAuthn virtual authenticator. B3 verifies each
ceremony exactly as it would a person's device.

The browser is never downloaded here: the candidate-gate image installs the
Chromium that the locked Playwright version drives.

The routes are built inside a function, so their annotations are evaluated
eagerly (no postponed annotations) for FastAPI to see the session dependency.
"""

import asyncio
import socket
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Annotated, Any

import pytest
import uvicorn
from fastapi import APIRouter, Depends, FastAPI, Response
from pgdbm import AsyncDatabaseManager
from playwright.async_api import Browser, CDPSession, Page, async_playwright

from aweb_naapp.console import (
    ClientIdentity,
    ConsoleRoute,
    ConsoleSession,
    ConsoleSessions,
    LoginLimiter,
    apply_console_migrations,
    console_login_router,
)
from aweb_naapp.runtime.approvals import ApprovalRevocation, PgApprovalStore
from aweb_naapp.runtime.origins import split_origins
from aweb_naapp.runtime.passkeys import OwnerActKind, Passkeys, RelyingParty
from tests.runtime.approvals.support import AuditOutbox
from tests.runtime.approvals.test_passkeys import Contacts, owner_act

SCOPE = "app.owner.a"
CONTACT = "owner-a@example.com"

PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><script src="/console.js"></script></head>
<body>console</body></html>
"""

SCRIPT = """
async function post(path, body) {
  const response = await fetch(path, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(body),
  });
  return {status: response.status, body: await response.json()};
}

window.enrol = async (token) => {
  const options = await post("/test/enrolment/options", {token});
  const publicKey = PublicKeyCredential.parseCreationOptionsFromJSON(options.body);
  const credential = await navigator.credentials.create({publicKey});
  return (await post("/test/enrolment", {token, credential: credential.toJSON()})).status;
};

window.login = async (scope) => {
  const options = await post("/login/options", {scope});
  if (options.status !== 200) return {status: options.status};
  const publicKey = PublicKeyCredential.parseRequestOptionsFromJSON(options.body);
  let assertion;
  try {
    assertion = await navigator.credentials.get({publicKey});
  } catch (error) {
    return {status: 0, error: error.name};
  }
  return post("/login", {scope, assertion: assertion.toJSON()});
};

window.whoami = async () => {
  const response = await fetch("/whoami");
  return {status: response.status, body: await response.json()};
};
"""


@dataclass
class Service:
    db: AsyncDatabaseManager
    passkeys: Passkeys
    contacts: Contacts
    origin: str


def _free_socket() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    return sock


def _human_app(passkeys: Passkeys, sessions: ConsoleSessions, limiter: LoginLimiter) -> FastAPI:
    pages = APIRouter(route_class=ConsoleRoute)

    @pages.get("/")
    async def page() -> Response:
        return Response(PAGE, media_type="text/html")

    @pages.get("/console.js")
    async def script() -> Response:
        return Response(SCRIPT, media_type="text/javascript")

    @pages.get("/whoami")
    async def whoami(
        session: Annotated[ConsoleSession, Depends(sessions.current)],
    ) -> dict[str, str]:
        return {"subject": session.subject, "scope": session.scope}

    # Enrolment is B3's and the app's own page; these stand in for that page.
    @pages.post("/test/enrolment/options")
    async def enrolment_options(body: dict[str, Any]) -> dict[str, Any]:
        return dict(await passkeys.enrolment_options(body["token"]))

    @pages.post("/test/enrolment")
    async def enrolment(body: dict[str, Any]) -> dict[str, bool]:
        await passkeys.complete_enrolment(body["token"], body["credential"])
        return {"enrolled": True}

    human = FastAPI()
    human.include_router(console_login_router(sessions=sessions, limiter=limiter))
    human.include_router(pages)
    return human


@pytest.fixture
async def service(test_db_factory) -> AsyncIterator[Service]:
    sock = _free_socket()
    port = sock.getsockname()[1]
    human_origin = f"http://localhost:{port}"
    db = await test_db_factory.create_db(suffix="naapp_console_browser", schema="app")
    audit = AuditOutbox(db)
    await audit.create()
    store = PgApprovalStore(db)
    await store.migrate()
    contacts = Contacts()
    passkeys = Passkeys(
        db,
        rp=RelyingParty(origin=human_origin, name="Console"),
        delivery=contacts,
        audit=audit,
        retirement=ApprovalRevocation(store, audit),
        enrolment_ttl=timedelta(hours=1),
        challenge_ttl=timedelta(minutes=5),
    )
    await passkeys.migrate()
    await apply_console_migrations(db)

    async def scopes(scope: str) -> bool:
        return scope == SCOPE

    sessions = ConsoleSessions(db, passkeys=passkeys, scopes=scopes)
    limiter = LoginLimiter(
        db, client_identity=ClientIdentity(), limit=20, window=timedelta(minutes=1)
    )
    app = split_origins(
        FastAPI(),
        _human_app(passkeys, sessions, limiter),
        agent_origin=f"http://127.0.0.1:{port}",
        human_origin=human_origin,
    )
    server = uvicorn.Server(uvicorn.Config(app, log_level="warning", lifespan="off"))
    serving = asyncio.create_task(server.serve(sockets=[sock]))
    while not server.started:
        await asyncio.sleep(0.01)
    try:
        yield Service(db, passkeys, contacts, human_origin)
    finally:
        server.should_exit = True
        await serving
        sock.close()


@pytest.fixture
async def browser() -> AsyncIterator[Browser]:
    async with async_playwright() as playwright:
        executable = Path(playwright.chromium.executable_path)
        if not executable.exists():
            pytest.fail(
                f"Chromium for Playwright is not installed at {executable}. The candidate-gate "
                "image installs it; locally, run `uv run playwright install chromium`."
            )
        browser = await playwright.chromium.launch()
        try:
            yield browser
        finally:
            await browser.close()


async def _console(browser: Browser, service: Service) -> tuple[Page, CDPSession, str]:
    """The console page in a fresh browser, with an enrolled virtual authenticator."""
    context = await browser.new_context()
    page = await context.new_page()
    cdp = await context.new_cdp_session(page)
    await cdp.send("WebAuthn.enable")
    added = await cdp.send(
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
    await page.goto(service.origin + "/")
    await service.passkeys.designate(
        scope=SCOPE,
        contact=CONTACT,
        owner_act=owner_act(OwnerActKind.DESIGNATE, CONTACT, SCOPE, str(uuid.uuid4())),
    )
    assert await page.evaluate("token => enrol(token)", service.contacts.last(CONTACT)) == 200
    return page, cdp, added["authenticatorId"]


async def test_an_owner_logs_in_in_a_browser_with_user_verification(
    service: Service, browser: Browser
) -> None:
    page, _, _ = await _console(browser, service)
    login = await page.evaluate("scope => login(scope)", SCOPE)
    assert login["status"] == 200
    whoami = await page.evaluate("() => whoami()")
    assert whoami["status"] == 200
    assert whoami["body"]["scope"] == SCOPE
    [cookie] = await page.context.cookies()
    assert cookie["name"].startswith("__Host-")
    assert (cookie["httpOnly"], cookie["secure"], cookie["sameSite"]) == (True, True, "Strict")


async def test_a_browser_login_without_user_verification_fails(
    service: Service, browser: Browser
) -> None:
    page, cdp, authenticator = await _console(browser, service)
    await cdp.send(
        "WebAuthn.setUserVerified", {"authenticatorId": authenticator, "isUserVerified": False}
    )
    login = await page.evaluate("scope => login(scope)", SCOPE)
    assert login["status"] != 200
    assert await page.context.cookies() == []
    assert (await page.evaluate("() => whoami()"))["status"] == 401
    assert await service.db.fetch_value("SELECT count(*) FROM {{tables.console_sessions}}") == 0
