"""Console passkey login on real PostgreSQL, through the human origin.

Every ceremony is real: B3 issues the options, the software authenticator
answers them, and py_webauthn verifies the assertion. Each owner has their own
scope; the app's predicate says which scopes may log in here.

The routes are built inside a function, so their annotations are evaluated
eagerly (no postponed annotations) for FastAPI to see the session dependency.
"""

import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import timedelta
from typing import Annotated, Any

import httpx
import pytest
from fastapi import APIRouter, Depends, FastAPI
from pgdbm import AsyncDatabaseManager

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
from tests.runtime.approvals.soft_authenticator import SoftAuthenticator
from tests.runtime.approvals.support import AuditOutbox
from tests.runtime.approvals.test_passkeys import Contacts, owner_act

AGENT = "https://api.console.example"
HUMAN = "https://console.example"
OWNER_A = "app.owner.a"
OWNER_B = "app.owner.b"


@dataclass
class Console:
    db: AsyncDatabaseManager
    passkeys: Passkeys
    contacts: Contacts
    sessions: ConsoleSessions
    allowed: set[str]

    async def enrol(self, scope: str) -> SoftAuthenticator:
        contact = f"{scope}@example.com"
        await self.passkeys.designate(
            scope=scope,
            contact=contact,
            owner_act=owner_act(OwnerActKind.DESIGNATE, contact, scope, str(uuid.uuid4())),
        )
        token = self.contacts.last(contact)
        device = SoftAuthenticator(HUMAN)
        await self.passkeys.complete_enrolment(
            token, device.create(dict(await self.passkeys.enrolment_options(token)))
        )
        return device


@pytest.fixture
async def console(test_db_factory) -> AsyncIterator[Console]:
    db = await test_db_factory.create_db(suffix="naapp_console_login", schema="app")
    audit = AuditOutbox(db)
    await audit.create()
    store = PgApprovalStore(db)
    await store.migrate()
    contacts = Contacts()
    passkeys = Passkeys(
        db,
        rp=RelyingParty(origin=HUMAN, name="Console"),
        delivery=contacts,
        audit=audit,
        retirement=ApprovalRevocation(store, audit),
        enrolment_ttl=timedelta(hours=1),
        challenge_ttl=timedelta(minutes=5),
    )
    await passkeys.migrate()
    await apply_console_migrations(db)
    yield Console(db, passkeys, contacts, ConsoleSessions(db), {OWNER_A, OWNER_B})


def _limiter(console: Console, limit: int = 20) -> LoginLimiter:
    return LoginLimiter(
        console.db, client_identity=ClientIdentity(), limit=limit, window=timedelta(minutes=1)
    )


def _app(console: Console, limiter: LoginLimiter, prefix: str = "") -> Any:
    async def scopes(scope: str) -> bool:
        return scope in console.allowed

    human = FastAPI()
    human.include_router(
        console_login_router(
            passkeys=console.passkeys,
            sessions=console.sessions,
            limiter=limiter,
            scopes=scopes,
            prefix=prefix,
        )
    )
    pages = APIRouter(route_class=ConsoleRoute)

    @pages.get("/whoami")
    async def whoami(
        session: Annotated[ConsoleSession, Depends(console.sessions.current)],
    ) -> dict[str, str]:
        return {"subject": session.subject, "scope": session.scope}

    human.include_router(pages)
    return split_origins(FastAPI(), human, agent_origin=AGENT, human_origin=HUMAN)


def _client(app: Any, origin: str = HUMAN) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=origin)


async def _login(
    client: httpx.AsyncClient, device: SoftAuthenticator, scope: str, prefix: str = "", **kw: Any
) -> httpx.Response:
    options = await client.post(f"{prefix}/login/options", json={"scope": scope})
    assert options.status_code == 200
    assertion = device.get(options.json(), **kw)
    response = await client.post(f"{prefix}/login", json={"scope": scope, "assertion": assertion})
    # Each request carries exactly the cookie a test gives it.
    client.cookies.clear()
    return response


def _cookie(response: httpx.Response) -> str:
    return response.headers["set-cookie"].split(";", 1)[0]


async def test_an_owner_logs_in_with_a_user_verified_passkey(console: Console) -> None:
    device = await console.enrol(OWNER_A)
    async with _client(_app(console, _limiter(console))) as client:
        response = await _login(client, device, OWNER_A)
        assert response.status_code == 200
        assert response.json()["csrf_token"]
        whoami = await client.get("/whoami", headers={"Cookie": _cookie(response)})
    assert whoami.status_code == 200
    assert whoami.json()["scope"] == OWNER_A
    assert whoami.json()["subject"]


async def test_login_without_user_verification_opens_no_session(console: Console) -> None:
    device = await console.enrol(OWNER_A)
    async with _client(_app(console, _limiter(console))) as client:
        response = await _login(client, device, OWNER_A, user_verified=False)
    assert response.status_code == 401
    assert "set-cookie" not in response.headers
    assert await console.db.fetch_value("SELECT count(*) FROM {{tables.console_sessions}}") == 0


async def test_each_owner_logs_in_only_to_their_own_scope(console: Console) -> None:
    device_a = await console.enrol(OWNER_A)
    device_b = await console.enrol(OWNER_B)
    async with _client(_app(console, _limiter(console))) as client:
        a = await _login(client, device_a, OWNER_A)
        b = await _login(client, device_b, OWNER_B)
        crossed = await _login(client, device_a, OWNER_B)
        whoami_a = await client.get("/whoami", headers={"Cookie": _cookie(a)})
        whoami_b = await client.get("/whoami", headers={"Cookie": _cookie(b)})
    assert whoami_a.json()["scope"] == OWNER_A
    assert whoami_b.json()["scope"] == OWNER_B
    assert whoami_a.json()["subject"] != whoami_b.json()["subject"]
    assert crossed.status_code == 401
    assert "set-cookie" not in crossed.headers


async def test_a_scope_the_app_does_not_accept_cannot_log_in(console: Console) -> None:
    device = await console.enrol(OWNER_A)
    async with _client(_app(console, _limiter(console))) as client:
        options = dict((await client.post("/login/options", json={"scope": OWNER_A})).json())
        console.allowed.discard(OWNER_A)
        refused_options = await client.post("/login/options", json={"scope": OWNER_A})
        refused_login = await client.post(
            "/login", json={"scope": OWNER_A, "assertion": device.get(options)}
        )
    assert refused_options.status_code == 401
    assert refused_login.status_code == 401
    assert "set-cookie" not in refused_login.headers


async def test_a_refused_scope_gets_the_same_answer_as_a_failed_login(console: Console) -> None:
    device = await console.enrol(OWNER_A)
    async with _client(_app(console, _limiter(console))) as client:
        unknown = await client.post("/login/options", json={"scope": "app.owner.nobody"})
        console.allowed.add("app.owner.nobody")
        no_approver = await client.post("/login/options", json={"scope": "app.owner.nobody"})
        failed = await _login(client, device, OWNER_A, user_verified=False)
    assert unknown.status_code == no_approver.status_code == failed.status_code == 401
    assert unknown.json() == no_approver.json() == failed.json()


async def test_login_requests_are_rate_limited_per_client(console: Console) -> None:
    await console.enrol(OWNER_A)
    limiter = _limiter(console, limit=2)
    async with _client(_app(console, limiter)) as client:
        codes = [
            (await client.post("/login/options", json={"scope": scope})).status_code
            for scope in (OWNER_A, OWNER_B, OWNER_A)
        ]
    assert codes[2] == 429
    assert (await limiter.volume(OWNER_A, since=timedelta(minutes=5))).requests == 2


async def test_a_refused_scope_is_not_metered(console: Console) -> None:
    limiter = _limiter(console)
    async with _client(_app(console, limiter)) as client:
        for n in range(3):
            await client.post("/login/options", json={"scope": f"app.owner.guess{n}"})
    volume = await console.db.fetch_value("SELECT count(*) FROM {{tables.console_login_volume}}")
    assert volume == 0


async def test_logout_needs_the_csrf_token_and_ends_the_session(console: Console) -> None:
    device = await console.enrol(OWNER_A)
    async with _client(_app(console, _limiter(console))) as client:
        response = await _login(client, device, OWNER_A)
        cookie, csrf = _cookie(response), response.json()["csrf_token"]
        without = await client.post("/logout", headers={"Cookie": cookie})
        logout = await client.post("/logout", headers={"Cookie": cookie, "X-CSRF-Token": csrf})
        after = await client.get("/whoami", headers={"Cookie": cookie})
    assert without.status_code == 403
    assert logout.status_code == 200
    assert "max-age=0" in logout.headers["set-cookie"].lower()
    assert after.status_code == 401


async def test_the_login_routes_take_a_prefix(console: Console) -> None:
    device = await console.enrol(OWNER_A)
    async with _client(_app(console, _limiter(console), prefix="/console")) as client:
        response = await _login(client, device, OWNER_A, prefix="/console")
        root = await client.post("/login/options", json={"scope": OWNER_A})
    assert response.status_code == 200
    assert root.status_code == 404


@pytest.mark.parametrize(
    "header",
    [
        ("Authorization", "Bearer token"),
        ("X-AWEB-Signature", "sig"),
        ("X-AWID-Team", "team"),
    ],
)
async def test_team_auth_is_refused_on_the_console(
    console: Console, header: tuple[str, str]
) -> None:
    device = await console.enrol(OWNER_A)
    async with _client(_app(console, _limiter(console))) as client:
        options = dict((await client.post("/login/options", json={"scope": OWNER_A})).json())
        login = await client.post(
            "/login",
            json={"scope": OWNER_A, "assertion": device.get(options)},
            headers={header[0]: header[1]},
        )
        client.cookies.clear()
        session = await _login(client, device, OWNER_A)
        whoami = await client.get(
            "/whoami", headers={"Cookie": _cookie(session), header[0]: header[1]}
        )
    assert login.status_code == 403
    assert "set-cookie" not in login.headers
    assert whoami.status_code == 403


async def test_the_console_is_not_served_on_the_agent_origin(console: Console) -> None:
    async with _client(_app(console, _limiter(console)), AGENT) as client:
        response = await client.post("/login/options", json={"scope": OWNER_A})
    assert response.status_code == 404


async def test_login_responses_carry_the_console_headers(console: Console) -> None:
    device = await console.enrol(OWNER_A)
    async with _client(_app(console, _limiter(console))) as client:
        responses = [
            await client.post("/login/options", json={"scope": OWNER_A}),
            await client.post("/login/options", json={"scope": "app.owner.nobody"}),
            await client.post("/login/options", json={}),
            await _login(client, device, OWNER_A),
        ]
    for response in responses:
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["referrer-policy"] == "no-referrer"
