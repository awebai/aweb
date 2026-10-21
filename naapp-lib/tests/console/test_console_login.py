"""Console passkey login on real PostgreSQL, through the human origin.

Every ceremony is real: B3 issues the options, the software authenticator
answers them, and py_webauthn verifies the assertion. Each owner has their own
scope; the app's predicate says which scopes may log in here.

The routes are built inside a function, so their annotations are evaluated
eagerly (no postponed annotations) for FastAPI to see the session dependency.
"""

from datetime import timedelta
from typing import Annotated, Any

import httpx
import pytest
from aweb_naapp_testing.webauthn import SoftAuthenticator
from fastapi import APIRouter, Depends, FastAPI

from aweb_naapp.console import (
    ClientIdentity,
    ConsoleRoute,
    ConsoleSession,
    ConsoleSessions,
    LoginLimiter,
    console_login_router,
)
from aweb_naapp.runtime.origins import split_origins
from tests.console.support import HUMAN, OWNER_A, OWNER_B, Console

AGENT = "https://api.console.example"


def _limiter(console: Console, limit: int = 20) -> LoginLimiter:
    return LoginLimiter(
        console.db, client_identity=ClientIdentity(), limit=limit, window=timedelta(minutes=1)
    )


def _app(
    console: Console,
    limiter: LoginLimiter,
    prefix: str = "",
    sessions: ConsoleSessions | None = None,
) -> Any:
    sessions = sessions or console.sessions()
    human = FastAPI()
    human.include_router(console_login_router(sessions=sessions, limiter=limiter, prefix=prefix))
    pages = APIRouter(route_class=ConsoleRoute)

    @pages.get("/whoami")
    async def whoami(
        session: Annotated[ConsoleSession, Depends(sessions.current)],
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
    _, device = await console.enrol(OWNER_A)
    async with _client(_app(console, _limiter(console))) as client:
        response = await _login(client, device, OWNER_A)
        assert response.status_code == 200
        assert response.json()["csrf_token"]
        whoami = await client.get("/whoami", headers={"Cookie": _cookie(response)})
    assert whoami.status_code == 200
    assert whoami.json()["scope"] == OWNER_A
    assert whoami.json()["subject"]


async def test_login_without_user_verification_opens_no_session(console: Console) -> None:
    _, device = await console.enrol(OWNER_A)
    async with _client(_app(console, _limiter(console))) as client:
        response = await _login(client, device, OWNER_A, user_verified=False)
    assert response.status_code == 401
    assert "set-cookie" not in response.headers
    assert await console.db.fetch_value("SELECT count(*) FROM {{tables.console_sessions}}") == 0


async def test_each_owner_logs_in_only_to_their_own_scope(console: Console) -> None:
    _, device_a = await console.enrol(OWNER_A)
    _, device_b = await console.enrol(OWNER_B)
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
    _, device = await console.enrol(OWNER_A)
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
    _, device = await console.enrol(OWNER_A)
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
    _, device = await console.enrol(OWNER_A)
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
    _, device = await console.enrol(OWNER_A)
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
    _, device = await console.enrol(OWNER_A)
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
    _, device = await console.enrol(OWNER_A)
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


@pytest.mark.parametrize(
    ("path", "body", "field", "error_type"),
    [
        (
            "/login/options",
            {"scope": {"unexpected": "submitted-value"}},
            "scope",
            "string_type",
        ),
        (
            "/login",
            {"scope": ["submitted-value"], "assertion": {}},
            "scope",
            "string_type",
        ),
        (
            "/login",
            {"scope": OWNER_A, "assertion": "submitted-value"},
            "assertion",
            "dict_type",
        ),
        (
            "/login",
            {"scope": OWNER_A, "assertion": ["submitted-value"]},
            "assertion",
            "dict_type",
        ),
        (
            "/login",
            {"scope": OWNER_A, "unrelated": "submitted-value"},
            "assertion",
            "missing",
        ),
    ],
    ids=[
        "options-scope",
        "login-scope",
        "assertion-string",
        "assertion-list",
        "missing-assertion",
    ],
)
async def test_login_validation_returns_only_location_and_type(
    console: Console, path: str, body: dict[str, Any], field: str, error_type: str
) -> None:
    async with _client(_app(console, _limiter(console))) as client:
        response = await client.post(path, json=body)

    assert response.status_code == 422
    assert response.json() == {"detail": [{"loc": ["body", field], "type": error_type}]}
    assert "set-cookie" not in response.headers
    assert response.headers["cache-control"] == "no-store"


async def _closed(console: Console) -> int:
    return await console.db.fetch_value(
        "SELECT count(*) FROM {{tables.console_sessions}} WHERE closed_at IS NOT NULL"
    )


async def test_a_session_ends_when_a_recovery_replaces_its_approver(console: Console) -> None:
    _, device = await console.enrol(OWNER_A)
    async with _client(_app(console, _limiter(console))) as client:
        cookie = _cookie(await _login(client, device, OWNER_A))
        assert (await client.get("/whoami", headers={"Cookie": cookie})).status_code == 200
        await console.recover(OWNER_A, "new-phone@example.com")
        after = await client.get("/whoami", headers={"Cookie": cookie})
    assert after.status_code == 401
    assert after.json() == {"detail": "console_session_required"}
    assert await _closed(console) == 1


async def test_a_session_ends_when_the_app_stops_admitting_its_scope(console: Console) -> None:
    _, device = await console.enrol(OWNER_A)
    async with _client(_app(console, _limiter(console))) as client:
        cookie = _cookie(await _login(client, device, OWNER_A))
        console.allowed.discard(OWNER_A)
        refused = await client.get("/whoami", headers={"Cookie": cookie})
        console.allowed.add(OWNER_A)
        still_refused = await client.get("/whoami", headers={"Cookie": cookie})
    assert refused.status_code == still_refused.status_code == 401
    assert await _closed(console) == 1


async def test_another_owners_session_survives_a_recovery(console: Console) -> None:
    _, device_a = await console.enrol(OWNER_A)
    _, device_b = await console.enrol(OWNER_B)
    async with _client(_app(console, _limiter(console))) as client:
        cookie_b = _cookie(await _login(client, device_b, OWNER_B))
        await console.recover(OWNER_A, "new-phone@example.com")
        whoami = await client.get("/whoami", headers={"Cookie": cookie_b})
    assert whoami.status_code == 200
    assert whoami.json()["scope"] == OWNER_B


async def test_a_session_ends_when_the_owner_retires_its_approver(console: Console) -> None:
    subject, device = await console.enrol(OWNER_A)
    async with _client(_app(console, _limiter(console))) as client:
        cookie = _cookie(await _login(client, device, OWNER_A))
        assert (await client.get("/whoami", headers={"Cookie": cookie})).status_code == 200
        await console.retire(OWNER_A, subject)
        after = await client.get("/whoami", headers={"Cookie": cookie})
    assert after.status_code == 401
    assert after.json() == {"detail": "console_session_required"}
    assert await _closed(console) == 1
