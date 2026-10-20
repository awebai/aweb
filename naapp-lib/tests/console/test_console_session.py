"""The shared console session on real PostgreSQL, through a real ASGI app.

Login itself is B3's passkey assertion; here a test route opens the session
the way the login route does once B3 has verified the assertion, for owners
enrolled through real B3 ceremonies.

The routes are built inside a function, so their annotations are evaluated
eagerly (no postponed annotations) for FastAPI to see the session dependency.
"""

import asyncio
import hashlib
from datetime import timedelta
from http.cookies import SimpleCookie
from typing import Annotated

import httpx
import pytest
from fastapi import APIRouter, Depends, FastAPI, Response

from aweb_naapp.console import ConsoleRoute, ConsoleSession, ConsoleSessions
from tests.console.support import HUMAN, OWNER_A, OWNER_B, Console

ORIGIN = HUMAN


@pytest.fixture
async def owners(console: Console) -> dict[str, str]:
    """Each owner scope's enrolled approver subject."""
    return {scope: (await console.enrol(scope))[0] for scope in (OWNER_A, OWNER_B)}


def _app(sessions: ConsoleSessions) -> FastAPI:
    router = APIRouter(route_class=ConsoleRoute)

    @router.post("/test-login")
    async def login(response: Response, scope: str, subject: str) -> dict[str, str]:
        issued = await sessions.open(subject=subject, scope=scope, evidence_ref="ev-1")
        sessions.set_cookie(response, issued)
        return {"csrf": issued.csrf_token}

    @router.get("/whoami")
    async def whoami(
        session: Annotated[ConsoleSession, Depends(sessions.current)],
    ) -> dict[str, str]:
        return {"subject": session.subject, "scope": session.scope}

    @router.post("/change")
    async def change(
        session: Annotated[ConsoleSession, Depends(sessions.current)],
    ) -> dict[str, bool]:
        return {"changed": True}

    @router.post("/logout")
    async def logout(
        response: Response, session: Annotated[ConsoleSession, Depends(sessions.current)]
    ) -> dict[str, bool]:
        await sessions.close(session)
        sessions.clear_cookie(response)
        return {"closed": True}

    app = FastAPI()
    app.include_router(router)
    return app


async def _client(sessions: ConsoleSessions) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=_app(sessions)), base_url=ORIGIN)


async def _login(
    client: httpx.AsyncClient, owners: dict[str, str], scope: str = OWNER_A
) -> tuple[str, str]:
    response = await client.post("/test-login", params={"scope": scope, "subject": owners[scope]})
    # Each request carries exactly the cookie a test gives it.
    client.cookies.clear()
    cookie = SimpleCookie(response.headers["set-cookie"])
    (name,) = cookie.keys()
    return f"{name}={cookie[name].value}", response.json()["csrf"]


async def test_the_session_cookie_is_host_only_strict_and_short(
    console: Console, owners: dict[str, str]
) -> None:
    async with await _client(console.sessions()) as client:
        response = await client.post(
            "/test-login", params={"scope": OWNER_A, "subject": owners[OWNER_A]}
        )
    header = response.headers["set-cookie"]
    attributes = [part.strip().lower() for part in header.split(";")]
    assert attributes[0].startswith("__host-")
    assert "secure" in attributes
    assert "httponly" in attributes
    assert "samesite=strict" in attributes
    assert "path=/" in attributes
    assert not any(part.startswith("domain") for part in attributes)
    max_age = next(int(part.split("=")[1]) for part in attributes if part.startswith("max-age"))
    assert 0 < max_age <= 15 * 60


async def test_a_session_identifies_its_subject(console: Console, owners: dict[str, str]) -> None:
    async with await _client(console.sessions()) as client:
        cookie, _ = await _login(client, owners)
        response = await client.get("/whoami", headers={"Cookie": cookie})
        missing = await client.get("/whoami")
        forged = await client.get("/whoami", headers={"Cookie": cookie[:-4] + "AAAA"})
    assert response.status_code == 200
    assert response.json() == {"subject": owners[OWNER_A], "scope": OWNER_A}
    assert missing.status_code == 401
    assert forged.status_code == 401


async def test_the_token_is_stored_only_as_a_hash(console: Console, owners: dict[str, str]) -> None:
    async with await _client(console.sessions()) as client:
        cookie, csrf = await _login(client, owners)
    token = cookie.split("=", 1)[1]
    rows = await console.db.fetch_all("SELECT * FROM {{tables.console_sessions}}")
    stored = b"".join(
        value if isinstance(value, bytes) else str(value).encode()
        for row in rows
        for value in row.values()
    )
    assert token.encode() not in stored
    assert csrf.encode() not in stored
    assert hashlib.sha256(token.encode()).digest() in stored


async def test_an_expired_session_is_refused(console: Console, owners: dict[str, str]) -> None:
    async with await _client(console.sessions(ttl=timedelta(seconds=1))) as client:
        cookie, _ = await _login(client, owners)
        assert (await client.get("/whoami", headers={"Cookie": cookie})).status_code == 200
        await asyncio.sleep(1.2)
        assert (await client.get("/whoami", headers={"Cookie": cookie})).status_code == 401


async def test_a_session_lasts_at_most_fifteen_minutes(
    console: Console, owners: dict[str, str]
) -> None:
    console.sessions(ttl=timedelta(minutes=15))
    for ttl in (timedelta(minutes=15, seconds=1), timedelta(0)):
        with pytest.raises(ValueError):
            console.sessions(ttl=ttl)


async def test_a_state_change_needs_the_sessions_csrf_token(
    console: Console, owners: dict[str, str]
) -> None:
    async with await _client(console.sessions()) as client:
        cookie, csrf = await _login(client, owners)
        _, other_csrf = await _login(client, owners, OWNER_B)
        without = await client.post("/change", headers={"Cookie": cookie})
        wrong = await client.post("/change", headers={"Cookie": cookie, "X-CSRF-Token": "x" * 43})
        foreign = await client.post(
            "/change", headers={"Cookie": cookie, "X-CSRF-Token": other_csrf}
        )
        right = await client.post("/change", headers={"Cookie": cookie, "X-CSRF-Token": csrf})
    assert [r.status_code for r in (without, wrong, foreign)] == [403, 403, 403]
    assert right.status_code == 200


async def test_a_closed_session_is_refused(console: Console, owners: dict[str, str]) -> None:
    async with await _client(console.sessions()) as client:
        cookie, csrf = await _login(client, owners)
        response = await client.post("/logout", headers={"Cookie": cookie, "X-CSRF-Token": csrf})
        assert response.status_code == 200
        cleared = [part.strip().lower() for part in response.headers["set-cookie"].split(";")]
        assert "max-age=0" in cleared
        assert (await client.get("/whoami", headers={"Cookie": cookie})).status_code == 401


async def test_console_responses_carry_the_console_headers(
    console: Console, owners: dict[str, str]
) -> None:
    async with await _client(console.sessions()) as client:
        cookie, _ = await _login(client, owners)
        responses = [
            await client.get("/whoami", headers={"Cookie": cookie}),
            await client.get("/whoami"),
            await client.post("/change", headers={"Cookie": cookie}),
            await client.get("/whoami", headers={"Cookie": cookie, "Authorization": "Bearer x"}),
        ]
    for response in responses:
        csp = response.headers["content-security-policy"]
        directives = {d.strip().split(" ", 1)[0]: d.strip() for d in csp.split(";") if d.strip()}
        assert directives["default-src"] == "default-src 'none'"
        assert directives["frame-ancestors"] == "frame-ancestors 'none'"
        assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
        assert response.headers["referrer-policy"] == "no-referrer"
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-content-type-options"] == "nosniff"


async def test_ended_sessions_are_dropped_as_new_ones_open(
    console: Console, owners: dict[str, str]
) -> None:
    async with await _client(console.sessions(ttl=timedelta(seconds=1))) as client:
        expired, _ = await _login(client, owners)
        closing, csrf = await _login(client, owners)
        await client.post("/logout", headers={"Cookie": closing, "X-CSRF-Token": csrf})
        await asyncio.sleep(1.2)
        current, _ = await _login(client, owners)
        assert (await client.get("/whoami", headers={"Cookie": current})).status_code == 200
    rows = await console.db.fetch_value("SELECT count(*) FROM {{tables.console_sessions}}")
    assert rows == 1


async def test_opening_a_session_does_not_wait_on_a_locked_ended_one(
    console: Console, owners: dict[str, str]
) -> None:
    async with await _client(console.sessions()) as client:
        cookie, csrf = await _login(client, owners)
        await client.post("/logout", headers={"Cookie": cookie, "X-CSRF-Token": csrf})
        tx_context = console.db.transaction()
        tx = await tx_context.__aenter__()
        await tx.execute("SELECT * FROM {{tables.console_sessions}} FOR UPDATE")
        try:
            current, _ = await asyncio.wait_for(_login(client, owners), timeout=5)
        finally:
            await tx_context.__aexit__(None, None, None)
        assert (await client.get("/whoami", headers={"Cookie": current})).status_code == 200
