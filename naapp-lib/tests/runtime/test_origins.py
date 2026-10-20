"""One service on two origins: the agent origin and the human origin."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
import pytest
from fastapi import FastAPI, Request, Response

from aweb_naapp.runtime.origins import split_origins

AGENT = "https://api.example"
HUMAN = "https://console.example"


def _apps() -> tuple[FastAPI, FastAPI, list[str]]:
    seen: list[str] = []
    agent = FastAPI()
    human = FastAPI()

    @agent.get("/v1/echo")
    async def agent_echo(request: Request) -> dict[str, Any]:
        seen.append("agent")
        return {"cookie": request.headers.get("cookie"), "cookies": dict(request.cookies)}

    @agent.get("/v1/sets-cookie")
    async def agent_sets_cookie(response: Response) -> dict[str, str]:
        response.set_cookie("session", "agent-session")
        return {"origin": "agent"}

    @human.get("/login")
    async def human_login(request: Request, response: Response) -> dict[str, Any]:
        seen.append("human")
        response.set_cookie("__Host-console", "human-session", secure=True, path="/")
        return {"cookies": dict(request.cookies)}

    return agent, human, seen


def _client(app: Any, origin: str, **kwargs: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=origin, **kwargs)


async def test_each_origin_serves_only_its_own_app() -> None:
    agent, human, seen = _apps()
    app = split_origins(agent, human, agent_origin=AGENT, human_origin=HUMAN)
    async with _client(app, AGENT) as api, _client(app, HUMAN) as console:
        assert (await api.get("/v1/echo")).status_code == 200
        assert (await console.get("/login")).status_code == 200
        assert (await api.get("/login")).status_code == 404
        assert (await console.get("/v1/echo")).status_code == 404
    assert seen == ["agent", "human"]


async def test_a_cookie_sent_to_the_agent_origin_never_reaches_the_app() -> None:
    agent, human, _ = _apps()
    app = split_origins(agent, human, agent_origin=AGENT, human_origin=HUMAN)
    async with _client(app, AGENT) as api:
        response = await api.get("/v1/echo", headers={"Cookie": "__Host-console=human-session"})
    assert response.status_code == 200
    assert response.json() == {"cookie": None, "cookies": {}}


async def test_the_agent_origin_never_sets_a_cookie() -> None:
    agent, human, _ = _apps()
    app = split_origins(agent, human, agent_origin=AGENT, human_origin=HUMAN)
    async with _client(app, AGENT) as api:
        response = await api.get("/v1/sets-cookie")
    assert response.status_code == 200
    assert "set-cookie" not in response.headers
    assert response.json() == {"origin": "agent"}


async def test_the_human_origin_keeps_its_cookies() -> None:
    agent, human, _ = _apps()
    app = split_origins(agent, human, agent_origin=AGENT, human_origin=HUMAN)
    async with _client(app, HUMAN) as console:
        response = await console.get("/login", headers={"Cookie": "__Host-console=human-session"})
    assert response.status_code == 200
    assert response.json() == {"cookies": {"__Host-console": "human-session"}}
    assert response.headers["set-cookie"].startswith("__Host-console=human-session")


@pytest.mark.parametrize(
    "header",
    [
        ("Authorization", "DIDKey did:key:z6Mk 00"),
        ("authorization", "Bearer anything"),
        ("X-AWEB-Timestamp", "2026-10-20T00:00:00Z"),
        ("x-aweb-signed-payload", "e30"),
        ("X-AWID-Team-Certificate", "e30="),
    ],
)
async def test_a_team_auth_header_on_the_human_origin_is_refused_before_the_app(header) -> None:
    agent, human, seen = _apps()
    app = split_origins(agent, human, agent_origin=AGENT, human_origin=HUMAN)
    async with _client(app, HUMAN) as console:
        response = await console.get("/login", headers=[header])
    assert response.status_code == 403
    assert response.json()["code"] == "team_auth_refused"
    assert "set-cookie" not in response.headers
    assert seen == []


@pytest.mark.parametrize(
    "host",
    ["other.example", "api.example.evil", "console.example:8443", ""],
    ids=["other", "suffix", "other-port", "empty"],
)
async def test_a_request_for_another_host_is_misdirected(host: str) -> None:
    agent, human, seen = _apps()
    app = split_origins(agent, human, agent_origin=AGENT, human_origin=HUMAN)
    async with _client(app, AGENT) as client:
        response = await client.get("/v1/echo", headers={"Host": host})
    assert response.status_code == 421
    assert response.json()["code"] == "unknown_origin"
    assert seen == []


async def test_a_host_matches_with_or_without_its_default_port_and_in_any_case() -> None:
    agent, human, seen = _apps()
    app = split_origins(agent, human, agent_origin=AGENT, human_origin=HUMAN)
    async with _client(app, AGENT) as client:
        for host in ("api.example:443", "API.Example"):
            assert (await client.get("/v1/echo", headers={"Host": host})).status_code == 200
    assert seen == ["agent", "agent"]


async def test_an_explicit_port_is_part_of_the_origin() -> None:
    agent, human, seen = _apps()
    app = split_origins(
        agent, human, agent_origin="http://127.0.0.1:8000", human_origin="http://127.0.0.1:8001"
    )
    async with _client(app, "http://127.0.0.1:8001") as console:
        assert (await console.get("/login")).status_code == 200
        assert (await console.get("/login", headers={"Host": "127.0.0.1"})).status_code == 421
    assert seen == ["human"]


@pytest.mark.parametrize(
    ("agent_origin", "human_origin"),
    [
        (AGENT, AGENT),
        (AGENT, "https://API.example/"),
        (AGENT, "https://api.example:443"),
        (AGENT, "console.example"),
        (AGENT, "https://console.example/path"),
    ],
    ids=["same", "same-normalized", "same-default-port", "no-scheme", "with-path"],
)
def test_the_two_origins_must_be_distinct_plain_origins(agent_origin, human_origin) -> None:
    agent, human, _ = _apps()
    with pytest.raises(ValueError):
        split_origins(agent, human, agent_origin=agent_origin, human_origin=human_origin)


async def test_the_lifespan_is_the_agent_apps() -> None:
    events: list[str] = []

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        events.append("startup")
        yield
        events.append("shutdown")

    app = split_origins(
        FastAPI(lifespan=lifespan), FastAPI(), agent_origin=AGENT, human_origin=HUMAN
    )
    received: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
    for message in ({"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}):
        received.put_nowait(message)
    sent: list[dict[str, Any]] = []

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    await app({"type": "lifespan", "asgi": {"version": "3.0"}, "state": {}}, received.get, send)
    assert events == ["startup", "shutdown"]
    assert [message["type"] for message in sent] == [
        "lifespan.startup.complete",
        "lifespan.shutdown.complete",
    ]
