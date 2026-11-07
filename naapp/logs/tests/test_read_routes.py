"""The reader's API on logs' console origin (audit-substrate.md §B4, §B5), on
real PostgreSQL with a real AWID registry, real owner acts and a software
passkey: a designated reader logs in with its passkey, and the session's scope
is the only thing that says which team it reads."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

import httpx
from aweb_naapp.console import (
    ClientIdentity,
    ConsoleSessions,
    LoginLimiter,
    apply_console_migrations,
    console_login_router,
)
from aweb_naapp.hooks.envelope import verify
from aweb_naapp.runtime.origins import split_origins
from fastapi import FastAPI

from aweb_logs.ledger import append
from aweb_logs.read_routes import ReaderReads, reader_read_router
from aweb_logs.read_store import Cursor

from .fixtures import signed_event
from .reader_world import (
    CONSOLE,
    LOGS,
    World,
    console_headed,
    enrolled_reader,
    revocation,
    slot,
    world_fixture,  # noqa: F401
)

OTHER_TEAM = "other:example.com"


@asynccontextmanager
async def origins(world: World) -> AsyncIterator[tuple[httpx.AsyncClient, httpx.AsyncClient]]:
    """logs' console origin, serving login and the reader's API, and its agent
    origin, serving neither."""
    await apply_console_migrations(world.db)
    sessions = ConsoleSessions(
        world.db, passkeys=world.passkeys, scopes=world.directory.is_current_reader
    )
    limiter = LoginLimiter(
        world.db, client_identity=ClientIdentity(), limit=12, window=timedelta(minutes=1)
    )
    console = FastAPI()
    console.include_router(console_login_router(sessions=sessions, limiter=limiter))
    console.include_router(
        reader_read_router(
            ReaderReads(
                world.db,
                sessions=sessions,
                directory=world.directory,
                chain_keys=frozenset({world.signer.did_key}),
            )
        )
    )
    app = split_origins(FastAPI(), console, agent_origin=LOGS, human_origin=CONSOLE)
    async with (
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=CONSOLE) as human,
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=LOGS) as agent,
    ):
        yield human, agent


async def login(world: World, human: httpx.AsyncClient, scope: str) -> httpx.Response:
    options = await human.post("/login/options", json={"scope": scope})
    assert options.status_code == 200
    return await human.post(
        "/login", json={"scope": scope, "assertion": world.devices[scope].get(options.json())}
    )


async def other_team_event(world: World) -> None:
    signing, signature = signed_event("core", team_id=OTHER_TEAM)
    await append(
        world.db,
        world.signer,
        event=verify(signing, signature, team_id=OTHER_TEAM),
        signing_bytes=signing,
        signature=signature,
        key_evidence={"kid": "core", "did_key": "did:key:z", "admissions": []},
        received_at=datetime.now(UTC),
    )


async def test_a_reader_reads_its_own_teams_events_in_a_passkey_session(world: World):
    scope, _ = await enrolled_reader(world)
    await other_team_event(world)
    async with origins(world) as (human, _):
        assert (await login(world, human, scope)).status_code == 200
        response = await human.get("/v1/events")
    assert response.status_code == 200
    assert console_headed(response)
    events = response.json()["events"]
    assert [event["event_type"] for event in events] == ["credential.enrolled", "role.designated"]
    assert {event["mediation"] for event in events} == {"server"}
    assert response.json()["next_cursor"] is None


async def test_without_a_session_nothing_is_read(world: World):
    await enrolled_reader(world)
    async with origins(world) as (human, _):
        for path in ("/v1/events", "/v1/tail", "/v1/verify"):
            response = await human.get(path)
            assert (response.status_code, response.json()) == (
                401,
                {"detail": "console_session_required"},
            ), path


async def test_the_agent_origin_serves_no_reads(world: World):
    scope, _ = await enrolled_reader(world)
    async with origins(world) as (human, agent):
        await login(world, human, scope)
        agent.cookies = human.cookies
        for path in ("/v1/events", "/v1/tail", "/v1/verify"):
            assert (await agent.get(path)).status_code == 404, path


async def test_a_pending_slot_cannot_log_in(world: World):
    scope = await slot(world)
    async with origins(world) as (human, _):
        response = await human.post("/login/options", json={"scope": scope})
    assert (response.status_code, response.json()) == (401, {"detail": "login_refused"})


async def test_a_revoked_reader_s_session_ends(world: World):
    scope, reader = await enrolled_reader(world)
    async with origins(world) as (human, _):
        await login(world, human, scope)
        assert (await human.get("/v1/events")).status_code == 200
        signing, signature = world.owner.sign("app-role.revoke", revocation(scope, reader))
        await world.designations.revoke(signing=signing, signature=signature, scope=scope)
        response = await human.get("/v1/events")
    assert (response.status_code, response.json()) == (401, {"detail": "console_session_required"})


async def test_no_parameter_names_another_team(world: World):
    scope, _ = await enrolled_reader(world)
    await other_team_event(world)
    async with origins(world) as (human, _):
        await login(world, human, scope)
        for query in ({"team_id": OTHER_TEAM}, {"team": OTHER_TEAM}):
            response = await human.get("/v1/events", params=query)
            assert (response.status_code, response.json()) == (
                400,
                {"detail": "invalid_filter"},
            )
            assert OTHER_TEAM not in response.text


async def test_a_reader_filters_pages_and_tails(world: World):
    scope, _ = await enrolled_reader(world)
    async with origins(world) as (human, _):
        await login(world, human, scope)
        designated = await human.get("/v1/events", params={"event_type": "role.designated"})
        assert [e["event_type"] for e in designated.json()["events"]] == ["role.designated"]
        first = await human.get("/v1/events", params={"limit": "1"})
        assert [e["event_type"] for e in first.json()["events"]] == ["credential.enrolled"]
        rest = await human.get(
            "/v1/events", params={"limit": "1", "cursor": first.json()["next_cursor"]}
        )
        assert [e["event_type"] for e in rest.json()["events"]] == ["role.designated"]
        head = (await human.get("/v1/tail")).json()
        assert head == {"events": [], "next_cursor": Cursor(1, 2).encode()}
        assert (await human.get("/v1/tail", params={"after": head["next_cursor"]})).json() == head
        followed = await human.get("/v1/tail", params={"after": Cursor(1, 1).encode()})
        assert [e["event_type"] for e in followed.json()["events"]] == ["credential.enrolled"]
        assert followed.json()["next_cursor"] == head["next_cursor"]
        for bad in (
            [("limit", "-1")],
            [("cursor", "nonsense")],
            [("after", "x")],
            [("hook", "a"), ("hook", "b")],
            [("after", head["next_cursor"])],
        ):
            response = await human.get("/v1/events", params=bad)
            assert (response.status_code, response.json()) == (400, {"detail": "invalid_filter"})


async def test_a_reader_verifies_its_chain_without_content(world: World):
    scope, _ = await enrolled_reader(world)
    async with origins(world) as (human, _):
        await login(world, human, scope)
        response = await human.get("/v1/verify")
    assert response.status_code == 200
    report = response.json()
    assert (report["chain_epoch"], report["intact"]) == (1, True)
    assert report["delivery"]["scope"] == "observed_internal_only"
    assert report["conflicts"] == []
    assert "role.designated" not in response.text
    assert "payload" not in response.text
