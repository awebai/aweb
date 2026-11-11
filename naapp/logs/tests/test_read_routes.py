"""The reader's API on logs' console origin (audit-substrate.md §B4, §B5), on
real PostgreSQL with a real AWID registry, real owner acts and a software
passkey: a reader the owner named logs in with its bound passkey, and the
session's scope is the only thing that says which team it reads.

Each test appends its team's own events and reads those, so nothing here
depends on what logs records of the reader's designation."""

from __future__ import annotations

import io
import json
import uuid
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
from aweb_naapp_testing.owner_acts import TEAM_ID
from fastapi import FastAPI

from aweb_logs.export import verify_bundle
from aweb_logs.ledger import append
from aweb_logs.read_routes import ReaderReads, reader_read_router
from aweb_logs.read_store import Cursor

from .fixtures import signed_event
from .reader_world import (
    CONSOLE,
    LOGS,
    OTHER_READER,
    World,
    chained,
    console_headed,
    held_reader,
    reader_scope,
    revoked_reader,
    world_fixture,  # noqa: F401
)
from .reader_world import (
    TEAM_ID as TEAM,
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
    await team_event(world, "task.updated", team_id=OTHER_TEAM)


async def team_event(world: World, mutation_type: str, *, team_id: str = TEAM, seq: int = 1) -> str:
    """Append a core event of ``team_id`` to its chain: its event id."""
    event_id = str(uuid.uuid4())
    signing, signature = signed_event(
        "core",
        event_id=event_id,
        seq=seq,
        team_id=team_id,
        payload={"mutation_type": mutation_type, "changes": ["status"]},
    )
    await append(
        world.db,
        world.signer,
        event=verify(signing, signature, team_id=team_id),
        signing_bytes=signing,
        signature=signature,
        key_evidence={"kid": "core", "did_key": "did:key:z", "admissions": []},
        received_at=datetime.now(UTC),
    )
    return event_id


async def team_chain_ids(world: World) -> list[str]:
    """The event ids of the team's chain, newest first."""
    return [entry["event_id"] for entry in reversed(await chained(world))]


async def test_a_reader_reads_its_own_teams_events_in_a_passkey_session(world: World):
    scope, _ = await held_reader(world)
    await team_event(world, "task.updated")
    await other_team_event(world)
    async with origins(world) as (human, _):
        assert (await login(world, human, scope)).status_code == 200
        response = await human.get("/v1/events")
    assert response.status_code == 200
    assert console_headed(response)
    events = response.json()["events"]
    assert [event["event_id"] for event in events] == await team_chain_ids(world)
    assert "task.updated" in [event["event_type"] for event in events]
    assert {event["mediation"] for event in events} == {"server"}
    assert response.json()["next_cursor"] is None


async def test_without_a_session_nothing_is_read(world: World):
    await held_reader(world)
    async with origins(world) as (human, _):
        for path in ("/v1/events", "/v1/tail", "/v1/verify", "/v1/export"):
            response = await human.get(path)
            assert (response.status_code, response.json()) == (
                401,
                {"detail": "console_session_required"},
            ), path


async def test_the_agent_origin_serves_no_reads(world: World):
    scope, _ = await held_reader(world)
    async with origins(world) as (human, agent):
        await login(world, human, scope)
        agent.cookies = human.cookies
        for path in ("/v1/events", "/v1/tail", "/v1/verify", "/v1/export"):
            assert (await agent.get(path)).status_code == 404, path


async def test_a_scope_no_one_holds_cannot_log_in(world: World):
    await held_reader(world)
    revoked, _ = await held_reader(world, OTHER_READER)
    await revoked_reader(world, OTHER_READER)
    async with origins(world) as (human, _):
        for scope in (revoked, reader_scope("did:aw:5Zt1pAq7oS3uW4yB8cD2eF6gH9")):
            response = await human.post("/login/options", json={"scope": scope})
            assert (response.status_code, response.json()) == (
                401,
                {"detail": "login_refused"},
            ), scope


async def test_a_revoked_reader_s_session_ends(world: World):
    scope, _ = await held_reader(world)
    async with origins(world) as (human, _):
        await login(world, human, scope)
        assert (await human.get("/v1/events")).status_code == 200
        await revoked_reader(world)
        response = await human.get("/v1/events")
    assert (response.status_code, response.json()) == (401, {"detail": "console_session_required"})


async def test_no_parameter_names_another_team(world: World):
    scope, _ = await held_reader(world)
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
    scope, _ = await held_reader(world)
    updated = await team_event(world, "task.updated", seq=1)
    closed = await team_event(world, "task.closed", seq=2)
    head_seq = len(await chained(world))
    mutations = {"hook": "post-mutation-hook"}
    async with origins(world) as (human, _):
        await login(world, human, scope)
        only = await human.get("/v1/events", params={"event_type": "task.closed"})
        assert [e["event_id"] for e in only.json()["events"]] == [closed]
        first = await human.get("/v1/events", params={**mutations, "limit": "1"})
        assert [e["event_id"] for e in first.json()["events"]] == [closed]
        rest = await human.get(
            "/v1/events",
            params={**mutations, "limit": "1", "cursor": first.json()["next_cursor"]},
        )
        assert [e["event_id"] for e in rest.json()["events"]] == [updated]
        head = (await human.get("/v1/tail")).json()
        assert head == {"events": [], "next_cursor": Cursor(1, head_seq).encode()}
        assert (await human.get("/v1/tail", params={"after": head["next_cursor"]})).json() == head
        followed = await human.get("/v1/tail", params={"after": Cursor(1, head_seq - 1).encode()})
        assert [e["event_id"] for e in followed.json()["events"]] == [closed]
        assert followed.json()["next_cursor"] == head["next_cursor"]
        bad_queries: tuple[list[tuple[str, str | int | float | bool | None]], ...] = (
            [("limit", "-1")],
            [("cursor", "nonsense")],
            [("after", "x")],
            [("hook", "a"), ("hook", "b")],
            [("after", head["next_cursor"])],
        )
        for bad in bad_queries:
            response = await human.get("/v1/events", params=bad)
            assert (response.status_code, response.json()) == (400, {"detail": "invalid_filter"})


async def test_a_reader_verifies_its_chain_without_content(world: World):
    scope, _ = await held_reader(world)
    await team_event(world, "task.updated")
    async with origins(world) as (human, _):
        await login(world, human, scope)
        response = await human.get("/v1/verify")
    assert response.status_code == 200
    report = response.json()
    assert (report["chain_epoch"], report["intact"]) == (1, True)
    assert report["delivery"]["scope"] == "observed_internal_only"
    assert report["conflicts"] == []
    assert "task.updated" not in response.text
    assert "payload" not in response.text


async def test_verify_refuses_an_epoch_outside_the_chain_s_range(world: World):
    scope, _ = await held_reader(world)
    async with origins(world) as (human, _):
        await login(world, human, scope)
        for epoch in ("0", "-1", str(2**31), str(2**63)):
            response = await human.get("/v1/verify", params={"chain_epoch": epoch})
            assert (response.status_code, response.json()) == (
                400,
                {"detail": "invalid_filter"},
            ), epoch


async def test_a_reader_exports_its_teams_log_and_it_verifies_with_no_server(world: World):
    scope, _ = await held_reader(world)
    await other_team_event(world)
    async with origins(world) as (human, _):
        await login(world, human, scope)
        async with human.stream("GET", "/v1/export") as response:
            body = b"".join([chunk async for chunk in response.aiter_bytes()])
    assert response.status_code == 200
    assert console_headed(response)
    assert response.headers["content-type"].split(";")[0] == "application/jsonl"
    disposition = response.headers["content-disposition"]
    assert disposition.startswith("attachment;")
    filename = disposition.split('filename="', 1)[1].rstrip('"')
    assert filename.endswith(".jsonl") and "example.com" in filename
    assert all(c.isalnum() or c in "-._" for c in filename)
    lines = [json.loads(line) for line in body.splitlines()]
    assert lines[0] == {"v": 1, "type": "aweb.logs-export", "team_id": TEAM_ID}
    assert sum("event" in line for line in lines) == len(await chained(world))
    report = verify_bundle(
        io.BytesIO(body),
        receipt_keys=frozenset({world.signer.did_key}),
        checkpoint_keys=frozenset({world.signer.did_key}),
    )
    assert report.intact
    assert [epoch.chain_epoch for epoch in report.epochs] == [1]
