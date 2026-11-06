"""Owner activity reads the real scoped operational records without dispatch."""

from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import httpx
import pytest
from aweb_naapp.console import CONSOLE_HEADERS, apply_console_migrations
from aweb_naapp.dispatch import apply_dispatch_migrations
from aweb_naapp.hooks.commitment import CommitmentContext
from aweb_naapp.runtime.origins import split_origins
from aweb_naapp_testing.owner_acts import INSTALLATION_ID
from fastapi import FastAPI

from aweb_secrets.activity_service import ActivityReads
from aweb_secrets.broker_audit import record_broker_refusal
from aweb_secrets.console import OwnerConsole, owner_console_router
from aweb_secrets.console_activity import ConsoleActivity, console_activity_router
from aweb_secrets.console_ui import console_ui_router
from aweb_secrets.use_context import UseCommitments, apply_use_context_migrations
from tests.test_broker_audit import source
from tests.test_change_sets import ALICE, ORIGIN, TEAM, enrol_owner
from tests.test_change_sets import world as _world
from tests.test_console import API
from tests.test_console_changes import sign_in
from tests.test_use_approvals import REQUESTER

world = _world


async def application(w, *, origin=ORIGIN, agent_origin=API):
    await apply_console_migrations(w.db)
    await apply_dispatch_migrations(w.db)
    await apply_use_context_migrations(w.db)

    async def installation(installation_id, *, team_id: str | None = None):
        if installation_id != INSTALLATION_ID:
            raise LookupError(installation_id)
        return w.admitted

    console = OwnerConsole(
        db=w.db,
        passkeys=w.passkeys,
        credential_audit=w.credential_audit,
        directory=w.directory,
        fence=w.fence,
        verifier=w.owner.verifier,
        installation=installation,
    )
    app = FastAPI()
    app.include_router(owner_console_router(console))
    app.include_router(console_ui_router(sessions=console.sessions))
    app.include_router(
        console_activity_router(services=ConsoleActivity(console=console, reads=ActivityReads()))
    )
    return split_origins(FastAPI(), app, human_origin=origin, agent_origin=agent_origin)


@asynccontextmanager
async def clients(w):
    app = await application(w)
    async with (
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN) as human,
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=API) as agent,
    ):
        yield human, agent


async def recorded(w, when, *, installation=INSTALLATION_ID):
    async with w.db.transaction() as tx:
        return await record_broker_refusal(
            tx,
            producer=source(installation, 1),
            principal=REQUESTER,
            commitments=UseCommitments(
                CommitmentContext("secrets", TEAM, installation, 1, "request"), None, None
            ),
            code="grant_missing",
            occurred_at=when,
        )


async def test_owner_activity_pages_original_attribution_and_keyset_pagination(world):
    scope = await enrol_owner(world, ALICE, "alice@acme.com")
    async with clients(world) as (human, agent):
        assert (await human.get("/activity")).status_code == 303
        assert (await human.get("/activity/events")).status_code == 401
        assert (await agent.get("/activity")).status_code == 404
        await sign_in(world, human, scope)
        now = datetime.now(UTC)
        oldest = await recorded(world, now - timedelta(seconds=2))
        newest = await recorded(world, now)
        await recorded(world, now + timedelta(seconds=1), installation=str(uuid4()))
        first = await human.get("/activity/events?limit=1")
        assert first.status_code == 200
        [entry] = first.json()["entries"]
        assert entry["event_id"] == str(newest)
        assert entry["action"] == "refused" and entry["refusal_code"] == "grant_missing"
        assert entry["principal_did"] in (REQUESTER.did_aw, REQUESTER.did_key)
        # An older pre-intent refusal has no original correlation to invent.
        assert entry["request_id"] is None and entry["job_id"] is None
        assert not ({"actor", "payload", "params", "body", "request_sha256"} & set(entry))
        older = await human.get(
            "/activity/events", params={"limit": 1, "before": first.json()["next_cursor"]}
        )
        assert [e["event_id"] for e in older.json()["entries"]] == [str(oldest)]
        assert older.json()["next_cursor"] is None
        page = await human.get("/activity?limit=1")
        assert page.status_code == 200
        assert str(newest) in page.text and str(oldest) not in page.text
        assert 'rel="next"' in page.text
        for name, value in CONSOLE_HEADERS.items():
            assert page.headers[name] == value
        assert await world.db.fetch_value("SELECT COUNT(*) FROM {{tables.intents}}") == 0


@pytest.mark.parametrize("query", ["limit=0", "limit=101", "limit=bad", "before=bad", "before="])
async def test_invalid_activity_queries_return_bounded_errors(world, query):
    scope = await enrol_owner(world, ALICE, "alice@acme.com")
    async with clients(world) as (human, _):
        await sign_in(world, human, scope)
        response = await human.get("/activity/events?" + query)
        assert response.status_code == 400
        assert response.json()["detail"] in ("activity_cursor_invalid", "activity_limit_invalid")


async def test_activity_owner_revocation_and_f6_are_checked_before_read(world):
    from aweb_naapp.roles import unassign

    from aweb_secrets.owners import OWNER_ROLE

    scope = await enrol_owner(world, ALICE, "alice@acme.com")
    async with clients(world) as (human, _):
        await sign_in(world, human, scope)
        event_id = await recorded(world, datetime.now(UTC))
        await world.db.execute(
            "UPDATE {{tables.installation_fences}} SET fresh_until=clock_timestamp()-interval '1 second'"
        )
        response = await human.get("/activity/events")
        assert response.status_code == 503 and str(event_id) not in response.text
        await world.fence.refresh(TEAM)
        async with world.db.transaction() as tx:
            await unassign(tx, ALICE, OWNER_ROLE)
        response = await human.get("/activity/events")
        assert response.status_code == 401 and str(event_id) not in response.text
        assert "Max-Age=0" in response.headers["set-cookie"]
