"""Job/runner pages use the existing owner session and sole change writer."""

from contextlib import asynccontextmanager

import httpx
from aweb_naapp.console import CONSOLE_HEADERS, apply_console_migrations
from aweb_naapp.runtime.origins import split_origins
from aweb_naapp_testing.owner_acts import INSTALLATION_ID
from fastapi import FastAPI

from aweb_secrets.console import OwnerConsole, owner_console_router
from aweb_secrets.console_changes import ConsoleChanges, console_changes_router
from aweb_secrets.console_jobs import console_jobs_router
from aweb_secrets.console_ui import console_ui_router
from tests.test_change_sets import ALICE, ORIGIN, enrol_owner
from tests.test_change_sets import world as _world
from tests.test_console import API
from tests.test_console_changes import Registrations, sign_in
from tests.test_console_ui import Elements

world = _world


async def application(w, *, origin=ORIGIN, agent_origin=API):
    await apply_console_migrations(w.db)

    async def installation(installation_id, *, team_id: str | None = None):
        if installation_id != INSTALLATION_ID:
            raise LookupError(installation_id)
        return w.admitted

    console = OwnerConsole(
        db=w.db,
        passkeys=w.passkeys,
        directory=w.directory,
        fence=w.fence,
        verifier=w.owner.verifier,
        installation=installation,
    )
    changes = ConsoleChanges(
        console=console,
        changes=w.change_sets,
        approvals=w.approvals,
        registrations=Registrations(),
        after_commit=w.containment.evict,
    )
    app = FastAPI()
    app.include_router(owner_console_router(console))
    app.include_router(console_ui_router(sessions=console.sessions))
    app.include_router(console_changes_router(changes))
    app.include_router(console_jobs_router(changes=changes))
    return split_origins(FastAPI(), app, human_origin=origin, agent_origin=agent_origin)


@asynccontextmanager
async def clients(w):
    app = await application(w)
    async with (
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN) as human,
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=API) as agent,
    ):
        yield human, agent


async def test_job_runner_forms_use_current_owner_and_canonical_draft_endpoint(world):
    scope = await enrol_owner(world, ALICE, "alice@acme.com")
    root = f"/installations/{INSTALLATION_ID}"
    async with clients(world) as (human, agent):
        assert (await human.get("/jobs/new")).status_code == 303
        await sign_in(world, human, scope)
        for suffix in ("jobs/new", "runners/new"):
            response = await human.get(root + "/" + suffix)
            assert response.status_code == 200
            for name, value in CONSOLE_HEADERS.items():
                assert response.headers[name] == value
            assert (await agent.get(root + "/" + suffix)).status_code == 404
            forms = [attrs for tag, attrs in Elements(response.text).tags if tag == "form"]
            assert len(forms) == 1
            assert forms[0]["method"] == "post"
            assert forms[0]["action"] == root + "/change-sets"
            assert (await human.get("/" + suffix)).status_code == 303
        assert (await human.get("/installations/another/jobs/new")).status_code == 403
        assert await world.db.fetch_value("SELECT COUNT(*) FROM {{tables.change_sets}}") == 0
