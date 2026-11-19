# ruff: noqa: F811 -- pw is the imported real PG/B3 fixture.
"""Console translation retains real F6 projection/hold refusals and rollback."""

import httpx
import pytest
from fastapi import APIRouter, FastAPI

from aweb_naapp.console import CONSOLE_HEADERS, ConsoleRoute
from tests.console.test_human_role_authority import PUBLIC, authority_for
from tests.runtime.approvals.test_human_role_holders import (
    designate,
    holder,
    pw,  # noqa: F401 -- real PG/B3 fixture.
)


@pytest.mark.parametrize("phase", ["projection", "hold", "not_held"])
async def test_console_keeps_installation_refusal_status_and_rolls_back(pw, phase):
    authority = await authority_for(pw)
    await designate(pw, holder())
    target = await authority.session_target(PUBLIC, team_id=pw.owner.team_id)
    db = pw.passkeys.db
    await db.execute("CREATE TABLE tentative_console_effect (id INTEGER PRIMARY KEY)")
    if phase == "projection":
        # Another replica already observed a newer generation; an older cached
        # grant cannot replace it while projecting this target.
        await db.execute("UPDATE {{tables.installation_fences}} SET generation=generation+1")
        expected = (409, "generation_superseded")
    elif phase == "hold":
        # Original local freshness ended after projection, before the caller's
        # effect transaction prepares the held union. No remote rearm here.
        await db.execute("UPDATE {{tables.installation_fences}} SET fresh_until=NULL")
        expected = (503, "authority_unavailable")
    else:
        from tests.runtime.approvals.test_human_role_holders import revoke

        await revoke(pw)
        expected = (403, "role_not_held")

    router = APIRouter(route_class=ConsoleRoute)

    @router.post("/holding-effect")
    async def effect():
        async with db.transaction() as tx:
            await tx.execute("INSERT INTO tentative_console_effect VALUES (1)")
            if phase == "hold":
                await authority.hold_session_target(
                    tx, target, approver_pairs=[(target.b3_scope, target.subject)]
                )
            else:
                await authority.session_target(PUBLIC, team_id=target.team_id)
        return {"committed": True}

    app = FastAPI()
    app.include_router(router)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app, raise_app_exceptions=False),
        base_url="https://app.example.com",
    ) as client:
        refused = await client.post("/holding-effect")
    assert refused.status_code == expected[0], refused.text
    assert refused.json() == {"detail": expected[1]}
    for key, value in CONSOLE_HEADERS.items():
        assert refused.headers[key] == value
    assert await db.fetch_value("SELECT count(*) FROM tentative_console_effect") == 0
