"""The ordinary app page serves a stored session or credential handoff."""

from datetime import timedelta

import httpx
import pytest
from fastapi import FastAPI

from aweb_naapp.console import ClientIdentity, LoginLimiter
from aweb_naapp.console.handoff_page import handoff_page_router
from aweb_naapp.console.handoff_store import HandoffStore, parse_start
from tests.console.test_handoff_store import ORIGIN, handoff_db, start_body

__all__ = ["handoff_db"]


@pytest.mark.parametrize(
    "purpose,title", [("session", "Sign in with a passkey"), ("credential", "Create a passkey")]
)
async def test_app_handoff_page_keeps_the_stored_purpose_and_grants_nothing(
    handoff_db, purpose, title
):
    store = HandoffStore(handoff_db)
    created = await store.create(
        parse_start(start_body(purpose=purpose)), team_id="people:example.com"
    )
    app = FastAPI()
    app.include_router(
        handoff_page_router(
            store=store,
            limiter=LoginLimiter(
                handoff_db,
                client_identity=ClientIdentity(),
                limit=30,
                window=timedelta(minutes=1),
            ),
        )
    )
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN) as client:
        page = await client.get(f"/handoff/{created['handoff_id']}")
        assert page.status_code == 200
        assert f"<title>{title}</title>" in page.text
        assert f'data-purpose="{purpose}"' in page.text
        assert f'data-handoff-id="{created["handoff_id"]}"' in page.text
        assert (await client.get("/handoff-assets/handoff.js")).status_code == 200
        assert (await client.get("/handoff-assets/handoff.css")).status_code == 200
    row = await handoff_db.fetch_one(
        "SELECT completed_at, released_at FROM {{tables.console_handoffs}} WHERE handoff_id=$1::uuid",
        created["handoff_id"],
    )
    assert row["completed_at"] is None and row["released_at"] is None
    assert await handoff_db.fetch_value("SELECT COUNT(*) FROM {{tables.console_sessions}}") == 0
