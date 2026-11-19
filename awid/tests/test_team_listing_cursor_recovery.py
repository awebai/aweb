"""The routed team listing rejects malformed page state with a usable retry."""

from uuid import uuid4

import pytest
from awid.pagination import encode_cursor


@pytest.mark.asyncio
async def test_team_listing_recovery_for_invalid_cursor(client):
    path = "/v1/namespaces/cursor.example/teams"
    for cursor in (
        {},
        {"created_at": "2026-11-19T00:00:00Z", "team_uuid": 1},
        {"created_at": "not-a-date", "team_uuid": str(uuid4())},
    ):
        response = await client.get(path, params={"cursor": encode_cursor(cursor)})
        assert response.status_code == 400
        assert response.json() == {
            "detail": "Invalid cursor. Restart the team listing without a cursor and retry."
        }
    retried = await client.get(path)
    assert retried.status_code == 200
    assert retried.json() == {"teams": [], "has_more": False, "next_cursor": None}
