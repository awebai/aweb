"""The routed team listing rejects malformed page state with a usable retry."""

from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest
from awid.pagination import encode_cursor
from awid_service.routes.teams import _team_list_parameters, _TeamListingAccess
from fastapi import HTTPException


@pytest.mark.asyncio
async def test_team_listing_recovery_for_invalid_cursor(client):
    path = "/v1/namespaces/cursor.example/teams"
    for cursor in (
        {},
        {"created_at": "2026-11-19T00:00:00Z", "team_uuid": 1},
        {"created_at": "not-a-date", "team_uuid": str(uuid4())},
        {"created_at": "2026-11-19T00:00:00Z", "team_uuid": "not-a-uuid"},
        {"created_at": "2026-11-19", "team_uuid": str(uuid4())},
        {"created_at": "2026-11-19T00:00:00", "team_uuid": str(uuid4())},
    ):
        response = await client.get(path, params={"cursor": encode_cursor(cursor)})
        assert response.status_code == 422
        assert response.json() == {
            "detail": "Invalid cursor. Restart the team listing without a cursor and retry."
        }
    retried = await client.get(path)
    assert retried.status_code == 200
    assert retried.json() == {"teams": [], "has_more": False, "next_cursor": None}

    valid_page = await client.get(
        path,
        params={
            "cursor": encode_cursor(
                {
                    "created_at": "2026-11-19T01:00:00+01:00",
                    "team_uuid": "{12345678-1234-1234-1234-123456789ABC}",
                }
            )
        },
    )
    assert valid_page.status_code == 200
    assert valid_page.json() == {"teams": [], "has_more": False, "next_cursor": None}


@pytest.mark.parametrize(
    "cursor",
    [
        {},
        {"created_at": "2026-11-19T00:00:00Z", "team_uuid": 1},
        {
            "created_at": "not-a-date",
            "team_uuid": "12345678-1234-1234-1234-123456789abc",
        },
        {"created_at": "2026-11-19T00:00:00Z", "team_uuid": "not-a-uuid"},
        {
            "created_at": "2026-11-19",
            "team_uuid": "12345678-1234-1234-1234-123456789abc",
        },
        {
            "created_at": "2026-11-19T00:00:00",
            "team_uuid": "12345678-1234-1234-1234-123456789abc",
        },
    ],
)
def test_team_list_parameters_refuse_invalid_values_before_sql(cursor):
    with pytest.raises(HTTPException) as caught:
        _team_list_parameters(
            domain="local",
            access=_TeamListingAccess.VISIBLE_TO_READER,
            viewer_did=None,
            limit=1,
            cursor=cursor,
        )
    assert caught.value.status_code == 422
    assert (
        caught.value.detail
        == "Invalid cursor. Restart the team listing without a cursor and retry."
    )


@pytest.mark.parametrize(
    "uuid_spelling",
    [
        "12345678-1234-1234-1234-123456789abc",
        "12345678-1234-1234-1234-123456789ABC",
        "{12345678-1234-1234-1234-123456789abc}",
        "12345678123412341234123456789abc",
        "urn:uuid:12345678-1234-1234-1234-123456789abc",
    ],
)
@pytest.mark.parametrize(
    "timestamp", ["2026-11-19T00:00:00Z", "2026-11-19T01:00:00+01:00"]
)
def test_team_list_parameters_bind_valid_cursor_values(uuid_spelling, timestamp):
    parameters = _team_list_parameters(
        domain="local",
        access=_TeamListingAccess.VISIBLE_TO_READER,
        viewer_did=None,
        limit=1,
        cursor={"created_at": timestamp, "team_uuid": uuid_spelling},
    )
    assert parameters[3] == datetime(2026, 11, 19, tzinfo=timezone.utc)
    assert UUID(str(parameters[4])) == UUID("12345678-1234-1234-1234-123456789abc")
