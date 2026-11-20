"""The routed team listing rejects malformed page state with a usable retry."""

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from awid.did import did_from_public_key, generate_keypair
from awid.pagination import decode_cursor, encode_cursor
from awid_service.routes.teams import _team_list_parameters, _TeamListingAccess
from fastapi import HTTPException

from conftest import send_controller_request


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


@pytest.mark.asyncio
async def test_team_listing_cursor_pages_a_populated_registry(controller_app):
    env = controller_app
    path = "/v1/namespaces/local/teams"

    # The fixture's base team and these two writes all go through the real
    # create-team route. Order by exactly the listing's two documented fields.
    created = []
    first_team = await env.client.get(f"{path}/base")
    assert first_team.status_code == 200, first_team.text
    created.append(first_team.json())
    for name in ("cursor-alpha", "cursor-beta"):
        _, team_public_key = generate_keypair()
        response = await send_controller_request(
            env,
            "POST",
            path,
            {"domain": "local", "operation": "create_team", "name": name},
            {
                "name": name,
                "team_did_key": did_from_public_key(team_public_key),
                "visibility": "public",
            },
        )
        assert response.status_code == 200, response.text
        created.append(response.json())
    # Team UUIDs are cursor internals, absent from the public TeamResponse.
    ids = {
        row["name"]: row["team_uuid"]
        for row in await env.db.fetch_all(
            "SELECT name, team_uuid FROM {{tables.teams}} WHERE domain = $1", "local"
        )
    }
    expected = sorted(
        created,
        key=lambda team: (
            datetime.fromisoformat(team["created_at"]),
            ids[team["name"]],
        ),
    )

    first = await env.client.get(path, params={"limit": 1})
    assert first.status_code == 200, first.text
    page = first.json()
    assert page["teams"] == expected[:1]
    assert page["has_more"] is True
    cursor = decode_cursor(page["next_cursor"])
    assert cursor == {
        "created_at": expected[0]["created_at"],
        "team_uuid": str(ids[expected[0]["name"]]),
    }
    alternative_time = datetime.fromisoformat(cursor["created_at"]).astimezone(
        timezone(timedelta(hours=1))
    )
    alternative_cursor = encode_cursor(
        {
            "created_at": alternative_time.isoformat(),
            "team_uuid": "{" + cursor["team_uuid"].upper() + "}",
        }
    )
    middle = await env.client.get(path, params={"limit": 1, "cursor": alternative_cursor})
    assert middle.status_code == 200, middle.text
    page = middle.json()
    assert page["teams"] == expected[1:2]
    assert page["has_more"] is True

    last = await env.client.get(path, params={"limit": 1, "cursor": page["next_cursor"]})
    assert last.status_code == 200, last.text
    assert last.json() == {
        "teams": expected[2:],
        "has_more": False,
        "next_cursor": None,
    }
    beyond = await env.client.get(
        path,
        params={
            "limit": 1,
            "cursor": encode_cursor(
                {"created_at": expected[-1]["created_at"], "team_uuid": str(ids[expected[-1]["name"]])}
            ),
        },
    )
    assert beyond.status_code == 200, beyond.text
    assert beyond.json() == {"teams": [], "has_more": False, "next_cursor": None}


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
