"""Anonymous traffic cannot reach installation authority through a retired route."""

import pytest

from tests.test_production_bootstrap import root as root


@pytest.mark.parametrize("origin", ["public_origin", "console_origin"])
@pytest.mark.parametrize("known_team", [True, False])
async def test_retired_owner_route_never_refreshes_an_anonymous_callers_team(
    root, origin, known_team
):
    service, client, configured, member, installed, _, transport, _ = root
    before = len(transport.calls)
    response = await client.post(
        getattr(configured, origin)
        + "/installations/"
        + installed["installation_id"]
        + "/owner-acts",
        json={
            "team_id": member.team_id if known_team else "another:example.com",
            "principal": member.did_key,
            "contact": "untrusted@example.com",
            "signing": "e30=",
            "signature": "invalid",
        },
    )
    assert len(transport.calls) == before, "anonymous retired route refreshed team authority"
    assert response.status_code == 404, "the retired owner route must not be mounted"
    assert await service.runtime.db().fetch_value("SELECT count(*) FROM installation_fences") == 0
