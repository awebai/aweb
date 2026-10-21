"""The real AWID + real aweb composition: discovery reaches this server's real routes."""

from __future__ import annotations

import httpx
import pytest

from aweb_naapp.runtime.team_server import TeamServerUnavailable
from tests.real_stack import AWEB_URL

TEAM = "ops:stack.example"


@pytest.mark.asyncio
async def test_a_team_discovers_this_server_and_reaches_its_routes(real_stack):
    team_key = await real_stack.add_team(TEAM)
    await real_stack.publish_server(TEAM, team_key)

    server = await real_stack.directory().resolve(TEAM)
    assert (server.server_url, server.audience) == (AWEB_URL, AWEB_URL)

    async with httpx.AsyncClient(transport=real_stack.aweb) as client:
        response = await client.get(f"{server.server_url}/v1/hooks/producer-keys")
    assert response.status_code == 200, response.text
    assert set(response.json()) == {"keys", "as_of", "max_age_seconds"}


@pytest.mark.asyncio
async def test_an_unpublished_team_has_no_server(real_stack):
    await real_stack.add_team(TEAM)
    with pytest.raises(TeamServerUnavailable) as caught:
        await real_stack.directory().resolve(TEAM)
    assert caught.value.code == "team_server_unpublished"
