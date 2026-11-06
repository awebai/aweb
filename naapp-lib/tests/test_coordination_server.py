"""aweb_naapp_testing.server: a team's coordination server, found through the
team's AWID record and reached through its in-process transport."""

from __future__ import annotations

from uuid import uuid4

import httpx
import pytest
from aweb_naapp_testing import Member

from aweb_naapp.runtime.team_server import TeamServerUnavailable


def _member() -> Member:
    # The server's AWID client caches team keys in the Redis other runs share.
    return Member(team_id=f"t{uuid4().hex[:12]}:naapp.example", alias="alice")


async def test_a_published_team_finds_the_server_and_connects_to_it(coordination) -> None:
    member = _member()
    await coordination.add_member(member)
    directory = coordination.directory()
    with pytest.raises(TeamServerUnavailable) as unpublished:
        await directory.resolve(member.team_id)
    assert unpublished.value.code == "team_server_unpublished"

    await coordination.publish_server(member)
    server = await coordination.directory().resolve(member.team_id)
    assert server.server_url == coordination.server.url

    connected = await coordination.connect(member)
    assert (connected["team_id"], connected["alias"]) == (member.team_id, "alice")


async def test_a_member_of_a_team_unknown_to_awid_cannot_connect(coordination) -> None:
    with pytest.raises(httpx.HTTPStatusError) as refused:
        await coordination.connect(_member())
    assert refused.value.response.status_code == 401
