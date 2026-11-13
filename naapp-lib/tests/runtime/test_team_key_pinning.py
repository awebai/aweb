"""A team key a naapp admitted is not replaced by an unsigned registry answer.

The registry operator is modelled by writing the registry's own tables: that
is exactly the power the threat gives it. A second cache stands for the same
app after its in-memory facts expired or the process restarted.
"""

from __future__ import annotations

from aweb_naapp_testing import Member

from aweb_naapp.runtime.team_auth import AWIDTeamCache
from awid_service.testing import REGISTRY_URL

from tests.runtime.conftest import relying_app

ORIGIN = "https://app.example.com"
TEAM_ID = "backend:example.com"


def _team_cache(registry) -> AWIDTeamCache:
    return AWIDTeamCache(registry_url=REGISTRY_URL, ttl_seconds=60, transport=registry.transport)


async def test_substituted_registry_team_key_does_not_admit_a_forged_member(registry):
    member = Member(team_id=TEAM_ID)
    await registry.add_team(TEAM_ID, member.team_did_key, visibility="public")
    await registry.add_certificate(member.certificate())
    async with relying_app(registry, public_origin=ORIGIN, cache=_team_cache(registry)) as (client, _):
        admitted = await client.get("/v1/items", headers=member.headers(aud=ORIGIN, method="GET", path="/v1/items"))
    assert admitted.status_code == 200, admitted.text

    forger = Member(team_id=TEAM_ID, alias="mallory", certificate_id="forged-mallory")
    await registry.rotate_team_key(TEAM_ID, forger.team_did_key)
    await registry.add_certificate(forger.certificate())

    async with relying_app(registry, public_origin=ORIGIN, cache=_team_cache(registry)) as (client, _):
        forged = await client.get("/v1/items", headers=forger.headers(aud=ORIGIN, method="GET", path="/v1/items"))

    assert forged.status_code == 401, forged.text
    assert forged.json()["detail"] == "team_key_unverified"
