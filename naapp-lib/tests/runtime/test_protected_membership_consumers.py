"""A registry without protection evidence cannot opt a consumer into legacy."""

import json

import httpx
from aweb_naapp_testing import Member

from tests.runtime.conftest import relying_app

ORIGIN = "https://app.example.com"
TEAM = "backend:example.com"


async def test_missing_protection_projection_is_unavailable(registry):
    member = Member(team_id=TEAM)
    await registry.add_team(TEAM, member.team_did_key)
    await registry.add_certificate(member.certificate())

    def old_registry(request, response):
        if request.method != "GET" or response.status_code != 200:
            return None
        payload = response.json()
        if isinstance(payload, dict):
            payload.pop("protection", None)
            return httpx.Response(200, json=payload)
        return None

    # Strip the additive projection after the real registry answered, to model
    # an old selected registry. No fabricated positive authority is supplied.
    registry.transport.fault = old_registry
    async with relying_app(registry, public_origin=ORIGIN) as (client, _):
        response = await client.get(
            "/v1/items", headers=member.headers(aud=ORIGIN, method="GET", path="/v1/items")
        )
    assert response.status_code == 503, response.text
    assert "protected_state_unavailable" in json.dumps(response.json())
