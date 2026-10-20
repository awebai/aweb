"""A team certificate that cannot be canonicalised is refused, not a crash.

A lone-surrogate JSON escape survives a lenient JSON parse, then breaks UTF-8
encoding when the verifier canonicalises the certificate. The certificate
header is not covered by the member's signature, so anyone holding a captured
request could send one; the verifier answers 401, never 500.
"""

from __future__ import annotations

import base64
import json

import pytest

from tests.runtime.conftest import Member, relying_app

ORIGIN = "https://app.example.com"
TEAM_ID = "backend:example.com"


@pytest.fixture
async def member(registry) -> Member:
    member = Member(team_id=TEAM_ID)
    await registry.add_team(TEAM_ID, member.team_did_key)
    await registry.add_certificate(member.certificate())
    return member


async def test_a_lone_surrogate_in_the_certificate_is_a_401(registry, member) -> None:
    headers = member.headers(aud=ORIGIN, method="GET", path="/v1/items")
    text = json.dumps(member.certificate()).replace(
        '"version": 1', '"note": "\\ud800", "version": 1'
    )
    headers["X-AWID-Team-Certificate"] = base64.b64encode(text.encode()).decode()
    async with relying_app(registry, public_origin=ORIGIN) as (client, _):
        response = await client.get("/v1/items", headers=headers)
    assert response.status_code == 401, response.text
    assert response.json()["detail"] == "Team certificate signature verification failed"
