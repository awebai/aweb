"""Hostile team-auth headers are refused with a 401, never a crash.

The certificate header is not covered by the member's signature, and both it
and the signed payload are parsed before any signature is checked. A
lone-surrogate escape survives a lenient JSON parse and breaks canonical
encoding; deep nesting exhausts the JSON parser on some Python versions; an
oversized certificate is refused before it is decoded.
"""

from __future__ import annotations

import base64
import json

import pytest
from aweb_naapp_testing import Member

from tests.runtime.conftest import relying_app

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


async def test_a_lone_surrogate_in_the_signed_payload_is_a_401(registry, member) -> None:
    headers = member.headers(aud=ORIGIN, method="GET", path="/v1/items")
    padded = headers["X-AWEB-Signed-Payload"] + "=" * (-len(headers["X-AWEB-Signed-Payload"]) % 4)
    payload = base64.urlsafe_b64decode(padded).decode()
    poisoned = payload.replace('"aud":', '"note":"\\ud800","aud":', 1)
    assert poisoned != payload
    headers["X-AWEB-Signed-Payload"] = (
        base64.urlsafe_b64encode(poisoned.encode()).rstrip(b"=").decode()
    )
    async with relying_app(registry, public_origin=ORIGIN) as (client, _):
        response = await client.get("/v1/items", headers=headers)
    assert response.status_code == 401, response.text
    assert response.json()["detail"] == "Invalid X-AWEB-Signed-Payload"


@pytest.mark.parametrize("depth", [6000, 100000], ids=["under-the-cap", "over-the-cap"])
async def test_deeply_nested_certificate_is_a_401(registry, member, depth) -> None:
    headers = member.headers(aud=ORIGIN, method="GET", path="/v1/items")
    headers["X-AWID-Team-Certificate"] = base64.b64encode(b"[" * depth).decode()
    async with relying_app(registry, public_origin=ORIGIN) as (client, _):
        response = await client.get("/v1/items", headers=headers)
    assert response.status_code == 401, response.text
    assert response.json()["detail"] == "Malformed team certificate"


async def test_a_deeply_nested_signed_payload_is_a_401(registry, member) -> None:
    headers = member.headers(aud=ORIGIN, method="GET", path="/v1/items")
    headers["X-AWEB-Signed-Payload"] = base64.urlsafe_b64encode(b"[" * 100000).rstrip(b"=").decode()
    async with relying_app(registry, public_origin=ORIGIN) as (client, _):
        response = await client.get("/v1/items", headers=headers)
    assert response.status_code == 401, response.text
    assert response.json()["detail"] == "Invalid X-AWEB-Signed-Payload"
