"""The frozen team-auth v2 conformance vectors, verified byte for byte.

Every positive case is presented with its exact signed payload and signature; the
clock is pinned to the vector's timestamp. Each negative case is derived from its
positive case exactly as the vector file describes.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path

import pytest
from awid.signing import canonical_json_bytes, sign_message
from nacl.signing import SigningKey

from tests.runtime.conftest import Member, envelope_headers, relying_app

AWEB_ROOT = Path(__file__).resolve().parents[3]
VECTORS = json.loads((AWEB_ROOT / "docs" / "vectors" / "team-auth-envelope-v2.json").read_text())
CASES = {case["name"]: case for case in VECTORS["cases"]}


def member_for(case: dict) -> Member:
    member = Member(
        team_id=case["payload"]["team_id"],
        team_key=SigningKey(hashlib.sha256(b"team:" + case["name"].encode()).digest()),
        member_key=SigningKey(bytes.fromhex(case["seed_hex"])),
    )
    assert member.did_key == case["did_key"]
    return member


async def present(registry, case, *, public_origin=None, path=None, body=None, payload=None, signature=None):
    member = member_for(case)
    await registry.add_team(member.team_id, member.team_did_key)
    await registry.add_certificate(member.certificate())
    pinned = datetime.fromisoformat(case["payload"]["timestamp"].replace("Z", "+00:00"))
    headers = envelope_headers(
        did_key=case["did_key"],
        signature=signature or case["signature_b64"],
        timestamp=case["payload"]["timestamp"],
        signed_payload=payload or case["canonical_payload"].encode(),
        cert=member.certificate(),
    )
    async with relying_app(
        registry, public_origin=public_origin or case["payload"]["aud"], now=lambda: pinned
    ) as (client, _cache):
        return await client.post(
            path or case["payload"]["path"],
            content=(body if body is not None else case["body"]).encode(),
            headers=headers,
        )


@pytest.mark.parametrize("name", sorted(CASES))
async def test_positive_vector_authenticates(registry, name):
    case = CASES[name]
    response = await present(registry, case)
    assert response.status_code == 200, response.text
    assert response.json()["did_key"] == case["did_key"]
    assert response.json()["team_id"] == case["payload"]["team_id"]
    assert response.json()["cached_body"] == case["body"]


@pytest.mark.parametrize("negative", VECTORS["negative_cases"], ids=lambda n: n["name"])
async def test_negative_vector_is_refused(registry, negative):
    case = CASES[negative["derived_from"]]
    kwargs = {}
    if "presented_path" in negative:
        kwargs["path"] = negative["presented_path"]
    if "allowed_audiences" in negative:
        (kwargs["public_origin"],) = negative["allowed_audiences"]
    if "presented_body" in negative:
        kwargs["body"] = negative["presented_body"]
    if "remove_field" in negative:
        payload = dict(case["payload"])
        payload.pop(negative["remove_field"])
        kwargs["payload"] = canonical_json_bytes(payload)
        kwargs["signature"] = sign_message(bytes.fromhex(case["seed_hex"]), kwargs["payload"])
    response = await present(registry, case, **kwargs)
    assert response.status_code == 401, response.text
