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


async def publish(registry, member, *, protected):
    import base64

    from aweb_naapp_testing import did_key
    from nacl.signing import SigningKey

    await registry.add_team(TEAM, member.team_did_key)
    cert = member.certificate()
    await registry.add_certificate(cert)
    await registry.db.execute(
        "UPDATE {{tables.team_certificates}} SET certificate=$1 WHERE certificate_id=$2",
        base64.b64encode(json.dumps(cert).encode()).decode(), member.certificate_id,
    )
    if protected:
        await registry.db.execute(
            "INSERT INTO {{tables.team_protection}} "
            "(domain,name,service_id,service_did_key,generation) VALUES ($1,$2,$3,$4,1)",
            "example.com", "backend", "test-signer", did_key(SigningKey.generate()),
        )
    return cert


from dataclasses import replace

import pytest
from nacl.signing import SigningKey


@pytest.mark.parametrize("protected", [False, True], ids=["legacy", "protected"])
@pytest.mark.parametrize("change", ["genuine", "key", "alias", "rights", "unsigned", "unknown"])
async def test_request_checks_exact_admitted_artifact(registry, protected, change):
    member = Member(team_id=TEAM)
    certificate = await publish(registry, member, protected=protected)
    presented = member
    if change == "key":
        presented = replace(member, member_key=SigningKey.generate())
    elif change == "alias":
        presented = replace(member, alias="impostor")
    elif change == "rights":
        presented = replace(member, extra_cert_fields={"application_rights": ["admin"]})
    elif change == "unknown":
        presented = replace(member, certificate_id="unregistered")
    cert = presented.certificate()
    if change == "unsigned":
        cert = {**certificate, "alias": "unsigned"}
    async with relying_app(registry, public_origin=ORIGIN) as (client, _):
        response = await client.get(
            "/v1/items", headers=presented.headers(aud=ORIGIN, method="GET", path="/v1/items", cert=cert)
        )
    rejected = change in {"unsigned", "unknown"} or (protected and change in {"key", "alias", "rights"})
    assert response.status_code == (401 if rejected else 200), response.text
    if protected and change in {"key", "alias", "rights"}:
        assert "certificate_binding_mismatch" in response.text
