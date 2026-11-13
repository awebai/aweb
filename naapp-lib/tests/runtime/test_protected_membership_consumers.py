"""A registry without protection evidence cannot opt a consumer into legacy."""

import json
from dataclasses import replace

import httpx
import pytest
from aweb_naapp_testing import Member
from nacl.signing import SigningKey

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


@pytest.mark.parametrize("change", ["genuine", "key", "alias", "rights"])
async def test_hook_checks_full_registered_certificate(registry, change):
    import base64
    from datetime import UTC, datetime

    from aweb_naapp.hooks.delivery import ReceiveOptions, _verify_client_certificate
    from aweb_naapp.hooks.envelope import Envelope, Refused
    from aweb_naapp.runtime.team_auth import AWIDTeamCache

    member = Member(team_id=TEAM)
    await publish(registry, member, protected=True)
    presented = member
    if change == "key":
        presented = replace(member, member_key=SigningKey.generate())
    elif change == "alias":
        presented = replace(member, alias="impostor")
    elif change == "rights":
        presented = replace(member, extra_cert_fields={"rights": ["admin"]})
    cache = AWIDTeamCache(registry_url="https://registry.example", ttl_seconds=60, transport=registry.transport)
    facts = await cache.get(TEAM, member.certificate_id)
    envelope = Envelope(fields={"producer": {"certificate_id": member.certificate_id}},
                        hook="test.hook", event_id="event-1", team_id=TEAM,
                        producer_kind="client", producer_did_key=presented.did_key,
                        producer_kid="member", producer="client:"+member.certificate_id)
    options = ReceiveOptions(audience=ORIGIN, binding_id="binding", now=datetime.now(UTC),
                             team_key_did=facts.team_did_key,
                             registered_certificate_ids=facts.published_certificate_ids,
                             protection_observation=facts.protection_observation,
                             )
    encoded = base64.b64encode(json.dumps(presented.certificate()).encode()).decode()
    if change == "genuine":
        _verify_client_certificate(encoded, envelope, options)
    else:
        with pytest.raises(Refused, match="certificate_binding_mismatch"):
            _verify_client_certificate(encoded, envelope, options)


@pytest.mark.parametrize("surface", ["current-member", "startup"])
@pytest.mark.parametrize("change", ["genuine", "key", "alias"])
async def test_additional_member_checks_use_exact_artifact(registry, surface, change):
    from fastapi import HTTPException

    from aweb_naapp.runtime.team_auth import AWIDMemberCredential, AWIDTeamCache

    member = Member(team_id=TEAM)
    await publish(registry, member, protected=True)
    presented = member
    if change == "key":
        presented = replace(member, member_key=SigningKey.generate())
    elif change == "alias":
        presented = replace(member, alias="impostor")
    options = {}
    if surface == "startup":
        options["member_credentials"] = {TEAM: AWIDMemberCredential(
            signing_key=bytes(presented.member_key), certificate=presented.certificate(),
        )}
    cache = AWIDTeamCache(registry_url="https://registry.example", ttl_seconds=60,
                          transport=registry.transport, **options)
    async def check():
        if surface == "startup":
            await cache.check_member_credentials()
        else:
            await cache.check_current_member(TEAM, certificate_id=member.certificate_id,
                                            team_did_key=member.team_did_key,
                                            certificate=presented.certificate())
    if change == "genuine":
        await check()
    else:
        with pytest.raises((HTTPException, RuntimeError)) as refused:
            await check()
        assert "certificate_binding_mismatch" in str(refused.value)


async def test_id_only_evidence_cannot_authorize_protected_current_member(registry):
    from fastapi import HTTPException

    from aweb_naapp.runtime.team_auth import AWIDTeamCache

    member = Member(team_id=TEAM)
    await publish(registry, member, protected=True)
    cache = AWIDTeamCache(registry_url="https://registry.example", ttl_seconds=60,
                          transport=registry.transport)
    with pytest.raises(HTTPException) as refused:
        await cache.check_current_member(TEAM, certificate_id=member.certificate_id,
                                        team_did_key=member.team_did_key)
    assert refused.value.status_code == 503


@pytest.mark.parametrize("fault", ["null-blob", "down"])
async def test_unavailable_exact_membership_refuses(registry, fault):
    member = Member(team_id=TEAM)
    await publish(registry, member, protected=True)
    if fault == "null-blob":
        await registry.db.execute("UPDATE {{tables.team_certificates}} SET certificate=NULL")
    else:
        registry.transport.down = True
    async with relying_app(registry, public_origin=ORIGIN) as (client, _):
        response = await client.get(
            "/v1/items", headers=member.headers(aud=ORIGIN, method="GET", path="/v1/items")
        )
    assert response.status_code == 503, response.text


@pytest.mark.parametrize("private", [False, True], ids=["public", "private"])
@pytest.mark.parametrize("original_subject", ["genuine", "different"])
async def test_retained_subject_is_original_evidence(registry, private, original_subject):
    from awid_service.testing import SERVICE_TOKEN
    from fastapi import HTTPException

    from aweb_naapp.runtime.team_auth import AWIDTeamCache

    member = Member(team_id=TEAM)
    await publish(registry, member, protected=True)
    if private:
        await registry.db.execute("UPDATE {{tables.teams}} SET visibility='private'")
    principal = member.did_key if original_subject == "genuine" else Member(team_id=TEAM).did_key
    cache = AWIDTeamCache(registry_url="https://registry.example", ttl_seconds=60,
                          transport=registry.transport, service_token=SERVICE_TOKEN)
    async def check():
        return await cache.check_current_member(TEAM, certificate_id=member.certificate_id,
                                               team_did_key=member.team_did_key, principal=principal)
    if original_subject == "genuine":
        proof = await check()
        assert proof.principal == principal
        assert proof.is_fresh_at(proof.checked_at)
    else:
        with pytest.raises(HTTPException) as refused:
            await check()
        assert refused.value.status_code == 401
        assert "certificate_binding_mismatch" in str(refused.value.detail)


async def test_private_protected_presenter_needs_no_private_history_access(registry):
    member = Member(team_id=TEAM)
    await publish(registry, member, protected=True)
    await registry.db.execute("UPDATE {{tables.teams}} SET visibility='private'")
    async with relying_app(registry, public_origin=ORIGIN) as (client, _):
        response = await client.get(
            "/v1/items", headers=member.headers(aud=ORIGIN, method="GET", path="/v1/items")
        )
    assert response.status_code == 200, response.text
    # Only public per-certificate status is needed, never private metadata/history.
    assert all("/status" in request.url.path for request in registry.transport.calls)
