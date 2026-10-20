"""The did:aw current-key profile: a certificate's member_did_aw must name a DID
whose current key at the configured registry is the request's signer.

Real AWID routes on real PostgreSQL register and rotate every DID. A fault, when a
test sets one, alters a response only after the real handler produced it.
"""

from __future__ import annotations

import logging
import time
from dataclasses import replace

import httpx
import pytest
from awid.did import stable_id_from_did_key
from awid.log import canonical_server_origin
from nacl.signing import SigningKey

from aweb_naapp.runtime.team_auth import AWIDTeamCache, DidAwProfile
from tests.runtime.conftest import REGISTRY_URL, Member, did_key, relying_app

ORIGIN = "https://app.example.com"
TEAM_ID = "backend:example.com"
# A well-formed did:aw that no test registers.
UNREGISTERED_DID_AW = stable_id_from_did_key(did_key(SigningKey.generate()))


def did_lookups(registry) -> list[httpx.Request]:
    return [r for r in registry.transport.calls if r.method == "GET" and r.url.path.endswith("/key")]


@pytest.fixture(autouse=True)
def info_logs(caplog):
    caplog.set_level(logging.INFO, logger="aweb_naapp.runtime.team_auth")


def get_items(member: Member) -> dict[str, str]:
    return member.headers(aud=ORIGIN, method="GET", path="/v1/items")


async def certified(registry, *, member_key: SigningKey, did_aw: str | None, team_key: SigningKey,
                    certificate_id: str = "cert-1", alias: str = "alice") -> Member:
    extra = {"member_did_aw": did_aw} if did_aw else {}
    member = Member(team_id=TEAM_ID, team_key=team_key, member_key=member_key, certificate_id=certificate_id,
                    alias=alias, extra_cert_fields=extra)
    await registry.add_certificate(member.certificate())
    return member


@pytest.fixture
async def team_key(registry) -> SigningKey:
    key = SigningKey.generate()
    await registry.add_team(TEAM_ID, Member(team_id=TEAM_ID, team_key=key).team_did_key)
    return key


@pytest.fixture
async def global_member(registry, team_key) -> Member:
    key = SigningKey.generate()
    did_aw = await registry.register_did(key)
    return await certified(registry, member_key=key, did_aw=did_aw, team_key=team_key)


async def test_the_current_key_is_verified_against_the_registry(registry, global_member):
    async with relying_app(registry, public_origin=ORIGIN) as (client, _):
        response = await client.get("/v1/items", headers=get_items(global_member))
    assert response.status_code == 200, response.text
    assert response.json()["did_aw"] == global_member.extra_cert_fields["member_did_aw"]
    assert response.json()["did_aw_registry_verified"] is True
    assert len(did_lookups(registry)) == 1


async def test_a_rotated_out_key_is_refused_and_the_current_key_accepted(registry, team_key):
    old, new = SigningKey.generate(), SigningKey.generate()
    did_aw = await registry.register_did(old)
    old_member = await certified(registry, member_key=old, did_aw=did_aw, team_key=team_key)
    await registry.rotate_did(did_aw, old, new)
    # The old certificate stays active at AWID: only the current-key check refuses it.
    new_member = await certified(registry, member_key=new, did_aw=did_aw, team_key=team_key,
                                 certificate_id="cert-2", alias="alice-rotated")
    async with relying_app(registry, public_origin=ORIGIN) as (client, _):
        refused = await client.get("/v1/items", headers=get_items(old_member))
        accepted = await client.get("/v1/items", headers=get_items(new_member))
    assert refused.status_code == 401, refused.text
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["did_aw_registry_verified"] is True


@pytest.mark.parametrize("did_aw", [UNREGISTERED_DID_AW, "did:aw:not-base58!"], ids=["unregistered", "malformed"])
async def test_a_did_the_registry_does_not_know_is_refused(registry, team_key, did_aw):
    member = await certified(registry, member_key=SigningKey.generate(), did_aw=did_aw, team_key=team_key)
    async with relying_app(registry, public_origin=ORIGIN) as (client, _):
        response = await client.get("/v1/items", headers=get_items(member))
    assert response.status_code == 401, response.text


async def test_a_did_key_only_member_needs_no_global_identity(registry, team_key):
    member = await certified(registry, member_key=SigningKey.generate(), did_aw=None, team_key=team_key)
    async with relying_app(registry, public_origin=ORIGIN) as (client, _):
        response = await client.get("/v1/items", headers=get_items(member))
    assert response.status_code == 200, response.text
    assert response.json()["did_aw"] is None
    assert response.json()["did_aw_registry_verified"] is False
    assert did_lookups(registry) == []


def did_lookup_fault(kind: str):
    def fault(request: httpx.Request, response: httpx.Response) -> None:
        if not request.url.path.startswith("/v1/did/"):
            return
        if kind == "transport":
            raise httpx.ConnectError("injected registry outage", request=request)
        if kind == "http":
            response.status_code = 503
        elif kind == "json":
            response._content = b"{"
        elif kind == "other_did":
            response._content = response.content.replace(b'"did_aw":"did:aw:', b'"did_aw":"did:aw:x')
        elif kind == "bad_key":
            response._content = response.content.replace(b'"current_did_key":"did:key:', b'"current_did_key":"did:key:x')
    return fault


@pytest.mark.parametrize("kind", ["transport", "http", "json", "other_did", "bad_key"])
async def test_an_unavailable_registry_fails_closed_with_503(registry, global_member, kind, caplog):
    registry.transport.fault = did_lookup_fault(kind)
    async with relying_app(registry, public_origin=ORIGIN) as (client, cache):
        response = await client.get("/v1/items", headers=get_items(global_member))
    assert response.status_code == 503, response.text
    assert not cache._did_keys
    assert "AWID did:aw resolution failed" in caplog.text


async def test_an_expired_resolution_is_never_reused_when_the_registry_fails(registry, global_member, caplog):
    async with relying_app(registry, public_origin=ORIGIN) as (client, cache):
        assert (await client.get("/v1/items", headers=get_items(global_member))).status_code == 200
        [key] = cache._did_keys
        expired = replace(cache._did_keys[key], expires_at=-1)
        cache._did_keys[key] = expired
        registry.transport.fault = did_lookup_fault("http")
        assert (await client.get("/v1/items", headers=get_items(global_member))).status_code == 503
    assert cache._did_keys[key] is expired
    assert "AWID did:aw resolution failed" in caplog.text


async def test_a_resolution_is_keyed_by_registry_origin_and_did_and_reused_for_at_most_a_minute(registry, global_member):
    cache = AWIDTeamCache(registry_url=REGISTRY_URL + "/", ttl_seconds=600, transport=registry.transport)
    async with relying_app(registry, public_origin=ORIGIN, cache=cache) as (client, _):
        assert (await client.get("/v1/items", headers=get_items(global_member))).status_code == 200
        assert (await client.get("/v1/items", headers=get_items(global_member))).status_code == 200
    did_aw = global_member.extra_cert_fields["member_did_aw"]
    assert list(cache._did_keys) == [(canonical_server_origin(REGISTRY_URL), did_aw)]
    assert 0 < cache._did_keys[(canonical_server_origin(REGISTRY_URL), did_aw)].expires_at - time.monotonic() <= 60
    assert len(did_lookups(registry)) == 1


async def test_a_rotation_is_seen_once_the_cached_resolution_expires(registry, team_key):
    old, new = SigningKey.generate(), SigningKey.generate()
    did_aw = await registry.register_did(old)
    old_member = await certified(registry, member_key=old, did_aw=did_aw, team_key=team_key)
    async with relying_app(registry, public_origin=ORIGIN) as (client, cache):
        assert (await client.get("/v1/items", headers=get_items(old_member))).status_code == 200
        await registry.rotate_did(did_aw, old, new)
        [key] = cache._did_keys
        cache._did_keys[key] = replace(cache._did_keys[key], expires_at=-1)
        assert (await client.get("/v1/items", headers=get_items(old_member))).status_code == 401


# --- Observe: measure without refusing ---------------------------------------------


def outcomes(caplog) -> list[tuple[str, str]]:
    return [(r.did_aw_outcome, r.did_aw) for r in caplog.records if hasattr(r, "did_aw_outcome")]


async def test_observe_marks_a_match_verified(registry, global_member, caplog):
    async with relying_app(registry, public_origin=ORIGIN, did_aw_profile=DidAwProfile.OBSERVE) as (client, _):
        response = await client.get("/v1/items", headers=get_items(global_member))
    assert response.status_code == 200, response.text
    assert response.json()["did_aw_registry_verified"] is True
    assert outcomes(caplog) == [("match", global_member.extra_cert_fields["member_did_aw"])]


async def test_observe_admits_a_rotated_out_key_unverified_and_records_the_outcome(registry, team_key, caplog):
    old, new = SigningKey.generate(), SigningKey.generate()
    did_aw = await registry.register_did(old)
    old_member = await certified(registry, member_key=old, did_aw=did_aw, team_key=team_key)
    await registry.rotate_did(did_aw, old, new)
    async with relying_app(registry, public_origin=ORIGIN, did_aw_profile=DidAwProfile.OBSERVE) as (client, _):
        response = await client.get("/v1/items", headers=get_items(old_member))
    assert response.status_code == 200, response.text
    assert response.json()["did_aw"] == did_aw
    assert response.json()["did_aw_registry_verified"] is False
    assert outcomes(caplog) == [("key_mismatch", did_aw)]


async def test_observe_admits_an_unregistered_did_unverified(registry, team_key, caplog):
    member = await certified(registry, member_key=SigningKey.generate(), did_aw=UNREGISTERED_DID_AW, team_key=team_key)
    async with relying_app(registry, public_origin=ORIGIN, did_aw_profile=DidAwProfile.OBSERVE) as (client, _):
        response = await client.get("/v1/items", headers=get_items(member))
    assert response.status_code == 200, response.text
    assert response.json()["did_aw_registry_verified"] is False
    assert outcomes(caplog) == [("unregistered", UNREGISTERED_DID_AW)]


async def test_observe_admits_unverified_when_the_registry_is_unavailable(registry, global_member, caplog):
    registry.transport.fault = did_lookup_fault("http")
    async with relying_app(registry, public_origin=ORIGIN, did_aw_profile=DidAwProfile.OBSERVE) as (client, _):
        response = await client.get("/v1/items", headers=get_items(global_member))
    assert response.status_code == 200, response.text
    assert response.json()["did_aw_registry_verified"] is False
    assert outcomes(caplog) == [("unavailable", global_member.extra_cert_fields["member_did_aw"])]
    assert "AWID did:aw resolution failed" in caplog.text


async def test_observe_never_looks_up_a_did_key_only_member(registry, team_key, caplog):
    member = await certified(registry, member_key=SigningKey.generate(), did_aw=None, team_key=team_key)
    async with relying_app(registry, public_origin=ORIGIN, did_aw_profile=DidAwProfile.OBSERVE) as (client, _):
        response = await client.get("/v1/items", headers=get_items(member))
    assert response.status_code == 200, response.text
    assert did_lookups(registry) == []
    assert outcomes(caplog) == []
