"""Origin partitions over real sockets and the public resolver constructor seam.

The selected operator transport is actual HTTP to owned loopback peers. Peers
supply cache wire evidence; these cases do not grant registry/member authority.
"""

from __future__ import annotations

import json
from enum import StrEnum

import httpx
import pytest

from awid.did import did_from_public_key, generate_keypair
from awid.registry import CachedRegistryClient, RegistryClient
from test_registry_audience_dns import (
    AuthorityAnswer,
    registry_audience_dns as registry_audience_dns,
)
from test_id_status_client import BUNDLE, DOMAIN, SUBJECT, ClockedRedis
from test_registry_client import FakeRedis
from test_registry_evidence_boundaries import peer_factory as peer_factory


class TeamRead(StrEnum):
    METADATA = "metadata"
    KEY = "key"
    REVOCATIONS = "revocations"
    CERTIFICATES = "certificates"
    NAMESPACE = "namespace"
    ADDRESS = "address"
    ADDRESSES = "addresses"


async def team_read(client: CachedRegistryClient, family: TeamRead):
    if family is TeamRead.NAMESPACE:
        return (await client.get_namespace("example.com")).controller_did
    if family is TeamRead.ADDRESS:
        return (await client.resolve_address("example.com", "member")).did_aw
    if family is TeamRead.ADDRESSES:
        return [item.did_aw for item in await client.list_addresses("example.com")]
    if family is TeamRead.METADATA:
        return (await client.get_team("example.com", "engineering")).team_did_key
    if family is TeamRead.KEY:
        return await client.get_team_public_key("example.com", "engineering")
    if family is TeamRead.REVOCATIONS:
        return await client.get_team_revocations("example.com", "engineering")
    return [
        item.certificate_id
        for item in await client.list_team_certificates("example.com", "engineering")
    ]


def response_for(family: TeamRead, *, label: str) -> bytes:
    if family is TeamRead.NAMESPACE:
        value = {
            "namespace_id": "namespace",
            "domain": "example.com",
            "controller_did": label,
            "verification_status": "verified",
            "created_at": "2026-01-01T00:00:00Z",
        }
    elif family in (TeamRead.ADDRESS, TeamRead.ADDRESSES):
        address = {
            "address_id": "address",
            "domain": "example.com",
            "name": "member",
            "did_aw": label,
            "current_did_key": "unit-key",
            "created_at": "2026-01-01T00:00:00Z",
        }
        value = (
            address if family is TeamRead.ADDRESS else {"addresses": [address], "has_more": False}
        )
    elif family in (TeamRead.METADATA, TeamRead.KEY):
        value = {
            "team_id": "engineering:example.com",
            "name": "engineering",
            "domain": "example.com",
            "team_did_key": label,
            "created_at": "2026-01-01T00:00:00Z",
        }
    elif family is TeamRead.REVOCATIONS:
        value = {"revocations": [{"certificate_id": label}], "has_more": False}
    else:
        value = {
            "certificates": [
                {
                    "certificate_id": label,
                    "member_did_key": "unit-member",
                    "alias": "member",
                    "identity_scope": "local",
                    "issued_at": "2026-01-01T00:00:00Z",
                }
            ],
            "has_more": False,
        }
    return json.dumps(value).encode()


@pytest.mark.asyncio
@pytest.mark.parametrize("family", list(TeamRead))
async def test_team_evidence_is_partitioned_by_the_answering_registry(peer_factory, family):
    first, fallback = peer_factory(), peer_factory()
    first.response = response_for(family, label="authority-a")
    fallback.response = response_for(family, label="fallback-b")
    redis = FakeRedis()
    selected = first.origin
    routes = []

    async def resolve(domain):
        routes.append(domain)
        return selected

    client = CachedRegistryClient(
        first.origin,
        redis,
        domain_registry_resolver=resolve,
        transport=httpx.AsyncHTTPTransport(trust_env=False),
    )
    try:
        answer_a = await team_read(client, family)
        a_entries = {key: value for key, value in redis.values.items() if ":registry_cache:" in key}
        selected = fallback.origin
        answer_b = await team_read(client, family)
        assert answer_b != answer_a
        assert all(redis.values[key] == value for key, value in a_entries.items())
        selected = first.origin
        assert await team_read(client, family) == answer_a
        assert len(first.requests) == len(fallback.requests) == 1
        assert len(routes) == 3  # One pinned selection per read, including a miss.
        assert any(fallback.origin in key for key in redis.values if ":registry_cache:" in key)
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_status_refresh_records_its_origin_and_fresh_hits_do_no_discovery(
    peer_factory,
    registry_audience_dns,
):
    first, fallback = peer_factory(), peer_factory()
    first.response, fallback.response = b'{"registry":"a"}', b'{"registry":"b"}'
    clock, micro = [1_000_000], [0]
    redis = ClockedRedis(clock, micro)
    selected = first.origin
    routes = []

    async def resolve(domain):
        routes.append(domain)
        return selected

    client = CachedRegistryClient(
        first.origin,
        redis,
        transport=httpx.AsyncHTTPTransport(trust_env=False),
        domain_registry_resolver=resolve,
    )
    try:
        assert (await client.id_chain_evidence(BUNDLE, SUBJECT, domain=DOMAIN)).status == {
            "registry": "a"
        }
        a_entries = {key: value for key, value in redis.values.items() if ":registry_cache:" in key}
        selected = fallback.origin
        # A fresh hit retains the recorded origin; no discovery or HTTP work.
        clock[0] += 60
        assert (await client.id_chain_evidence(BUNDLE, SUBJECT, domain=DOMAIN)).status == {
            "registry": "a"
        }
        assert len(routes) == len(registry_audience_dns.queries) == len(first.requests) == 1
        assert fallback.requests == []
        clock[0] += 1
        assert (await client.id_chain_evidence(BUNDLE, SUBJECT, domain=DOMAIN)).status == {
            "registry": "b"
        }
        assert all(redis.values[key] == value for key, value in a_entries.items())
        assert any(fallback.origin in key for key in redis.values if ":registry_cache:" in key)
        assert len(routes) == len(registry_audience_dns.queries) == 2
        assert len(first.requests) == len(fallback.requests) == 1
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_failed_txt_lookup_does_not_overwrite_the_other_registrys_evidence(
    peer_factory,
    registry_audience_dns,
):
    first, fallback = peer_factory(), peer_factory()
    first.response = response_for(TeamRead.REVOCATIONS, label="revoked-on-a")
    fallback.response = response_for(TeamRead.REVOCATIONS, label="revoked-on-b")
    dns_reader = RegistryClient("https://api.awid.ai")
    redis = FakeRedis()

    async def selected_peer(domain):
        # Use actual public TXT discovery/fallback, then the operator test's
        # loopback peers for each selected registry's wire response.
        origin = await dns_reader.registry_audience(domain)
        return first.origin if origin == "https://override.example" else fallback.origin

    client = CachedRegistryClient(
        first.origin,
        redis,
        domain_registry_resolver=selected_peer,
        transport=httpx.AsyncHTTPTransport(trust_env=False),
    )
    try:
        assert await client.get_team_revocations("example.com", "engineering") == {"revoked-on-a"}
        a_entries = dict(redis.values)
        registry_audience_dns.answer = AuthorityAnswer.UNAVAILABLE
        assert await client.get_team_revocations("example.com", "engineering") == {"revoked-on-b"}
        assert all(redis.values[key] == value for key, value in a_entries.items())
        registry_audience_dns.answer = AuthorityAnswer.OVERRIDE
        assert await client.get_team_revocations("example.com", "engineering") == {"revoked-on-a"}
        assert len(first.requests) == len(fallback.requests) == 1
        assert len(registry_audience_dns.queries) == 3
    finally:
        await client.aclose()
        await dns_reader.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("suffix", ["", "/"], ids=["canonical", "trailing-slash"])
async def test_team_metadata_write_invalidates_the_same_canonical_origin(peer_factory, suffix):
    first = peer_factory()
    seed, public = generate_keypair()
    value = json.loads(response_for(TeamRead.METADATA, label=did_from_public_key(public)))
    value["visibility"] = "private"
    first.response = json.dumps(value).encode()
    client = CachedRegistryClient(first.origin + suffix, FakeRedis())
    try:
        assert (await client.get_team("example.com", "engineering")).visibility == "private"
        value["visibility"] = "public"
        first.response = json.dumps(value).encode()
        assert (
            await client.set_team_visibility("example.com", "engineering", "public", seed)
        ).visibility == "public"
        assert (await client.get_team("example.com", "engineering")).visibility == "public"
        assert [request[0] for request in first.requests] == ["GET", "POST", "GET"]
    finally:
        await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("suffix", ["", "/"], ids=["canonical", "trailing-slash"])
async def test_id_write_fences_other_clients_using_the_same_canonical_origin(
    peer_factory,
    registry_audience_dns,
    suffix,
):
    from awid.id_tree_requests import REGISTER_PATH
    from test_id_registry_client import EXAMPLE, _bundle, signer_for

    first = peer_factory()
    first.response = b'{"registry":"before-write"}'
    first.replies[("POST", REGISTER_PATH)] = (200, json.dumps(EXAMPLE["response"]).encode())
    redis = ClockedRedis([1_000_000], [0])
    reader = CachedRegistryClient(first.origin, redis)
    writer = CachedRegistryClient(first.origin + suffix, redis)
    try:
        assert (await reader.id_chain_evidence(BUNDLE, SUBJECT, domain=DOMAIN)).status == {
            "registry": "before-write"
        }
        first.response = b'{"registry":"after-write"}'
        await writer.register_id_certificate(
            _bundle("alice", "bob"),
            signer=signer_for("bob"),
            expected_head=None,
            invitation_id=None,
        )
        assert (await reader.id_chain_evidence(BUNDLE, SUBJECT, domain=DOMAIN)).status == {
            "registry": "after-write"
        }
        assert len(registry_audience_dns.queries) == 2
    finally:
        await reader.aclose()
        await writer.aclose()
