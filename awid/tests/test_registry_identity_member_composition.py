"""Identity evidence and member-authenticated reads share one registry client."""

from __future__ import annotations

import inspect
from uuid import uuid4

import pytest
from awid.test_services import redis_url
from awid.did import stable_id_from_did_key
from awid.registry import CachedRegistryClient, RegistryClient, RegistryError
from redis.asyncio import Redis
from test_team_visibility_enforcement import (
    _create_team,
    _register_member,
    _setup_namespace,
)


@pytest.mark.asyncio
@pytest.mark.parametrize("cached", [False, True], ids=["registry", "cached-registry"])
async def test_identity_evidence_and_private_team_reads_keep_both_inputs(
    client, controller_identity, fake_domain_verifier, cached
):
    # A unique domain isolates both real Redis caches from every other test.
    domain = f"registry-merge-{uuid4().hex}.example"
    name = "readers"
    controller_key, controller_did = controller_identity
    await _setup_namespace(client, controller_key, controller_did, domain)
    team_key, team_did, _ = await _create_team(
        client, controller_key, controller_did, domain, name
    )
    member_key, member_did, _ = await _register_member(
        client, team_key, team_did, domain, name, "registry-reader"
    )
    dns_queries = []

    async def domain_verifier(queried):
        dns_queries.append(queried)
        return await fake_domain_verifier(queried)

    options = {
        "registry_url": "http://testserver",
        "transport": client._transport,
        "domain_verifier": domain_verifier,
        "member_signing_keys": {f"{name}:{domain}": member_key},
    }
    redis = (
        Redis.from_url(redis_url())
        if cached
        else None
    )
    unsigned = RegistryClient("http://testserver", transport=client._transport)
    registry = None
    cleanup_keys = []
    try:
        if cached:
            registry = CachedRegistryClient(redis_client=redis, **options)
        else:
            registry = RegistryClient(**options)
        assert (
            inspect.signature(type(registry)).parameters["domain_verifier"].kind
            is inspect.Parameter.KEYWORD_ONLY
        )
        # A private read succeeds only when this client's configured member
        # key signs the actual request and the real AWID gate accepts it.
        with pytest.raises(RegistryError) as refused:
            await unsigned.get_team(domain, name)
        assert refused.value.status_code == 403
        team = await registry.get_team(domain, name)
        assert team is not None and team.visibility == "private"
        assert team.team_did_key == team_did

        # A global ID without a chain still obtains a current namespace/status
        # snapshot. This does not claim the member has an enrolled identity.
        subject = {"id": stable_id_from_did_key(member_did), "did_key": member_did}
        if cached:
            cleanup_keys.extend(
                [
                    registry._team_metadata_cache_key(domain, name),
                    registry._id_status_cache_key(
                        {"v": 1, "domain": domain, "ids": [subject["id"]]}
                    ),
                ]
            )
        evidence = await registry.id_chain_evidence(None, subject, domain=domain)
        assert dns_queries == [domain]
        assert evidence.age_seconds is not None
        assert evidence.namespace_authority["controller_key"] == controller_did
        assert evidence.status["domain"] == domain
        assert evidence.status["identities"] == []
    finally:
        try:
            if redis is not None and cleanup_keys:
                await redis.delete(*cleanup_keys)
        finally:
            if registry is not None:
                await registry.aclose()
            await unsigned.aclose()
            if redis is not None:
                await redis.aclose()
