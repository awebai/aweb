"""Fresh controller evidence from the real AWID team endpoint."""

import os

import httpx
import pytest
from redis.asyncio import Redis

from awid.did import did_from_public_key, generate_keypair
from awid.registry import MalformedTeamKeyError, RegistryClient
from awid_service.testing import REGISTRY_URL, running_registry


@pytest.mark.asyncio
@pytest.mark.parametrize("registry_origin", [None, REGISTRY_URL])
@pytest.mark.parametrize("bad_key", ["", "did:key:unusable"], ids=["empty", "invalid"])
async def test_fresh_team_key_distinguishes_unusable_controller_from_absent_team(
    test_db_factory, registry_origin, bad_key
):
    database = await test_db_factory.create_db(suffix="fresh_team_key")
    domain = "fresh-key.example"
    _, public_key = generate_keypair()
    did = did_from_public_key(public_key)

    async with (
        Redis.from_url(os.environ["REDIS_URL"]) as redis,
        running_registry(database.config.get_dsn(), redis=redis) as registry,
    ):
        await registry.add_team(f"valid:{domain}", did)

        def unusable_answer(request, response):
            assert request.url.path == f"/v1/namespaces/{domain}/teams/valid"
            assert response.status_code == 200
            body = response.json()
            assert body["team_did_key"] == did
            body["team_did_key"] = bad_key
            return httpx.Response(200, json=body)

        client = RegistryClient(REGISTRY_URL, transport=registry.transport)
        try:
            assert await client.get_team_public_key_fresh(
                domain, "valid", registry_origin=registry_origin
            ) == did
            assert await client.get_team_public_key_fresh(
                domain, "absent", registry_origin=registry_origin
            ) is None
            registry.transport.fault = unusable_answer
            with pytest.raises(MalformedTeamKeyError, match="usable controller key"):
                await client.get_team_public_key_fresh(
                    domain, "valid", registry_origin=registry_origin
                )
        finally:
            await client.aclose()
