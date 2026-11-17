"""Real registry/Redis quotas remain enforced for separate transport peers."""

import asyncio

import httpx
import pytest
from awid.did import did_from_public_key, generate_keypair
from awid.registry import RegistryClient, RegistryError
from test_native_holder import signature


async def register(client):
    seed, public = generate_keypair()
    key = did_from_public_key(public)
    return await client.register_did_with_signer(
        key, signer=lambda payload: (key, signature(seed, payload))
    )


async def exhaust(client):
    # At most two real hourly windows can occur inside the enclosing 15s.
    # Twenty-one requests therefore encounter the unchanged 10/hour limit.
    for _ in range(21):
        try:
            await register(client)
        except RegistryError as error:
            assert error.status_code == 429
            return
    pytest.fail("DID registration limit was not enforced")


@pytest.mark.asyncio
async def test_independent_holder_peer_keeps_real_quota_without_resetting_loopback(
    native_holder,
):
    app, registry = native_holder.app, native_holder.registry
    async with asyncio.timeout(15):
        async with RegistryClient(
            "http://registry.test", transport=httpx.ASGITransport(app=app)
        ) as loopback:
            await exhaust(loopback)
            # Both independent registry fixtures and real TCP clients formerly
            # used this one peer, so the first call below reproduced their 429.
            keys = [
                key
                async for key in app.state.redis.scan_iter(
                    match="aweb:rl:did_register:127.0.0.1:*"
                )
            ]
            old_counts = {key: await app.state.redis.get(key) for key in keys}
            assert old_counts
            await register(registry)
            await exhaust(registry)
            assert {key: await app.state.redis.get(key) for key in keys} == old_counts
