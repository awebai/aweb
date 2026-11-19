"""Unit cache admission tests; transport/Redis stand-ins grant no member authority."""

import asyncio
from contextlib import AsyncExitStack, aclosing

import httpx
import pytest

from awid.registry import CachedRegistryClient, RegistryError
from test_registry_client import FakeRedis


@pytest.mark.asyncio
async def test_distinct_verified_certificates_have_independent_miss_budgets():
    redis = FakeRedis()
    reads = []

    def registry_reply(request):
        reads.append(request.url.path)
        return httpx.Response(200, json={"certificates": [], "has_more": False})

    async with AsyncExitStack() as stack:
        clients = [
            await stack.enter_async_context(
                aclosing(
                    CachedRegistryClient(
                        registry_url="http://registry.test",
                        redis_client=redis,
                        transport=httpx.MockTransport(registry_reply),
                    )
                )
            )
            for _ in range(2)
        ]
        for certificate_id in ("alice", "bob", "carol"):
            assert (
                await clients[0].refresh_team_certificates_after_miss(
                    "example.test", "team", certificate_id=certificate_id
                )
                == []
            )
        assert len(reads) == 3
        for client in clients:
            with pytest.raises(RegistryError) as refused:
                await client.refresh_team_certificates_after_miss(
                    "example.test", "team", certificate_id="alice"
                )
            assert refused.value.status_code == 503
        assert len(reads) == 3


@pytest.mark.asyncio
async def test_same_verified_certificate_coalesces_waiters_and_preserves_cancellation():
    entered, release = asyncio.Event(), asyncio.Event()
    reads = []

    async def registry_reply(request):
        reads.append(request.url.path)
        entered.set()
        await release.wait()
        return httpx.Response(200, json={"certificates": [], "has_more": False})

    async with aclosing(
        CachedRegistryClient(
            registry_url="http://registry.test",
            redis_client=FakeRedis(),
            transport=httpx.MockTransport(registry_reply),
        )
    ) as client:
        first = asyncio.create_task(
            client.refresh_team_certificates_after_miss(
                "example.test", "team", certificate_id="alice"
            )
        )
        await asyncio.wait_for(entered.wait(), 1)
        second = asyncio.create_task(
            client.refresh_team_certificates_after_miss(
                "example.test", "team", certificate_id="alice"
            )
        )
        # Let the second waiter attach before cancelling the first waiter.
        await asyncio.sleep(0)
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        release.set()
        assert await asyncio.wait_for(second, 1) == []
        assert len(reads) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("registered_before_refresh", [True, False])
async def test_different_verified_members_share_positive_refresh_but_recheck_a_later_registration(
    registered_before_refresh,
):
    entered, release = asyncio.Event(), asyncio.Event()
    registered = ["alice", "bob"] if registered_before_refresh else ["alice"]
    reads = []

    async def registry_reply(request):
        snapshot = list(registered)
        reads.append(snapshot)
        if len(reads) == 1:
            entered.set()
            await release.wait()
        return httpx.Response(
            200,
            json={
                "certificates": [
                    {
                        "certificate_id": cert_id,
                        "member_did_key": "unit-member",
                        "alias": cert_id,
                        "identity_scope": "local",
                        "issued_at": "2026-01-01T00:00:00Z",
                    }
                    for cert_id in snapshot
                ],
                "has_more": False,
            },
        )

    async with aclosing(
        CachedRegistryClient(
            registry_url="http://registry.test",
            redis_client=FakeRedis(),
            transport=httpx.MockTransport(registry_reply),
        )
    ) as client:
        alice = asyncio.create_task(
            client.refresh_team_certificates_after_miss(
                "example.test", "team", certificate_id="alice"
            )
        )
        await asyncio.wait_for(entered.wait(), 1)
        if not registered_before_refresh:
            registered.append("bob")
        bob = asyncio.create_task(
            client.refresh_team_certificates_after_miss(
                "example.test", "team", certificate_id="bob"
            )
        )
        await asyncio.sleep(0)
        release.set()
        alice_result, bob_result = await asyncio.wait_for(asyncio.gather(alice, bob), 1)
        assert "alice" in {cert.certificate_id for cert in alice_result}
        assert "bob" in {cert.certificate_id for cert in bob_result}
        assert len(reads) == (1 if registered_before_refresh else 2)
