"""Certificate miss admission coordinates overlapping readers on real Redis."""

import asyncio
import os
from contextlib import aclosing
from uuid import uuid4

import httpx
import pytest
from awid.registry import CachedRegistryClient, TeamCertificateStanding
from redis.asyncio import Redis
from test_team_visibility_enforcement import _register_member


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "next_window", [False, True], ids=["same-window", "next-window"]
)
async def test_inflight_list_started_during_admission_owns_the_refresh(
    controller_app,
    next_window,
):
    env = controller_app
    domain, team = "local", "base"
    _, _, certificate_id = await _register_member(
        env.client, *env.team, domain, team, "overlapping-reader"
    )
    origin = f"http://{uuid4().hex}.registry.test"
    list_path = f"/v1/namespaces/{domain}/teams/{team}/certificates"
    list_entered = asyncio.Event()
    release_list = asyncio.Event()
    second_entered = asyncio.Event()
    second_admitted = asyncio.Event()
    arrivals = 0
    admissions = []
    reads = []

    class ObservedTransport(httpx.ASGITransport):
        async def handle_async_request(self, request):
            path = request.url.path
            reads.append(path)
            if path == list_path:
                list_entered.set()
                await release_list.wait()
            return await super().handle_async_request(request)

    class InterleavedClient(CachedRegistryClient):
        async def _admit_team_certificate_read(self, window_key, *, allow_point):
            nonlocal arrivals
            arrivals += 1
            arrival = arrivals
            if arrival == 1:
                # Both callers must observe an empty in-flight map.
                await second_entered.wait()
            else:
                assert arrival == 2
                second_entered.set()
                await list_entered.wait()
                if next_window:
                    # Expire the first reservation while its list is in flight.
                    assert await redis.delete(window_key) == 1

            result = await super()._admit_team_certificate_read(
                window_key, allow_point=allow_point
            )
            admissions.append(result)
            if arrival == 2:
                second_admitted.set()
            return result

    transport = ObservedTransport(app=env.app, client=env.client._transport.client)
    async with (
        Redis.from_url(os.environ["REDIS_URL"]) as redis,
        aclosing(InterleavedClient(origin, redis, transport=transport)) as sdk,
    ):
        try:
            async with asyncio.timeout(5), asyncio.TaskGroup() as callers:
                pending = [
                    callers.create_task(
                        sdk.refresh_team_certificates_after_miss(
                            domain, team, certificate_id=certificate_id
                        )
                    )
                    for _ in range(2)
                ]
                await second_admitted.wait()
                release_list.set()
            assert admissions == [-1, -1 if next_window else 0]
            assert [call.result() for call in pending] == [
                TeamCertificateStanding.ACTIVE,
                TeamCertificateStanding.ACTIVE,
            ]
            assert reads == [list_path]
        finally:
            release_list.set()
            keys = [key async for key in redis.scan_iter(match=f"*{origin}:*")]
            if keys:
                await redis.delete(*keys)
