"""Cold remote work is coalesced and negative evidence never authorizes."""

import asyncio

import httpx
import pytest
from fastapi import HTTPException

from aweb_naapp.runtime.team_auth import AWIDTeamCache


async def test_unknown_team_requests_share_a_bounded_negative_answer():
    requests = []

    async def missing(request):
        requests.append(request)
        await asyncio.sleep(0)
        return httpx.Response(404, json={"detail": "Team not found"})

    cache = AWIDTeamCache(registry_url="https://registry.example", ttl_seconds=60,
                          service_token="test", transport=httpx.MockTransport(missing))
    answers = await asyncio.gather(*(cache.get("missing:example.com", "unknown") for _ in range(16)),
                                   return_exceptions=True)
    assert all(isinstance(answer, HTTPException) and answer.status_code == 401 for answer in answers)
    assert len(requests) == 1
    for n in range(260):
        with pytest.raises(HTTPException):
            await cache.get(f"missing{n}:example.com", "unknown")
    assert len(cache._unknown_teams) <= 256


async def test_anonymous_unknown_certificate_reads_coalesce_and_cool_down():
    requests = []

    async def missing(request):
        requests.append(request)
        await asyncio.sleep(0)
        return httpx.Response(404, json={"detail": "unknown certificate"})

    cache = AWIDTeamCache(registry_url="https://registry.example", ttl_seconds=60,
                          transport=httpx.MockTransport(missing))
    answers = await asyncio.gather(*(cache.get("public:example.com", "unknown") for _ in range(16)),
                                   return_exceptions=True)
    assert all(isinstance(answer, HTTPException) and answer.status_code == 401 for answer in answers)
    assert len(requests) == 1
    with pytest.raises(HTTPException):
        await cache.get("public:example.com", "unknown")
    assert len(requests) == 1


@pytest.mark.parametrize("service_token", [None, "test"])
async def test_distinct_cold_inputs_bound_actual_remote_producers(service_token):
    active, maximum = 0, 0
    started = asyncio.Event()

    async def missing(request):
        nonlocal active, maximum
        active += 1
        maximum = max(maximum, active)
        if active == 16:
            started.set()
        await started.wait()
        await asyncio.sleep(0)
        active -= 1
        return httpx.Response(404, json={"detail": "Team not found"})

    cache = AWIDTeamCache(registry_url="https://registry.example", ttl_seconds=60,
                          service_token=service_token, transport=httpx.MockTransport(missing))
    async with asyncio.timeout(5):
        answers = await asyncio.gather(*(cache.get(f"missing{n}:example.com", "unknown") for n in range(100)),
                                       return_exceptions=True)
    assert all(isinstance(answer, HTTPException) and answer.status_code == 401 for answer in answers)
    assert maximum == 16
    assert active == 0
