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
