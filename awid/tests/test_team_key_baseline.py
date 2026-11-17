"""Admission enrichment cannot affect an already admitted key.

AWID, PostgreSQL and UDP DNS are real. HTTP faults below alter only an actual
handler's completed response, modelling a refusing/broken registry front end.
No authority answer is fabricated as a successful proof.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from fastapi import FastAPI
import httpx
import pytest

from awid.registry import RegistryClient, RegistryError
from awid.team_key_acts import (
    MemoryTeamKeyPins,
    TeamKeyMemo,
    TeamKeyPin,
    pinned_team_key,
)
import team_key_delegation_support as support

world = support.world
controller_keypair = support.controller_keypair


class ObservedRegistry(httpx.AsyncBaseTransport):
    def __init__(self, app, fault=None):
        self.inner = httpx.ASGITransport(app)
        self.calls = []
        self.attempts = []
        self.fault = fault
        self.release = asyncio.Event()

    async def handle_async_request(self, request):
        self.attempts.append(request.url.path)
        response = await self.inner.handle_async_request(request)
        await response.aread()
        if request.url.path.endswith("/key-act"):
            if self.fault in (403, 404):
                response.status_code = self.fault
                response._content = b'{"detail":"a different front-end refusal"}'
                response.headers["content-length"] = str(len(response.content))
            elif self.fault == "stall":
                await self.release.wait()
        self.calls.append((request.url.path, response.status_code))
        return response

    async def aclose(self):
        self.release.set()
        await self.inner.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", [403, 404, "evidence", "stall"])
@pytest.mark.parametrize("measuring_move", [False, True])
async def test_unchanged_request_does_not_read_or_wait_for_enrichment(
    world, fault, measuring_move
):
    transport = ObservedRegistry(world.app, fault)
    origin = world.sdk.registry_url
    sdk = RegistryClient(origin, transport=transport)
    team_id = "base:" + world.domain
    pins = MemoryTeamKeyPins()
    original = await pins.first_sight(team_id, world.team[1])
    if measuring_move:
        moved = TeamKeyPin(
            world.team[1], datetime(2020, 1, 1, tzinfo=timezone.utc), world.parent[1]
        )
        assert await pins.move(team_id, expected=original, new=moved)
    initial = await pins.pin(team_id)

    async def evidence(domain):
        # This real status read deliberately propagates its RegistryError,
        # unlike the normal cached producer which returns unavailable evidence.
        await sdk.fetch_id_certificate_status(
            domain, {"v": 1, "domain": domain, "ids": []}, registry_origin=origin
        )
        return await sdk.namespace_evidence(domain)

    try:
        # Establish the fault against the actual service before asserting that
        # an admitted-key request never touches that faulting path.
        if fault == "evidence":
            await world.db.execute(
                "UPDATE {{tables.dns_namespaces}} SET parent_domain=NULL, parent_controller_key=NULL WHERE domain=$1",
                world.domain,
            )
            with pytest.raises(RegistryError) as refused:
                await evidence(world.domain)
            assert refused.value.status_code == 503
        elif fault == "stall":
            with pytest.raises(TimeoutError):
                await asyncio.wait_for(sdk.get_team_key_act(world.domain, "base"), 0.05)
        else:
            async with httpx.AsyncClient(transport=transport, base_url=origin) as probe:
                response = await probe.get(
                    f"/v1/namespaces/{world.domain}/teams/base/key-act"
                )
                assert response.status_code == fault
                assert response.json() == {"detail": "a different front-end refusal"}

        transport.calls.clear()
        transport.attempts.clear()
        world.dns.queries = 0
        app = FastAPI()

        @app.get("/key")
        async def key():
            return {
                "key": await pinned_team_key(
                    team_id,
                    world.team[1],
                    pins=pins,
                    fetch_act=lambda: sdk.get_team_key_act(world.domain, "base"),
                    resolver=world.resolver,
                    enforce=True,
                    memo=TeamKeyMemo(),
                    fetch_namespace_evidence=evidence,
                )
            }

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app, raise_app_exceptions=False),
            base_url="https://relying.example",
        ) as client:
            # A stalled front end remains blocked until finally below. Returning
            # successfully before release proves it did not delay this request.
            response = await asyncio.wait_for(client.get("/key"), 2)
        assert response.status_code == 200, response.text
        assert response.json() == {"key": world.team[1]}
        assert transport.calls == []
        assert transport.attempts == []
        assert world.dns.queries == 0
        assert await pins.pin(team_id) == initial
    finally:
        transport.release.set()
        await sdk.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", [403, 404, "evidence", "stall"])
async def test_first_admission_failure_is_optional_and_never_polled_again(world, fault):
    transport = ObservedRegistry(world.app, fault)
    sdk = RegistryClient(world.sdk.registry_url, transport=transport)
    pins = MemoryTeamKeyPins()
    team_id = "base:" + world.domain

    async def evidence(domain):
        await sdk.fetch_id_certificate_status(
            domain,
            {"v": 1, "domain": domain, "ids": []},
            registry_origin=sdk.registry_url,
        )
        return await sdk.namespace_evidence(domain)

    if fault == "evidence":
        await world.db.execute(
            "UPDATE {{tables.dns_namespaces}} SET parent_domain=NULL,parent_controller_key=NULL WHERE domain=$1",
            world.domain,
        )
    try:

        async def read():
            return await pinned_team_key(
                team_id,
                world.team[1],
                pins=pins,
                fetch_act=lambda: sdk.get_team_key_act(world.domain, "base"),
                resolver=world.resolver,
                enforce=True,
                fetch_namespace_evidence=evidence,
                memo=TeamKeyMemo(),
            )

        # The only optional attempt is bounded even when the real handler's
        # response is held. Later requests use new memos, like process restarts,
        # but the admitted pin remembers the missing/failed baseline.
        assert await asyncio.wait_for(read(), 3) == world.team[1]
        assert transport.attempts
        attempts = list(transport.attempts)
        assert (await pins.pin(team_id)).act_at is None
        for _ in range(3):
            assert await asyncio.wait_for(read(), 2) == world.team[1]
        assert transport.attempts == attempts
    finally:
        transport.release.set()
        await sdk.aclose()
