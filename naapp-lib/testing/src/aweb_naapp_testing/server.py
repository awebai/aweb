"""A team's coordination server for naapp tests (the ``server`` extra).

AWID (``awid_service.testing``) and the aweb server (``aweb.testing``) run
in-process on their own test databases and the Redis at ``REDIS_URL``. A naapp
finds the server as it does in production, through the team's AWID
``aweb.team-server/1`` record, and reaches each service through its recording
transport.

Load it as a pytest plugin next to pgdbm's fixtures::

    pytest_plugins = ("pgdbm.fixtures.conftest", "aweb_naapp_testing.server")

The ``coordination`` fixture sets the server's environment with
``monkeypatch``, as the server reads its configuration from there.
"""

from __future__ import annotations

import json
import os
from collections.abc import AsyncIterator
from dataclasses import dataclass

import pytest_asyncio
from aweb.testing import Server, running_server
from awid_service.testing import REGISTRY_URL, SERVICE_TOKEN, Registry, running_registry
from redis.asyncio import Redis

from aweb_naapp.runtime.team_auth import AWIDTeamCache
from aweb_naapp.runtime.team_server import TeamServerDirectory
from aweb_naapp_testing import Member


@dataclass
class Coordination:
    """AWID and a coordination server, the teams' server once each publishes it."""

    registry: Registry
    server: Server

    async def add_member(self, member: Member) -> None:
        """Registers the member's team, if new, and its certificate in AWID."""
        name, domain = member.team_id.split(":", 1)
        known = await self.registry.db.fetch_value(
            "SELECT 1 FROM {{tables.teams}} WHERE domain = $1 AND name = $2", domain, name
        )
        if known is None:
            await self.registry.add_team(member.team_id, member.team_did_key)
        await self.registry.add_certificate(member.certificate())

    async def publish_server(self, member: Member) -> None:
        """Publishes the server as the member's team server, signed by the team key."""
        await self.registry.publish_team_server(
            member.team_id, member.team_key, server_url=self.server.url
        )

    async def connect(self, member: Member) -> dict:
        """Connects the member through the server's own ``POST /v1/connect``,
        which provisions its team and agent there; returns the server's answer."""
        body = json.dumps({"hostname": "naapp-test"}).encode()
        headers = member.headers(aud=self.server.url, method="POST", path="/v1/connect", body=body)
        async with self.server.client() as client:
            response = await client.post(
                "/v1/connect", content=body, headers={**headers, "Content-Type": "application/json"}
            )
        response.raise_for_status()
        return response.json()

    def directory(self, *, ttl_seconds: int = 60) -> TeamServerDirectory:
        """Team-server discovery against this AWID, as a naapp runs it."""

        async def no_registry_override(domain: str) -> str | None:
            return None

        team_cache = AWIDTeamCache(
            registry_url=REGISTRY_URL,
            ttl_seconds=60,
            service_token=SERVICE_TOKEN,
            transport=self.registry.transport,
        )
        return TeamServerDirectory(
            team_cache=team_cache,
            transport=self.registry.transport,
            registry_override=no_registry_override,
            ttl_seconds=ttl_seconds,
        )


@pytest_asyncio.fixture
async def coordination(test_db_factory, monkeypatch) -> AsyncIterator[Coordination]:
    monkeypatch.setenv("AWEB_DATABASE_URL", "postgresql://unused/aweb")
    monkeypatch.setenv("AWID_SERVICE_TOKEN", SERVICE_TOKEN)
    monkeypatch.setenv("AWID_REGISTRY_URL", REGISTRY_URL)
    awid_db = await test_db_factory.create_db(suffix="coordination_awid")
    server_db = await test_db_factory.create_db(suffix="coordination_aweb")
    async with Redis.from_url(
        os.environ.get("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True
    ) as redis:
        async with running_registry(awid_db.config.get_dsn(), redis=redis) as registry:
            async with running_server(
                server_db.config.get_dsn(), redis, awid_transport=registry.transport
            ) as server:
                yield Coordination(registry=registry, server=server)
