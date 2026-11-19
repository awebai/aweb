"""A team's coordination server for naapp tests (the ``server`` extra).

AWID (``awid_service.testing``) and the aweb server (``aweb.testing``) run
in-process on their own test databases and the Redis at ``REDIS_URL``. A naapp
finds the server as it does in production, through the team's AWID
``aweb.team-server/1`` record, and reaches each service through its recording
transport.

Load it as a pytest plugin next to pgdbm's fixtures::

    pytest_plugins = ("pgdbm.fixtures.conftest", "aweb_naapp_testing.server")

The ``coordination`` fixture sets the server's environment with
``monkeypatch``, as the server reads its configuration from there. AWID and
the server share one DNS: the server's `_awid` lookups answer what AWID's own
domain verifier answers, so a namespace a test registers (``registered_human``)
is visible to both, and nothing reaches real DNS.

The server reads the AWID ``coordination_registry`` gives: this repository's,
in-process. A test module overrides that fixture to run against another AWID,
for example the release production runs (``production_registry``).

``listening_coordination`` composes the same two services as a deployment
does instead: each serves real HTTP on a local socket, the naapp names AWID by
its ``awid_registry_url`` setting, and every `_awid` lookup in the process asks
a real local DNS server (:func:`aweb_naapp_testing.network.process_dns`) that
publishes each registered team's namespace record. No transport is handed to
the naapp and no private state is set on it.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass
from typing import Any

import httpx
import pytest_asyncio
import uvicorn
from aweb.testing import Server, running_server
from awid.dns_verify import DnsVerificationError, DomainAuthority, awid_txt_value
from awid_service.deps import get_domain_verifier
from awid_service.testing import REGISTRY_URL, SERVICE_TOKEN, Registry, running_registry
from redis.asyncio import Redis

from aweb_naapp.runtime.team_auth import AWIDTeamCache
from aweb_naapp.runtime.team_server import TeamServerDirectory
from aweb_naapp_testing import Member
from aweb_naapp_testing.network import DnsServer, process_dns


@dataclass
class Coordination:
    """AWID and a coordination server, the teams' server once each publishes it.

    ``server_database_url`` is the server's own database, for the operator
    commands a server's operator runs against it."""

    registry: Registry
    server: Server
    server_database_url: str

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
        if response.is_error:
            # The server's refusal detail, which raise_for_status() drops.
            raise httpx.HTTPStatusError(
                f"/v1/connect answered {response.status_code}: {response.text}",
                request=response.request,
                response=response,
            )
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


def awid_dns(registry: Registry):
    """The `_awid` lookup ``registry`` itself uses: its test override, or no
    record at all (tests never reach real DNS)."""

    async def verify(domain: str) -> DomainAuthority:
        override = registry.app.dependency_overrides.get(get_domain_verifier)
        if override is None:
            raise DnsVerificationError(f"No TXT records found for _awid.{domain}")
        return await override()(domain)

    return verify


@pytest_asyncio.fixture
async def coordination_registry(test_db_factory) -> AsyncIterator[Registry]:
    awid_db = await test_db_factory.create_db(suffix="coordination_awid")
    async with Redis.from_url(
        os.environ.get("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True
    ) as redis:
        async with running_registry(awid_db.config.get_dsn(), redis=redis) as registry:
            yield registry


@pytest_asyncio.fixture
async def coordination(
    test_db_factory, monkeypatch, coordination_registry
) -> AsyncIterator[Coordination]:
    monkeypatch.setenv("AWEB_DATABASE_URL", "postgresql://unused/aweb")
    monkeypatch.setenv("AWID_SERVICE_TOKEN", SERVICE_TOKEN)
    monkeypatch.setenv("AWID_REGISTRY_URL", REGISTRY_URL)
    server_db = await test_db_factory.create_db(suffix="coordination_aweb")
    async with Redis.from_url(
        os.environ.get("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True
    ) as redis:
        async with running_server(
            server_db.config.get_dsn(),
            redis,
            awid_transport=coordination_registry.transport,
            domain_verifier=awid_dns(coordination_registry),
        ) as server:
            yield Coordination(
                registry=coordination_registry,
                server=server,
                server_database_url=server_db.config.get_dsn(),
            )


class Listener:
    """A local socket, bound now so its origin is known before the app it will
    serve exists (a service names its own public origin at construction)."""

    def __init__(self, host: str = "127.0.0.1", *, name: str | None = None) -> None:
        self._socket = socket.socket()
        self._socket.bind((host, 0))
        self.origin = f"http://{name or host}:{self._socket.getsockname()[1]}"

    @asynccontextmanager
    async def serving(self, app: Any) -> AsyncIterator[str]:
        """Serves ``app`` over real HTTP on this socket; yields its origin."""
        server = uvicorn.Server(uvicorn.Config(app, lifespan="off", log_level="error", ws="none"))
        serving = asyncio.create_task(server.serve(sockets=[self._socket]))
        try:
            for _ in range(250):
                if server.started or serving.done():
                    break
                await asyncio.sleep(0.02)
            if not server.started:
                serving.result() if serving.done() else None
                raise RuntimeError(f"the listener at {self.origin} did not start")
            yield self.origin
        finally:
            server.should_exit = True
            await asyncio.wait_for(serving, 5)
            self._socket.close()


@dataclass
class ListeningCoordination(Coordination):
    """:class:`Coordination` served over real HTTP: AWID at ``registry_url`` and
    the server at ``server.url``, both found through ``dns``."""

    registry_url: str = ""
    dns: DnsServer | None = None

    async def add_member(self, member: Member) -> None:
        """Registers the member as :meth:`Coordination.add_member` does, and
        publishes its team namespace's `_awid` record, naming this AWID."""
        await super().add_member(member)
        assert self.dns is not None
        domain = member.team_id.split(":", 1)[1]
        record = awid_txt_value(member.team_did_key, self.registry_url)
        self.dns.records[(f"_awid.{domain}", "TXT")] = [json.dumps(record)]


@pytest_asyncio.fixture
async def listening_coordination(
    test_db_factory, monkeypatch
) -> AsyncIterator[ListeningCoordination]:
    async with AsyncExitStack() as stack:
        dns = await stack.enter_async_context(process_dns())
        redis = await stack.enter_async_context(
            Redis.from_url(
                os.environ.get("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True
            )
        )
        awid_db = await test_db_factory.create_db(suffix="coordination_awid")
        registry = await stack.enter_async_context(
            running_registry(awid_db.config.get_dsn(), redis=redis)
        )
        registry_listener = Listener()
        # Served there, AWID answers to that origin too.
        registry.app.state.awid_public_origins = (
            *registry.app.state.awid_public_origins,
            registry_listener.origin,
        )
        registry_url = await stack.enter_async_context(registry_listener.serving(registry.app))
        # A test deployment of AWID (as production_registry runs the release):
        # its delivery-origin policy admits a plain-http localhost team server,
        # where production requires https at a public name.
        monkeypatch.setenv("APP_ENV", "test")
        monkeypatch.setenv("AWEB_DATABASE_URL", "postgresql://unused/aweb")
        monkeypatch.setenv("AWID_SERVICE_TOKEN", SERVICE_TOKEN)
        monkeypatch.setenv("AWID_REGISTRY_URL", registry_url)
        server_db = await test_db_factory.create_db(suffix="coordination_aweb")
        server_listener = Listener(name="localhost")
        server = await stack.enter_async_context(
            running_server(
                server_db.config.get_dsn(),
                redis,
                awid_transport=httpx.AsyncHTTPTransport(),
                public_origin=server_listener.origin,
            )
        )
        await stack.enter_async_context(server_listener.serving(server.app))
        yield ListeningCoordination(
            registry=registry,
            server=server,
            server_database_url=server_db.config.get_dsn(),
            registry_url=registry_url,
            dns=dns,
        )
