"""A team key Library admitted is not replaced by an unsigned registry answer.

Library's own app on real PostgreSQL reads a real AWID over HTTP. The registry
operator is modelled by writing the registry's own tables, the power the threat
gives it; rotation goes through the real route, signed by the namespace's
controller. DNS is the one answer the test supplies.

The team's published server is one Library may not reach, so an authenticated
member is answered 403 team_server_not_allowed, and nothing past
authentication has to run. A member who does not authenticate is answered 401.
"""

from __future__ import annotations

import asyncio
import socket
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import dns.asyncresolver
import httpx
import pytest
import uvicorn
from aweb_naapp_testing import Member
from aweb_naapp_testing.network import DnsServer
from awid_service.testing import Registry, dns_naming, running_registry
from nacl.signing import SigningKey
from pgdbm import AsyncDatabaseManager

from library.api import create_app
from library.config import Settings

pytest_plugins = ("pgdbm.fixtures.conftest",)
DOMAIN = "library-pins.test"
TEAM_ID = f"backend:{DOMAIN}"
ORIGIN = "https://library.example.com"
TEAM_SERVER = "http://127.0.0.1:9/team"


@dataclass
class World:
    registry: Registry
    namespace_key: SigningKey
    client: httpx.AsyncClient
    db: AsyncDatabaseManager


@asynccontextmanager
async def _serving(registry: Registry) -> AsyncIterator[str]:
    """``registry`` over HTTP on this host; yields its origin."""
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        server = uvicorn.Server(
            uvicorn.Config(registry.app, lifespan="off", log_level="error", ws="none")
        )
        serving = asyncio.create_task(server.serve(sockets=[listener]))
        try:
            async with asyncio.timeout(5):
                while not server.started:
                    if serving.done():
                        await serving
                    await asyncio.sleep(0.01)
            yield f"http://127.0.0.1:{listener.getsockname()[1]}"
        finally:
            server.should_exit = True
            await serving


@pytest.fixture
async def system_dns(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[None]:
    """The process's DNS holds no records: no domain publishes an _awid statement."""
    server = DnsServer()
    await server.start()
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = ["127.0.0.1"]
    resolver.port = server.port
    resolver.timeout = resolver.lifetime = 1
    monkeypatch.setattr(dns.asyncresolver, "default_resolver", resolver)
    try:
        yield
    finally:
        server.close()


@pytest.fixture
async def world(
    test_db_factory, system_dns: None, monkeypatch: pytest.MonkeyPatch
) -> AsyncIterator[World]:
    monkeypatch.setenv("AWEB_ENFORCE_TEAM_KEY_PINS", "true")
    namespace_key = SigningKey.generate()
    registry_db = await test_db_factory.create_db(suffix="library_pins_awid")
    library_db = await test_db_factory.create_db(suffix="library_pins")
    async with (
        running_registry(registry_db.config.get_dsn()) as registry,
        _serving(registry) as registry_origin,
    ):
        app = create_app(
            Settings(
                _env_file=None,
                database_url=library_db.config.get_dsn(),
                db_schema=library_db.config.schema_name,
                awid_registry_url=registry_origin,
                public_origin=ORIGIN,
            ),
            awid_txt_resolver=dns_naming(DOMAIN, namespace_key),
        )
        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN) as client,
        ):
            yield World(registry, namespace_key, client, library_db)


async def _publish_server(world: World, team_key: SigningKey, *, issued_at: datetime) -> None:
    with pytest.MonkeyPatch.context() as environment:
        # AWID stores a plain-http loopback server only as a development
        # registry that allows insecure origins.
        environment.setenv("APP_ENV", "development")
        environment.setenv("AWID_ALLOW_INSECURE_DELIVERY_ORIGIN", "1")
        await world.registry.publish_team_server(
            TEAM_ID, team_key, server_url=TEAM_SERVER, issued_at=issued_at
        )


async def _shelf(world: World, member: Member) -> httpx.Response:
    return await world.client.get(
        "/v1/shelf", headers=member.headers(aud=ORIGIN, method="GET", path="/v1/shelf")
    )


def _assert_authenticated(response: httpx.Response) -> None:
    assert response.status_code == 403, response.text
    assert response.json()["detail"]["code"] == "team_server_not_allowed"


async def _admitted(world: World) -> Member:
    member = Member(team_id=TEAM_ID)
    await world.registry.add_team(
        TEAM_ID, member.team_did_key, namespace_controller=world.namespace_key
    )
    await world.registry.add_certificate(member.certificate(), team_key=member.team_key)
    await _publish_server(
        world, member.team_key, issued_at=datetime.now(UTC) - timedelta(minutes=1)
    )
    _assert_authenticated(await _shelf(world, member))
    assert await _pinned_key(world) == member.team_did_key
    return member


async def _pinned_key(world: World) -> str | None:
    return await world.db.fetch_value(
        "SELECT team_did_key FROM {{tables.team_key_pins}} WHERE team_id = $1", TEAM_ID
    )


async def test_a_substituted_registry_team_key_does_not_admit_a_forged_member(
    world: World,
) -> None:
    member = await _admitted(world)
    forger = Member(team_id=TEAM_ID, alias="mallory", certificate_id="forged-mallory")
    await world.registry.rotate_team_key(TEAM_ID, forger.team_did_key)
    await world.registry.add_certificate(forger.certificate(), team_key=forger.team_key)

    forged = await _shelf(world, forger)

    assert forged.status_code == 401, forged.text
    assert forged.json()["detail"].startswith("team_key_unverified")
    assert await _pinned_key(world) == member.team_did_key


async def test_a_rotation_signed_by_the_dns_controller_moves_the_pin(world: World) -> None:
    await _admitted(world)
    rotated = Member(team_id=TEAM_ID, alias="dave", certificate_id="rotated-dave")
    # A controller act carries whole seconds and must be newer than the pin.
    await asyncio.sleep(1)
    await world.registry.rotate_team_key_by_controller(
        TEAM_ID, rotated.team_did_key, world.namespace_key
    )
    await world.registry.add_certificate(rotated.certificate(), team_key=rotated.team_key)
    await _publish_server(world, rotated.team_key, issued_at=datetime.now(UTC))

    _assert_authenticated(await _shelf(world, rotated))

    assert await _pinned_key(world) == rotated.team_did_key
