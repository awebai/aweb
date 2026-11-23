"""A team's published server address is reached only through the egress rule.

Real AWID on real PostgreSQL stores each team's signed server record through
its own route and validator; the app is a real NaappRuntime. A team that
publishes its server on the app's own loopback, or under an https name that
resolves to a private address, gets a refusal and no connection, unless the
operator listed exactly that origin as one of its own team servers and its
address is inside the operator's network.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from aweb_naapp_testing import REGISTRY_URL, SERVICE_TOKEN, Member
from aweb_naapp_testing.network import DnsServer
from aweb_naapp_testing.team_server_site import team_server_site
from fastapi import Depends, FastAPI
from nacl.signing import SigningKey

from aweb_naapp.egress import DnsResolver
from aweb_naapp.manifest import canonical_bytes
from aweb_naapp.runtime.app import NaappRuntime
from aweb_naapp.runtime.app_credentials import APP_GRANT_READ, HOOK_RESOLVE
from aweb_naapp.runtime.hook_resolver import HookResolutionUnavailable
from aweb_naapp.runtime.operator_egress import OperatorEgress
from tests.runtime.test_naapp_runtime import allow_all
from tests.runtime.test_served_manifest import (
    HOSTED_ORIGIN,
    ExampleSettings,
    _key_file,
    _v2_template,
)

TEAM_ID = "ops:egress.example"
PRIVATE_NAME = "coord.egress.example"
REFUSED = "team_server_not_allowed"


@asynccontextmanager
async def listener(host: str) -> AsyncIterator[tuple[int, list[str]]]:
    """A TCP listener on ``host`` that records every connection and closes it."""
    connections: list[str] = []

    async def accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        connections.append(str(writer.get_extra_info("peername")))
        writer.close()

    server = await asyncio.start_server(accept, host, 0)
    try:
        yield server.sockets[0].getsockname()[1], connections
    finally:
        server.close()
        await server.wait_closed()


def _runtime(
    tmp_path: Path,
    registry,
    *,
    database_url: str = "postgresql://localhost/unused",
    resolver: DnsResolver | None = None,
    **settings,
) -> NaappRuntime:
    keys = (("grants", [APP_GRANT_READ]), ("hooks", [HOOK_RESOLVE]))
    files = {kid: _key_file(tmp_path, kid, bytes(SigningKey.generate()).hex()) for kid, _ in keys}
    manifest = tmp_path / "manifest.json"
    manifest.write_bytes(canonical_bytes(_v2_template(*keys)))
    migrations = tmp_path / "migrations"
    migrations.mkdir(exist_ok=True)
    app_settings = ExampleSettings(
        _env_file=None,
        app_key_files=files,
        awid_registry_url=REGISTRY_URL,
        awid_service_token=SERVICE_TOKEN,
        database_url=database_url,
        **settings,
    )
    runtime = NaappRuntime(
        app_settings,
        module_name="example",
        migrations_path=migrations,
        manifest_path=manifest,
        awid_transport=registry.transport,
        # The guard the production factories build, with this test's DNS.
        egress=OperatorEgress.from_settings(app_settings, resolver=resolver),
    )

    async def no_registry_override(domain: str) -> None:
        return None

    # The team's domain publishes no registry statement in DNS.
    runtime.team_server_directory()._registry_override = no_registry_override
    return runtime


async def _member_of_team_serving_at(registry, server_url: str) -> Member:
    member = Member(team_id=TEAM_ID)
    await registry.add_team(TEAM_ID, member.team_did_key)
    await registry.add_certificate(member.certificate(), team_key=member.team_key)
    with pytest.MonkeyPatch.context() as environment:
        if server_url.startswith("http://"):
            # AWID stores a plain-http loopback server only as a development
            # registry that allows insecure origins, as the e2e stacks run it.
            environment.setenv("APP_ENV", "development")
            environment.setenv("AWID_ALLOW_INSECURE_DELIVERY_ORIGIN", "1")
        await registry.publish_team_server(
            TEAM_ID,
            member.team_key,
            server_url=server_url,
            issued_at=datetime.now(UTC) - timedelta(minutes=1),
        )
    return member


@asynccontextmanager
async def serving(runtime: NaappRuntime) -> AsyncIterator[httpx.AsyncClient]:
    """The app with one guarded tool route, started with the runtime's lifespan."""
    app = FastAPI(lifespan=runtime.lifespan)
    guard = runtime.authorized(grants=runtime.installation_grants(), policy=allow_all)

    @app.post("/v1/things", dependencies=[Depends(guard)])
    async def create():
        return {}

    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=HOSTED_ORIGIN) as client,
    ):
        yield client


async def _member_request(client: httpx.AsyncClient, member: Member) -> httpx.Response:
    return await client.post(
        "/v1/things",
        headers=member.headers(aud=HOSTED_ORIGIN, method="POST", path="/v1/things"),
    )


def _refusal_code(response: httpx.Response) -> str | None:
    detail = response.json().get("detail")
    return detail.get("code") if isinstance(detail, dict) else None


def _assert_actionable_refusal(response: httpx.Response) -> None:
    # Retrying cannot help: the operator lists its own server, or the team's
    # controller publishes a reachable one.
    assert response.status_code == 403
    assert _refusal_code(response) == REFUSED
    message = response.json()["detail"]["message"]
    assert isinstance(message, str) and message


async def _database_url(test_db_factory) -> str:
    database = await test_db_factory.create_db(suffix="team_server_egress")
    return database.config.get_dsn()


async def test_a_loopback_team_server_is_refused_without_a_connection(
    tmp_path, registry, test_db_factory
):
    async with listener("127.0.0.1") as (port, connections):
        member = await _member_of_team_serving_at(registry, f"http://127.0.0.1:{port}/x")
        runtime = _runtime(tmp_path, registry, database_url=await _database_url(test_db_factory))
        async with serving(runtime) as client:
            response = await _member_request(client, member)
            with pytest.raises(HookResolutionUnavailable) as refused:
                await runtime.hook_resolver().core_producer_keys(TEAM_ID)

    assert connections == []
    _assert_actionable_refusal(response)
    assert refused.value.code == REFUSED


@asynccontextmanager
async def loopback_name() -> AsyncIterator[tuple[int, list[str], DnsResolver]]:
    """An https name only this test's DNS answers, with this host's loopback."""
    dns = DnsServer(records={(PRIVATE_NAME, "A"): ["127.0.0.1"]})
    await dns.start()
    try:
        async with listener("127.0.0.1") as (port, connections):
            yield port, connections, DnsResolver(nameservers=["127.0.0.1"], port=dns.port)
    finally:
        dns.close()


async def test_an_https_name_resolving_to_loopback_is_refused_without_a_connection(
    tmp_path, registry, test_db_factory
):
    async with loopback_name() as (port, connections, resolver):
        member = await _member_of_team_serving_at(registry, f"https://{PRIVATE_NAME}:{port}/x")
        runtime = _runtime(
            tmp_path, registry, resolver=resolver, database_url=await _database_url(test_db_factory)
        )
        async with serving(runtime) as client:
            response = await _member_request(client, member)

    assert connections == []
    _assert_actionable_refusal(response)


def _coordination_server() -> FastAPI:
    """A team server that answers every read with 404: reached, and nothing granted."""
    return FastAPI()


async def test_an_unlisted_team_server_on_a_private_address_is_refused_without_a_connection(
    tmp_path, registry, test_db_factory
):
    async with team_server_site(tmp_path, _coordination_server()) as site:
        member = await _member_of_team_serving_at(registry, f"{site.origin}/x")
        runtime = _runtime(
            tmp_path,
            registry,
            resolver=site.resolver(),
            database_url=await _database_url(test_db_factory),
            **site.settings(listed=False),
        )
        async with serving(runtime) as client:
            response = await _member_request(client, member)
            with pytest.raises(HookResolutionUnavailable) as refused:
                await runtime.hook_resolver().core_producer_keys(TEAM_ID)

    assert site.tls.connections == 0
    _assert_actionable_refusal(response)
    assert refused.value.code == REFUSED


async def test_a_refusal_is_not_kept_once_the_operator_lists_its_own_server(
    tmp_path, registry, test_db_factory
):
    # The same team, registry and database: first unlisted, then listed after
    # a restart. Nothing remembers the refusal.
    database_url = await _database_url(test_db_factory)
    async with team_server_site(tmp_path, _coordination_server()) as site:
        member = await _member_of_team_serving_at(registry, f"{site.origin}/x")
        unlisted = _runtime(
            tmp_path,
            registry,
            resolver=site.resolver(),
            database_url=database_url,
            **site.settings(listed=False),
        )
        async with serving(unlisted) as client:
            refused = await _member_request(client, member)
        listed = _runtime(
            tmp_path,
            registry,
            resolver=site.resolver(),
            database_url=database_url,
            **site.settings(),
        )
        async with serving(listed) as client:
            reached = await _member_request(client, member)

    _assert_actionable_refusal(refused)
    assert site.tls.connections == 1
    assert [seen.request_line for seen in site.tls.seen] == ["GET /x/v1/apps/self/grant HTTP/1.1"]
    assert _refusal_code(reached) != REFUSED


@pytest.mark.parametrize(
    "entry",
    [
        "http://coord.egress.example",  # plain http
        "http://127.0.0.1:8000",  # plain http on loopback
        "https://coord.egress.example/x",  # a path
        "https://user@coord.egress.example",  # userinfo
        "https://*.egress.example",  # a wildcard
        "https://coord.egress.example?x=1",  # a query
        "not a url",
    ],
)
def test_a_malformed_listed_origin_stops_the_app_starting(tmp_path, registry, entry):
    with pytest.raises(ValueError):
        _runtime(
            tmp_path,
            registry,
            hook_internal_destinations="allowed",
            hook_internal_cidr="10.20.0.0/16",
            team_server_internal_origins=[entry],
        )
