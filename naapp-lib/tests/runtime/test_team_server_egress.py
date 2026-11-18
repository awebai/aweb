"""A team's published server address is reached only through the egress rule.

Real AWID on real PostgreSQL stores each team's signed server record through
its own route and validator; the app is a real NaappRuntime. A team that
publishes its server on the app's own loopback, or under an https name that
resolves to a private address, gets a refusal and no connection, unless the
operator listed exactly that origin as one of its own team servers.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from aweb_naapp_testing import REGISTRY_URL, SERVICE_TOKEN, Member
from aweb_naapp_testing.network import DnsServer, local_address
from fastapi import Depends, FastAPI
from nacl.signing import SigningKey

from aweb_naapp.egress import AddressPolicy, DnsResolver, Egress
from aweb_naapp.manifest import canonical_bytes
from aweb_naapp.runtime.app import NaappRuntime
from aweb_naapp.runtime.app_credentials import APP_GRANT_READ, HOOK_RESOLVE
from aweb_naapp.runtime.hook_resolver import HookResolutionUnavailable
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
    team_server_egress: Egress | None = None,
    team_server_transport: httpx.AsyncBaseTransport | None = None,
    **settings,
) -> NaappRuntime:
    keys = (("grants", [APP_GRANT_READ]), ("hooks", [HOOK_RESOLVE]))
    files = {kid: _key_file(tmp_path, kid, bytes(SigningKey.generate()).hex()) for kid, _ in keys}
    manifest = tmp_path / "manifest.json"
    manifest.write_bytes(canonical_bytes(_v2_template(*keys)))
    migrations = tmp_path / "migrations"
    migrations.mkdir(exist_ok=True)
    extra = {} if team_server_egress is None else {"team_server_egress": team_server_egress}
    runtime = NaappRuntime(
        ExampleSettings(
            _env_file=None,
            app_key_files=files,
            awid_registry_url=REGISTRY_URL,
            awid_service_token=SERVICE_TOKEN,
            database_url=database_url,
            **settings,
        ),
        module_name="example",
        migrations_path=migrations,
        manifest_path=manifest,
        awid_transport=registry.transport,
        team_server_transport=team_server_transport,
        **extra,
    )

    async def no_registry_override(domain: str) -> None:
        return None

    # The team's domain publishes no registry statement in DNS.
    runtime.team_server_directory()._registry_override = no_registry_override
    return runtime


async def _member_of_team_serving_at(registry, server_url: str) -> Member:
    member = Member(team_id=TEAM_ID)
    await registry.add_team(TEAM_ID, member.team_did_key)
    await registry.add_certificate(member.certificate())
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
    assert response.status_code >= 400
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
async def private_name(host: str) -> AsyncIterator[Egress]:
    """An egress whose resolver answers PRIVATE_NAME with ``host``.

    AWID accepts any https name as a team server, whatever it resolves to.
    """
    assert ipaddress.ip_address(host).is_private, f"{host} must not be a public address"
    dns = DnsServer(records={(PRIVATE_NAME, "A"): [host]})
    await dns.start()
    try:
        yield Egress(
            addresses=AddressPolicy(),
            resolver=DnsResolver(nameservers=["127.0.0.1"], port=dns.port),
            user_agent="team-server-egress-test",
        )
    finally:
        dns.close()


@pytest.mark.parametrize("address", ["private", "loopback"])
async def test_an_https_name_resolving_to_an_internal_address_is_refused(
    tmp_path, registry, test_db_factory, address
):
    host = local_address() if address == "private" else "127.0.0.1"
    async with listener(host) as (port, connections), private_name(host) as egress:
        member = await _member_of_team_serving_at(registry, f"https://{PRIVATE_NAME}:{port}/x")
        runtime = _runtime(
            tmp_path,
            registry,
            team_server_egress=egress,
            database_url=await _database_url(test_db_factory),
        )
        async with serving(runtime) as client:
            response = await _member_request(client, member)
            with pytest.raises(HookResolutionUnavailable) as refused:
                await runtime.hook_resolver().core_producer_keys(TEAM_ID)

    assert connections == []
    _assert_actionable_refusal(response)
    assert refused.value.code == REFUSED


class RecordingTransport(httpx.AsyncBaseTransport):
    def __init__(self, status_code: int = 200, headers: dict[str, str] | None = None) -> None:
        self.requests: list[httpx.Request] = []
        self._status_code = status_code
        self._headers = headers or {}

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return httpx.Response(self._status_code, headers=self._headers, json={})


async def test_an_injected_transport_does_not_reach_an_origin_the_operator_did_not_list(
    tmp_path, registry, test_db_factory
):
    transport = RecordingTransport()
    member = await _member_of_team_serving_at(registry, "http://127.0.0.1:9/x")
    runtime = _runtime(
        tmp_path,
        registry,
        team_server_transport=transport,
        database_url=await _database_url(test_db_factory),
    )
    async with serving(runtime) as client:
        response = await _member_request(client, member)
        with pytest.raises(HookResolutionUnavailable) as refused:
            await runtime.hook_resolver().core_producer_keys(TEAM_ID)

    assert transport.requests == []
    _assert_actionable_refusal(response)
    assert refused.value.code == REFUSED


async def test_an_operator_listed_loopback_origin_is_reached(tmp_path, registry, test_db_factory):
    async with listener("127.0.0.1") as (port, connections):
        origin = f"http://127.0.0.1:{port}"
        member = await _member_of_team_serving_at(registry, f"{origin}/x")
        runtime = _runtime(
            tmp_path,
            registry,
            team_server_internal_origins=[origin],
            database_url=await _database_url(test_db_factory),
        )
        async with serving(runtime) as client:
            response = await _member_request(client, member)

    assert connections != []
    assert _refusal_code(response) != REFUSED


async def test_a_redirect_from_a_listed_origin_is_not_followed(tmp_path, registry, test_db_factory):
    transport = RecordingTransport(302, {"location": "http://127.0.0.1:9/elsewhere"})
    member = await _member_of_team_serving_at(registry, "http://127.0.0.1:8000/x")
    runtime = _runtime(
        tmp_path,
        registry,
        team_server_transport=transport,
        team_server_internal_origins=["http://127.0.0.1:8000"],
        database_url=await _database_url(test_db_factory),
    )
    async with serving(runtime) as client:
        response = await _member_request(client, member)

    assert [str(request.url) for request in transport.requests] == [
        "http://127.0.0.1:8000/x/v1/apps/self/grant"
    ]
    assert response.status_code >= 400


def test_listed_origins_are_logged_once_at_startup(tmp_path, registry, caplog):
    with caplog.at_level(logging.WARNING, logger="aweb_naapp.runtime.team_server"):
        _runtime(
            tmp_path,
            registry,
            team_server_internal_origins=["http://127.0.0.1:8000", "https://Coord.Egress.Example"],
        )
    warnings = [record for record in caplog.records if record.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "http://127.0.0.1:8000" in warnings[0].getMessage()
    assert "https://coord.egress.example" in warnings[0].getMessage()


def test_no_startup_warning_when_no_origin_is_listed(tmp_path, registry, caplog):
    with caplog.at_level(logging.WARNING, logger="aweb_naapp.runtime.team_server"):
        _runtime(tmp_path, registry)
    assert not [record for record in caplog.records if record.levelno >= logging.WARNING]


def test_a_well_formed_listed_origin_is_accepted(tmp_path, registry):
    runtime = _runtime(
        tmp_path,
        registry,
        team_server_internal_origins=["http://127.0.0.1:8000", "https://coord.egress.example"],
    )
    assert runtime.installation_grants() is not None


@pytest.mark.parametrize(
    "entry",
    [
        "http://coord.egress.example",  # http off loopback
        "http://127.0.0.1:8000/x",  # a path
        "https://user@coord.egress.example",  # userinfo
        "https://*.egress.example",  # a wildcard
        "https://coord.egress.example?x=1",  # a query
        "not a url",
    ],
)
def test_a_malformed_listed_origin_stops_the_app_starting(tmp_path, registry, entry):
    with pytest.raises(ValueError):
        _runtime(tmp_path, registry, team_server_internal_origins=[entry])
