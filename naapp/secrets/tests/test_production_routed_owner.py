"""Install, activate and designate through the maintained product surfaces."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import ssl
import subprocess
import sys
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from ipaddress import ip_network
from typing import Any, cast

import asyncpg
import dns.asyncresolver as dns_api
import httpx
import pytest
import pytest_asyncio
from aweb.app_manifests import ManifestFetcher
from aweb.config import AppInternalOrigins
from aweb_naapp.egress import AddressPolicy, DnsResolver, Egress, InternalDestinations
from aweb_naapp.hooks.owner_act import CORE_ACTS, hook_binding_subject
from aweb_naapp_testing import Member
from aweb_naapp_testing.databases import SchemaDatabases
from aweb_naapp_testing.network import DnsServer, local_address, make_certificates
from aweb_naapp_testing.owner_acts import TeamOwner
from aweb_naapp_testing.server import (
    Coordination,
    awid_dns,
    running_coordination,
    running_coordination_registry,
)
from aweb_naapp_testing.smtp import SmtpServer
from awid_service.testing import SERVICE_TOKEN
from nacl.signing import SigningKey
from pgdbm.testing import AsyncTestDatabase, DatabaseTestConfig
from service_server import Listener, serving
from team_journey_support import HOOK_READINESS_DEADLINE, hooks_ready_at, select_hook_bindings

from aweb_secrets.app import SecretsService
from aweb_secrets.composition import create_service
from aweb_secrets.config import ServiceSettings
from aweb_secrets.owners import owner_scope
from tests.production_database import PreparedDatabaseFactory
from tests.production_logs import logs_receiver
from tests.test_composition import settings
from tests.test_owner_delivery import CONTACT, PATH, delivery
from tests.test_production_bootstrap import (
    EnrolledOwner,
    mounted_owner_console,
    mounted_owner_verifier,
)

_BINDINGS = "/v1/apps/hook-bindings"
_LOGS_NAME = "logs.routed-owner.test"
_VALIDATION = "validation"
ROUTED_GRANT_SECONDS = 8
_CORE_POOL = 3
_LOGS_POOL = 2
_SECRETS_POOL = 5
_PREPARED_POOL = 1

pytestmark = pytest.mark.asyncio(loop_scope="module")


@dataclass(frozen=True)
class RoutedOwner:
    service: SecretsService = field(repr=False)
    coordination: Coordination = field(repr=False)
    member: Member = field(repr=False)
    settings: ServiceSettings = field(repr=False)
    installation: dict[str, Any]
    holder: EnrolledOwner = field(repr=False)
    client: httpx.AsyncClient = field(repr=False)
    smtp: SmtpServer = field(repr=False)


async def _grant_install_owner(coordination: Coordination, member: Member) -> None:
    """Run the operator's install-admin command against the fixture's database."""
    dsn = coordination.server.db.get_manager().config.get_dsn()
    result = await asyncio.to_thread(
        subprocess.run,
        [
            sys.executable,
            "-c",
            "from aweb.cli import app; app()",
            "install-admin",
            "grant",
            "--team-id",
            member.team_id,
            "--principal-did",
            member.did_key,
            "--role",
            "owner",
        ],
        env={**os.environ, "AWEB_DATABASE_URL": dsn},
        capture_output=True,
        timeout=30,
    )
    assert result.returncode == 0, "test operator could not grant install-admin"
    assert json.loads(result.stdout)["role"] == "owner"


async def _team_request(
    coordination: Coordination,
    member: Member,
    method: str,
    path: str,
    *,
    body: dict[str, Any] | None = None,
    params: dict[str, str] | None = None,
) -> dict[str, Any]:
    raw = json.dumps(body).encode() if body is not None else b""
    async with coordination.server.client() as client:
        request = client.build_request(
            method, path, content=raw, params=params, headers={"Content-Type": "application/json"}
        )
        request.headers.update(
            member.headers(
                aud=coordination.server.url,
                method=request.method,
                path=request.url.raw_path.decode("ascii"),
                body=raw,
            )
        )
        response = await client.send(request)
    assert response.status_code == 200, f"{method} {path} returned {response.status_code}"
    return response.json()


async def _install(coordination: Coordination, member: Member, origin: str) -> dict[str, Any]:
    preview = await _team_request(
        coordination, member, "POST", "/v1/apps/preview", body={"origin": origin}
    )
    installed = await _team_request(
        coordination,
        member,
        "POST",
        "/v1/apps/install",
        body={
            "origin": origin,
            "app_id": preview["app_id"],
            "digest": preview["digest"],
            "granted_scopes": preview["resolved"]["install_scopes"],
        },
    )
    assert installed["origin_verified"] and installed["state"] == "active"
    return installed


async def _activate_hooks(
    coordination: Coordination, member: Member, owner: TeamOwner, apps: dict[str, str]
) -> datetime:
    async def listed() -> dict[str, list[dict]]:
        return {
            name: (
                await _team_request(
                    coordination,
                    member,
                    "GET",
                    _BINDINGS,
                    params={"team_id": member.team_id, "app_id": app_id},
                )
            )["bindings"]
            for name, app_id in apps.items()
        }

    selected = list(select_hook_bindings(await listed()).values())
    for row in selected:
        registration = row["kind"] == "registration"
        subject = hook_binding_subject(
            binding_id=row["binding_id"],
            installation_id=row["installation_id"],
            generation=row["generation"],
            app_id=row["app_id"],
            origin=row["origin"],
            digest=row["digest"],
            kind=row["kind"],
            catalog_id=row["catalog_id"],
            catalog_version=row["catalog_version"],
            hook=row["hook"],
            tool=row["tool"],
            method=row["method"],
            path=row["path"],
            scopes=row["scopes"] if registration else None,
            reads=None if registration else row["reads"],
        )
        signing, signature = owner.sign("hook-binding.activate", subject)
        await _team_request(
            coordination,
            member,
            "POST",
            f"{_BINDINGS}/{row['binding_id']}/activate",
            body={"act": base64.b64encode(signing).decode(), "signature": signature},
        )
    return hooks_ready_at([row for rows in (await listed()).values() for row in rows], selected)


async def _designate(
    service: SecretsService,
    client: httpx.AsyncClient,
    config: ServiceSettings,
    coordination: Coordination,
    member: Member,
    installation: dict[str, Any],
    dns: DnsServer,
    *,
    alias: str,
) -> EnrolledOwner:
    # The delivery tests already build a real controller act and registered
    # human for this exact production endpoint and relying party.
    act, principal, device = await delivery(
        (service, client, config, member, installation, dns), coordination.registry, alias=alias
    )
    assert device is not None
    declared = await client.post(PATH, json=act)
    assert declared.status_code == 200, f"owner designation returned {declared.status_code}"
    assert declared.json()["principal"] == principal.principal_did
    scope = owner_scope(installation["installation_id"], member.team_id, principal.principal_did)
    options = await client.post("/login/options", json={"scope": scope})
    assert options.status_code == 200
    logged = await client.post(
        "/login", json={"scope": scope, "assertion": device.get(options.json())}
    )
    assert logged.status_code == 200
    csrf = logged.json()["csrf_token"]
    assert isinstance(csrf, str) and csrf
    return EnrolledOwner(
        scope,
        {"principal": principal.principal_did, "contact": CONTACT},
        None,
        device,
        csrf,
    )


class _RoutedTestDatabase(AsyncTestDatabase):
    def get_test_db_config(self, schema=None, **kwargs):
        config = super().get_test_db_config(schema, **kwargs)
        return config.model_copy(update={"min_connections": 1, "max_connections": 1})


@dataclass(frozen=True)
class _RoutedDatabases:
    stack: AsyncExitStack
    config: DatabaseTestConfig = field(repr=False)

    async def create_db(self, suffix=None, schema=None):
        return await self.stack.enter_async_context(
            _RoutedTestDatabase.create(suffix=suffix, schema=schema, config=self.config)
        )


async def _check_capacity(config: DatabaseTestConfig, worlds: int) -> None:
    # Each owned database retains one pgdbm admin connection (its create/drop
    # calls are serial) and one provisioning connection. Both Logs databases
    # have a runtime pool. Each Secrets database also has a prepared-role pool.
    core = 2 * (2 + _CORE_POOL)
    shared = core + 2 * (2 + _LOGS_POOL)
    per_world = 2 + _PREPARED_POOL + _SECRETS_POOL
    # The CLI's ordinary pgdbm pool can use 20. All its invocations finish
    # before opening Logs or Secrets, so count that pool only during bootstrap.
    required = max(core + 20, shared + worlds * per_world)
    connection = await asyncpg.connect(
        host=config.host,
        port=config.port,
        user=config.user,
        password=config.password,
        database="postgres",
    )
    try:
        available = await connection.fetchval(
            "SELECT current_setting('max_connections')::int"
            " - current_setting('superuser_reserved_connections')::int"
            " - COALESCE(current_setting('reserved_connections',true)::int,0)"
            " - (SELECT count(*) FROM pg_stat_activity WHERE backend_type='client backend')"
        )
    finally:
        await connection.close()
    assert available >= required, (
        f"routed owner tests need {required} PostgreSQL connections; {available} available"
    )


@dataclass(frozen=True)
class _RoutedApp:
    service: SecretsService = field(repr=False)
    settings: ServiceSettings = field(repr=False)
    smtp: SmtpServer = field(repr=False)


@dataclass(frozen=True)
class _InstalledOwnerApp:
    app: _RoutedApp
    member: Member = field(repr=False)
    installation: dict[str, Any]


@dataclass(frozen=True)
class _RoutedOwnerBatch:
    coordination: Coordination = field(repr=False)
    dns: DnsServer = field(repr=False)
    tls: ssl.SSLContext = field(repr=False)
    installations: dict[str, _InstalledOwnerApp]

    def client(self, settings: ServiceSettings, *, cookies: httpx.Cookies | None = None):
        return httpx.AsyncClient(
            base_url=settings.console_origin, trust_env=False, verify=self.tls, cookies=cookies
        )


def _selected_worlds(request: pytest.FixtureRequest) -> list[str]:
    # A focused node selection should only start its own world.
    keys = {}
    for item in request.session.items:
        if item.getparent(pytest.Module) is not request.node:
            continue
        if "production_routed_validation_owner" in item.fixturenames:
            keys[_VALIDATION] = None
        elif "production_routed_owner" in item.fixturenames:
            keys[item.nodeid] = None
    return list(keys)


async def _start_app(
    apps, prepared, coordination, directory, host, network, certificates, egress, logs_origin
) -> _RoutedApp:
    db = await prepared.create_db(suffix="production_routed_owner")
    smtp = apps.enter_context(SmtpServer(directory / "secrets-smtp"))
    base = settings(db, directory, smtp)

    def compose(ports: tuple[int, ...]) -> SecretsService:
        return create_service(
            base.model_copy(
                update={
                    "public_origin": f"https://{host}:{ports[0]}",
                    "console_origin": f"https://localhost:{ports[1]}",
                    "awid_service_token": SERVICE_TOKEN,
                    "db_pool_max_connections": _SECRETS_POOL,
                }
            ),
            awid_transport=coordination.registry.transport,
            awid_domain_verifier=awid_dns(coordination.registry),
            team_server_transport=coordination.server.transport,
            hook_egress=egress,
            hook_internal_cidr=network,
            hook_internal_origins=frozenset({logs_origin}),
        )

    running = await apps.enter_async_context(
        serving(
            compose,
            listeners=(Listener(host, 0), Listener("127.0.0.1", 0)),
            certificates=certificates,
        )
    )
    service = cast(SecretsService, running.app)
    return _RoutedApp(service, cast(ServiceSettings, service.runtime.settings), smtp)


@pytest_asyncio.fixture(scope="module")
async def routed_owner_batch(request, tmp_path_factory) -> AsyncIterator[_RoutedOwnerBatch]:
    keys = _selected_worlds(request)
    assert keys, "the routed owner fixture has no selected cases"
    db_config = DatabaseTestConfig.from_env()
    await _check_capacity(db_config, len(keys))
    directory = tmp_path_factory.mktemp("routed-owner")
    host = local_address()
    network = ip_network(f"{host}/32")
    certificates = make_certificates(directory, ["localhost", _LOGS_NAME], [host, "127.0.0.1"])
    tls = ssl.create_default_context(cafile=str(certificates.ca_file))
    dns = DnsServer(records={(_LOGS_NAME, "A"): [host]})
    await dns.start()
    try:
        with pytest.MonkeyPatch.context() as patch:
            patch.setenv("AWEB_APP_GRANT_MAX_AGE_SECONDS", str(ROUTED_GRANT_SECONDS))
            resolver = dns_api.Resolver(configure=False)
            resolver.nameservers, resolver.port = ["127.0.0.1"], dns.port
            patch.setattr(dns_api, "default_resolver", resolver)
            egress = Egress(
                addresses=AddressPolicy(internal_destinations=InternalDestinations.ALLOWED),
                resolver=DnsResolver(nameservers=["127.0.0.1"], port=dns.port),
                user_agent="secrets-root/routed-owner-test",
                ca_file=certificates.ca_file,
            )
            async with AsyncExitStack() as databases, AsyncExitStack() as apps:
                factory = SchemaDatabases(_RoutedDatabases(databases, db_config))
                prepared = PreparedDatabaseFactory(
                    factory=factory, stack=databases, runtime_pool_limit=_PREPARED_POOL
                )
                registry = await apps.enter_async_context(
                    running_coordination_registry(factory, database_pool_limit=_CORE_POOL)
                )
                coordination = await apps.enter_async_context(
                    running_coordination(factory, patch, registry, database_pool_limit=_CORE_POOL)
                )
                namespace_controller = SigningKey.generate()
                members = {}
                for index, key in enumerate(keys):
                    alias = f"routed-{index}"
                    member = Member(
                        team_id=f"{alias}:example.com", certificate_id=alias, alias=alias
                    )
                    member.extra_cert_fields = {
                        "member_did_aw": await registry.register_did(member.member_key)
                    }
                    await coordination.add_member(member, namespace_controller=namespace_controller)
                    await coordination.publish_server(member)
                    await coordination.connect(member)
                    await _grant_install_owner(coordination, member)
                    members[key] = member

                logs_origin, _, _ = await apps.enter_async_context(
                    logs_receiver(
                        factory,
                        registry,
                        coordination.server.transport,
                        directory,
                        host,
                        _LOGS_NAME,
                        certificates,
                        database_pool_limit=_LOGS_POOL,
                    )
                )
                started = {}
                for key, member in members.items():
                    world_dir = directory / member.alias
                    world_dir.mkdir()
                    started[key] = await _start_app(
                        apps,
                        prepared,
                        coordination,
                        world_dir,
                        host,
                        network,
                        certificates,
                        egress,
                        logs_origin,
                    )
                origins = frozenset(
                    [logs_origin, *(app.settings.public_origin for app in started.values())]
                )
                patch.setattr(
                    coordination.server.app.state,
                    "manifest_fetcher",
                    ManifestFetcher(egress=egress, internal=AppInternalOrigins(origins, network)),
                    raising=False,
                )

                installations = {}
                deadlines = []
                for key, app in started.items():
                    member = members[key]
                    installation = await _install(coordination, member, app.settings.public_origin)
                    logs = await _install(coordination, member, logs_origin)
                    verifier = mounted_owner_verifier(app.service)
                    owner = TeamOwner(
                        member.team_key, verifier, member.team_id, verifier.current_team_key
                    )
                    deadlines.append(
                        await _activate_hooks(
                            coordination,
                            member,
                            owner.for_acts(CORE_ACTS, audience=coordination.server.url),
                            {"secrets": installation["app_id"], "logs": logs["app_id"]},
                        )
                    )
                    installations[key] = _InstalledOwnerApp(app, member, installation)

                # Each install published its own deadline. Overlap those
                # windows and wait once for the last, keeping the journey margin.
                delay = (max(deadlines) - datetime.now(UTC)).total_seconds()
                assert delay <= HOOK_READINESS_DEADLINE.total_seconds()
                await asyncio.sleep(max(delay, 0))
                yield _RoutedOwnerBatch(coordination, dns, tls, installations)
    finally:
        dns.close()


async def _enrolled_owner(batch: _RoutedOwnerBatch, key: str, client: httpx.AsyncClient):
    world = batch.installations[key]
    app = world.app
    holder = await _designate(
        app.service,
        client,
        app.settings,
        batch.coordination,
        world.member,
        world.installation,
        batch.dns,
        alias=f"{world.member.alias}-owner",
    )
    return RoutedOwner(
        app.service,
        batch.coordination,
        world.member,
        app.settings,
        world.installation,
        holder,
        client,
        app.smtp,
    )


@pytest_asyncio.fixture(loop_scope="module")
async def production_routed_owner(request, routed_owner_batch) -> AsyncIterator[RoutedOwner]:
    batch = routed_owner_batch
    key = request.node.nodeid
    async with batch.client(batch.installations[key].app.settings) as client:
        yield await _enrolled_owner(batch, key, client)


@pytest_asyncio.fixture(scope="module")
async def enrolled_validation_owner(routed_owner_batch) -> AsyncIterator[RoutedOwner]:
    batch = routed_owner_batch
    async with batch.client(batch.installations[_VALIDATION].app.settings) as client:
        yield await _enrolled_owner(batch, _VALIDATION, client)


@pytest_asyncio.fixture(loop_scope="module")
async def production_routed_validation_owner(
    routed_owner_batch, enrolled_validation_owner
) -> AsyncIterator[RoutedOwner]:
    owner = enrolled_validation_owner
    # Each requester gets its own jar while reusing the real S4 session.
    async with routed_owner_batch.client(owner.settings, cookies=owner.client.cookies) as client:
        yield replace(owner, client=client)


@pytest_asyncio.fixture(loop_scope="module")
async def routed_anonymous_client(
    routed_owner_batch, production_routed_validation_owner
) -> AsyncIterator[httpx.AsyncClient]:
    async with routed_owner_batch.client(production_routed_validation_owner.settings) as client:
        yield client


async def test_product_setup_yields_a_signed_in_owner_of_the_installed_generation(
    production_routed_owner,
):
    world = production_routed_owner
    admitted = await mounted_owner_console(world.service).installation(
        world.installation["installation_id"], team_id=world.member.team_id
    )
    assert admitted.installation_id == world.installation["installation_id"]
    assert admitted.generation == world.installation["generation"]
    assert (await world.client.get("/", follow_redirects=False)).status_code == 200
