"""A member route admits a request only for a team that installed the app, at
the installation its grant names.

Real AWID and a real coordination server on real PostgreSQL: the team installs
the app on its own server through the server's installation store, and the app
is a real NaappRuntime that reads the team's grant from that server.

No ``from __future__ import annotations``: FastAPI resolves the route's
``Depends(runtime.installed_member(...))`` annotation at definition time.
"""

import asyncio
import hashlib
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from time import monotonic_ns
from typing import Annotated

import dns.asyncresolver
import httpx
import pytest
from aweb.app_manifests import FetchedManifest
from aweb.installations import install_verified_manifest_on, uninstall_installation_on
from aweb_naapp_testing import Member
from aweb_naapp_testing.network import DnsServer
from aweb_naapp_testing.server import Coordination
from awid_service.testing import REGISTRY_URL, SERVICE_TOKEN
from fastapi import Depends, FastAPI
from nacl.signing import SigningKey

from aweb_naapp.manifest import canonical_bytes, load_manifest
from aweb_naapp.runtime.app import InstalledMember, NaappRuntime
from aweb_naapp.runtime.installation import apply_installation_migrations
from tests.runtime.test_naapp_runtime import allow_all
from tests.runtime.test_served_manifest import (
    HOSTED_ORIGIN,
    ExampleSettings,
    _key_file,
    _v2_template,
)


@dataclass
class Deployment:
    runtime: NaappRuntime
    client: httpx.AsyncClient
    admitted: list[InstalledMember]


def _runtime(tmp_path: Path, coordination: Coordination, database_url: str) -> NaappRuntime:
    key = _key_file(tmp_path, "grant-read", bytes(SigningKey.generate()).hex())
    manifest = tmp_path / "manifest.json"
    template = _v2_template(("grant-read", ["app-grant-read"]))
    template["app"]["version"] = "1.0.0"
    manifest.write_bytes(canonical_bytes(template))
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    settings = ExampleSettings(
        _env_file=None,
        database_url=database_url,
        app_key_files={"grant-read": key},
        awid_registry_url=REGISTRY_URL,
        awid_service_token=SERVICE_TOKEN,
        **coordination.site.settings(),
    )
    runtime = NaappRuntime(
        settings,
        module_name="example",
        migrations_path=migrations,
        manifest_path=manifest,
        stores=(apply_installation_migrations,),
        awid_transport=coordination.registry.transport,
        egress=coordination.site.egress(settings),
    )
    return runtime


@pytest.fixture(autouse=True)
async def dns_with_no_awid_statements(monkeypatch) -> AsyncIterator[None]:
    """The process's DNS is a test server holding no records: every team's
    domain publishes no _awid statement, so its registry is the app's own."""
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


@asynccontextmanager
async def deployment(
    tmp_path: Path, coordination: Coordination, test_db_factory
) -> AsyncIterator[Deployment]:
    database = await test_db_factory.create_db(suffix="installed_member")
    runtime = _runtime(tmp_path, coordination, database.config.get_dsn())
    admitted: list[InstalledMember] = []
    app = FastAPI(lifespan=runtime.lifespan)
    member = runtime.installed_member(policy=allow_all)

    @app.post("/v1/things")
    async def create(installed: Annotated[InstalledMember, Depends(member)]) -> dict:
        admitted.append(installed)
        async with installed.permit.transaction() as tx:
            await tx.fetch_value("SELECT 1")
        return {}

    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=HOSTED_ORIGIN) as client,
    ):
        yield Deployment(runtime, client, admitted)


async def _member_of_a_team_on(coordination: Coordination, team_id: str) -> Member:
    member = Member(team_id=team_id)
    await coordination.add_member(member)
    await coordination.connect(member)
    await coordination.publish_server(member)
    return member


async def _install(coordination: Coordination, runtime: NaappRuntime, team_id: str) -> dict:
    data = runtime.manifest_bytes
    fetched = FetchedManifest(
        origin=runtime.settings.public_origin,
        url=runtime.settings.public_origin + "/manifests/v2.json",
        digest="sha256:" + hashlib.sha256(data).hexdigest(),
        data=data,
        manifest=load_manifest(data),
    )
    async with coordination.server.db.get_manager().transaction() as tx:
        return await install_verified_manifest_on(
            tx,
            team_id=team_id,
            fetched=fetched,
            granted_scopes=list(runtime.manifest.install_scopes),
        )


async def _create(client: httpx.AsyncClient, member: Member) -> httpx.Response:
    return await client.post(
        "/v1/things", headers=member.headers(aud=HOSTED_ORIGIN, method="POST", path="/v1/things")
    )


def _assert_refused_with_a_reason(response: httpx.Response, status: int) -> None:
    assert response.status_code == status, response.text
    detail = response.json()["detail"]
    assert isinstance(detail["code"], str) and detail["code"]
    assert isinstance(detail["message"], str) and detail["message"]


async def test_a_member_of_an_installing_team_is_admitted_at_its_installation(
    tmp_path, coordination, test_db_factory
):
    async with deployment(tmp_path, coordination, test_db_factory) as app:
        member = await _member_of_a_team_on(coordination, "ops:installed.example")
        installation = await _install(coordination, app.runtime, member.team_id)

        response = await _create(app.client, member)

    assert response.status_code == 200, response.text
    [installed] = app.admitted
    assert installed.principal.team_id == member.team_id
    assert installed.permit.admitted.installation_id == installation["installation_id"]
    assert installed.permit.admitted.generation == installation["generation"]
    assert installed.authorization.grant.installation_id == installation["installation_id"]


async def test_a_member_of_a_team_that_never_installed_the_app_is_refused(
    tmp_path, coordination, test_db_factory
):
    async with deployment(tmp_path, coordination, test_db_factory) as app:
        member = await _member_of_a_team_on(coordination, "ops:uninstalled.example")

        response = await _create(app.client, member)

    _assert_refused_with_a_reason(response, 403)
    assert app.admitted == []


async def test_a_member_is_refused_once_the_team_uninstalls_the_app(
    tmp_path, coordination, test_db_factory, monkeypatch
):
    # The server tells the app to reread a grant after one second.
    monkeypatch.setenv("AWEB_APP_GRANT_MAX_AGE_SECONDS", "1")
    async with deployment(tmp_path, coordination, test_db_factory) as app:
        member = await _member_of_a_team_on(coordination, "ops:leaving.example")
        installation = await _install(coordination, app.runtime, member.team_id)
        assert (await _create(app.client, member)).status_code == 200
        async with coordination.server.db.get_manager().transaction() as tx:
            await uninstall_installation_on(
                tx,
                team_id=member.team_id,
                app_id=app.runtime.manifest.app_id,
                expected_generation=installation["generation"],
            )
        grant = await app.runtime.installation_grants().status_for(member.team_id)
        assert grant is not None
        await _wait_until_stale(grant.fresh_until)

        response = await _create(app.client, member)

    _assert_refused_with_a_reason(response, 403)
    assert len(app.admitted) == 1


async def _wait_until_stale(fresh_until_ns: int) -> None:
    await asyncio.sleep(max(0, (fresh_until_ns - monotonic_ns()) / 1e9) + 0.01)


def test_a_member_route_that_is_no_declared_tool_refuses_to_start(tmp_path, coordination):
    runtime = _runtime(tmp_path, coordination, "postgresql://localhost/unused")
    app = FastAPI()
    member = runtime.installed_member(policy=allow_all)

    @app.post("/v1/things/purge")
    async def purge(installed: Annotated[InstalledMember, Depends(member)]) -> dict:
        return {}

    with pytest.raises(RuntimeError):
        runtime.check_authorized_routes(app)
