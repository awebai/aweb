"""Install, activate and designate through the maintained product surfaces."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import ssl
import subprocess
import sys
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from datetime import UTC, datetime
from ipaddress import ip_network
from typing import Any, cast

import dns.asyncresolver as dns_api
import httpx
import pytest
from aweb.app_manifests import ManifestFetcher
from aweb.config import AppInternalOrigins
from aweb_naapp.egress import AddressPolicy, DnsResolver, Egress, InternalDestinations
from aweb_naapp.hooks.owner_act import CORE_ACTS, hook_binding_subject
from aweb_naapp_testing import Member
from aweb_naapp_testing.network import DnsServer, local_address, make_certificates
from aweb_naapp_testing.owner_acts import TeamOwner
from aweb_naapp_testing.server import Coordination, awid_dns
from aweb_naapp_testing.smtp import SmtpServer
from awid_service.testing import SERVICE_TOKEN
from service_server import Listener, serving
from team_journey_support import HOOK_READINESS_DEADLINE, hooks_ready_at, select_hook_bindings

from aweb_secrets.app import SecretsService
from aweb_secrets.composition import create_service
from aweb_secrets.config import ServiceSettings
from aweb_secrets.owners import owner_scope
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
    headers = member.headers(aud=coordination.server.url, method=method, path=path, body=raw)
    async with coordination.server.client() as client:
        response = await client.request(
            method,
            path,
            content=raw,
            params=params,
            headers={**headers, "Content-Type": "application/json"},
        )
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
) -> None:
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
    ready = hooks_ready_at([row for rows in (await listed()).values() for row in rows], selected)
    delay = (ready - datetime.now(UTC)).total_seconds()
    assert delay <= HOOK_READINESS_DEADLINE.total_seconds()
    await asyncio.sleep(max(delay, 0))


async def _designate(
    service: SecretsService,
    client: httpx.AsyncClient,
    config: ServiceSettings,
    coordination: Coordination,
    member: Member,
    installation: dict[str, Any],
    dns: DnsServer,
) -> EnrolledOwner:
    # The delivery tests already build a real controller act and registered
    # human for this exact production endpoint and relying party.
    act, principal, device = await delivery(
        (service, client, config, member, installation, dns), coordination.registry
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
    return EnrolledOwner(
        scope,
        {"principal": principal.principal_did, "contact": CONTACT},
        None,
        device,
        logged.json()["csrf_token"],
    )


@pytest.fixture
async def production_routed_owner(
    coordination: Coordination, test_db_factory, prepared_service_databases, tmp_path, monkeypatch
):
    registry = coordination.registry
    transport = coordination.server.transport
    member = Member(team_id="root:example.com")
    member.extra_cert_fields = {"member_did_aw": await registry.register_did(member.member_key)}
    await coordination.add_member(member)
    await coordination.publish_server(member)
    await coordination.connect(member)
    await _grant_install_owner(coordination, member)

    host = local_address()
    network = ip_network(f"{host}/32")
    certificates = make_certificates(tmp_path, ["localhost", _LOGS_NAME], [host, "127.0.0.1"])
    dns = DnsServer(records={(_LOGS_NAME, "A"): [host]})
    await dns.start()
    try:
        resolver = dns_api.Resolver(configure=False)
        resolver.nameservers, resolver.port = ["127.0.0.1"], dns.port
        monkeypatch.setattr(dns_api, "default_resolver", resolver)
        egress = Egress(
            addresses=AddressPolicy(internal_destinations=InternalDestinations.ALLOWED),
            resolver=DnsResolver(nameservers=["127.0.0.1"], port=dns.port),
            user_agent="secrets-root/routed-owner-test",
            ca_file=certificates.ca_file,
        )
        async with AsyncExitStack() as apps:
            logs_origin, _, _ = await apps.enter_async_context(
                logs_receiver(
                    test_db_factory, registry, transport, tmp_path, host, _LOGS_NAME, certificates
                )
            )
            db = await prepared_service_databases.create_db(suffix="production_routed_owner")
            smtp = apps.enter_context(SmtpServer(tmp_path / "secrets-smtp"))
            base = settings(db, tmp_path, smtp)

            def compose(ports: tuple[int, ...]) -> SecretsService:
                return create_service(
                    base.model_copy(
                        update={
                            "public_origin": f"https://{host}:{ports[0]}",
                            "console_origin": f"https://localhost:{ports[1]}",
                            "awid_service_token": SERVICE_TOKEN,
                        }
                    ),
                    awid_transport=registry.transport,
                    awid_domain_verifier=awid_dns(registry),
                    team_server_transport=transport,
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
            config = cast(ServiceSettings, service.runtime.settings)
            monkeypatch.setattr(
                coordination.server.app.state,
                "manifest_fetcher",
                ManifestFetcher(
                    egress=egress,
                    internal=AppInternalOrigins(
                        frozenset({config.public_origin, logs_origin}), network
                    ),
                ),
                raising=False,
            )
            installation = await _install(coordination, member, config.public_origin)
            logs = await _install(coordination, member, logs_origin)
            verifier = mounted_owner_verifier(service)
            owner = TeamOwner(member.team_key, verifier, member.team_id, verifier.current_team_key)
            await _activate_hooks(
                coordination,
                member,
                owner.for_acts(CORE_ACTS, audience=coordination.server.url),
                {"secrets": installation["app_id"], "logs": logs["app_id"]},
            )
            client = await apps.enter_async_context(
                httpx.AsyncClient(
                    base_url=config.console_origin,
                    trust_env=False,
                    verify=ssl.create_default_context(cafile=str(certificates.ca_file)),
                )
            )
            holder = await _designate(
                service, client, config, coordination, member, installation, dns
            )
            yield RoutedOwner(
                service, coordination, member, config, installation, holder, client, smtp
            )
    finally:
        dns.close()


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
