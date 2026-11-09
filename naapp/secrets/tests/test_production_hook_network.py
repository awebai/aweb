"""Production owner events drain through the supplied real DNS/TLS hook network."""

import asyncio
import json
from contextlib import AsyncExitStack
from datetime import UTC, datetime, timedelta
from ipaddress import ip_network

import dns.asyncresolver as dns_api
import httpx
import pytest
from aweb_logs.chain import open_receipt
from aweb_naapp.egress import AddressPolicy, DnsResolver, Egress, InternalDestinations
from aweb_naapp.hooks.delivery import ReceiveOptions, verify_delivery
from aweb_naapp.hooks.envelope import open_envelope
from aweb_naapp_testing import Member
from aweb_naapp_testing.network import DnsServer, TlsServer, local_address, make_certificates
from aweb_naapp_testing.owner_acts import AUDIENCE
from aweb_naapp_testing.smtp import SmtpServer
from awid.dns_verify import awid_txt_value
from awid_service.testing import REGISTRY_URL, SERVICE_TOKEN

from aweb_secrets.composition import create_service
from aweb_secrets.deployment import DeploymentSettings, create_deployment
from tests.production_authority import authority, install, install_audit_receiver, no_dns_override
from tests.production_logs import logs_receiver
from tests.test_composition import settings
from tests.test_production_bootstrap import owner_body


@pytest.mark.parametrize(
    "internal,listed,denied,guard_denied,deployment",
    [
        (False, True, False, False, False),
        (True, True, False, False, False),
        (True, False, False, False, False),
        (True, True, True, False, False),
        (True, True, False, True, False),
        (True, True, False, False, True),
    ],
)
async def test_production_hook_delivery_uses_explicit_dns_ca_and_internal_network(
    test_db_factory,
    registry,
    tmp_path,
    monkeypatch,
    internal,
    listed,
    denied,
    guard_denied,
    deployment,
):
    deliverable = internal and listed and not denied and not guard_denied
    member = Member(team_id="root:example.com")
    host, name = local_address(), "logs.root-hooks.test"
    certificates = make_certificates(tmp_path, [name], [host])
    dns = DnsServer(records={(name, "A"): [host]})
    target = TlsServer(certificates, host)
    verified = []
    binding_id = None
    origin = ""

    async def receive(seen):
        method, path, _ = seen.request_line.split(" ")
        received = verify_delivery(
            method,
            path,
            dict(seen.headers),
            seen.body,
            ReceiveOptions(audience=origin, binding_id=binding_id, now=datetime.now(UTC)),
        )
        verified.append(received.envelope)
        return (
            200,
            json.dumps(
                {
                    "event_id": str(received.envelope.event_id),
                    "disposition": "appended",
                }
            ).encode(),
            [("Content-Type", "application/json")],
        )

    target.respond = receive
    await dns.start()
    try:
        if deployment:
            dns.records[("_awid.example.com", "TXT")] = [
                '"' + awid_txt_value(member.team_did_key, REGISTRY_URL) + '"'
            ]
            system_dns = dns_api.Resolver(configure=False)
            system_dns.nameservers = ["127.0.0.1"]
            system_dns.port = dns.port
            monkeypatch.setattr(dns_api, "default_resolver", system_dns)
        async with authority(test_db_factory, registry, member) as (aweb_db, transport):
            async with AsyncExitStack() as stack:
                if deployment:
                    origin, logs_manifest, logs_db = await stack.enter_async_context(
                        logs_receiver(
                            test_db_factory, registry, transport, tmp_path, host, name, certificates
                        )
                    )
                else:
                    await target.start()
                    origin = f"https://{name}:{target.port}"
                database = await test_db_factory.create_db(suffix="production_hook_network")
                with SmtpServer(tmp_path / "smtp") as smtp:
                    configured = settings(database, tmp_path, smtp).model_copy(
                        update={
                            "public_origin": AUDIENCE,
                            "awid_service_token": SERVICE_TOKEN,
                            "egress_denied_networks": (
                                ip_network(f"{host}/32" if denied else "192.0.2.0/24"),
                            ),
                        }
                    )
                    if not deployment:
                        service = create_service(
                            configured,
                            awid_transport=registry.transport,
                            team_server_transport=transport,
                            hook_egress=Egress(
                                addresses=AddressPolicy(
                                    internal_destinations=InternalDestinations.ALLOWED,
                                    denied=(
                                        ip_network(
                                            f"{host}/32" if guard_denied else "198.51.100.0/24"
                                        ),
                                    ),
                                ),
                                resolver=DnsResolver(nameservers=["127.0.0.1"], port=dns.port),
                                user_agent="secrets-root/hooks-test",
                                ca_file=certificates.ca_file,
                            ),
                            hook_internal_cidr=ip_network(f"{host}/32") if internal else None,
                            hook_internal_origins=frozenset({origin}) if listed else frozenset(),
                        )
                    else:
                        monkeypatch.setenv("SECRETS_HOOK_INTERNAL_DESTINATIONS", "allowed")
                        monkeypatch.setenv("SECRETS_HOOK_INTERNAL_CIDR", f"{host}/32")
                        monkeypatch.setenv("SECRETS_HOOK_INTERNAL_ORIGINS", json.dumps([origin]))
                        monkeypatch.setenv("SECRETS_HOOK_CA_FILE", str(certificates.ca_file))
                        service = create_deployment(
                            DeploymentSettings(_env_file=None, **configured.model_dump()),
                            resolver=DnsResolver(nameservers=["127.0.0.1"], port=dns.port),
                            awid_transport=registry.transport,
                            team_server_transport=transport,
                        )
                    if not deployment:
                        service.runtime.team_server_directory()._registry_override = no_dns_override
                    async with service.api_app.router.lifespan_context(service.api_app):
                        async with httpx.AsyncClient(
                            transport=httpx.ASGITransport(service)
                        ) as client:
                            manifest = await client.get(AUDIENCE + "/manifests/v2.json")
                            assert manifest.status_code == 200
                            installed = await install(
                                aweb_db, member, manifest.content, ["secrets:admin"]
                            )
                            if deployment:
                                await install(aweb_db, member, logs_manifest, [])
                                # External owner-activation precondition, as in the
                                # existing receiver fixture; no ceremony is claimed.
                                await aweb_db.execute(
                                    "UPDATE {{tables.app_hook_bindings}} SET state='active',activated_at=$2::timestamptz - INTERVAL '60 seconds',active_from=$2,activation_act_sha256=$3 WHERE team_id=$1",
                                    member.team_id,
                                    datetime.now(UTC) - timedelta(minutes=1),
                                    "ab" * 32,
                                )
                            else:
                                await install_audit_receiver(aweb_db, member, origin=origin)
                            view = await service.runtime.hook_registrations().view(
                                member.team_id,
                                "post-governance-hook",
                            )
                            assert view is not None and len(view.registrations) == 1
                            binding_id = view.registrations[0].binding_id
                            _, body = owner_body(configured, member, installed["installation_id"])
                            response = await client.post(
                                configured.console_origin
                                + f"/installations/{installed['installation_id']}/owner-acts",
                                json=body,
                            )
                            assert response.status_code == 200
                            db = service.runtime.db()
                            async with asyncio.timeout(10):
                                while True:
                                    rows = await db.fetch_all(
                                        "SELECT event_id,state,last_error_class FROM outbox_deliveries"
                                    )
                                    if rows and all(
                                        row["state"] == "delivered"
                                        if deliverable
                                        else row["last_error_class"] is not None
                                        for row in rows
                                    ):
                                        break
                                    await asyncio.sleep(0.02)
                            assert dns.queries[(name, "A")] > 0
                            if deliverable:
                                assert [row["state"] for row in rows] == ["delivered"]
                                if deployment:
                                    records = await logs_db.fetch_all(
                                        "SELECT event_id,signing_bytes,receipt_bytes,receipt_signature FROM {{tables.chain_events}} WHERE team_id=$1",
                                        member.team_id,
                                    )
                                    assert len(records) == 1
                                    record = records[0]
                                    receipt = open_receipt(
                                        record["receipt_bytes"], record["receipt_signature"]
                                    )
                                    assert (
                                        str(receipt.event_id)
                                        == str(rows[0]["event_id"])
                                        == str(record["event_id"])
                                    )
                                    assert (
                                        receipt.team_id == member.team_id and receipt.team_seq == 1
                                    )
                                    expected = next(
                                        key["did_key"]
                                        for key in json.loads(logs_manifest)["app_keys"]
                                        if "logs-receipt" in key["purposes"]
                                    )
                                    assert receipt.did_key == expected
                                    event = open_envelope(record["signing_bytes"]).fields
                                    assert dns.queries[("_awid.example.com", "TXT")] > 0
                                else:
                                    assert len(verified) == 1
                                    event = verified[0].fields
                                    assert target.seen[0].sni == name
                                assert event["team_id"] == member.team_id
                                assert event["payload"]["act"] == "role.designated"
                            else:
                                assert [row["state"] for row in rows] == ["pending"]
                                assert (
                                    rows[0]["last_error_class"]
                                    == "egress_refused:destination_address_denied"
                                )
                                assert target.seen == [] and verified == []
                    assert service.runtime.connected_db() is None
    finally:
        await target.close()
        dns.close()
