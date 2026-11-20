"""Production owner events drain through the supplied real DNS/TLS hook network.

The hook receiver and the team's coordination server both live on this
host's private address, in the operator's network, under names only the
site's DNS answers and one disposable CA: Secrets reaches both through its
one egress guard, built from its settings.
"""

import asyncio
import json
from contextlib import AsyncExitStack
from datetime import UTC, datetime, timedelta

import dns.asyncresolver as dns_api
import httpx
import pytest
from aweb_logs.chain import open_receipt
from aweb_naapp.hooks.delivery import ReceiveOptions, verify_delivery
from aweb_naapp.hooks.envelope import open_envelope
from aweb_naapp_testing import Member
from aweb_naapp_testing.network import TlsServer
from aweb_naapp_testing.owner_acts import AUDIENCE
from aweb_naapp_testing.smtp import SmtpServer
from aweb_naapp_testing.team_server_site import team_server_site
from awid.dns_verify import awid_txt_value
from awid_service.testing import REGISTRY_URL, SERVICE_TOKEN

from aweb_secrets.composition import create_service
from aweb_secrets.deployment import DeploymentSettings, create_deployment
from tests.human_owner import member_key
from tests.production_authority import (
    authority,
    install,
    install_audit_receiver,
    no_dns_override,
)
from tests.production_logs import logs_receiver
from tests.test_composition import settings
from tests.test_production_bootstrap import enrolled_owner


@pytest.mark.parametrize(
    "listed,deployment",
    [(True, False), (False, False), (True, True)],
    ids=["listed", "not-listed", "deployment"],
)
async def test_production_hook_delivery_uses_explicit_dns_ca_and_internal_network(
    test_db_factory, registry, tmp_path, monkeypatch, listed, deployment
):
    member = Member(member_key=member_key("alice"), team_id="root:example.com")
    name = "logs.root-hooks.test"
    verified = []
    binding_id = None
    origin = ""

    async def receive(seen):
        received = verify_delivery(
            seen.method,
            seen.target,
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

    async with (
        team_server_site(tmp_path / "aweb", also_names=(name,)) as site,
        authority(test_db_factory, registry, member, site) as aweb_db,
    ):
        host, dns = site.host, site.dns
        target = TlsServer(site.certificates, host)
        target.respond = receive
        try:
            if deployment:
                dns.records[("_awid.example.com", "TXT")] = [
                    '"' + awid_txt_value(member.team_did_key, REGISTRY_URL) + '"'
                ]
                system_dns = dns_api.Resolver(configure=False)
                system_dns.nameservers = ["127.0.0.1"]
                system_dns.port = dns.port
                monkeypatch.setattr(dns_api, "default_resolver", system_dns)
            async with AsyncExitStack() as stack:
                if deployment:
                    origin, logs_manifest, logs_db = await stack.enter_async_context(
                        logs_receiver(test_db_factory, registry, site, tmp_path, name)
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
                            **site.settings(),
                            "hook_internal_origins": (
                                frozenset({origin}) if listed else frozenset()
                            ),
                        }
                    )
                    if not deployment:
                        service = create_service(
                            configured,
                            awid_transport=registry.transport,
                            egress=site.egress(configured),
                        )
                    else:
                        service = create_deployment(
                            DeploymentSettings(_env_file=None, **configured.model_dump()),
                            resolver=site.resolver(),
                            awid_transport=registry.transport,
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
                            client.owner_fixture_registry = registry
                            await enrolled_owner(
                                (service, client, configured, member, installed, smtp, site, dns)
                            )
                            db = service.runtime.db()
                            async with asyncio.timeout(10):
                                while True:
                                    rows = await db.fetch_all(
                                        "SELECT event_id,state,last_error_class FROM outbox_deliveries"
                                    )
                                    if rows and all(
                                        row["state"] == "delivered"
                                        if listed
                                        else row["last_error_class"] is not None
                                        for row in rows
                                    ):
                                        break
                                    await asyncio.sleep(0.02)
                            assert dns.queries[(name, "A")] > 0
                            if listed:
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
