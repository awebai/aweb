"""Production owner events drain through the supplied real DNS/TLS hook network."""

import asyncio
import json
from datetime import UTC, datetime
from ipaddress import ip_network

import httpx
import pytest
from aweb_naapp.egress import AddressPolicy, DnsResolver, Egress, InternalDestinations
from aweb_naapp.hooks.delivery import ReceiveOptions, verify_delivery
from aweb_naapp_testing import Member
from aweb_naapp_testing.network import DnsServer, TlsServer, local_address, make_certificates
from aweb_naapp_testing.owner_acts import AUDIENCE
from aweb_naapp_testing.smtp import SmtpServer
from awid_service.testing import SERVICE_TOKEN

from aweb_secrets.composition import create_service
from tests.production_authority import authority, install, install_audit_receiver, no_dns_override
from tests.test_composition import settings
from tests.test_production_bootstrap import owner_body


@pytest.mark.parametrize("internal", [False, True])
async def test_production_hook_delivery_uses_explicit_dns_ca_and_internal_network(
    test_db_factory, registry, tmp_path, internal
):
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
        await target.start()
        origin = f"https://{name}:{target.port}"
        async with authority(test_db_factory, registry, member) as (aweb_db, transport):
            database = await test_db_factory.create_db(suffix="production_hook_network")
            with SmtpServer(tmp_path / "smtp") as smtp:
                configured = settings(database, tmp_path, smtp).model_copy(
                    update={
                        "public_origin": AUDIENCE,
                        "awid_service_token": SERVICE_TOKEN,
                    }
                )
                service = create_service(
                    configured,
                    awid_transport=registry.transport,
                    team_server_transport=transport,
                    hook_egress=Egress(
                        addresses=AddressPolicy(internal_destinations=InternalDestinations.ALLOWED),
                        resolver=DnsResolver(nameservers=["127.0.0.1"], port=dns.port),
                        user_agent="secrets-root/hooks-test",
                        ca_file=certificates.ca_file,
                    ),
                    hook_internal_cidr=ip_network(f"{host}/32") if internal else None,
                )
                service.runtime.team_server_directory()._registry_override = no_dns_override
                async with service.api_app.router.lifespan_context(service.api_app):
                    async with httpx.AsyncClient(transport=httpx.ASGITransport(service)) as client:
                        manifest = await client.get(AUDIENCE + "/manifests/v2.json")
                        assert manifest.status_code == 200
                        installed = await install(
                            aweb_db, member, manifest.content, ["secrets:admin"]
                        )
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
                                    "SELECT state,last_error_class FROM outbox_deliveries"
                                )
                                if rows and all(
                                    row["state"] == "delivered"
                                    if internal
                                    else row["last_error_class"] is not None
                                    for row in rows
                                ):
                                    break
                                await asyncio.sleep(0.02)
                        assert dns.queries[(name, "A")] > 0
                        if internal:
                            assert [row["state"] for row in rows] == ["delivered"]
                            assert len(verified) == 1
                            event = verified[0].fields
                            assert event["team_id"] == member.team_id
                            assert event["payload"]["act"] == "role.designated"
                            assert target.seen[0].sni == name
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
