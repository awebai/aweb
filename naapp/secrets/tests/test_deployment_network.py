"""The deployment preflight checks all real DNS answers before starting stores."""

import json

import httpx
import pytest
from aweb_naapp.egress import DnsResolver, EgressNotSent, EgressRefused
from aweb_naapp_testing.network import DnsServer, local_address
from aweb_naapp_testing.smtp import SmtpServer

from aweb_secrets.deployment import DeploymentSettings, create_deployment
from tests.test_composition import settings


@pytest.mark.parametrize(
    "answer", ["inside", "outside", "mixed", "denied", "dns_failure", "missing_ca", "malformed_ca"]
)
async def test_hook_origin_addresses_are_checked_before_service_startup(
    test_db_factory, tmp_path, monkeypatch, answer
):
    host, name = local_address(), "logs.deployment.test"
    records = [host] if answer in {"inside", "denied"} else ["192.0.2.7"]
    if answer == "mixed":
        records.append(host)
    dns = DnsServer(records={} if answer == "dns_failure" else {(name, "A"): records})
    await dns.start()
    try:
        database = await test_db_factory.create_db(suffix="deployment_preflight")
        with SmtpServer(tmp_path / "smtp") as smtp:
            monkeypatch.setenv("SECRETS_HOOK_INTERNAL_DESTINATIONS", "allowed")
            monkeypatch.setenv("SECRETS_HOOK_INTERNAL_CIDR", f"{host}/32")
            monkeypatch.setenv("SECRETS_HOOK_INTERNAL_ORIGINS", json.dumps([f"https://{name}"]))
            configured = settings(database, tmp_path, smtp).model_dump()
            if answer in {"missing_ca", "malformed_ca"}:
                ca = tmp_path / "bad-hook-ca"
                if answer == "malformed_ca":
                    ca.write_text("not a certificate")
                monkeypatch.setenv("SECRETS_HOOK_CA_FILE", str(ca))
                with pytest.raises(OSError):
                    create_deployment(DeploymentSettings(_env_file=None, **configured))
                assert not dns.queries
                return
            if answer == "denied":
                configured.pop("egress_denied_networks")
                monkeypatch.setenv("SECRETS_EGRESS_DENIED_NETWORKS", json.dumps([host]))
            deployment = create_deployment(
                DeploymentSettings(_env_file=None, **configured),
                resolver=DnsResolver(nameservers=["127.0.0.1"], port=dns.port),
            )
            context = deployment.api_app.router.lifespan_context(deployment.api_app)
            if answer != "inside":
                with pytest.raises((EgressRefused, EgressNotSent)):
                    async with context:
                        pytest.fail("startup accepted an unauthorized origin address")
                assert deployment.runtime.connected_db() is None
            else:
                async with context:
                    async with httpx.AsyncClient(
                        transport=httpx.ASGITransport(deployment)
                    ) as client:
                        ready = await client.get(configured["public_origin"] + "/ready")
                        assert ready.status_code == 200
                assert deployment.runtime.connected_db() is None
            assert dns.queries[(name, "A")] > 0
    finally:
        dns.close()
