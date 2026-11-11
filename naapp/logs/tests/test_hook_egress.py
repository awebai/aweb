"""logs delivers its hook events through the egress guard its LOGS_ settings
configure: the internal destinations it may reach, the networks it never
reaches and the CA it trusts. Every internal origin's real DNS answers are
checked before logs starts its stores."""

from __future__ import annotations

import json

import httpx
import pytest
from aweb_naapp.egress import DnsResolver, EgressNotSent, EgressRefused
from aweb_naapp_testing.network import DnsServer, local_address
from pydantic import ValidationError

from aweb_logs.app import create_app

from .deployment import no_mail
from .test_app import ORIGIN, _deployment_on

NAME = "receiver.logs-hooks.test"


@pytest.fixture
async def database(test_db_factory):
    return await test_db_factory.create_db(suffix="logs_hook_egress")


async def chain_tables(database) -> int:
    return await database.fetch_value(
        "SELECT count(*) FROM information_schema.tables"
        " WHERE table_schema = $1 AND table_name = 'chain_heads'",
        database.schema or "public",
    )


def internal(monkeypatch: pytest.MonkeyPatch, host: str) -> None:
    monkeypatch.setenv("LOGS_HOOK_INTERNAL_DESTINATIONS", "allowed")
    monkeypatch.setenv("LOGS_HOOK_INTERNAL_CIDR", f"{host}/32")
    monkeypatch.setenv("LOGS_HOOK_INTERNAL_ORIGINS", json.dumps([f"https://{NAME}"]))


@pytest.mark.parametrize("answer", ["inside", "outside", "mixed", "denied", "dns_failure"])
async def test_internal_hook_origins_are_checked_before_logs_starts(
    tmp_path, database, monkeypatch, answer
) -> None:
    host = local_address()
    records = [host] if answer in {"inside", "denied"} else ["192.0.2.7"]
    if answer == "mixed":
        records.append(host)
    dns = DnsServer(records={} if answer == "dns_failure" else {(NAME, "A"): records})
    await dns.start()
    try:
        internal(monkeypatch, host)
        if answer == "denied":
            monkeypatch.setenv("LOGS_EGRESS_DENIED_NETWORKS", json.dumps([host]))
        service = create_app(
            _deployment_on(tmp_path, database),
            email=no_mail(),
            resolver=DnsResolver(nameservers=["127.0.0.1"], port=dns.port),
        )
        context = service.api_app.router.lifespan_context(service.api_app)
        if answer == "inside":
            async with context:
                async with httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=service), base_url=ORIGIN
                ) as client:
                    assert (await client.get("/ready")).status_code == 200
        else:
            with pytest.raises((EgressRefused, EgressNotSent)):
                async with context:
                    pytest.fail("logs started with an unauthorized hook origin address")
            assert await chain_tables(database) == 0
        assert dns.queries[(NAME, "A")] > 0
    finally:
        dns.close()


@pytest.mark.parametrize("ca", ["missing", "malformed"])
def test_logs_refuses_hook_trust_material_it_cannot_load(
    tmp_path, database, monkeypatch, ca
) -> None:
    path = tmp_path / "hook-ca.pem"
    if ca == "malformed":
        path.write_text("not a certificate")
    monkeypatch.setenv("LOGS_HOOK_CA_FILE", str(path))
    with pytest.raises(OSError):
        create_app(_deployment_on(tmp_path, database), email=no_mail())


@pytest.mark.parametrize(
    "unset", ["LOGS_HOOK_INTERNAL_DESTINATIONS", "LOGS_HOOK_INTERNAL_CIDR", "LOGS_HOOK_INTERNAL_ORIGINS"]
)
def test_logs_refuses_internal_hook_settings_given_in_part(
    tmp_path, database, monkeypatch, unset
) -> None:
    internal(monkeypatch, local_address())
    monkeypatch.delenv(unset)
    with pytest.raises(ValidationError):
        _deployment_on(tmp_path, database)
