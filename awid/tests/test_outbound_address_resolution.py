"""Outbound DNS policy over UDP, with strict discovery as the neighboring path."""

import asyncio

import dns.asyncresolver
import dns.message
import dns.rcode
import dns.rrset
import pytest
import pytest_asyncio
from nacl.signing import SigningKey

from awid.did import did_key_from_signing_key
from awid.external_authority import (
    PUBLIC_REGISTRY_ORIGIN,
    SystemTXTOutcomeResolver,
    discover_outbound_registry_authority,
    discover_registry_authority,
)
from awid.federation_errors import FederationAuthorityError

CONTROLLER = did_key_from_signing_key(bytes(SigningKey(bytes(range(32)))))
PIN = "https://private-registry.example"


@pytest_asyncio.fixture
async def dns_server(monkeypatch):
    state = {"rcode": dns.rcode.NOERROR, "records": [], "queries": [], "drop": False}

    class DNS(asyncio.DatagramProtocol):
        def connection_made(self, transport):
            self.transport = transport

        def datagram_received(self, data, address):
            request = dns.message.from_wire(data)
            state["queries"].append(str(request.question[0].name))
            if state["drop"]:
                return
            response = dns.message.make_response(request)
            response.set_rcode(state["rcode"])
            if state["records"]:
                response.answer.append(dns.rrset.from_text(
                    request.question[0].name, 0, "IN", "TXT", *state["records"],
                ))
            self.transport.sendto(response.to_wire(), address)

    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
        DNS, local_addr=("127.0.0.1", 0),
    )
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = ["127.0.0.1"]
    resolver.port = transport.get_extra_info("sockname")[1]
    resolver.timeout = resolver.lifetime = 0.05
    monkeypatch.setattr(dns.asyncresolver, "default_resolver", resolver)
    try:
        yield state
    finally:
        transport.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", ["nxdomain", "nodata", "unrelated", "servfail", "timeout"])
async def test_outbound_fallback_and_strict_discovery_stay_distinct(dns_server, outcome):
    dns_server["rcode"] = {
        "nxdomain": dns.rcode.NXDOMAIN, "servfail": dns.rcode.SERVFAIL,
    }.get(outcome, dns.rcode.NOERROR)
    dns_server["records"] = ['"unrelated=value"'] if outcome == "unrelated" else []
    dns_server["drop"] = outcome == "timeout"
    selected = await discover_outbound_registry_authority(
        "customer.test", SystemTXTOutcomeResolver(), configured_origin=PIN,
    )
    assert selected.registry_origin == PIN
    assert selected.selection == "configured"
    if outcome in {"servfail", "timeout"}:
        with pytest.raises(FederationAuthorityError, match="sender_registry_discovery_failed"):
            await discover_registry_authority("customer.test", SystemTXTOutcomeResolver())
    else:
        strict = await discover_registry_authority("customer.test", SystemTXTOutcomeResolver())
        assert strict.registry_origin == PUBLIC_REGISTRY_ORIGIN
        assert strict.selection == "public_default"
    assert dns_server["queries"]


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", ["refused", "formerr", "malformed", "ambiguous"])
async def test_outbound_never_falls_back_on_rejected_or_bad_dns(dns_server, outcome):
    if outcome in {"refused", "formerr"}:
        dns_server["rcode"] = dns.rcode.REFUSED if outcome == "refused" else dns.rcode.FORMERR
    elif outcome == "malformed":
        dns_server["records"] = ['"awid=v1; controller=invalid;"']
    else:
        dns_server["records"] = [
            f'"awid=v1; controller={CONTROLLER}; registry=https://one.example;"',
            f'"awid=v1; controller={CONTROLLER}; registry=https://two.example;"',
        ]
    for read in (discover_registry_authority, discover_outbound_registry_authority):
        kwargs = {"configured_origin": PIN} if read is discover_outbound_registry_authority else {}
        with pytest.raises(FederationAuthorityError, match="sender_registry_discovery_failed"):
            await read("customer.test", SystemTXTOutcomeResolver(), **kwargs)


@pytest.mark.asyncio
async def test_valid_foreign_record_and_own_domain_pin(dns_server):
    dns_server["records"] = [
        f'"awid=v1; controller={CONTROLLER}; registry=https://foreign.example;"',
    ]
    selected = await discover_outbound_registry_authority(
        "customer.test", SystemTXTOutcomeResolver(), configured_origin=PIN,
    )
    assert selected.registry_origin == "https://foreign.example"
    assert selected.controller_did == CONTROLLER
    dns_server["queries"].clear()
    own = await discover_outbound_registry_authority(
        "customer.test", SystemTXTOutcomeResolver(), configured_origin=PIN, own_domain="customer.test",
    )
    assert own.registry_origin == PIN
    assert dns_server["queries"] == []


# Reuse the existing wire-fault fixture: these are response-validation tests,
# not substitutes for the mounted real-registry server tests.
from test_address_absence_contract import response_server  # noqa: E402,F401
from awid.did import stable_id_from_public_key  # noqa: E402
from awid.registry import RegistryClient, RegistryError  # noqa: E402


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", [
    None, "domain", "name", "key", "origin", "key-mismatch", "key-404",
    "key-malformed", "address-absent", "legacy-address-absent", "uncoded-404",
    "namespace-domain", "namespace-controller", "namespace-404",
])
async def test_outbound_reader_checks_selected_registry_binding(response_server, fault):  # noqa: F811
    state = response_server
    stable = stable_id_from_public_key(bytes(SigningKey(bytes(range(32))).verify_key))
    address = {
        "address_id": "address", "domain": "customer.test", "name": "bob",
        "did_aw": stable, "current_did_key": CONTROLLER, "created_at": "2026-11-19T00:00:00Z",
        "delivery": {"origin": "https://server.example"},
    }
    key = {"did_aw": stable, "current_did_key": CONTROLLER}
    if fault in {"domain", "name"}:
        address[fault] = "wrong"
    elif fault == "key":
        address["current_did_key"] = "did:key:invalid"
    elif fault == "origin":
        address["delivery"]["origin"] = "not-an-origin"
    elif fault == "key-mismatch":
        key["current_did_key"] = did_key_from_signing_key(bytes(SigningKey(bytes(reversed(range(32))))))
    elif fault == "key-malformed":
        key = {}
    namespace = {"domain": "customer.test", "controller_did": CONTROLLER}
    if fault == "namespace-domain":
        namespace["domain"] = "wrong.test"
    elif fault == "namespace-controller":
        namespace["controller_did"] = "did:key:invalid"
    first = {"status": 200, "body": address}
    if fault in {"address-absent", "uncoded-404"}:
        first = {"status": 404, "body": {"detail":
            {"code": "address_not_found"} if fault == "address-absent" else "Not Found"}}
    if fault == "legacy-address-absent":
        first = {"status": 404, "body": {"detail": "Address not found"}}
    state["responses"] = [
        first, {"status": 404 if fault == "key-404" else 200, "body": key},
        {"status": 404 if fault == "namespace-404" else 200, "body": namespace},
    ]
    client = RegistryClient(state["origin"])
    try:
        if fault is None:
            result = await client.resolve_outbound_address("customer.test", "bob", own_domain="customer.test")
            assert result.did_aw == stable
            assert result.current_did_key == CONTROLLER
            assert result.delivery.origin == "https://server.example"
            assert len(state["requests"]) == 3
        elif fault in {"address-absent", "legacy-address-absent"}:
            assert await client.resolve_outbound_address("customer.test", "bob", own_domain="customer.test") is None
            assert len(state["requests"]) == 1
        else:
            with pytest.raises((FederationAuthorityError, RegistryError)):
                await client.resolve_outbound_address("customer.test", "bob", own_domain="customer.test")
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_outbound_handle_namespace_keeps_literal_underscore(dns_server):
    selected = await discover_outbound_registry_authority(
        "contact_team.test", SystemTXTOutcomeResolver(), configured_origin=PIN,
    )
    assert selected.registry_origin == PIN
    assert dns_server["queries"] == ["_awid.contact_team.test."]
    with pytest.raises(FederationAuthorityError, match="sender_registry_unresolvable"):
        await discover_registry_authority("contact_team.test", SystemTXTOutcomeResolver())
