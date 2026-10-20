"""The egress guard against real local DNS and TLS servers.

The TLS server listens on loopback, which the address policy denies. Tests that
must reach it run as an internal destination with the exact CIDR 127.0.0.1/32
under ``internal_destinations: allowed``. Tests of denied addresses never need
a server: the guard refuses before it connects.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from dataclasses import dataclass
from ipaddress import ip_address, ip_network
from pathlib import Path

import pytest

from aweb_naapp.egress import (
    AddressPolicy,
    Bounds,
    DnsResolver,
    Egress,
    EgressNotSent,
    EgressOutcomeUnknown,
    EgressRefused,
    InternalDestinations,
    canonical_url,
)

from .servers import Certificates, DnsServer, TlsServer, make_certificates

NAME = "api.egress.test"
OTHER_NAME = "other.egress.test"
LOOPBACK = ip_network("127.0.0.1/32")
ALLOWED = AddressPolicy(internal_destinations=InternalDestinations.ALLOWED)


@dataclass
class Network:
    dns: DnsServer
    tls: TlsServer
    certificates: Certificates

    def egress(self, policy: AddressPolicy = ALLOWED, bounds: Bounds | None = None) -> Egress:
        return Egress(
            addresses=policy,
            resolver=DnsResolver(nameservers=["127.0.0.1"], port=self.dns.port),
            user_agent="egress-test/1",
            ca_file=self.certificates.ca_file,
            bounds=bounds or Bounds(),
        )

    def url(self, path: str, name: str = NAME) -> str:
        return f"https://{name}:{self.tls.port}{path}"


@pytest.fixture
async def network(tmp_path: Path) -> AsyncIterator[Network]:
    certificates = make_certificates(tmp_path, [NAME, OTHER_NAME], ["127.0.0.1"])
    dns = DnsServer(records={(NAME, "A"): ["127.0.0.1"]})
    tls = TlsServer(certificates)
    await dns.start()
    await tls.start()
    try:
        yield Network(dns, tls, certificates)
    finally:
        dns.close()
        await tls.close()


async def test_pinned_connection_sends_sni_and_host_as_the_canonical_name(
    network: Network,
) -> None:
    response = await network.egress().send(
        "GET", canonical_url(network.url("/echo", name="API.Egress.TEST")), internal=LOOPBACK
    )
    assert response.status == 200
    assert response.address == ip_address("127.0.0.1")
    seen = network.tls.seen[-1]
    assert seen.sni == NAME
    assert seen.request_line == "GET /echo HTTP/1.1"
    headers = {name.lower(): value for name, value in seen.headers}
    assert headers["host"] == f"{NAME}:{network.tls.port}"
    assert headers["user-agent"] == "egress-test/1"


async def test_caller_headers_and_body_are_sent(network: Network) -> None:
    await network.egress().send(
        "POST",
        canonical_url(network.url("/echo")),
        headers=[("Content-Type", "application/json"), ("X-Vendor", "1")],
        header_allow=["X-Vendor"],
        body=b'{"a": 1}',
        internal=LOOPBACK,
    )
    seen = network.tls.seen[-1]
    assert ("Content-Type", "application/json") in seen.headers
    assert ("X-Vendor", "1") in seen.headers
    assert seen.body == b'{"a": 1}'


async def test_refused_header_sends_nothing(network: Network) -> None:
    with pytest.raises(EgressRefused) as refused:
        await network.egress().send(
            "GET",
            canonical_url(network.url("/ok")),
            headers=[("Authorization", "Bearer canary")],
            header_allow=["Authorization"],
            internal=LOOPBACK,
        )
    assert refused.value.code == "header_not_allowed"
    assert network.tls.seen == []
    assert sum(network.dns.queries.values()) == 0


DENIED_ANSWERS = [
    ("A", "127.0.0.1"),
    ("A", "10.1.2.3"),
    ("A", "172.16.5.4"),
    ("A", "192.168.0.10"),
    ("A", "100.64.1.1"),
    ("A", "169.254.169.254"),
    ("A", "0.0.0.0"),
    ("A", "224.0.0.251"),
    ("A", "255.255.255.255"),
    ("A", "198.18.0.1"),
    ("AAAA", "::1"),
    ("AAAA", "fe80::1"),
    ("AAAA", "fd00::1"),
    ("AAAA", "ff02::1"),
    ("AAAA", "::ffff:10.0.0.1"),
    ("AAAA", "::ffff:169.254.169.254"),
    ("AAAA", "64:ff9b::a9fe:a9fe"),
    ("AAAA", "2002:a00:1::1"),
    ("AAAA", "2001:0:4136:e378:8000:63bf:f5ff:fffe"),
]


@pytest.mark.parametrize(("kind", "address"), DENIED_ANSWERS)
async def test_name_resolving_to_a_denied_range_is_refused(
    network: Network, kind: str, address: str
) -> None:
    network.dns.records = {("denied.egress.test", kind): [address]}
    with pytest.raises(EgressRefused) as refused:
        await network.egress(AddressPolicy()).send(
            "GET", canonical_url(network.url("/ok", name="denied.egress.test"))
        )
    assert refused.value.code == "destination_address_denied"
    assert network.dns.queries[("denied.egress.test", kind)] == 1
    assert network.tls.seen == []


async def test_one_public_and_one_private_record_is_refused(network: Network) -> None:
    network.dns.records = {
        ("mixed.egress.test", "A"): ["93.184.215.14"],
        ("mixed.egress.test", "AAAA"): ["fd00::7"],
    }
    with pytest.raises(EgressRefused) as refused:
        await network.egress(AddressPolicy()).send(
            "GET", canonical_url(network.url("/ok", name="mixed.egress.test"))
        )
    assert refused.value.code == "destination_address_denied"


async def test_answer_changing_between_check_and_connect_cannot_move_the_connection(
    network: Network,
) -> None:
    # The first answer is the validated loopback server; any later lookup
    # would return an address outside the destination's CIDR.
    network.dns.records = {
        (NAME, "A"): lambda count: ["127.0.0.1"] if count == 1 else ["10.9.9.9"],
    }
    response = await network.egress().send(
        "GET", canonical_url(network.url("/ok")), internal=LOOPBACK
    )
    assert response.status == 200
    assert response.address == ip_address("127.0.0.1")
    assert network.dns.queries[(NAME, "A")] == 1
    assert len(network.tls.seen) == 1


async def test_redirect_is_returned_with_location_intact(network: Network) -> None:
    response = await network.egress().send(
        "GET", canonical_url(network.url("/redirect")), internal=LOOPBACK
    )
    assert response.status == 302
    assert ("location", "https://elsewhere.example/next") in [
        (name.lower(), value) for name, value in response.headers
    ]
    assert len(network.tls.seen) == 1


async def test_proxy_in_the_environment_has_no_effect(
    network: Network, monkeypatch: pytest.MonkeyPatch
) -> None:
    for variable in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(variable, "http://127.0.0.1:9")
    response = await network.egress().send(
        "GET", canonical_url(network.url("/ok")), internal=LOOPBACK
    )
    assert response.status == 200
    assert len(network.tls.seen) == 1


async def test_certificate_from_an_untrusted_ca_is_not_sent(network: Network) -> None:
    # Only the system trust store: the test CA is not in it.
    egress = Egress(
        addresses=ALLOWED,
        resolver=DnsResolver(nameservers=["127.0.0.1"], port=network.dns.port),
        user_agent="egress-test/1",
    )
    with pytest.raises(EgressNotSent):
        await egress.send("GET", canonical_url(network.url("/ok")), internal=LOOPBACK)
    assert network.tls.seen == []


async def test_certificate_for_another_name_is_not_sent(network: Network) -> None:
    network.dns.records = {("unnamed.egress.test", "A"): ["127.0.0.1"]}
    with pytest.raises(EgressNotSent):
        await network.egress().send(
            "GET", canonical_url(network.url("/ok", name="unnamed.egress.test")), internal=LOOPBACK
        )
    assert network.tls.seen == []


async def test_unknown_name_is_not_sent(network: Network) -> None:
    with pytest.raises(EgressNotSent):
        await network.egress().send(
            "GET", canonical_url(network.url("/ok", name="missing.egress.test")), internal=LOOPBACK
        )


async def test_closed_port_is_not_sent(network: Network) -> None:
    with pytest.raises(EgressNotSent):
        await network.egress().send("GET", canonical_url(f"https://{NAME}:9/ok"), internal=LOOPBACK)


async def test_no_answer_within_the_total_bound_is_outcome_unknown(network: Network) -> None:
    egress = network.egress(bounds=Bounds(total_timeout=0.5))
    with pytest.raises(EgressOutcomeUnknown):
        await egress.send("GET", canonical_url(network.url("/slow")), internal=LOOPBACK)
    assert len(network.tls.seen) == 1


async def test_response_over_the_bound_is_truncated_and_reported(network: Network) -> None:
    egress = network.egress(bounds=Bounds(max_response_bytes=1000))
    response = await egress.send(
        "GET", canonical_url(network.url("/big?n=5000")), internal=LOOPBACK
    )
    assert response.truncated is True
    assert len(response.body) == 1000
    whole = await egress.send("GET", canonical_url(network.url("/big?n=1000")), internal=LOOPBACK)
    assert whole.truncated is False
    assert len(whole.body) == 1000


async def test_request_body_over_the_bound_sends_nothing(network: Network) -> None:
    egress = network.egress(bounds=Bounds(max_request_bytes=10))
    with pytest.raises(EgressRefused):
        await egress.send(
            "POST", canonical_url(network.url("/echo")), body=b"x" * 11, internal=LOOPBACK
        )
    assert network.tls.seen == []
    assert sum(network.dns.queries.values()) == 0


def test_bounds_can_only_be_lowered() -> None:
    Bounds(connect_timeout=1, total_timeout=2, max_request_bytes=10, max_response_bytes=10)
    for raised in (
        {"connect_timeout": 5.1},
        {"total_timeout": 30.1},
        {"max_request_bytes": 1024 * 1024 + 1},
        {"max_response_bytes": 4 * 1024 * 1024 + 1},
        {"total_timeout": 0},
    ):
        with pytest.raises(ValueError):
            Bounds(**raised)  # type: ignore[arg-type]


async def test_internal_destination_is_refused_when_disabled(network: Network) -> None:
    with pytest.raises(EgressRefused) as refused:
        await network.egress(AddressPolicy()).send(
            "GET", canonical_url(network.url("/ok")), internal=LOOPBACK
        )
    assert refused.value.code == "internal_destinations_disabled"
    assert sum(network.dns.queries.values()) == 0


async def test_ip_literal_is_refused_when_disabled(network: Network) -> None:
    for internal in (LOOPBACK, None):
        with pytest.raises(EgressRefused) as refused:
            await network.egress(AddressPolicy()).send(
                "GET", canonical_url(f"https://127.0.0.1:{network.tls.port}/ok"), internal=internal
            )
        assert refused.value.code == "internal_destinations_disabled"
    assert network.tls.seen == []


async def test_ip_literal_passes_as_an_exact_internal_cidr_when_allowed(network: Network) -> None:
    response = await network.egress().send(
        "GET", canonical_url(f"https://127.0.0.1:{network.tls.port}/echo"), internal=LOOPBACK
    )
    assert response.status == 200
    assert sum(network.dns.queries.values()) == 0
    assert json.loads(response.body)["sni"] is None


async def test_internal_cidr_must_hold_the_resolved_address(network: Network) -> None:
    with pytest.raises(EgressRefused) as refused:
        await network.egress().send(
            "GET", canonical_url(network.url("/ok")), internal=ip_network("127.0.0.2/32")
        )
    assert refused.value.code == "destination_address_denied"
    assert network.tls.seen == []
