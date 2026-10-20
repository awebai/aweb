"""The egress guard against real local DNS and TLS servers.

The guard refuses loopback for every destination, so the TLS server listens on
this host's own non-loopback address, and tests that reach it name it as an
internal destination with that address's exact CIDR, under
``internal_destinations: allowed``. Tests of refused addresses use public
destinations and never need a server: the guard refuses before it connects.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from dataclasses import dataclass
from ipaddress import ip_address
from pathlib import Path

import pytest

from aweb_naapp.egress import (
    AddressPolicy,
    Bounds,
    CanonicalURL,
    Destination,
    DnsResolver,
    Egress,
    EgressNotSent,
    EgressOutcomeUnknown,
    EgressRefused,
    HeaderRules,
    InternalDestinations,
    parse_destination,
)

from .servers import Certificates, DnsServer, TlsServer, local_address, make_certificates

NAME = "api.egress.test"
ALLOWED = AddressPolicy(internal_destinations=InternalDestinations.ALLOWED)
RULES = HeaderRules(injected=[], amz_allowed=[], is_credential=lambda value: False)
METHODS = ["GET", "POST"]


@dataclass
class Network:
    dns: DnsServer
    tls: TlsServer
    certificates: Certificates
    host: str

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

    def internal(self, host: str = NAME, cidr: str | None = None, **entry) -> Destination:
        """The TLS server as an internal destination, confirmed while allowed."""
        return parse_destination(
            {
                "host": host,
                "port": self.tls.port,
                "path": "/**",
                "methods": METHODS,
                "network": "internal",
                "cidr": cidr or f"{self.host}/32",
                **entry,
            },
            internal_destinations=InternalDestinations.ALLOWED,
        )

    def public(self, host: str) -> Destination:
        return parse_destination(
            {"host": host, "port": self.tls.port, "path": "/**", "methods": METHODS},
            internal_destinations=InternalDestinations.DISABLED,
        )


@pytest.fixture
async def network(tmp_path: Path) -> AsyncIterator[Network]:
    host = local_address()
    certificates = make_certificates(tmp_path, [NAME], [host])
    dns = DnsServer(records={(NAME, "A"): [host]})
    tls = TlsServer(certificates, host)
    await dns.start()
    await tls.start()
    try:
        yield Network(dns, tls, certificates, host)
    finally:
        dns.close()
        await tls.close()


async def _send(network: Network, method: str, path: str, **kwargs):
    destination = kwargs.pop("destination", None) or network.internal()
    egress = kwargs.pop("egress", None) or network.egress()
    url = kwargs.pop("url", None) or network.url(path)
    return await egress.send(method, url, destination, header_rules=RULES, **kwargs)


async def test_pinned_connection_sends_sni_and_host_as_the_canonical_name(
    network: Network,
) -> None:
    response = await _send(network, "GET", "", url=network.url("/echo", name="API.Egress.TEST"))
    assert response.status == 200
    assert response.address == ip_address(network.host)
    seen = network.tls.seen[-1]
    assert seen.sni == NAME
    assert seen.request_line == "GET /echo HTTP/1.1"
    headers = {name.lower(): value for name, value in seen.headers}
    assert headers["host"] == f"{NAME}:{network.tls.port}"
    assert headers["user-agent"] == "egress-test/1"


async def test_caller_headers_and_body_are_sent(network: Network) -> None:
    await _send(
        network,
        "POST",
        "/echo",
        destination=network.internal(header_allow=["X-Vendor"]),
        headers=[("Content-Type", "application/json"), ("X-Vendor", "1")],
        body=b'{"a": 1}',
    )
    seen = network.tls.seen[-1]
    assert ("Content-Type", "application/json") in seen.headers
    assert ("X-Vendor", "1") in seen.headers
    assert seen.body == b'{"a": 1}'


async def test_refused_header_sends_nothing(network: Network) -> None:
    with pytest.raises(EgressRefused) as refused:
        await _send(
            network,
            "GET",
            "/ok",
            destination=network.internal(header_allow=["Authorization"]),
            headers=[("Authorization", "Bearer canary")],
        )
    assert refused.value.code == "header_not_allowed"
    assert network.tls.seen == []
    assert sum(network.dns.queries.values()) == 0


async def test_a_url_outside_the_destination_sends_nothing(network: Network) -> None:
    narrow = network.internal(path="/v1/**")
    for method, url in (
        ("GET", network.url("/v2/x")),
        ("DELETE", network.url("/v1/x")),
        ("GET", f"https://other.egress.test:{network.tls.port}/v1/x"),
    ):
        with pytest.raises(EgressRefused) as refused:
            await _send(network, method, "", url=url, destination=narrow)
        assert refused.value.code == "destination_not_in_scope"
    assert network.tls.seen == []
    assert sum(network.dns.queries.values()) == 0


async def test_a_hand_built_url_is_canonicalized_again(network: Network) -> None:
    forged = CanonicalURL(host=NAME, port=network.tls.port, path="/v1/../admin")
    with pytest.raises(EgressRefused) as refused:
        await _send(network, "GET", "", url=forged, destination=network.internal(path="/v1/**"))
    assert (refused.value.code, refused.value.rule) == ("destination_not_in_scope", "path")
    assert network.tls.seen == []


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
    ("AAAA", "fd00:ec2::254"),
    ("AAAA", "ff02::1"),
    ("AAAA", "::ffff:10.0.0.1"),
    ("AAAA", "::ffff:169.254.169.254"),
    ("AAAA", "::ffff:0:a9fe:a9fe"),
    ("AAAA", "64:ff9b::a9fe:a9fe"),
    ("AAAA", "2002:a00:1::1"),
    ("AAAA", "2001:0:4136:e378:8000:63bf:f5ff:fffe"),
    ("AAAA", "5f00::1"),
]


@pytest.mark.parametrize(("kind", "address"), DENIED_ANSWERS)
async def test_name_resolving_to_a_denied_range_is_refused(
    network: Network, kind: str, address: str
) -> None:
    name = "denied.egress.test"
    network.dns.records = {(name, kind): [address]}
    with pytest.raises(EgressRefused) as refused:
        await _send(
            network,
            "GET",
            "",
            url=network.url("/ok", name=name),
            destination=network.public(name),
            egress=network.egress(AddressPolicy()),
        )
    assert refused.value.code == "destination_address_denied"
    assert network.dns.queries[(name, kind)] == 1
    assert network.tls.seen == []


async def test_one_public_and_one_private_record_is_refused(network: Network) -> None:
    name = "mixed.egress.test"
    network.dns.records = {(name, "A"): ["93.184.215.14"], (name, "AAAA"): ["fd00::7"]}
    with pytest.raises(EgressRefused) as refused:
        await _send(
            network,
            "GET",
            "",
            url=network.url("/ok", name=name),
            destination=network.public(name),
            egress=network.egress(AddressPolicy()),
        )
    assert refused.value.code == "destination_address_denied"


async def test_answer_changing_between_check_and_connect_cannot_move_the_connection(
    network: Network,
) -> None:
    # The first answer is the validated server; any later lookup would return
    # an address outside the destination's CIDR.
    network.dns.records = {
        (NAME, "A"): lambda count: [network.host] if count == 1 else ["10.9.9.9"],
    }
    response = await _send(network, "GET", "/ok")
    assert response.status == 200
    assert response.address == ip_address(network.host)
    assert network.dns.queries[(NAME, "A")] == 1
    assert len(network.tls.seen) == 1


async def test_redirect_is_returned_with_location_intact(network: Network) -> None:
    response = await _send(network, "GET", "/redirect")
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
    response = await _send(network, "GET", "/ok")
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
        await _send(network, "GET", "/ok", egress=egress)
    assert network.tls.seen == []


async def test_certificate_for_another_name_is_not_sent(network: Network) -> None:
    name = "unnamed.egress.test"
    network.dns.records = {(name, "A"): [network.host]}
    with pytest.raises(EgressNotSent):
        await _send(
            network,
            "GET",
            "",
            url=network.url("/ok", name=name),
            destination=network.internal(name),
        )
    assert network.tls.seen == []


async def test_unknown_name_is_not_sent(network: Network) -> None:
    name = "missing.egress.test"
    with pytest.raises(EgressNotSent):
        await _send(
            network,
            "GET",
            "",
            url=network.url("/ok", name=name),
            destination=network.internal(name),
        )


async def test_closed_port_is_not_sent(network: Network) -> None:
    destination = network.internal(port=9)
    with pytest.raises(EgressNotSent):
        await _send(network, "GET", "", url=f"https://{NAME}:9/ok", destination=destination)


async def test_no_answer_within_the_total_bound_is_outcome_unknown(network: Network) -> None:
    with pytest.raises(EgressOutcomeUnknown):
        await _send(
            network, "GET", "/slow", egress=network.egress(bounds=Bounds(total_timeout=0.5))
        )
    assert len(network.tls.seen) == 1


async def test_resolution_counts_against_the_total_bound(network: Network) -> None:
    # A slow answer and an upstream that never answers must still end at the total bound.
    network.dns.delay = 0.6
    egress = network.egress(bounds=Bounds(connect_timeout=1.0, total_timeout=1.0))
    started = asyncio.get_running_loop().time()
    with pytest.raises(EgressOutcomeUnknown):
        await _send(network, "GET", "/slow", egress=egress)
    assert asyncio.get_running_loop().time() - started < 1.3


async def test_resolution_past_the_total_bound_is_not_sent(network: Network) -> None:
    network.dns.delay = 1.0
    egress = network.egress(bounds=Bounds(connect_timeout=2.0, total_timeout=0.5))
    started = asyncio.get_running_loop().time()
    with pytest.raises(EgressNotSent):
        await _send(network, "GET", "/ok", egress=egress)
    assert asyncio.get_running_loop().time() - started < 0.8
    assert network.tls.seen == []


async def test_response_over_the_bound_is_truncated_and_reported(network: Network) -> None:
    egress = network.egress(bounds=Bounds(max_response_bytes=1000))
    response = await _send(network, "GET", "/big?n=5000", egress=egress)
    assert response.truncated is True
    assert len(response.body) == 1000
    whole = await _send(network, "GET", "/big?n=1000", egress=egress)
    assert whole.truncated is False
    assert len(whole.body) == 1000


async def test_request_body_over_the_bound_sends_nothing(network: Network) -> None:
    egress = network.egress(bounds=Bounds(max_request_bytes=10))
    with pytest.raises(EgressRefused):
        await _send(network, "POST", "/echo", egress=egress, body=b"x" * 11)
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
        await _send(network, "GET", "/ok", egress=network.egress(AddressPolicy()))
    assert refused.value.code == "internal_destinations_disabled"
    assert sum(network.dns.queries.values()) == 0


async def test_ip_literal_is_refused_when_disabled(network: Network) -> None:
    literal = f"https://{network.host}:{network.tls.port}/ok"
    with pytest.raises(EgressRefused) as refused:
        await _send(
            network,
            "GET",
            "",
            url=literal,
            destination=network.internal(host=network.host),
            egress=network.egress(AddressPolicy()),
        )
    assert refused.value.code == "internal_destinations_disabled"
    with pytest.raises(EgressRefused) as refused:
        await _send(network, "GET", "", url=literal, destination=network.public("api.example.com"))
    assert refused.value.code == "destination_not_in_scope"
    assert network.tls.seen == []


async def test_ip_literal_passes_as_an_exact_internal_cidr_when_allowed(network: Network) -> None:
    response = await _send(
        network,
        "GET",
        "",
        url=f"https://{network.host}:{network.tls.port}/echo",
        destination=network.internal(host=network.host),
    )
    assert response.status == 200
    assert sum(network.dns.queries.values()) == 0
    assert json.loads(response.body)["sni"] is None


async def test_internal_cidr_must_hold_the_resolved_address(network: Network) -> None:
    with pytest.raises(EgressRefused) as refused:
        await _send(network, "GET", "/ok", destination=network.internal(cidr="10.99.0.0/16"))
    assert refused.value.code == "destination_address_denied"
    assert network.tls.seen == []


# Injected credential headers and the encoding the guard asks for

INJECTING = HeaderRules(
    injected=["Authorization", "X-Vendor-Key"], amz_allowed=[], is_credential=lambda value: False
)


def _sent_headers(network: Network) -> dict[str, list[str]]:
    sent: dict[str, list[str]] = {}
    for name, value in network.tls.seen[-1].headers:
        sent.setdefault(name.lower(), []).append(value)
    return sent


async def test_an_injected_credential_header_reaches_the_wire(network: Network) -> None:
    egress = network.egress()
    await egress.send(
        "GET",
        network.url("/echo"),
        network.internal(header_allow=["X-Vendor"]),
        header_rules=INJECTING,
        headers=[("X-Vendor", "1")],
        injected=[("Authorization", "Bearer canary-token"), ("X-Vendor-Key", "k-1")],
    )
    sent = _sent_headers(network)
    assert sent["authorization"] == ["Bearer canary-token"]
    assert sent["x-vendor-key"] == ["k-1"]
    assert sent["x-vendor"] == ["1"]
    assert sent["host"] == [f"{NAME}:{network.tls.port}"]
    assert sent["user-agent"] == ["egress-test/1"]


@pytest.mark.parametrize(
    "injected",
    [
        [("X-Undeclared", "v")],
        [("Authorization", "Bearer a"), ("authorization", "Bearer b")],
        [("Authorization", "Bearer a\r\nX-Smuggled: 1")],
        [("Authorization", "Bearer ☃")],
        [("Bad Name", "v")],
    ],
)
async def test_an_injected_header_outside_the_rules_sends_nothing(
    network: Network, injected: list[tuple[str, str]]
) -> None:
    rules = HeaderRules(
        injected=["Authorization", "X-Undeclared-Not", "Bad Name"],
        amz_allowed=[],
        is_credential=lambda value: False,
    )
    with pytest.raises(EgressRefused) as refused:
        await network.egress().send(
            "GET", network.url("/ok"), network.internal(), header_rules=rules, injected=injected
        )
    assert refused.value.code == "header_not_allowed"
    assert network.tls.seen == []
    assert sum(network.dns.queries.values()) == 0


@pytest.mark.parametrize(
    "name",
    ["Host", "User-Agent", "Connection", "Content-Length", "Accept-Encoding", "Transfer-Encoding"],
)
async def test_the_guard_set_headers_cannot_be_injected(network: Network, name: str) -> None:
    rules = HeaderRules(injected=[name], amz_allowed=[], is_credential=lambda value: False)
    with pytest.raises(EgressRefused) as refused:
        await network.egress().send(
            "GET",
            network.url("/ok"),
            network.internal(),
            header_rules=rules,
            injected=[(name, "x")],
        )
    assert refused.value.code == "header_not_allowed"
    assert network.tls.seen == []


async def test_a_refused_injected_value_never_appears_in_the_refusal(network: Network) -> None:
    secret = "Bearer canary-secret-value"
    rules = HeaderRules(injected=["Authorization"], amz_allowed=[], is_credential=lambda v: False)
    for injected in ([("Authorization", secret + "\n")], [("X-Other", secret)]):
        with pytest.raises(EgressRefused) as refused:
            await network.egress().send(
                "GET", network.url("/ok"), network.internal(), header_rules=rules, injected=injected
            )
        assert "canary-secret-value" not in str(refused.value)
        assert "canary-secret-value" not in repr(refused.value)


async def test_the_guard_asks_for_the_identity_encoding(network: Network) -> None:
    await _send(network, "GET", "/echo")
    assert _sent_headers(network)["accept-encoding"] == ["identity"]


async def test_a_caller_cannot_set_the_accepted_encoding(network: Network) -> None:
    with pytest.raises(EgressRefused) as refused:
        await _send(
            network,
            "GET",
            "/ok",
            destination=network.internal(header_allow=["Accept-Encoding"]),
            headers=[("Accept-Encoding", "gzip")],
        )
    assert refused.value.code == "header_not_allowed"
    assert network.tls.seen == []


async def test_an_encoded_response_is_returned_as_it_came(network: Network) -> None:
    response = await _send(network, "GET", "/encoded")
    assert response.status == 200
    assert ("Content-Encoding", "gzip") in response.headers
    assert response.body != b"hidden"
