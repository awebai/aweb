"""The address policy refuses every denied range, directly or embedded in IPv6."""

from __future__ import annotations

from ipaddress import ip_address, ip_network

import pytest

from aweb_naapp.egress import AddressPolicy, EgressRefused, InternalDestinations

DENIED = [
    "0.0.0.0",
    "0.1.2.3",
    "127.0.0.1",
    "127.255.255.254",
    "10.0.0.1",
    "172.16.0.1",
    "172.31.255.255",
    "192.168.1.1",
    "100.64.0.1",
    "100.127.255.255",
    "169.254.169.254",
    "169.254.0.1",
    "224.0.0.1",
    "239.255.255.250",
    "255.255.255.255",
    "240.0.0.1",
    "192.0.2.1",
    "198.51.100.7",
    "203.0.113.9",
    "198.18.0.1",
    "198.19.255.255",
    "192.0.0.170",
    "::",
    "::1",
    "fe80::1",
    "fc00::1",
    "fd12:3456::1",
    "ff02::1",
    "2001:db8::1",
    "3fff::1",
    "2001:2::1",
    "fec0::1",
    "100::1",
    # IPv4-mapped and IPv4-compatible forms of denied addresses.
    "::ffff:127.0.0.1",
    "::ffff:10.0.0.1",
    "::ffff:169.254.169.254",
    "::127.0.0.1",
    "::8.8.8.8",
    # NAT64 well-known prefix embedding a denied address; local-use NAT64.
    "64:ff9b::a00:1",
    "64:ff9b::7f00:1",
    "64:ff9b:1::808:808",
    # 6to4 embedding a denied address.
    "2002:a00:1::1",
    "2002:7f00:1::",
    "2002:a9fe:a9fe::1",
    # Teredo with a denied client (stored inverted) or a denied server.
    "2001:0:4136:e378:8000:63bf:f5ff:fffe",
    "2001:0:a00:1:8000:63bf:f7f7:f7f7",
]

ALLOWED = [
    "8.8.8.8",
    "1.1.1.1",
    "93.184.215.14",
    "100.63.255.255",
    "100.128.0.0",
    "172.32.0.1",
    "2606:4700:4700::1111",
    "2a00:1450:4001:80b::200e",
    "::ffff:8.8.8.8",
    "64:ff9b::808:808",
    "2002:808:808::1",
    "2001:0:4136:e378:8000:63bf:f7f7:f7f7",
]


@pytest.mark.parametrize("address", DENIED)
def test_denied_address_is_refused(address: str) -> None:
    with pytest.raises(EgressRefused) as refused:
        AddressPolicy().check([ip_address(address)])
    assert refused.value.code == "destination_address_denied"


@pytest.mark.parametrize("address", ALLOWED)
def test_public_address_passes(address: str) -> None:
    AddressPolicy().check([ip_address(address)])


def test_one_private_record_among_public_ones_refuses_the_name() -> None:
    addresses = [ip_address("8.8.8.8"), ip_address("10.0.0.1"), ip_address("1.1.1.1")]
    with pytest.raises(EgressRefused) as refused:
        AddressPolicy().check(addresses)
    assert refused.value.code == "destination_address_denied"


def test_no_address_is_refused() -> None:
    with pytest.raises(EgressRefused) as refused:
        AddressPolicy().check([])
    assert refused.value.code == "destination_address_denied"


def test_deployment_denied_addresses_are_refused_directly_and_embedded() -> None:
    policy = AddressPolicy(denied=(ip_network("203.0.112.0/24"),))
    AddressPolicy().check([ip_address("203.0.112.5")])
    for address in ("203.0.112.5", "::ffff:203.0.112.5", "64:ff9b::cb00:7005"):
        with pytest.raises(EgressRefused) as refused:
            policy.check([ip_address(address)])
        assert refused.value.code == "destination_address_denied"


INTERNAL = ip_network("10.20.0.0/24")


def test_internal_destination_is_refused_when_disabled() -> None:
    with pytest.raises(EgressRefused) as refused:
        AddressPolicy().check([ip_address("10.20.0.5")], internal=INTERNAL)
    assert refused.value.code == "internal_destinations_disabled"


def test_internal_destination_passes_inside_its_exact_cidr_when_allowed() -> None:
    policy = AddressPolicy(internal_destinations=InternalDestinations.ALLOWED)
    policy.check([ip_address("10.20.0.5")], internal=INTERNAL)


def test_internal_destination_refuses_an_address_outside_its_cidr() -> None:
    policy = AddressPolicy(internal_destinations=InternalDestinations.ALLOWED)
    for address in ("10.20.1.5", "8.8.8.8"):
        with pytest.raises(EgressRefused) as refused:
            policy.check([ip_address("10.20.0.5"), ip_address(address)], internal=INTERNAL)
        assert refused.value.code == "destination_address_denied"


def test_allowed_setting_does_not_open_denied_ranges_to_public_destinations() -> None:
    policy = AddressPolicy(internal_destinations=InternalDestinations.ALLOWED)
    with pytest.raises(EgressRefused) as refused:
        policy.check([ip_address("10.20.0.5")])
    assert refused.value.code == "destination_address_denied"


def test_deployment_denied_addresses_stay_denied_inside_an_internal_cidr() -> None:
    policy = AddressPolicy(
        internal_destinations=InternalDestinations.ALLOWED,
        denied=(ip_network("10.20.0.1/32"),),
    )
    with pytest.raises(EgressRefused) as refused:
        policy.check([ip_address("10.20.0.1")], internal=INTERNAL)
    assert refused.value.code == "destination_address_denied"
