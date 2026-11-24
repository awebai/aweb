"""The address policy against the frozen egress address vector, read in place."""

from __future__ import annotations

import json
from ipaddress import ip_address, ip_network
from pathlib import Path

import pytest

from aweb_naapp.egress import (
    AddressPolicy,
    EgressRefused,
    InternalDestinations,
    check_internal_cidr,
)
from aweb_naapp.egress.addresses import DENIED_IPV4, DENIED_IPV6, FLOOR, NAT64, PUBLIC_IPV6

AWEB_ROOT = Path(__file__).resolve().parents[3]
VECTORS = json.loads((AWEB_ROOT / "docs" / "vectors" / "egress-address-v1.json").read_text())


def test_the_ranges_are_the_vectors() -> None:
    assert [str(n) for n in DENIED_IPV4] == VECTORS["denied_ipv4"]
    assert [str(n) for n in DENIED_IPV6] == VECTORS["denied_ipv6"]
    assert [str(n) for n in FLOOR] == VECTORS["floor_ipv4"] + VECTORS["floor_ipv6"]
    assert (str(NAT64), str(PUBLIC_IPV6)) == (VECTORS["nat64"], VECTORS["public_ipv6"])


def _check(policy: AddressPolicy, addresses: list[str], cidr: str | None = None) -> str:
    internal = ip_network(cidr) if cidr else None
    try:
        policy.check([ip_address(a) for a in addresses], internal=internal)
    except EgressRefused as refused:
        return refused.code
    return "allowed"


@pytest.mark.parametrize("address", VECTORS["public_denied"])
def test_public_denied(address: str) -> None:
    assert _check(AddressPolicy(), [address]) == "destination_address_denied"


@pytest.mark.parametrize("address", VECTORS["public_allowed"])
def test_public_allowed(address: str) -> None:
    assert _check(AddressPolicy(), [address]) == "allowed"


@pytest.mark.parametrize("case", VECTORS["mixed_records"], ids=lambda c: c["name"])
def test_one_refused_record_refuses_the_name(case: dict) -> None:
    assert _check(AddressPolicy(), case["addresses"]) == "destination_address_denied"


def test_no_address_is_refused() -> None:
    assert _check(AddressPolicy(), []) == "destination_address_denied"


@pytest.mark.parametrize("case", VECTORS["internal"], ids=lambda c: c["name"])
def test_internal(case: dict) -> None:
    policy = AddressPolicy(internal_destinations=InternalDestinations(case["setting"]))
    assert _check(policy, case["addresses"], case["cidr"]) == case["result"]


@pytest.mark.parametrize("case", VECTORS["deployment_denied"], ids=lambda c: c["name"])
def test_deployment_denied(case: dict) -> None:
    policy = AddressPolicy(
        internal_destinations=InternalDestinations.ALLOWED,
        denied=tuple(ip_network(n) for n in case["denied"]),
    )
    assert _check(policy, case["addresses"], case["cidr"]) == case["result"]


@pytest.mark.parametrize("cidr", VECTORS["internal_cidrs"]["valid"])
def test_internal_cidr_valid(cidr: str) -> None:
    check_internal_cidr(cidr)


@pytest.mark.parametrize("cidr", VECTORS["internal_cidrs"]["refused"])
def test_internal_cidr_refused(cidr: str) -> None:
    with pytest.raises(EgressRefused) as refused:
        check_internal_cidr(cidr)
    assert (refused.value.code, refused.value.rule) == ("destination_not_in_scope", "network")


def test_the_policy_refuses_an_unbounded_internal_cidr() -> None:
    # The address alone would pass; only the CIDR is out of bounds.
    policy = AddressPolicy(internal_destinations=InternalDestinations.ALLOWED)
    policy.check([ip_address("10.0.0.1")], internal=ip_network("10.0.0.0/8"))
    with pytest.raises(EgressRefused) as refused:
        policy.check([ip_address("10.0.0.1")], internal=ip_network("0.0.0.0/0"))
    assert refused.value.rule == "network"
