"""Which resolved addresses an outbound request may connect to.

The contract is the egress address conformance vector in ``docs/vectors``.
Every address a name resolves to is checked, and one refused address refuses
the name. A floor of ranges (loopback, link-local and cloud metadata,
unspecified, multicast) is refused for every destination, internal ones
included. A public destination's IPv6 address must be global unicast, and
IPv6 forms that carry an IPv4 address (NAT64, 6to4, Teredo) are checked
against the IPv4 ranges as well, so a refused IPv4 address cannot be reached
by writing it as IPv6.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_network

from .refused import EgressRefused

IPAddress = IPv4Address | IPv6Address
IPNetwork = IPv4Network | IPv6Network

DENIED_IPV4: tuple[IPv4Network, ...] = tuple(
    IPv4Network(cidr)
    for cidr in (
        "0.0.0.0/8",  # "this network" and unspecified
        "127.0.0.0/8",  # loopback
        "10.0.0.0/8",  # RFC 1918
        "172.16.0.0/12",  # RFC 1918
        "192.168.0.0/16",  # RFC 1918
        "100.64.0.0/10",  # CGNAT shared address space
        "169.254.0.0/16",  # link-local, cloud metadata
        "192.0.0.0/24",  # IETF protocol assignments
        "192.0.2.0/24",  # documentation
        "198.51.100.0/24",  # documentation
        "203.0.113.0/24",  # documentation
        "198.18.0.0/15",  # benchmarking
        "224.0.0.0/4",  # multicast
        "240.0.0.0/4",  # reserved, including broadcast
    )
)

# Inside 2000::/3, the only IPv6 a public destination may use besides NAT64.
DENIED_IPV6: tuple[IPv6Network, ...] = tuple(
    IPv6Network(cidr)
    for cidr in (
        "64:ff9b:1::/48",  # local-use NAT64
        "2001:2::/48",  # benchmarking
        "2001:db8::/32",  # documentation
        "3fff::/20",  # documentation
    )
)

PUBLIC_IPV6 = IPv6Network("2000::/3")
NAT64 = IPv6Network("64:ff9b::/96")

# Refused for every destination, internal ones included.
FLOOR: tuple[IPNetwork, ...] = tuple(
    ip_network(cidr)
    for cidr in (
        "0.0.0.0/8",  # "this network" and unspecified
        "127.0.0.0/8",  # loopback
        "169.254.0.0/16",  # link-local, cloud metadata
        "224.0.0.0/4",  # multicast
        "::/8",  # unspecified, loopback, IPv4-mapped/compatible/translated (NAT64 aside)
        "fe80::/10",  # link-local
        "fd00:ec2::254/128",  # cloud metadata
        "ff00::/8",  # multicast
    )
)

MIN_INTERNAL_PREFIX = {4: 8, 6: 32}


class InternalDestinations(StrEnum):
    """The deploy-level switch for destinations inside the deployment's network."""

    DISABLED = "disabled"
    ALLOWED = "allowed"


def embedded_ipv4(address: IPv6Address) -> tuple[IPv4Address, ...]:
    """The IPv4 addresses an IPv6 address carries and would route to."""
    if address in NAT64:
        return (IPv4Address(int(address) & 0xFFFFFFFF),)
    if address.sixtofour is not None:
        return (address.sixtofour,)
    if address.teredo is not None:
        return address.teredo
    return ()


def _in_floor(address: IPAddress) -> bool:
    if isinstance(address, IPv6Address) and address in NAT64:
        return any(_in_floor(v4) for v4 in embedded_ipv4(address))
    return any(address.version == n.version and address in n for n in FLOOR)


def check_internal_cidr(cidr: str | IPNetwork) -> IPNetwork:
    """An internal destination's CIDR: exact, not too wide, and clear of the floor."""
    try:
        network = ip_network(cidr, strict=True) if isinstance(cidr, str) else cidr
    except ValueError as error:
        raise EgressRefused("destination_not_in_scope", "network", str(cidr)) from error
    if network.prefixlen < MIN_INTERNAL_PREFIX[network.version]:
        raise EgressRefused("destination_not_in_scope", "network", f"{network} is too wide")
    inside_nat64 = isinstance(network, IPv6Network) and network.subnet_of(NAT64)
    for floor in FLOOR:
        if floor.version != network.version or not network.overlaps(floor):
            continue
        if inside_nat64 and str(floor) == "::/8":
            continue
        raise EgressRefused("destination_not_in_scope", "network", f"{network} overlaps {floor}")
    return network


@dataclass(frozen=True)
class AddressPolicy:
    """The deployment's address rules.

    ``denied`` adds the deployment's own egress and metadata addresses to the
    built-in ranges; they stay denied even inside an internal destination's
    CIDR. ``internal_destinations`` is an operator setting, never an
    installation's: under ``disabled`` no internal destination is reachable,
    whatever an owner confirms.
    """

    internal_destinations: InternalDestinations = InternalDestinations.DISABLED
    denied: tuple[IPNetwork, ...] = ()

    def check(self, addresses: Iterable[IPAddress], *, internal: IPNetwork | None = None) -> None:
        """Refuse unless every address may be connected to.

        ``internal`` is the exact CIDR of a ``network: internal`` destination.
        Such a destination needs ``internal_destinations: allowed``, and then
        every address must fall inside that CIDR. Otherwise no address may fall
        in a denied range.
        """
        addresses = list(addresses)
        if not addresses:
            raise EgressRefused("destination_address_denied", "address", "the name has no address")
        if internal is not None and self.internal_destinations is not InternalDestinations.ALLOWED:
            raise EgressRefused("internal_destinations_disabled", "internal_destinations")
        if internal is not None:
            check_internal_cidr(internal)
        for address in addresses:
            if _in_floor(address) or self._deployment_denies(address):
                raise EgressRefused("destination_address_denied", "address", str(address))
            if internal is not None:
                if address.version != internal.version or address not in internal:
                    raise EgressRefused("destination_address_denied", "address", str(address))
            elif self._is_denied(address):
                raise EgressRefused("destination_address_denied", "address", str(address))

    def _deployment_denies(self, address: IPAddress) -> bool:
        candidates: tuple[IPAddress, ...] = (address,)
        if isinstance(address, IPv6Address):
            candidates += embedded_ipv4(address)
        return any(
            candidate.version == network.version and candidate in network
            for candidate in candidates
            for network in self.denied
        )

    def _is_denied(self, address: IPAddress) -> bool:
        if isinstance(address, IPv4Address):
            return any(address in network for network in DENIED_IPV4)
        if address not in NAT64 and (
            address not in PUBLIC_IPV6 or any(address in network for network in DENIED_IPV6)
        ):
            return True
        return any(self._is_denied(v4) for v4 in embedded_ipv4(address))
