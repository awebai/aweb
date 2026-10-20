"""Which resolved addresses an outbound request may connect to.

Every address a name resolves to is checked, and one denied address refuses
the name. IPv6 forms that carry an IPv4 address (IPv4-mapped, NAT64, 6to4 and
Teredo) are checked against the IPv4 ranges as well, so a denied IPv4 address
cannot be reached by writing it as IPv6.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

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

DENIED_IPV6: tuple[IPv6Network, ...] = tuple(
    IPv6Network(cidr)
    for cidr in (
        "::/96",  # unspecified, loopback and IPv4-compatible
        "100::/64",  # discard-only
        "64:ff9b:1::/48",  # local-use NAT64
        "2001:2::/48",  # benchmarking
        "2001:db8::/32",  # documentation
        "3fff::/20",  # documentation
        "fc00::/7",  # unique local
        "fe80::/10",  # link-local
        "fec0::/10",  # deprecated site-local
        "ff00::/8",  # multicast
    )
)

NAT64 = IPv6Network("64:ff9b::/96")


class InternalDestinations(StrEnum):
    """The deploy-level switch for destinations inside the deployment's network."""

    DISABLED = "disabled"
    ALLOWED = "allowed"


def embedded_ipv4(address: IPv6Address) -> tuple[IPv4Address, ...]:
    """The IPv4 addresses an IPv6 address carries and would route to."""
    if address.ipv4_mapped is not None:
        return (address.ipv4_mapped,)
    if address in NAT64:
        return (IPv4Address(int(address) & 0xFFFFFFFF),)
    if address.sixtofour is not None:
        return (address.sixtofour,)
    if address.teredo is not None:
        return address.teredo
    return ()


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
        for address in addresses:
            if self._deployment_denies(address):
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
        if any(address in network for network in DENIED_IPV6):
            return True
        return any(self._is_denied(v4) for v4 in embedded_ipv4(address))
