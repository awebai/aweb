"""Reaching the operator's own network: the one rule for every guarded send
that may go there, hook deliveries and team-server reads alike.

A destination is first sent as public. Whether its address is internal is a
fact about the operator's network, not about the destination, so when the
guard refuses that attempt because the name resolves to a denied address, and
only then, an operator who allows internal destinations on its egress, names
its network and independently lists the destination's exact origin for this
purpose gets exactly one more attempt: the same request as an internal
destination, which the guard resolves afresh and accepts only if every
address is inside that network. The guard refuses before connecting, so the
first attempt sent nothing. A hosted deployment does none of this, so its
first refusal is final.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass
from ipaddress import IPv4Network, IPv6Network
from typing import Any

from awid.log import canonical_server_origin

from aweb_naapp.egress.refused import EgressRefused
from aweb_naapp.egress.send import Egress, Response
from aweb_naapp.egress.urls import Destination, canonical_url, parse_destination

# The one refusal that may be followed by an attempt inside the operator's network.
DENIED_ADDRESS = "destination_address_denied"


def origin_authority(origin: str) -> str | None:
    """The canonical https authority of an exact origin, or None when
    ``origin`` is not one: a path, a pattern or a non-canonical spelling never
    matches anything."""
    try:
        if canonical_server_origin(origin) != origin:
            return None
        return canonical_url(origin).authority
    except (ValueError, EgressRefused):
        return None


@dataclass(frozen=True)
class InternalReach:
    """The operator's network and the exact origins one purpose may reach in it."""

    cidr: IPv4Network | IPv6Network
    authorities: frozenset[str]

    @classmethod
    def of(
        cls, cidr: IPv4Network | IPv6Network | None, origins: Iterable[str]
    ) -> InternalReach | None:
        """None, which permits no second attempt, without a network or an origin."""
        authorities = frozenset(
            authority for origin in origins if (authority := origin_authority(origin)) is not None
        )
        if cidr is None or not authorities:
            return None
        return cls(cidr=cidr, authorities=authorities)

    def admits(self, url: str) -> bool:
        """Whether ``url``'s canonical authority is one of the listed origins'."""
        try:
            return canonical_url(url).authority in self.authorities
        except EgressRefused:
            return False


async def send_reaching_internal(
    egress: Egress,
    entry: Mapping[str, Any],
    public: Destination,
    *,
    url: str,
    reach: InternalReach | None,
    send: Callable[[Destination], Awaitable[Response]],
) -> Response:
    """Send to ``public``, the destination ``entry`` parsed as public; on a
    denied address only, and only when ``reach`` admits ``url``, send the same
    request once more as an internal destination bound to ``reach.cidr``.

    Every other refusal, and the internal attempt's own, is raised as the
    guard raised it.
    """
    try:
        return await send(public)
    except EgressRefused as refused:
        if refused.code != DENIED_ADDRESS or reach is None or not reach.admits(url):
            raise
    internal = parse_destination(
        {**entry, "network": "internal", "cidr": str(reach.cidr)},
        internal_destinations=egress.addresses.internal_destinations,
    )
    return await send(internal)
