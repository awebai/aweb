"""Client-IP rate attribution under an operator-configured proxy trust model."""

from __future__ import annotations

import ipaddress
import json
import logging
import os
from functools import lru_cache

from starlette.requests import Request


logger = logging.getLogger(__name__)


@lru_cache(maxsize=32)
def _networks(spec: str) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    if not spec.strip():
        return ()
    try:
        text = spec.strip()
        tokens = json.loads(text) if text.startswith("[") else text.replace("|", ",").split(",")
        if not isinstance(tokens, list) or not tokens:
            raise ValueError("expected a nonempty CIDR list")
        if not all(isinstance(value, str) and value.strip() for value in tokens):
            raise ValueError("expected CIDR strings")
        return tuple(ipaddress.ip_network(value.strip(), strict=False) for value in tokens)
    except (ValueError, TypeError):
        logger.warning("Invalid client-IP CIDR configuration; using the socket peer")
        return ()


def resolve_client_ip(request: Request) -> str:
    """Resolve a rate key from XFF only for configured, trusted proxy peers.

    Both AWEB_CF_EDGE_CIDRS and AWEB_TRUSTED_PROXY_CIDRS must be nonempty and
    valid. The socket peer must be in the trusted proxy range and the rightmost
    XFF entry in a CF edge range. Then walk left past trusted proxy/CF hops.

    On Render, the configured proxy range includes our first-party private
    services. These callers are trusted by assumption and may choose their
    rate attribution, including by fabricating an entire CF-looking chain.
    A CF suffix is not independent authentication of ingress. This model
    requires the private network to be restricted to the operator's services.

    Missing/invalid configuration or a malformed chain uses the socket peer.
    Other client-IP headers and the retired blanket trust switch are ignored.
    The embedding server must preserve the socket peer in request.client.
    See docs/awid-sot.md#client-ip-rate-attribution for the trust boundary.
    """
    peer = request.client.host if request.client and request.client.host else "unknown"
    cf_edges = _networks(os.getenv("AWEB_CF_EDGE_CIDRS", ""))
    proxies = _networks(os.getenv("AWEB_TRUSTED_PROXY_CIDRS", ""))
    if not cf_edges or not proxies:
        return peer
    try:
        peer_ip = ipaddress.ip_address(peer)
        if not any(peer_ip in network for network in proxies):
            return peer
        # Repeated header field lines form one list, in wire order. The last
        # field line must participate in the rightmost-hop check too.
        lines = request.headers.getlist("x-forwarded-for")
        if not lines:
            return peer
        chain = tuple(ipaddress.ip_address(value.strip()) for value in ",".join(lines).split(","))
    except ValueError:
        return peer
    if not any(chain[-1] in network for network in cf_edges):
        return peer
    trusted_hops = proxies + cf_edges
    for hop in reversed(chain):
        if not any(hop in network for network in trusted_hops):
            return str(hop)
    return peer
