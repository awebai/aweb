"""The transport for requests whose destination another party names.

A delivery origin or a registry origin comes from a record this server does not
control. Before any connection its origin passes the federation origin policy,
its host is resolved once, and every answer passes the address policy. The
request then connects to an admitted address, while TLS verification, SNI and
``Host`` keep naming the origin. Proxy settings in the environment are not read.

Federated delivery alone also admits the origins the operator lists in
``AWEB_FEDERATION_PRIVATE_DELIVERY_ORIGINS`` when they resolve to private,
loopback or link-local addresses; registry reads never do.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
from urllib.parse import urlsplit

import httpx
from awid.external_authority import (
    OriginContext,
    canonical_protocol_domain,
    canonical_registry_origin,
    isolated_registry_test_enabled,
    validate_resolved_addresses,
)
from awid.external_registry import HostResolver
from awid.federation_errors import FederationAuthorityError

logger = logging.getLogger(__name__)

RESOLVE_TIMEOUT_SECONDS = 5
FALLBACK_CONNECT_TIMEOUT_SECONDS = 2.0
PRIVATE_DELIVERY_ORIGINS_SETTING = "AWEB_FEDERATION_PRIVATE_DELIVERY_ORIGINS"


class DestinationRefused(httpx.TransportError):
    """The origin does not pass the outbound origin policy."""


class AddressRefused(DestinationRefused):
    """The origin resolves to an address the outbound address policy does not admit."""


def private_delivery_origins(raw: str, *, origin_context: OriginContext) -> frozenset[str]:
    """Parse the comma-separated delivery origins allowed to resolve to private addresses.

    Each entry is an exact origin, ``scheme://host[:port]`` named by host, kept
    in the canonical form the transport compares against. Blank items are
    skipped; any other entry that is not such an origin raises ``ValueError``
    naming it.
    """
    origins = set()
    for entry in (raw or "").split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            origin = canonical_registry_origin(entry, context=origin_context)
            canonical_protocol_domain(urlsplit(origin).hostname or "")
        except FederationAuthorityError:
            raise ValueError(
                f"{PRIVATE_DELIVERY_ORIGINS_SETTING} entry {entry!r} is not a delivery origin: "
                "each entry is an https origin named by host, scheme://host[:port], "
                "with no path, query, user information, address literal or wildcard"
            ) from None
        origins.add(origin)
    return frozenset(origins)


async def admitted_addresses(
    origin: str,
    *,
    host_resolver: HostResolver,
    origin_context: OriginContext,
    private_origins: frozenset[str] = frozenset(),
) -> tuple[str, ...]:
    """Resolve the origin's host once and return its addresses when every one is admitted.

    Only an isolated development origin, or an origin in ``private_origins``,
    may resolve to a private, loopback or link-local address. Federated
    delivery is the only caller that passes ``private_origins``.
    """
    async with asyncio.timeout(RESOLVE_TIMEOUT_SECONDS):
        answers = await host_resolver.resolve_all(urlsplit(origin).hostname)
    return validate_resolved_addresses(
        answers,
        allow_nonpublic_test=(
            isolated_registry_test_enabled(origin, origin_context) or origin in private_origins
        ),
    )


class PinnedTransport(httpx.AsyncBaseTransport):
    """Sends requests for one origin to one of its admitted addresses."""

    def __init__(self, origin, approved_ips, ssl_context):
        self.origin = httpx.URL(origin)
        self.ip = approved_ips[0]
        self.transport = httpx.AsyncHTTPTransport(verify=ssl_context or True, trust_env=False)

    async def handle_async_request(self, request):
        if (request.url.scheme, request.url.host, request.url.port) != (
            self.origin.scheme, self.origin.host, self.origin.port
        ):
            raise FederationAuthorityError("sender_registry_origin_forbidden")
        request.headers["Host"] = self.origin.netloc.decode("ascii")
        request.extensions["sni_hostname"] = self.origin.raw_host.decode("ascii")
        request.url = request.url.copy_with(host=self.ip)
        return await self.transport.handle_async_request(request)

    async def aclose(self):
        await self.transport.aclose()


class _ClosingStream(httpx.AsyncByteStream):
    """A response body that closes the connection it arrived on."""

    def __init__(self, stream, transport: PinnedTransport) -> None:
        self._stream = stream
        self._transport = transport

    async def __aiter__(self):
        async for chunk in self._stream:
            yield chunk

    async def aclose(self) -> None:
        try:
            await self._stream.aclose()
        finally:
            await self._transport.aclose()


class AddressCheckedTransport(httpx.AsyncBaseTransport):
    """Admits each request's origin, then sends it through a ``PinnedTransport`` of its own.

    An origin is ``https`` and named by host; only an isolated development
    deployment admits ``http`` or an address literal. An origin in
    ``private_delivery_origins`` may resolve to a private, loopback or
    link-local address. Every request is resolved and checked again, the admitted addresses are tried in order until one
    accepts a connection, and no connection outlives its response, so a
    connection is never shared between two origins.
    """

    def __init__(
        self,
        *,
        host_resolver: HostResolver,
        origin_context: OriginContext,
        ssl_context: ssl.SSLContext | None = None,
        private_delivery_origins: frozenset[str] = frozenset(),
    ) -> None:
        self.host_resolver = host_resolver
        self.origin_context = origin_context
        self.private_delivery_origins = private_delivery_origins
        self._ssl_context = ssl_context or httpx.create_ssl_context(trust_env=False)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        try:
            origin = canonical_registry_origin(
                f"{request.url.scheme}://{request.url.netloc.decode('ascii')}",
                context=self.origin_context,
            )
            try:
                approved_ips = await admitted_addresses(
                    origin,
                    host_resolver=self.host_resolver,
                    origin_context=self.origin_context,
                    private_origins=self.private_delivery_origins,
                )
            except FederationAuthorityError as exc:
                if exc.reason != "sender_registry_origin_forbidden":
                    raise
                self._log_refused_address(origin)
                raise AddressRefused("destination address refused", request=request) from exc
            return await self._send_to_first_reachable(request, origin, approved_ips)
        except TimeoutError as exc:
            raise httpx.ConnectTimeout("destination lookup timed out", request=request) from exc
        except FederationAuthorityError as exc:
            if exc.reason == "sender_registry_origin_forbidden":
                raise DestinationRefused("destination refused", request=request) from exc
            raise httpx.ConnectError("destination lookup failed", request=request) from exc

    def _log_refused_address(self, origin: str) -> None:
        if origin in self.private_delivery_origins:
            logger.warning(
                "Federated delivery to %s refused: it resolves to an address that is "
                "neither public nor private, loopback or link-local",
                origin,
            )
        else:
            logger.warning(
                "Federated delivery to %s refused: it resolves to a non-public address. "
                "If this is a server you operate on a private network, add %s to %s",
                origin, origin, PRIVATE_DELIVERY_ORIGINS_SETTING,
            )

    async def _send_to_first_reachable(
        self, request: httpx.Request, origin: str, approved_ips: tuple[str, ...]
    ) -> httpx.Response:
        """Send to the admitted addresses in order until one accepts a connection.

        Only a failure to connect moves on to the next address, so a request is
        never sent twice. An address that is not the last gets a short connect
        timeout, which leaves time for the ones after it.
        """
        timeouts = request.extensions.get("timeout", {})
        for position, ip in enumerate(approved_ips, start=1):
            last = position == len(approved_ips)
            connect = timeouts.get("connect")
            if not last:
                connect = min(connect or FALLBACK_CONNECT_TIMEOUT_SECONDS, FALLBACK_CONNECT_TIMEOUT_SECONDS)
            request.extensions["timeout"] = {**timeouts, "connect": connect}
            pinned = PinnedTransport(origin, (ip,), self._ssl_context)
            try:
                response = await pinned.handle_async_request(request)
            except (httpx.ConnectError, httpx.ConnectTimeout):
                await pinned.aclose()
                if last:
                    raise
                # The pinned transport rewrote the URL to the address it tried.
                request.url = request.url.copy_with(host=httpx.URL(origin).host)
                continue
            except BaseException:
                await pinned.aclose()
                raise
            response.stream = _ClosingStream(response.stream, pinned)
            return response
        raise AssertionError("an admitted origin has at least one address")


def delivery_transport(federation_authority, *host_set) -> httpx.AsyncBaseTransport | None:
    """The transport federated delivery sends through.

    A transport the embedding host set takes precedence; otherwise it is the
    federation authority's, which shares the authority's resolver and origin
    policy.
    """
    for transport in host_set:
        if transport is not None:
            return transport
    return getattr(federation_authority, "delivery_transport", None)
