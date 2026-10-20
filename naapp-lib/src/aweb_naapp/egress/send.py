"""Sending one request through a pinned, verified connection.

The name is resolved once, with the guard's own resolver, and every A and
AAAA record is checked. The connection then goes to one validated address
and nowhere else: the network backend ignores the name it is handed, so a
second resolution cannot happen. TLS verifies the certificate against the
canonical name, and SNI and ``Host`` carry that name. Redirects come back as
responses, no proxy is read from the environment, and the bounds can only be
lowered.

A failure before any byte of the request was written raises
:class:`EgressNotSent`; a failure after raises :class:`EgressOutcomeUnknown`,
because the upstream may have acted on it.
"""

from __future__ import annotations

import asyncio
import ssl
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Protocol

import dns.asyncresolver
import dns.exception
import dns.name
import dns.resolver
import httpcore

from .addresses import AddressPolicy, InternalDestinations, IPAddress, IPNetwork
from .headers import HeaderRefusal, check_headers
from .refused import EgressRefused
from .urls import CanonicalURL

CONNECT_TIMEOUT_SECONDS = 5.0
TOTAL_TIMEOUT_SECONDS = 30.0
MAX_REQUEST_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024


class EgressNotSent(Exception):
    """The request failed before any byte of it was written."""


class EgressOutcomeUnknown(Exception):
    """The request failed after bytes of it were written; it may have taken effect."""


@dataclass(frozen=True)
class Bounds:
    """Timeouts and sizes for one request. Each may only be lowered."""

    connect_timeout: float = CONNECT_TIMEOUT_SECONDS
    total_timeout: float = TOTAL_TIMEOUT_SECONDS
    max_request_bytes: int = MAX_REQUEST_BYTES
    max_response_bytes: int = MAX_RESPONSE_BYTES

    def __post_init__(self) -> None:
        for value, ceiling in (
            (self.connect_timeout, CONNECT_TIMEOUT_SECONDS),
            (self.total_timeout, TOTAL_TIMEOUT_SECONDS),
            (self.max_request_bytes, MAX_REQUEST_BYTES),
            (self.max_response_bytes, MAX_RESPONSE_BYTES),
        ):
            if not 0 < value <= ceiling:
                raise ValueError(f"a bound must be above 0 and at most {ceiling}")


@dataclass(frozen=True)
class Response:
    """An upstream response, cut at the response bound.

    ``truncated`` is true when the body was cut. ``address`` is the one
    address the request was sent to.
    """

    status: int
    headers: list[tuple[str, str]]
    body: bytes
    truncated: bool
    address: IPAddress


class Resolver(Protocol):
    async def resolve(self, host: str) -> list[IPAddress]:
        """Every A and AAAA address of ``host``; raises EgressNotSent if none."""
        ...


class DnsResolver:
    """The guard's own resolver: A and AAAA queries, no search domains.

    Without ``nameservers`` it uses the system's resolver configuration.
    """

    def __init__(self, nameservers: Sequence[str] | None = None, port: int = 53) -> None:
        self._resolver = dns.asyncresolver.Resolver(configure=nameservers is None)
        if nameservers is not None:
            self._resolver.nameservers = list(nameservers)
        self._resolver.port = port

    async def resolve(self, host: str) -> list[IPAddress]:
        name = dns.name.from_text(host)
        answers = await asyncio.gather(
            self._query(name, "A"), self._query(name, "AAAA"), return_exceptions=True
        )
        addresses: list[IPAddress] = []
        for answer in answers:
            if isinstance(answer, dns.resolver.NXDOMAIN):
                raise EgressNotSent(f"{host} does not exist") from answer
            if isinstance(answer, BaseException):
                raise EgressNotSent(f"{host} could not be resolved") from answer
            addresses += answer
        if not addresses:
            raise EgressNotSent(f"{host} has no address")
        return addresses

    async def _query(self, name: dns.name.Name, kind: str) -> list[IPAddress]:
        try:
            answer = await self._resolver.resolve(name, kind, search=False)
        except dns.resolver.NoAnswer:
            return []
        return [ip_address(record.address) for record in answer]


@dataclass(frozen=True)
class Egress:
    """The deployment's egress: its address policy, resolver, trust and bounds.

    ``ca_file`` adds trust anchors to the system store; verification itself
    cannot be turned off.
    """

    addresses: AddressPolicy
    resolver: Resolver
    user_agent: str
    ca_file: Path | None = None
    bounds: Bounds = Bounds()

    async def send(
        self,
        method: str,
        url: CanonicalURL,
        *,
        headers: Sequence[tuple[str, str]] = (),
        header_allow: Iterable[str] = (),
        refuse_header: HeaderRefusal | None = None,
        body: bytes = b"",
        internal: IPNetwork | None = None,
        bounds: Bounds | None = None,
    ) -> Response:
        """Send one request to ``url``.

        The caller has already matched ``url`` against its destination;
        ``internal`` is that destination's exact CIDR when it is internal.
        """
        bounds = bounds or self.bounds
        headers = check_headers(headers, header_allow=header_allow, refuse=refuse_header)
        if len(body) > bounds.max_request_bytes:
            raise EgressRefused("params_invalid", "request_body", "over the request bound")
        if url.ip is not None or internal is not None:
            if self.addresses.internal_destinations is not InternalDestinations.ALLOWED:
                raise EgressRefused("internal_destinations_disabled", "internal_destinations")
            if internal is None:
                raise EgressRefused("destination_not_in_scope", "host", "an IP literal")
        # One deadline covers resolution and the exchange, so total_timeout is
        # the longest a send can take.
        deadline = asyncio.get_running_loop().time() + bounds.total_timeout
        if url.ip is not None:
            addresses: list[IPAddress] = [url.ip]
        else:
            addresses = await self._resolve(url.host, bounds, deadline)
        self.addresses.check(addresses, internal=internal)
        return await self._exchange(method, url, addresses[0], headers, body, bounds, deadline)

    async def _resolve(self, host: str, bounds: Bounds, deadline: float) -> list[IPAddress]:
        resolve_by = min(deadline, asyncio.get_running_loop().time() + bounds.connect_timeout)
        try:
            async with asyncio.timeout_at(resolve_by):
                return await self.resolver.resolve(host)
        except TimeoutError as error:
            raise EgressNotSent(f"resolving {host} timed out") from error

    def _ssl_context(self) -> ssl.SSLContext:
        context = ssl.create_default_context()
        if self.ca_file is not None:
            context.load_verify_locations(cafile=self.ca_file)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context

    async def _exchange(
        self,
        method: str,
        url: CanonicalURL,
        address: IPAddress,
        headers: list[tuple[str, str]],
        body: bytes,
        bounds: Bounds,
        deadline: float,
    ) -> Response:
        backend = _PinnedBackend(address)
        request_headers = [
            ("Host", url.authority),
            ("User-Agent", self.user_agent),
            *headers,
            ("Connection", "close"),
        ]
        if body or method in ("POST", "PUT", "PATCH"):
            request_headers.append(("Content-Length", str(len(body))))
        timeouts = {
            "connect": bounds.connect_timeout,
            "read": bounds.total_timeout,
            "write": bounds.total_timeout,
            "pool": bounds.connect_timeout,
        }
        try:
            async with asyncio.timeout_at(deadline):
                async with httpcore.AsyncConnectionPool(
                    ssl_context=self._ssl_context(), network_backend=backend, retries=0
                ) as pool:
                    async with pool.stream(
                        method.encode("ascii"),
                        httpcore.URL(
                            scheme=b"https",
                            host=url.host.encode("ascii"),
                            port=url.port,
                            target=url.target.encode("ascii"),
                        ),
                        headers=[
                            (k.encode("latin-1"), v.encode("latin-1")) for k, v in request_headers
                        ],
                        content=body,
                        extensions={"timeout": timeouts},
                    ) as response:
                        content, truncated = await _bounded(response, bounds.max_response_bytes)
                        return Response(
                            status=response.status,
                            headers=[
                                (k.decode("latin-1"), v.decode("latin-1"))
                                for k, v in response.headers
                            ],
                            body=content,
                            truncated=truncated,
                            address=address,
                        )
        except (httpcore.ConnectError, httpcore.ConnectTimeout) as error:
            raise EgressNotSent(str(error) or type(error).__name__) from error
        except (
            TimeoutError,
            httpcore.NetworkError,
            httpcore.TimeoutException,
            httpcore.ProtocolError,
        ) as error:
            if backend.wrote:
                raise EgressOutcomeUnknown(str(error) or type(error).__name__) from error
            raise EgressNotSent(str(error) or type(error).__name__) from error


async def _bounded(response: httpcore.Response, limit: int) -> tuple[bytes, bool]:
    content = bytearray()
    async for chunk in response.aiter_stream():
        content += chunk
        if len(content) > limit:
            return bytes(content[:limit]), True
    return bytes(content), False


class _PinnedBackend(httpcore.AsyncNetworkBackend):
    """Connects every request to one address, whatever host it is handed.

    It records whether any byte of the request was written, so a failure can
    be classified as not sent or of unknown outcome.
    """

    def __init__(self, address: IPAddress) -> None:
        self._address = address
        self._inner = httpcore.AnyIOBackend()
        self.wrote = False

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        stream = await self._inner.connect_tcp(
            str(self._address), port, timeout=timeout, socket_options=socket_options
        )
        return _RecordingStream(stream, self)

    async def connect_unix_socket(
        self, path: str, timeout: float | None = None, socket_options: Iterable[Any] | None = None
    ) -> httpcore.AsyncNetworkStream:
        raise httpcore.ConnectError("unix sockets are not an egress destination")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


class _RecordingStream(httpcore.AsyncNetworkStream):
    def __init__(self, inner: httpcore.AsyncNetworkStream, backend: _PinnedBackend) -> None:
        self._inner = inner
        self._backend = backend

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return await self._inner.read(max_bytes, timeout)

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        if buffer:
            self._backend.wrote = True
        await self._inner.write(buffer, timeout)

    async def aclose(self) -> None:
        await self._inner.aclose()

    async def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.AsyncNetworkStream:
        stream = await self._inner.start_tls(ssl_context, server_hostname, timeout)
        return _RecordingStream(stream, self._backend)

    def get_extra_info(self, info: str) -> Any:
        return self._inner.get_extra_info(info)
