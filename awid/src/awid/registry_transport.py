"""Address-checked, pinned transport for domain-selected registry origins."""

from __future__ import annotations

import httpx

from awid.external_authority import (
    canonical_registry_origin,
    validate_resolved_addresses,
)
from awid.external_registry import SystemHostResolver
from awid.federation_errors import FederationAuthorityError


class _ClosingStream(httpx.AsyncByteStream):
    def __init__(self, stream, transport):
        self.stream = stream
        self.transport = transport

    async def __aiter__(self):
        async for chunk in self.stream:
            yield chunk

    async def aclose(self):
        try:
            await self.stream.aclose()
        finally:
            await self.transport.aclose()


class RegistryOverrideTransport(httpx.AsyncBaseTransport):
    """Resolve once per request; refuse any nonpublic answer before connecting.

    Explicit operator-configured registries and injected transports retain their
    existing policy. DNS-selected origins always use production address policy.
    The request owner's timeout covers lookup, connection and response reading.
    """

    async def handle_async_request(self, request):
        try:
            canonical_registry_origin(str(request.url.copy_with(path="/", query=None)))
            addresses = validate_resolved_addresses(
                await SystemHostResolver().resolve_all(request.url.host)
            )
        except FederationAuthorityError as exc:
            raise httpx.ConnectError(
                "registry destination refused or unavailable", request=request
            ) from exc
        origin_url = request.url
        request.headers["Host"] = origin_url.netloc.decode("ascii")
        request.extensions["sni_hostname"] = origin_url.host
        for position, address in enumerate(addresses):
            transport = httpx.AsyncHTTPTransport(trust_env=False)
            request.url = origin_url.copy_with(host=address)
            try:
                response = await transport.handle_async_request(request)
            except (httpx.ConnectError, httpx.ConnectTimeout):
                await transport.aclose()
                if position == len(addresses) - 1:
                    raise
                continue
            except BaseException:
                await transport.aclose()
                raise
            response.stream = _ClosingStream(response.stream, transport)
            return response
        raise AssertionError("address validation requires a nonempty answer")
