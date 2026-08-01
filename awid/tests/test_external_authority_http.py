from __future__ import annotations

import asyncio
import json
import ssl

import pytest
import trustme

from awid.external_http import PinnedRegistryHTTP
from awid.federation_errors import FederationAuthorityError


def _tls_contexts() -> tuple[ssl.SSLContext, ssl.SSLContext]:
    ca = trustme.CA()
    certificate = ca.issue_cert("registry.test")
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    certificate.configure_cert(server)
    client = ssl.create_default_context()
    ca.configure_trust(client)
    return server, client


@pytest.mark.asyncio
async def test_pinned_tls_dials_selected_ip_and_preserves_hostname() -> None:
    observed: dict[str, object] = {"requests": 0, "sni": None}
    server_context, client_context = _tls_contexts()
    server_context.set_servername_callback(
        lambda _socket, server_name, _context: observed.__setitem__("sni", server_name)
    )

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        request = await reader.readuntil(b"\r\n\r\n")
        observed["requests"] = int(observed["requests"]) + 1
        observed["request"] = request
        body = b'{"ok":true}'
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
            + body
        )
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=server_context)
    port = server.sockets[0].getsockname()[1]
    client = PinnedRegistryHTTP(
        origin=f"https://registry.test:{port}",
        approved_ips=("127.0.0.1",),
        authority_generation=7,
        ssl_context=client_context,
    )
    try:
        assert await client.get_json("/v1/test") == {"ok": True}
    finally:
        await client.aclose()
        server.close()
        await server.wait_closed()

    assert observed["requests"] == 1
    assert observed["sni"] == "registry.test"
    request = observed["request"]
    assert b"Host: registry.test:" + str(port).encode() in request
    assert b"Accept-Encoding: identity" in request
    assert b"Authorization:" not in request
    assert b"Cookie:" not in request


@pytest.mark.asyncio
async def test_pinned_transport_never_follows_redirect() -> None:
    requests: list[bytes] = []
    server_context, client_context = _tls_contexts()

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        requests.append(await reader.readuntil(b"\r\n\r\n"))
        writer.write(
            b"HTTP/1.1 302 Found\r\nLocation: https://internal.example/secret\r\n"
            b"Content-Length: 0\r\nConnection: close\r\n\r\n"
        )
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=server_context)
    port = server.sockets[0].getsockname()[1]
    client = PinnedRegistryHTTP(
        origin=f"https://registry.test:{port}",
        approved_ips=("127.0.0.1",),
        authority_generation=8,
        ssl_context=client_context,
    )
    try:
        with pytest.raises(FederationAuthorityError) as raised:
            await client.get_json("/redirect")
        assert raised.value.reason == "sender_registry_protocol_invalid"
    finally:
        await client.aclose()
        server.close()
        await server.wait_closed()
    assert len(requests) == 1


@pytest.mark.asyncio
async def test_pinned_transport_bounds_identity_encoded_json() -> None:
    server_context, client_context = _tls_contexts()

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.readuntil(b"\r\n\r\n")
        body = json.dumps({"value": "x" * 128}).encode()
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Encoding: identity\r\n"
            + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
            + body
        )
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=server_context)
    port = server.sockets[0].getsockname()[1]
    client = PinnedRegistryHTTP(
        origin=f"https://registry.test:{port}",
        approved_ips=("127.0.0.1",),
        authority_generation=9,
        max_response_bytes=32,
        ssl_context=client_context,
    )
    try:
        with pytest.raises(FederationAuthorityError) as raised:
            await client.get_json("/large")
        assert raised.value.reason == "sender_identity_evidence_too_large"
    finally:
        await client.aclose()
        server.close()
        await server.wait_closed()
