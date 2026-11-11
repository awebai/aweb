"""Socket-level controls for acwy's close-after-pool-selection race.

The full human-enrollment reproduction lives in Cloud at c79c6b036. Here
the real SDK pool and Uvicorn TLS connection isolate the transport boundary.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from types import SimpleNamespace

import httpcore._async.http11 as http11
import httpx
import pytest
import trustme
import uvicorn
from uvicorn.protocols.http.h11_impl import H11Protocol

from awid.registry import RegistryClient, RegistryError


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("idle_seconds", "custom_transport"),
    [(4.999, False), (0.25, False), (4.999, True)],
    ids=["reconnect-before-server-deadline", "reuse-short-idle", "caller-owned-pool"],
)
async def test_registry_pool_idle_close(tmp_path, monkeypatch, idle_seconds, custom_transport):
    ca = trustme.CA()
    certificate = ca.issue_cert("127.0.0.1")
    cert_path, key_path, ca_path = (tmp_path / name for name in ("cert.pem", "key.pem", "ca.pem"))
    certificate.cert_chain_pems[0].write_to_path(cert_path)
    certificate.private_key_pem.write_to_path(key_path)
    ca.cert_pem.write_to_path(ca_path)
    monkeypatch.setenv("SSL_CERT_FILE", str(ca_path))
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    fault = SimpleNamespace(server=None, client=None, fired=False, attempts=0)
    writes = []

    async def app(scope, receive, send):
        body = b""
        while True:
            event = await receive()
            body += event.get("body", b"")
            if not event.get("more_body", False):
                break
        if scope["path"] == "/write":
            writes.append(body)
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-length", b"2")]})
        await send({"type": "http.response.body", "body": b"{}"})

    class Protocol(H11Protocol):
        def on_response_complete(self):
            super().on_response_complete()
            if self.scope["path"] == "/health":
                fault.server = self

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    origin = f"https://127.0.0.1:{sock.getsockname()[1]}"
    server = uvicorn.Server(uvicorn.Config(
        app, http=Protocol, lifespan="off", ws="none", access_log=False,
        log_level="warning", ssl_certfile=str(cert_path), ssl_keyfile=str(key_path),
    ))
    task = asyncio.create_task(server.serve(sockets=[sock]))
    registry = None
    try:
        async with asyncio.timeout(10):
            while not server.started:
                if task.done():
                    await task
                await asyncio.sleep(0.01)
        # Override only HTTPcore's idle clock, not asyncio/Uvicorn's clock.
        clock = SimpleNamespace(now=0.0)
        monkeypatch.setattr(http11, "time", SimpleNamespace(monotonic=lambda: clock.now))
        send_headers = http11.AsyncHTTP11Connection._send_request_headers

        async def at_selection(connection, request):
            if request.url.target == b"/health":
                fault.client = connection
            else:
                fault.attempts += 1
                if connection is fault.client and idle_seconds == 4.999:
                    fault.fired = True
                    # The server deadline precedes the client's: the latter
                    # starts only after the previous response is consumed.
                    # Fire the real idle-close callback after pool selection.
                    fault.server.timeout_keep_alive_handler()
                    await asyncio.sleep(0)
                elif idle_seconds == 0.25:
                    assert connection is fault.client
            return await send_headers(connection, request)

        monkeypatch.setattr(http11.AsyncHTTP11Connection, "_send_request_headers", at_selection)
        transport = None
        if custom_transport:
            transport = httpx.AsyncHTTPTransport(
                verify=ssl.create_default_context(cafile=str(ca_path)),
                limits=httpx.Limits(keepalive_expiry=5.0),
            )
        registry = RegistryClient(registry_url=origin, transport=transport)
        await registry.health()
        assert fault.server is not None and fault.client is not None
        clock.now = idle_seconds
        if custom_transport:
            with pytest.raises(RegistryError) as unavailable:
                await registry._request_json("POST", "/write", content=b"exact operation bytes")
            assert unavailable.value.code == "unavailable"
            assert isinstance(unavailable.value.__cause__, httpx.RemoteProtocolError)
            assert fault.fired
            assert writes == []
        else:
            assert await registry._request_json("POST", "/write", content=b"exact operation bytes") == {}
            assert writes == [b"exact operation bytes"]
            assert not fault.fired
        assert fault.attempts == 1  # No transport error is replayed as another write.
    finally:
        if registry is not None:
            await registry.aclose()
        server.should_exit = True
        await task
        sock.close()
