"""A real AWID registry address that accepts a request and never finishes answering.

It sends a response head and then one body byte at a time, so no single read
times out and only the registry client's total request deadline ends the call.
That deadline is ``asyncio.timeout`` in ``RegistryClient._request_json``, which
raises the builtin ``TimeoutError``.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

_HEAD = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: application/json\r\n"
    b"Content-Length: 1048576\r\n"
    b"\r\n"
)


@asynccontextmanager
async def stalled_registry_url(*, byte_interval: float = 0.02) -> AsyncGenerator[str]:
    async def answer_slowly(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await reader.readuntil(b"\r\n\r\n")
            writer.write(_HEAD)
            while not writer.is_closing():
                writer.write(b" ")
                await writer.drain()
                await asyncio.sleep(byte_interval)
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(answer_slowly, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.close()
        server.close_clients()
        await server.wait_closed()
