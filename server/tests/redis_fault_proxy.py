"""A TCP proxy in front of the real Redis, so a test can cut one client's link.

The proxy forwards bytes unchanged. ``cut()`` closes every live connection and
refuses new ones until ``restore()``; the Redis server and every client that
does not go through the proxy are unaffected.
"""

from __future__ import annotations

import asyncio
import contextlib
from urllib.parse import urlparse


class RedisFaultProxy:
    def __init__(self, redis_url: str) -> None:
        parsed = urlparse(redis_url)
        self._target_host = parsed.hostname or "localhost"
        self._target_port = parsed.port or 6379
        self._database = (parsed.path or "/0").lstrip("/") or "0"
        self._server: asyncio.base_events.Server | None = None
        self._writers: set[asyncio.StreamWriter] = set()
        self._tasks: set[asyncio.Task] = set()
        self.is_cut = False

    @property
    def url(self) -> str:
        assert self._server is not None
        port = self._server.sockets[0].getsockname()[1]
        return f"redis://127.0.0.1:{port}/{self._database}"

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._accept, "127.0.0.1", 0)

    async def stop(self) -> None:
        self.cut()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
        for task in list(self._tasks):
            task.cancel()
        for task in list(self._tasks):
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task

    def cut(self) -> None:
        self.is_cut = True
        for writer in list(self._writers):
            writer.close()
        self._writers.clear()

    def restore(self) -> None:
        self.is_cut = False

    async def _accept(self, client_reader, client_writer) -> None:
        if self.is_cut:
            client_writer.close()
            return
        try:
            upstream_reader, upstream_writer = await asyncio.open_connection(
                self._target_host, self._target_port
            )
        except OSError:
            client_writer.close()
            return
        self._writers.update({client_writer, upstream_writer})
        for source, sink in ((client_reader, upstream_writer), (upstream_reader, client_writer)):
            task = asyncio.create_task(self._pipe(source, sink))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)

    async def _pipe(self, reader, writer) -> None:
        try:
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            writer.close()
            self._writers.discard(writer)
