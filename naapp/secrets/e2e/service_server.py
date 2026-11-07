"""Owned S19 listeners and one ASGI lifespan, without another service composition.

The factory builds the real service once after its ports are bound. Requests
on every listener share its lifespan state. The caller owns process signals;
this in-process server never replaces handlers or starts another worker.
"""

from __future__ import annotations

import asyncio
import ipaddress
import math
import socket
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import ExitStack, asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from typing import Any

import uvicorn
from aweb_naapp_testing.network import Certificates
from starlette.types import ASGIApp, Message


class ServiceServerError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Listener:
    host: str
    port: int

    def __post_init__(self) -> None:
        # Binding must not do ambient DNS discovery. The receiver already
        # obtains its explicit non-loopback address from its environment.
        try:
            address = ipaddress.ip_address(self.host)
        except ValueError:
            raise ValueError("service_listener_invalid") from None
        if not isinstance(address, ipaddress.IPv4Address):
            raise ValueError("service_listener_invalid")
        if type(self.port) is not int or not 0 <= self.port <= 65535:
            raise ValueError("service_listener_invalid")


@dataclass(frozen=True)
class RunningApplication:
    app: ASGIApp = field(repr=False)
    ports: tuple[int, ...]


async def _cancel(task: asyncio.Task[Any], timeout: float) -> None:
    if not task.done():
        task.cancel()
    done, _ = await asyncio.wait({task}, timeout=timeout)
    if not done:
        raise ServiceServerError("service_shutdown_failed")
    # Retrieve even a startup exception without logging its private message.
    await asyncio.gather(task, return_exceptions=True)


class _Lifespan:
    """Own the ASGI task explicitly so startup cancellation cannot orphan it."""

    def __init__(self, app: ASGIApp) -> None:
        self.state: dict[str, Any] = {}
        self._incoming: asyncio.Queue[Message] = asyncio.Queue()
        self._outgoing: asyncio.Queue[Message] = asyncio.Queue()

        async def run() -> None:
            await app(
                {
                    "type": "lifespan",
                    "asgi": {"version": "3.0", "spec_version": "2.0"},
                    "state": self.state,
                },
                self._incoming.get,
                self._outgoing.put,
            )

        self._task = asyncio.create_task(run(), name="s19-lifespan")
        self.started = False

    async def _event(self, expected: str, timeout: float) -> None:
        incoming = asyncio.create_task(self._outgoing.get(), name="s19-lifespan-event")
        try:
            done, _ = await asyncio.wait(
                {incoming, self._task},
                timeout=timeout,
                return_when=asyncio.FIRST_COMPLETED,
            )
            message = (
                incoming.result()
                if incoming in done
                else (self._outgoing.get_nowait() if not self._outgoing.empty() else None)
            )
            if message is None or message.get("type") != expected:
                raise ServiceServerError("service_lifespan_failed")
            if expected == "lifespan.startup.complete" and self._task.done():
                raise ServiceServerError("service_lifespan_failed")
        finally:
            await _cancel(incoming, timeout)

    async def start(self, timeout: float) -> None:
        await self._incoming.put({"type": "lifespan.startup"})
        await self._event("lifespan.startup.complete", timeout)
        self.started = True

    async def close(self, timeout: float) -> None:
        try:
            if self.started and self._task.done():
                raise ServiceServerError("service_shutdown_failed")
            if self.started and not self._task.done():
                await self._incoming.put({"type": "lifespan.shutdown"})
                await self._event("lifespan.shutdown.complete", timeout)
                done, _ = await asyncio.wait({self._task}, timeout=timeout)
                if not done or self._task.exception() is not None:
                    raise ServiceServerError("service_shutdown_failed")
        except Exception:
            raise ServiceServerError("service_shutdown_failed") from None
        finally:
            await _cancel(self._task, timeout)


class _Server(uvicorn.Server):
    @contextmanager
    def capture_signals(self) -> Iterator[None]:
        # The harness owns signals/cancellation. Multiple S19 services must
        # never replace each other's process-global handlers.
        yield


async def _stop(server: _Server, task: asyncio.Task[None], timeout: float) -> None:
    server.should_exit = True
    done, _ = await asyncio.wait({task}, timeout=timeout)
    try:
        if not done:
            server.force_exit = True
            for connection in list(server.server_state.connections):
                connection.shutdown()
            for request in list(server.server_state.tasks):
                request.cancel()
            await _cancel(task, timeout)
        else:
            await asyncio.gather(task, return_exceptions=True)
        requests = set(server.server_state.tasks)
        if requests:
            for request in requests:
                request.cancel()
            completed, pending = await asyncio.wait(requests, timeout=timeout)
            await asyncio.gather(*completed, return_exceptions=True)
            if pending:
                raise ServiceServerError("service_shutdown_failed")
    finally:
        for listener in getattr(server, "servers", []):
            listener.close()
            await listener.wait_closed()


@asynccontextmanager
async def serving(
    factory: Callable[[tuple[int, ...]], ASGIApp],
    *,
    listeners: tuple[Listener, ...],
    certificates: Certificates | None = None,
    lifespan: bool = True,
    startup_timeout: float = 30,
    shutdown_timeout: float = 10,
) -> AsyncIterator[RunningApplication]:
    """Publish only a started app; close only this context's sockets and tasks.

    TLS is explicit for local/browser/receiver fixtures. Plain loopback HTTP
    may sit behind the operator's TLS tunnel; only loopback proxy headers are
    trusted. No settings, credentials or authority are inferred here.
    """
    if not listeners or any(
        not math.isfinite(value) or value <= 0 for value in (startup_timeout, shutdown_timeout)
    ):
        raise ValueError("service_server_configuration_invalid")
    lifecycle = None
    server = None
    task = None
    with ExitStack() as sockets:
        bound = []
        try:
            for listener in listeners:
                sock = sockets.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((listener.host, listener.port))
                bound.append(sock)
        except OSError:
            raise ServiceServerError("service_bind_failed") from None
        ports = tuple(sock.getsockname()[1] for sock in bound)
        try:
            try:
                app = factory(ports)
                if not callable(app):
                    raise ServiceServerError("service_startup_failed")
                if lifespan:
                    lifecycle = _Lifespan(app)
                    await lifecycle.start(startup_timeout)

                async def requests(scope, receive, send):
                    if lifecycle is not None:
                        scope = {**scope, "state": lifecycle.state.copy()}
                    await app(scope, receive, send)

                config = uvicorn.Config(
                    requests,
                    lifespan="off",
                    http="h11",
                    ws="none",
                    log_config=None,
                    log_level="critical",
                    access_log=False,
                    proxy_headers=True,
                    forwarded_allow_ips="127.0.0.1",
                    ssl_certfile=None if certificates is None else str(certificates.cert_file),
                    ssl_keyfile=None if certificates is None else str(certificates.key_file),
                    timeout_graceful_shutdown=math.ceil(shutdown_timeout),
                )
                server = _Server(config)
                task = asyncio.create_task(server.serve(sockets=bound), name="s19-server")
                async with asyncio.timeout(startup_timeout):
                    while not server.started:
                        if task.done():
                            raise ServiceServerError("service_startup_failed")
                        await asyncio.sleep(0.01)
            except Exception:
                raise ServiceServerError("service_startup_failed") from None
            yield RunningApplication(app, ports)
        finally:
            try:
                if task is not None and server is not None:
                    await _stop(server, task, shutdown_timeout)
            finally:
                if lifecycle is not None:
                    await lifecycle.close(shutdown_timeout)
