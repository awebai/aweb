"""One pool connection per request, lent to one borrower at a time.

pgdbm takes a pool connection for every statement, and the pool resets each
connection it gets back: a request of ten statements pays ten checkouts and
ten reset round trips. Inside a connection scope, every DatabaseManager on the
same pool lends the scope's connection instead, so a request pays one checkout
and one reset.

The lending rule keeps today's semantics. The connection is lent only while
no other borrower holds it, so a manager call made inside another manager's
transaction, or concurrent branches of a gather, still take their own pool
connections, as they always did. A scope never opens a transaction: what each
statement sees and locks is unchanged.

A borrowed operation that raises or is cancelled discards the connection: it
goes back to the pool, which resets or terminates it, and every later acquire
in the scope uses the pool. A closed scope lends nothing, so a task spawned
during a request that outlives it uses the pool too.

A scope never holds an idle connection across a wait. When a borrow ends the
scope parks its connection back in the pool unless another statement borrows
it within IDLE_PARK_SECONDS, so a request waiting on the network (AWID, a
federation peer, DNS) holds no connection and an outage elsewhere cannot
drain the pool; back-to-back statements still share one checkout.

Every checkout waits at most ACQUIRE_TIMEOUT_SECONDS for the pool; an
exhausted pool fails the request with a retryable 503 instead of hanging it.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from contextvars import ContextVar
from typing import Any, AsyncIterator, Optional

from fastapi import HTTPException
from fastapi.responses import JSONResponse
from pgdbm import AsyncDatabaseManager

IDLE_PARK_SECONDS = 0.01
ACQUIRE_TIMEOUT_SECONDS = 10.0


class DatabaseUnavailable(HTTPException):
    """The pool had no connection to give within ACQUIRE_TIMEOUT_SECONDS."""

    def __init__(self) -> None:
        super().__init__(
            status_code=503,
            detail={"code": "database_unavailable", "retryable": True},
            headers={"Retry-After": "1"},
        )


async def _acquire_from(pool: Any) -> Any:
    try:
        return await pool.acquire(timeout=ACQUIRE_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        raise DatabaseUnavailable() from None


class ConnectionScope:
    """The connection that the statements of one scope share."""

    def __init__(self) -> None:
        self._pool: Optional[Any] = None
        self._connection: Optional[Any] = None
        self._borrowed = False
        self._discarded = False
        self._idle_park: Optional[asyncio.TimerHandle] = None
        self._parking: Optional[asyncio.Task] = None
        self.closed = False

    def lends_for(self, pool: Any) -> bool:
        return (
            not self.closed
            and not self._discarded
            and not self._borrowed
            and (self._pool is None or self._pool is pool)
        )

    @asynccontextmanager
    async def borrow(self, pool: Any) -> AsyncIterator[Any]:
        self._borrowed = True
        self._cancel_idle_park()
        try:
            if self._connection is None:
                self._connection = await _acquire_from(pool)
                self._pool = pool
            try:
                yield self._connection
            except BaseException:
                self._discarded = True
                raise
        finally:
            self._borrowed = False
            if self.closed or self._discarded:
                await self._release()
            else:
                self._idle_park = asyncio.get_running_loop().call_later(IDLE_PARK_SECONDS, self._park_when_idle)

    def _cancel_idle_park(self) -> None:
        if self._idle_park is not None:
            self._idle_park.cancel()
            self._idle_park = None

    def _park_when_idle(self) -> None:
        self._idle_park = None
        if not self._borrowed and self._connection is not None:
            self._parking = asyncio.ensure_future(self.park())

    async def park(self) -> None:
        """Return the connection to the pool while nothing borrows it; the next
        statement in the scope checks out a fresh one."""
        if not self._borrowed:
            await self._release()

    async def close(self) -> None:
        self.closed = True
        self._cancel_idle_park()
        if not self._borrowed:
            await self._release()

    async def _release(self) -> None:
        connection, self._connection = self._connection, None
        if connection is not None:
            assert self._pool is not None
            await self._pool.release(connection)


_active_scope: ContextVar[Optional[ConnectionScope]] = ContextVar("aweb_connection_scope", default=None)


@asynccontextmanager
async def connection_scope() -> AsyncIterator[ConnectionScope]:
    """Share one connection among the statements run inside this block.

    Inside an open scope this joins it; inside a closed one (a stream body
    after its response started) it opens a scope of its own.
    """
    active = _active_scope.get()
    if active is not None and not active.closed:
        yield active
        return
    scope = ConnectionScope()
    token = _active_scope.set(scope)
    try:
        yield scope
    finally:
        try:
            await scope.close()
        finally:
            _active_scope.reset(token)


class DatabaseManager(AsyncDatabaseManager):
    """A pgdbm manager that lends the active connection scope's connection."""

    @asynccontextmanager
    async def acquire(self) -> AsyncIterator[Any]:
        scope = _active_scope.get()
        if self._pool is None:
            async with super().acquire() as connection:  # raises pgdbm's PoolError
                yield connection
            return
        if scope is None or not scope.lends_for(self._pool):
            connection = await _acquire_from(self._pool)
            try:
                yield connection
            finally:
                await self._pool.release(connection)
            return
        async with scope.borrow(self._pool) as connection:
            yield connection


class ConnectionScopeMiddleware:
    """Open a connection scope for each HTTP request, closed when its response starts.

    Statements in a streaming body, in background tasks or in anything else
    that runs after the response starts take pool connections, as without a
    scope. Installed inside another scope (a mounted app), it joins that one.

    Installed outermost, it also answers an exhausted pool that surfaced
    before any response started (in another middleware, say) with the
    retryable 503 rather than letting it become a 500.
    """

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        response_started = False
        async with connection_scope() as connections:

            async def send_closing_on_start(message: dict) -> None:
                nonlocal response_started
                if message["type"] == "http.response.start":
                    response_started = True
                    await connections.close()
                await send(message)

            try:
                await self.app(scope, receive, send_closing_on_start)
            except DatabaseUnavailable as exc:
                if response_started:
                    raise
                await JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=exc.headers)(
                    scope, receive, send,
                )
