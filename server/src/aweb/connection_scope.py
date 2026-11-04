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
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from contextvars import ContextVar
from typing import Any, AsyncIterator, Optional

from pgdbm import AsyncDatabaseManager


class ConnectionScope:
    """The connection that the statements of one scope share."""

    def __init__(self) -> None:
        self._pool: Optional[Any] = None
        self._connection: Optional[Any] = None
        self._borrowed = False
        self._discarded = False
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
        try:
            if self._connection is None:
                self._connection = await pool.acquire()
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

    async def close(self) -> None:
        self.closed = True
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
        if scope is None or not scope.lends_for(self._pool):
            async with super().acquire() as connection:
                yield connection
            return
        async with scope.borrow(self._pool) as connection:
            yield connection


class ConnectionScopeMiddleware:
    """Open a connection scope for each HTTP request, closed when its response starts.

    Statements in a streaming body, in background tasks or in anything else
    that runs after the response starts take pool connections, as without a
    scope. Installed inside another scope (a mounted app), it joins that one.
    """

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        async with connection_scope() as connections:

            async def send_closing_on_start(message: dict) -> None:
                if message["type"] == "http.response.start":
                    await connections.close()
                await send(message)

            await self.app(scope, receive, send_closing_on_start)
