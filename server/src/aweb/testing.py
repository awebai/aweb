"""The aweb coordination server in-process, for the tests of the services that
rely on it.

:func:`running_server` runs this server's own ``create_app`` in library mode on
a database the test owns, with its migrations applied, and the Redis it is
given. Every AWID call goes through ``awid_transport`` (for example
``awid_service.testing``'s registry). The server is reached through
:attr:`Server.transport`, which records every request and carries the same
``fault``, ``down`` and ``delay`` controls as AWID's.

The server reads its configuration from the environment, in library mode too,
and this module writes none of it. The caller sets at least
``AWEB_DATABASE_URL`` (any value: the database used is the one given here) and
``AWID_SERVICE_TOKEN`` (the token the AWID behind ``awid_transport`` expects),
typically with pytest's ``monkeypatch``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

import httpx
from awid.db_config import build_database_config
from awid_service.testing import ServiceTransport
from fastapi import FastAPI
from pgdbm import AsyncDatabaseManager
from redis.asyncio import Redis

from .api import create_app
from .db import DatabaseInfra

SERVER_URL = "https://aweb.example"


@dataclass
class Server:
    """A running in-process aweb server: its app, its database and its transport."""

    app: FastAPI
    db: DatabaseInfra
    transport: ServiceTransport
    url: str = SERVER_URL

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=self.transport, base_url=self.url)


@asynccontextmanager
async def running_server(
    database_url: str,
    redis: Redis,
    *,
    awid_transport: httpx.AsyncBaseTransport,
    public_origin: str = SERVER_URL,
) -> AsyncIterator[Server]:
    """This server, with its migrations applied, on the empty database at ``database_url``."""
    pool = await AsyncDatabaseManager.create_shared_pool(
        build_database_config(connection_string=database_url)
    )
    infra = DatabaseInfra()
    try:
        await infra.initialize(shared_pool=pool)
        app = create_app(
            db_infra=infra, redis=redis, awid_transport=awid_transport, public_origin=public_origin
        )
        async with app.router.lifespan_context(app):
            yield Server(app=app, db=infra, transport=ServiceTransport(app), url=public_origin)
    finally:
        await infra.close()
        await pool.close()
