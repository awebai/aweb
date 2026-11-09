"""Serve the test upstream over TLS, where the egress guard can reach it.

The guard refuses loopback for every destination, so the upstream listens on
this host's own non-loopback address, with a certificate from a throwaway CA
that the test's egress trusts.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from aweb_naapp_testing.network import Certificates
from fastapi import FastAPI
from service_server import Listener
from service_server import serving as serve_application


@asynccontextmanager
async def serving(app: FastAPI, certificates: Certificates, host: str) -> AsyncIterator[int]:
    """Run ``app`` over HTTPS on ``host`` and yield its port."""
    async with serve_application(
        lambda ports: app,
        listeners=(Listener(host, 0),),
        certificates=certificates,
        lifespan=False,
    ) as running:
        yield running.ports[0]
