"""Serve the test upstream over TLS, where the egress guard can reach it.

The guard refuses loopback for every destination, so the upstream listens on
this host's own non-loopback address, with a certificate from a throwaway CA
that the test's egress trusts.
"""

from __future__ import annotations

import asyncio
import socket
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import uvicorn
from aweb_naapp_testing.network import Certificates
from fastapi import FastAPI


@asynccontextmanager
async def serving(app: FastAPI, certificates: Certificates, host: str) -> AsyncIterator[int]:
    """Run ``app`` over HTTPS on ``host`` and yield its port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, 0))
    config = uvicorn.Config(
        app,
        ssl_certfile=str(certificates.cert_file),
        ssl_keyfile=str(certificates.key_file),
        log_level="warning",
        access_log=False,
        lifespan="off",
    )
    server = uvicorn.Server(config)
    task = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        while not server.started:
            if task.done():
                task.result()
            await asyncio.sleep(0.01)
        yield sock.getsockname()[1]
    finally:
        server.should_exit = True
        await task
        sock.close()
