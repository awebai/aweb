"""The AWID release production runs, as published, for tests that prove a
service works against it rather than against this repository's AWID.

:func:`running_production_registry` serves that release in its own process,
from the locked project ``PRODUCTION_AWID_PROJECT`` names (in this repository,
``scripts/test-egress/production-awid``), on a schema of its own in the test's
PostgreSQL. It yields the same :class:`awid_service.testing.Registry` the
in-process registry gives: seeding writes go to the release's own tables (the
same 001-011 schema), and its ``transport`` carries each request over real HTTP
to the release, whatever host the client names, so a test can swap one
registry for the other. ``fault``, ``down`` and ``delay`` work as there.

The release verifies no DNS (``AWID_SKIP_DNS_VERIFY``) and serves
``REGISTRY_URL`` as its public origin, to ``SERVICE_TOKEN`` as the in-process
registry does. Its ``app`` is a :class:`ReleaseApp`:
what a test sets there is read back by the test's own side only.
"""

from __future__ import annotations

import asyncio
import os
import socket
import tempfile
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace

import httpx
from awid_service.testing import REGISTRY_URL, SERVICE_TOKEN, Registry, ServiceTransport
from pgdbm import AsyncDatabaseManager, DatabaseConfig

_SCHEMA_PREFIX = "production_awid_"


def _project() -> Path:
    configured = os.environ.get("PRODUCTION_AWID_PROJECT")
    project = (
        Path(configured)
        if configured
        else Path(__file__).resolve().parents[4] / "scripts/test-egress/production-awid"
    )
    if not (project / "uv.lock").is_file():
        raise RuntimeError(
            f"no locked production AWID project at {project}: set PRODUCTION_AWID_PROJECT "
            "and run uv sync --frozen there"
        )
    return project


class _Forward(httpx.AsyncBaseTransport):
    """Sends each request to ``origin`` over real HTTP."""

    def __init__(self, origin: httpx.URL) -> None:
        self._origin = origin
        self._http = httpx.AsyncHTTPTransport()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        url = request.url.copy_with(
            scheme=self._origin.scheme, host=self._origin.host, port=self._origin.port
        )
        headers = [(name, value) for name, value in request.headers.raw if name.lower() != b"host"]
        forwarded = httpx.Request(request.method, url, headers=headers, content=await request.aread())
        return await self._http.handle_async_request(forwarded)

    async def aclose(self) -> None:
        await self._http.aclose()


class ReleaseApp:
    """The settings a test gives an in-process registry's app, kept for the
    test's own side; the release in its own process never reads them."""

    def __init__(self) -> None:
        self.dependency_overrides: dict = {}
        self.state = SimpleNamespace()


class ProductionServiceTransport(ServiceTransport):
    """:class:`ServiceTransport` over real HTTP to a running release."""

    def __init__(self, origin: str) -> None:
        self._inner = _Forward(httpx.URL(origin))
        self.calls = []
        self.fault = None
        self.down = False
        self.delay = 0.0


@asynccontextmanager
async def running_production_registry(
    database_url: str, *, redis_url: str | None = None
) -> AsyncIterator[Registry]:
    """The production release on the PostgreSQL at ``database_url``, applying
    its own migrations to a schema it alone uses, which is dropped on exit."""
    schema = _SCHEMA_PREFIX + uuid.uuid4().hex
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    origin = f"http://127.0.0.1:{port}"
    env = {name: value for name, value in os.environ.items() if name != "PYTHONPATH"}
    env.update(
        AWID_DATABASE_URL=database_url,
        AWID_DB_SCHEMA=schema,
        AWID_REDIS_URL=redis_url or os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
        AWID_RATE_LIMIT_BACKEND="memory",
        AWID_SKIP_DNS_VERIFY="1",
        AWID_PUBLIC_ORIGINS=REGISTRY_URL,
        AWID_SERVICE_TOKEN=SERVICE_TOKEN,
        APP_ENV="test",
    )
    process = await asyncio.create_subprocess_exec(
        "uv", "run", "--offline", "--frozen", "--project", str(_project()),
        "awid", "--host", "127.0.0.1", "--port", str(port),
        cwd=tempfile.gettempdir(), env=env,
    )
    db: AsyncDatabaseManager | None = None
    transport: ProductionServiceTransport | None = None
    try:
        async with httpx.AsyncClient(base_url=origin, timeout=1) as client:
            async with asyncio.timeout(60):
                while True:
                    if process.returncode is not None:
                        raise RuntimeError("the production AWID exited before it was ready")
                    try:
                        if (await client.get("/health")).status_code == 200:
                            break
                    except httpx.TransportError:
                        pass
                    await asyncio.sleep(0.1)
        db = AsyncDatabaseManager(DatabaseConfig(connection_string=database_url, schema=schema))
        await db.connect()
        transport = ProductionServiceTransport(origin)
        yield Registry(app=ReleaseApp(), db=db, transport=transport)  # type: ignore[arg-type]
    finally:
        if process.returncode is None:
            process.terminate()
            try:
                async with asyncio.timeout(10):
                    await process.wait()
            except TimeoutError:
                process.kill()
                await process.wait()
        if transport is not None:
            await transport._inner.aclose()
        if db is not None:
            await db.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
            await db.disconnect()
