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

The release serves ``REGISTRY_URL`` as its public origin, to ``SERVICE_TOKEN``,
as the in-process registry does. Its ``app`` is a :class:`ReleaseApp`. A test
gives a namespace's DNS authority as it gives the in-process registry, through
``app.dependency_overrides[get_domain_verifier]``; the release, whose own
domain verifier is that one override, asks the test process for the answer
over loopback HTTP each time it verifies a domain. Nothing reaches real DNS.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import os
import socket
import subprocess
import tempfile
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace

import httpx
from awid.dns_verify import DnsVerificationError
from awid_service.testing import (
    REGISTRY_URL,
    SERVICE_TOKEN,
    Registry,
    ServiceTransport,
    fixture_domain_authority,
)
from pgdbm import AsyncDatabaseManager, DatabaseConfig

_SCHEMA_PREFIX = "production_awid_"

# Runs in the release's own environment: its app, its migrations, and a domain
# verifier that asks the test process (argv[2]) for each domain's authority.
_SERVE_RELEASE = """
import json, sys, urllib.error, urllib.parse, urllib.request
import uvicorn
from awid.dns_verify import DnsVerificationError, DomainAuthority
from awid_service.deps import get_domain_verifier
from awid_service.main import create_app

authority_url = sys.argv[2]

async def verify(domain):
    try:
        with urllib.request.urlopen(authority_url + urllib.parse.quote(domain, safe=""), timeout=5) as answer:
            return DomainAuthority(**json.load(answer))
    except urllib.error.HTTPError as refused:
        raise DnsVerificationError(refused.read().decode()) from None

app = create_app()
app.dependency_overrides[get_domain_verifier] = lambda: verify
uvicorn.run(app, fd=int(sys.argv[1]))
"""


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


def _prepared_project(env: dict[str, str]) -> Path:
    """The locked project, whose environment was synced before the tests ran
    (make production-awid-sync); the fixture starts it as it is and never syncs."""
    project = _project()
    check = subprocess.run(
        ["uv", "sync", "--offline", "--frozen", "--check", "--project", str(project)],
        env=env,
        capture_output=True,
        text=True,
    )
    if check.returncode != 0:
        raise RuntimeError(
            f"the production AWID environment of {project} is not prepared: "
            f"run make production-awid-sync first ({check.stderr.strip()})"
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
        forwarded = httpx.Request(
            request.method, url, headers=headers, content=await request.aread()
        )
        return await self._http.handle_async_request(forwarded)

    async def aclose(self) -> None:
        await self._http.aclose()


class ReleaseApp:
    """The settings a test gives an in-process registry's app. The release
    reads only the domain verifier override, through :func:`_serve_authority`."""

    def __init__(self) -> None:
        self.dependency_overrides: dict = {}
        self.state = SimpleNamespace()


async def _serve_authority(app: ReleaseApp) -> asyncio.Server:
    """Loopback HTTP answering ``GET /<domain>`` with the authority ``app``'s
    domain verifier override gives, or 404 with the refusal."""

    async def answer(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request_line = (await reader.readline()).decode()
            while (await reader.readline()) not in (b"\r\n", b"\n", b""):
                pass
            domain = httpx.URL(request_line.split()[1]).path.lstrip("/")
            try:
                authority = await fixture_domain_authority(app.dependency_overrides, domain)
                status, body = "200 OK", dataclasses.asdict(authority)
            except DnsVerificationError as refused:
                status, body = "404 Not Found", {"refused": str(refused)}
            content = json.dumps(body).encode()
            writer.write(
                f"HTTP/1.1 {status}\r\ncontent-type: application/json\r\n"
                f"content-length: {len(content)}\r\nconnection: close\r\n\r\n".encode()
                + content
            )
            await writer.drain()
        finally:
            writer.close()

    return await asyncio.start_server(answer, "127.0.0.1", 0)


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
    env = {name: value for name, value in os.environ.items() if name != "PYTHONPATH"}
    env.pop("VIRTUAL_ENV", None)
    project = _prepared_project(env)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        port = sock.getsockname()[1]
        origin = f"http://127.0.0.1:{port}"
        env.update(
            AWID_DATABASE_URL=database_url,
            AWID_DB_SCHEMA=schema,
            AWID_REDIS_URL=redis_url or os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
            AWID_RATE_LIMIT_BACKEND="memory",
            AWID_PUBLIC_ORIGINS=REGISTRY_URL,
            AWID_SERVICE_TOKEN=SERVICE_TOKEN,
            APP_ENV="test",
        )
        env.pop("AWID_SKIP_DNS_VERIFY", None)
        app = ReleaseApp()
        authority = await _serve_authority(app)
        authority_port = authority.sockets[0].getsockname()[1]
        process = await asyncio.create_subprocess_exec(
            "uv",
            "run",
            "--offline",
            "--frozen",
            "--no-sync",
            "--project",
            str(project),
            "python",
            "-c",
            _SERVE_RELEASE,
            str(sock.fileno()),
            f"http://127.0.0.1:{authority_port}/",
            cwd=tempfile.gettempdir(),
            env=env,
            pass_fds=(sock.fileno(),),
        )
    db: AsyncDatabaseManager | None = None
    transport: ProductionServiceTransport | None = None
    registry: Registry | None = None
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
        registry = Registry(app=app, db=db, transport=transport)  # type: ignore[arg-type]
        yield registry
    finally:
        try:
            if process.returncode is None:
                process.terminate()
                try:
                    async with asyncio.timeout(10):
                        await process.wait()
                except TimeoutError:
                    process.kill()
                    await process.wait()
            authority.close()
            await authority.wait_closed()
            if transport is not None:
                await transport._inner.aclose()
            if db is not None:
                await db.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
                await db.disconnect()
        finally:
            if registry is not None:
                await registry.aclose()
