"""The runtime's own health checks, on a real database and the real outbox."""

from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import asyncpg
import httpx
import pytest
from fastapi import FastAPI
from pydantic_settings import SettingsConfigDict

from aweb_naapp.manifest import write_manifest_file
from aweb_naapp.outbox import OutboxEvent, enqueue, mint_event_id
from aweb_naapp.runtime.app import NaappRuntime
from aweb_naapp.runtime.health import mount_health
from aweb_naapp.runtime.settings import NaappSettings

ORIGIN = "https://app.example"


class ExampleSettings(NaappSettings):
    model_config = SettingsConfigDict(env_prefix="EXAMPLE_")

    public_origin: str = ORIGIN
    app_id: str = "example"


def _runtime(tmp_path: Path, database_url: str) -> NaappRuntime:
    manifest_path = tmp_path / "aweb-app.json"
    write_manifest_file(
        manifest_path, {"manifest_version": 1, "app": {"id": "example", "origin": ORIGIN}, "tools": []}
    )
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    return NaappRuntime(
        ExampleSettings(_env_file=None, database_url=database_url),
        module_name="example",
        migrations_path=migrations,
        manifest_path=manifest_path,
    )


@pytest.fixture
async def database_url(test_db_factory) -> str:
    database = await test_db_factory.create_db(suffix="naapp_health")
    return database.config.get_dsn()


async def _results(runtime: NaappRuntime) -> dict[str, tuple[bool, dict]]:
    return {
        name: ((result := await check()).ok, dict(result.detail))
        for name, check in runtime.health_checks().items()
    }


async def test_the_database_and_an_empty_outbox_are_healthy(tmp_path: Path, database_url: str) -> None:
    runtime = _runtime(tmp_path, database_url)
    app = FastAPI(lifespan=runtime.lifespan)
    async with app.router.lifespan_context(app):
        assert await _results(runtime) == {
            "database": (True, {}),
            "outbox": (True, {"oldest_undelivered_age_seconds": None}),
        }


async def test_the_outbox_reports_the_age_of_its_oldest_undelivered_event(
    tmp_path: Path, database_url: str
) -> None:
    runtime = _runtime(tmp_path, database_url)
    app = FastAPI(lifespan=runtime.lifespan)
    async with app.router.lifespan_context(app):
        db = runtime.db()
        async with db.transaction() as tx:
            await enqueue(
                tx,
                OutboxEvent(
                    event_id=mint_event_id(),
                    team_id="backend:example.com",
                    kind="example/thing.changed",
                    occurred_at=datetime.now(UTC),
                    payload=b"{}",
                ),
            )
        await db.execute(
            "UPDATE {{tables.outbox_events}} SET created_at = NOW() - interval '90 seconds'"
        )
        ok, detail = (await _results(runtime))["outbox"]
        assert ok
        assert 90 <= detail["oldest_undelivered_age_seconds"] < 120


async def test_a_backlog_read_that_does_not_answer_in_time_leaves_the_outbox_check_passing(
    tmp_path: Path, database_url: str, monkeypatch: pytest.MonkeyPatch, caplog
) -> None:
    import aweb_naapp.runtime.app as app_module

    monkeypatch.setattr(app_module, "OUTBOX_BACKLOG_READ_TIMEOUT_SECONDS", 0, raising=False)
    runtime = _runtime(tmp_path, database_url)
    app = FastAPI(lifespan=runtime.lifespan)
    async with app.router.lifespan_context(app):
        assert await _results(runtime) == {"database": (True, {}), "outbox": (True, {})}
    assert [record.getMessage() for record in caplog.records if record.levelname == "ERROR"] == [
        "Outbox backlog could not be read"
    ]


async def test_the_probes_follow_the_database(
    tmp_path: Path, database_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    import aweb_naapp.runtime.health as health

    monkeypatch.setattr(health, "HEALTH_CHECK_CACHE_SECONDS", 0)
    runtime = _runtime(tmp_path, database_url)
    app = FastAPI(lifespan=runtime.lifespan)
    health.mount_health(app, runtime.settings, checks=runtime.health_checks())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=ORIGIN
    ) as client:
        async with app.router.lifespan_context(app):
            for path in ("/live", "/ready", "/health"):
                assert (await client.get(path)).status_code == 200, path
            report = (await client.get("/health")).json()
            assert report["checks"] == {"database": "ok", "outbox": "ok"}
            assert report["details"] == {"outbox": {"oldest_undelivered_age_seconds": None}}
        # The lifespan has ended: the app no longer holds a database connection.
        assert (await client.get("/live")).status_code == 200
        for path in ("/ready", "/health"):
            response = await client.get(path)
            assert response.status_code == 503, path
            assert response.json()["status"] == "unhealthy"
            assert response.json()["checks"] == {"database": "error", "outbox": "error"}


async def test_nothing_is_healthy_outside_the_lifespan(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path, "postgresql://localhost/unused")
    assert await _results(runtime) == {"database": (False, {}), "outbox": (False, {})}


class ClosingRelay:
    """A TCP relay to PostgreSQL that holds back the server's close.

    Everything the server sends reaches the client at once, but when the server
    closes a connection the client side stays open until the client next writes
    or closes. A backend terminated while its connection is idle therefore
    delivers its FATAL error to the client first, and the client meets the
    closed connection only on its next query: on a real network the two can
    arrive in either order, and this relay fixes the order that matters.
    """

    def __init__(self, host: str, port: int) -> None:
        self._upstream = (host, port)
        self._server: asyncio.AbstractServer | None = None
        self._writers: list[asyncio.StreamWriter] = []
        self._tasks: set[asyncio.Task] = set()
        self.server_closes = 0
        self._closed = asyncio.Condition()

    async def start(self) -> int:
        self._server = await asyncio.start_server(self._accept, "127.0.0.1", 0)
        return self._server.sockets[0].getsockname()[1]

    async def _accept(
        self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter
    ) -> None:
        upstream_reader, upstream_writer = await asyncio.open_connection(*self._upstream)
        self._writers += [client_writer, upstream_writer]
        server_closed = asyncio.Event()

        async def to_server() -> None:
            # Once the server has closed, the client's next write (or its own
            # close) is the moment it learns the connection is gone.
            while data := await client_reader.read(65536):
                if server_closed.is_set():
                    break
                upstream_writer.write(data)
                await upstream_writer.drain()

        async def to_client() -> None:
            while data := await upstream_reader.read(65536):
                client_writer.write(data)
                await client_writer.drain()
            server_closed.set()
            async with self._closed:
                self.server_closes += 1
                self._closed.notify_all()

        try:
            await asyncio.gather(to_server(), to_client())
        except (ConnectionError, OSError):
            pass
        finally:
            for writer in (client_writer, upstream_writer):
                writer.close()

    async def wait_for_server_closes(self, count: int) -> None:
        async with self._closed:
            await self._closed.wait_for(lambda: self.server_closes >= count)

    async def close(self) -> None:
        for writer in self._writers:
            writer.close()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()


# Long enough for the client's event loop to read what the relay already
# delivered to its socket. Nothing in that time can show the client the close,
# which the relay holds back, so a longer wait does not change the outcome.
CLIENT_READS_DELIVERED_BYTES_SECONDS = 0.2
# A shutdown that has not finished by then is hung, not slow: the lifespan
# closes a pool whose connections are all already gone.
SHUTDOWN_BOUND_SECONDS = 10


async def test_the_lifespan_ends_after_the_database_drops_its_connections_and_a_probe_failed(
    tmp_path: Path, database_url: str
) -> None:
    direct = urlsplit(database_url)
    relay = ClosingRelay(direct.hostname or "localhost", direct.port or 5432)
    relay_port = await relay.start()
    credentials, at, _ = direct.netloc.rpartition("@")
    relayed_url = urlunsplit(direct._replace(netloc=f"{credentials}{at}127.0.0.1:{relay_port}"))
    runtime = _runtime(tmp_path, relayed_url)
    app = FastAPI(lifespan=runtime.lifespan)
    mount_health(app, runtime.settings, checks=runtime.health_checks())
    try:
        async with AsyncExitStack() as running:
            await running.enter_async_context(app.router.lifespan_context(app))
            admin = await asyncpg.connect(database_url)
            try:
                terminated = await admin.fetchval(
                    "SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity"
                    " WHERE datname = current_database() AND pid <> pg_backend_pid()"
                )
            finally:
                await admin.close()
            assert terminated >= 1
            await relay.wait_for_server_closes(terminated)
            await asyncio.sleep(CLIENT_READS_DELIVERED_BYTES_SECONDS)

            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url=ORIGIN
            ) as client:
                ready = await client.get("/ready")
            assert ready.status_code == 503
            assert ready.json()["checks"]["database"] == "error"

            async with asyncio.timeout(SHUTDOWN_BOUND_SECONDS):
                await running.aclose()
    finally:
        await relay.close()
