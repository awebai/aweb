"""Library is ready only while its database answers; it stays live regardless,
and it still shuts down once its database is gone."""

from __future__ import annotations

import asyncio
from urllib.parse import urlsplit, urlunsplit

import asyncpg
import httpx
import pytest
from aweb_naapp_testing.databases import TEST_SCHEMA

# A shutdown that has not finished in this long is taken to have hung.
SHUTDOWN_BOUND_SECONDS = 15.0


class ShutdownHung(AssertionError):
    """The app's lifespan did not finish after its database stopped answering."""


async def _set_connections(database_url: str, *, allowed: bool) -> None:
    parts = urlsplit(database_url)
    name = parts.path.lstrip("/")
    admin = await asyncpg.connect(urlunsplit(parts._replace(path="/postgres")))
    try:
        await admin.execute(
            f'ALTER DATABASE "{name}" WITH ALLOW_CONNECTIONS {"true" if allowed else "false"}'
        )
        if not allowed:
            await admin.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1",
                name,
            )
    finally:
        await admin.close()


async def test_ready_fails_and_live_holds_once_the_database_stops_answering(
    database_url: str, caplog: pytest.LogCaptureFixture
) -> None:
    from library.api import create_app
    from library.config import Settings

    app = create_app(
        Settings(
            _env_file=None,
            database_url=database_url,
            db_schema=TEST_SCHEMA,
            public_origin="https://library.aweb.ai",
        )
    )
    lifespan = app.router.lifespan_context(app)
    await lifespan.__aenter__()
    try:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://library.test") as client:
            await _set_connections(database_url, allowed=False)
            ready = await client.get("/ready")
            assert ready.status_code == 503, ready.text
            assert ready.json()["status"] == "unhealthy"
            assert (await client.get("/live")).status_code == 200
        assert "Health check database failed" in caplog.text
    finally:
        await _set_connections(database_url, allowed=True)
    # Only once the rule above has held: a failure there is never the expected one.
    try:
        await asyncio.wait_for(lifespan.__aexit__(None, None, None), SHUTDOWN_BOUND_SECONDS)
    except TimeoutError:
        raise ShutdownHung(
            f"Library did not shut down within {SHUTDOWN_BOUND_SECONDS}s after its "
            "database connections were terminated"
        ) from None
