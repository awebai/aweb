"""The runtime's own health checks, on a real database and the real outbox."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from fastapi import FastAPI
from pydantic_settings import SettingsConfigDict

from aweb_naapp.manifest import write_manifest_file
from aweb_naapp.outbox import OutboxEvent, enqueue, mint_event_id
from aweb_naapp.runtime.app import NaappRuntime
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
