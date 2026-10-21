"""The runtime's own health checks, on a real database and the real outbox."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

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


async def test_nothing_is_healthy_outside_the_lifespan(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path, "postgresql://localhost/unused")
    assert await _results(runtime) == {"database": (False, {}), "outbox": (False, {})}
