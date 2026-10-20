"""The shared naapp wiring on a real database and real AWID routes.

No ``from __future__ import annotations``: FastAPI resolves the route's
``Depends(runtime.principal)`` annotations at definition time.
"""

from pathlib import Path
from typing import Annotated

import httpx
import pytest
from fastapi import Depends, FastAPI
from pgdbm import AsyncDatabaseManager
from pydantic_settings import SettingsConfigDict

from aweb_naapp.runtime.app import NaappRuntime
from aweb_naapp.runtime.settings import NaappSettings
from aweb_naapp.runtime.team_auth import Principal

from .conftest import REGISTRY_URL, Member

ORIGIN = "https://app.example"


class ExampleSettings(NaappSettings):
    model_config = SettingsConfigDict(env_prefix="EXAMPLE_")

    public_origin: str = ORIGIN
    app_id: str = "example"


def _migrations(tmp_path: Path) -> Path:
    path = tmp_path / "migrations"
    path.mkdir()
    (path / "001_initial.sql").write_text(
        "CREATE TABLE {{tables.things}} (id integer PRIMARY KEY);\n"
    )
    return path


def _app(runtime: NaappRuntime) -> FastAPI:
    app = FastAPI(lifespan=runtime.lifespan)

    @app.post("/v1/things")
    async def create_thing(
        actor: Annotated[Principal, Depends(runtime.principal)],
        db: Annotated[AsyncDatabaseManager, Depends(runtime.db)],
    ) -> dict[str, object]:
        await db.execute("INSERT INTO {{tables.things}} (id) VALUES (1)")
        return {"team_id": actor.team_id, "alias": actor.alias}

    return app


@pytest.fixture
async def app_database_url(test_db_factory) -> str:
    database = await test_db_factory.create_db(suffix="naapp_app")
    return database.config.get_dsn()


async def test_principal_authenticates_and_records_the_observed_member(
    registry, app_database_url: str, tmp_path: Path
) -> None:
    member = Member(team_id="backend:example.com")
    await registry.add_team(member.team_id, member.team_did_key)
    await registry.add_certificate(member.certificate())
    settings = ExampleSettings(
        _env_file=None, database_url=app_database_url, awid_registry_url=REGISTRY_URL
    )
    runtime = NaappRuntime(
        settings,
        module_name="example",
        migrations_path=_migrations(tmp_path),
        awid_transport=registry.transport,
    )
    app = _app(runtime)
    body = b"{}"

    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=ORIGIN
        ) as client:
            signed = await client.post(
                "/v1/things",
                content=body,
                headers=member.headers(aud=ORIGIN, method="POST", path="/v1/things", body=body),
            )
            unsigned = await client.post("/v1/things", content=body)

        assert signed.status_code == 200, signed.text
        assert signed.json() == {"team_id": member.team_id, "alias": "alice"}
        assert unsigned.status_code == 401
        db = runtime.db()
        assert await db.fetch_value("SELECT count(*) FROM things") == 1
        assert await db.fetch_value("SELECT team_did_key FROM teams") == member.team_did_key
        assert await db.fetch_value("SELECT did_key FROM agents") == member.did_key

    assert runtime.connected_db() is None


async def test_the_database_is_unavailable_outside_the_lifespan(tmp_path: Path) -> None:
    settings = ExampleSettings(_env_file=None, database_url="postgresql://localhost/unused")
    runtime = NaappRuntime(settings, module_name="example", migrations_path=_migrations(tmp_path))
    assert runtime.connected_db() is None
    with pytest.raises(RuntimeError):
        runtime.db()
    with pytest.raises(RuntimeError):
        runtime.team_cache()
