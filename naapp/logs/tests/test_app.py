"""The logs app on the shared runtime (build plan L1): its served manifest,
its health on real PostgreSQL, and its chain key loaded or the app refused."""

from __future__ import annotations

import hashlib
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pytest
from aweb_naapp.manifest import load_manifest
from aweb_naapp.runtime.app_keys import AppKeyError
from awid.did import did_from_public_key
from fastapi import FastAPI
from pgdbm import AsyncDatabaseManager

from aweb_logs.app import chain_signer, create_app, serve
from aweb_logs.chain import CHECKPOINT_PURPOSE, RECEIPT_PURPOSE
from aweb_logs.config import LogsSettings

from .deployment import (
    TEST_APP_ID,
    did_key_of,
    served_manifest,
    template,
    write_key_file,
    write_key_files,
)

ORIGIN = "https://logs.example.test"


def _chain_kid() -> str:
    (kid,) = (e["kid"] for e in template()["app_keys"] if RECEIPT_PURPOSE in e["purposes"])
    return kid


def _deployment(
    tmp_path: Path, database_url: str, *, db_schema: str = "public"
) -> LogsSettings:
    return LogsSettings(
        _env_file=None,
        database_url=database_url,
        db_schema=db_schema,
        public_origin=ORIGIN,
        app_id=TEST_APP_ID,
        app_key_files=write_key_files(tmp_path),
    )


def _deployment_on(tmp_path: Path, database: AsyncDatabaseManager) -> LogsSettings:
    """A deployment on the test database, in the schema the test database gives."""
    return _deployment(tmp_path, database.config.get_dsn(), db_schema=database.schema or "public")


@pytest.fixture
async def database(test_db_factory) -> AsyncDatabaseManager:
    return await test_db_factory.create_db(suffix="logs_app")


@asynccontextmanager
async def running(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=ORIGIN) as client:
            yield client


async def test_the_catalog_lists_the_served_manifest(tmp_path: Path, database) -> None:
    settings = _deployment_on(tmp_path, database)
    async with running(create_app(settings)) as client:
        catalog = (await client.get("/.well-known/aweb-app-versions.json")).json()
        (variant,) = catalog["variants"]
        served = await client.get(variant["url"])
        assert served.status_code == 200
        assert variant["digest"] == "sha256:" + hashlib.sha256(served.content).hexdigest()
        manifest = json.loads(served.content)
        assert manifest["app"]["origin"] == ORIGIN
        assert {e["kid"]: e["did_key"] for e in manifest["app_keys"]} == {
            kid: did_key_of(path) for kid, path in settings.app_key_files.items()
        }
        assert (await client.get("/.well-known/aweb-app.json")).status_code == 404


async def test_logs_serves_no_docs_surface(tmp_path: Path, database) -> None:
    settings = _deployment_on(tmp_path, database)
    async with running(create_app(settings)) as client:
        for path in ("/docs", "/redoc", "/openapi.json", "/"):
            assert (await client.get(path)).status_code == 404, path


async def test_logs_is_ready_with_its_chain_tables(tmp_path: Path, database) -> None:
    settings = _deployment_on(tmp_path, database)
    async with running(create_app(settings)) as client:
        ready = await client.get("/ready")
        assert ready.status_code == 200, ready.text
        tables = await database.fetch_all(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = $1",
            settings.db_schema,
        )
        assert {"chain_epochs", "chain_heads", "chain_events", "chain_checkpoints"} <= {
            row["table_name"] for row in tables
        }


def test_logs_does_not_start_without_its_chain_key(tmp_path: Path) -> None:
    settings = _deployment(tmp_path, "postgresql://localhost/logs")
    files = dict(settings.app_key_files)
    del files[_chain_kid()]
    with pytest.raises(AppKeyError):
        create_app(settings.model_copy(update={"app_key_files": files}))


def test_logs_does_not_start_with_a_key_for_a_kid_its_template_does_not_declare(
    tmp_path: Path,
) -> None:
    settings = _deployment(tmp_path, "postgresql://localhost/logs")
    files = {**settings.app_key_files, "logs-other": write_key_file(tmp_path / "other")}
    with pytest.raises(AppKeyError):
        create_app(settings.model_copy(update={"app_key_files": files}))


def test_the_chain_signer_signs_with_the_configured_key_for_this_origin(tmp_path: Path) -> None:
    settings = _deployment(tmp_path, "postgresql://localhost/logs")
    signer = chain_signer(
        settings, load_manifest(served_manifest(settings.app_key_files, origin=ORIGIN))
    )
    assert (signer.logs_origin, signer.kid) == (ORIGIN, _chain_kid())
    assert did_from_public_key(bytes(signer.signing_key.verify_key)) == did_key_of(
        settings.app_key_files[_chain_kid()]
    )


def test_receipts_and_checkpoints_under_two_keys_are_refused(tmp_path: Path) -> None:
    settings = _deployment(tmp_path, "postgresql://localhost/logs")
    manifest = template()
    (chain,) = (e for e in manifest["app_keys"] if e["kid"] == _chain_kid())
    chain["purposes"] = [RECEIPT_PURPOSE]
    manifest["app_keys"].append({"kid": "logs-checkpoints", "purposes": [CHECKPOINT_PURPOSE]})
    files = {**settings.app_key_files, "logs-checkpoints": write_key_file(tmp_path / "checkpoints")}
    with pytest.raises(AppKeyError):
        chain_signer(
            settings.model_copy(update={"app_key_files": files}),
            load_manifest(served_manifest(files, origin=ORIGIN, manifest=manifest)),
        )


async def test_logs_starts_from_its_environment_and_serves_its_committed_template(
    tmp_path: Path, database, monkeypatch: pytest.MonkeyPatch
) -> None:
    key_files = write_key_files(tmp_path)
    monkeypatch.setenv("LOGS_DATABASE_URL", database.config.get_dsn())
    monkeypatch.setenv("LOGS_DB_SCHEMA", database.schema or "public")
    monkeypatch.setenv("LOGS_PUBLIC_ORIGIN", ORIGIN)
    monkeypatch.setenv("LOGS_APP_ID", TEST_APP_ID)
    monkeypatch.setenv("LOGS_APP_KEY_FILES", json.dumps({kid: str(path) for kid, path in key_files.items()}))
    async with running(serve()) as client:
        catalog = (await client.get("/.well-known/aweb-app-versions.json")).json()
        served = await client.get(catalog["variants"][0]["url"])
    assert served.content == served_manifest(key_files, origin=ORIGIN)
