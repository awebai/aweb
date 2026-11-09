"""The logs app on the shared runtime (build plan L1): its served manifest,
its health on real PostgreSQL, its chain key loaded or the app refused, and its
two origins, each serving only its own routes."""

from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
from aweb_naapp.hooks import envelope as hook_envelope
from aweb_naapp.manifest import load_manifest
from aweb_naapp.runtime.app_keys import AppKeyError
from aweb_naapp.runtime.origins import OriginApps
from awid.did import did_from_public_key
from pgdbm import AsyncDatabaseManager

from aweb_logs.app import chain_signer, create_app, serve
from aweb_logs.chain import CHECKPOINT_PURPOSE, RECEIPT_PURPOSE, open_checkpoint
from aweb_logs.config import LogsSettings
from aweb_logs.ledger import append

from .deployment import (
    TEST_APP_ID,
    did_key_of,
    no_mail,
    served_manifest,
    template,
    write_key_file,
    write_key_files,
)
from .fixtures import TEAM_ID, signed_event

ORIGIN = "https://logs.example.test"
CONSOLE = "https://console.logs.example.test"


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
        console_origin=CONSOLE,
        app_id=TEST_APP_ID,
        app_key_files=write_key_files(tmp_path),
    )


def _deployment_on(tmp_path: Path, database: AsyncDatabaseManager) -> LogsSettings:
    """A deployment on the test database, in the schema the test database gives."""
    return _deployment(tmp_path, database.config.get_dsn(), db_schema=database.schema or "public")


@pytest.fixture
async def database(test_db_factory) -> AsyncDatabaseManager:
    return await test_db_factory.create_db(suffix="logs_app")


def _app(settings: LogsSettings) -> OriginApps:
    return create_app(settings, email=no_mail())


@asynccontextmanager
async def running(service: OriginApps, origin: str = ORIGIN) -> AsyncIterator[httpx.AsyncClient]:
    async with service.api_app.router.lifespan_context(service.api_app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=service), base_url=origin
        ) as client:
            yield client


async def test_the_catalog_lists_the_served_manifest(tmp_path: Path, database) -> None:
    settings = _deployment_on(tmp_path, database)
    async with running(_app(settings)) as client:
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
    async with running(_app(settings)) as client:
        for path in ("/docs", "/redoc", "/openapi.json", "/"):
            assert (await client.get(path)).status_code == 404, path


async def test_logs_is_ready_with_its_chain_tables(tmp_path: Path, database) -> None:
    settings = _deployment_on(tmp_path, database)
    async with running(_app(settings)) as client:
        ready = await client.get("/ready")
        assert ready.status_code == 200, ready.text
        tables = await database.fetch_all(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = $1",
            settings.db_schema,
        )
        assert {"chain_epochs", "chain_heads", "chain_events", "chain_checkpoints"} <= {
            row["table_name"] for row in tables
        }


async def test_a_running_logs_checkpoints_each_team_whose_chain_moved(tmp_path: Path, database) -> None:
    settings = _deployment_on(tmp_path, database)
    settings = settings.model_copy(update={"checkpoint_interval_seconds": 0.05})
    signer = chain_signer(
        settings, load_manifest(served_manifest(settings.app_key_files, origin=ORIGIN))
    )
    signing, signature = signed_event("core", event_id=str(uuid.uuid4()), seq=1)
    async with running(_app(settings)):
        await append(
            database,
            signer,
            event=hook_envelope.verify(signing, signature, team_id=TEAM_ID),
            signing_bytes=signing,
            signature=signature,
            key_evidence={},
            received_at=datetime.now(UTC),
        )
        checkpoint = None
        for _ in range(100):
            checkpoint = await database.fetch_one(
                "SELECT signing_bytes, signature FROM {{tables.chain_checkpoints}} WHERE team_id = $1",
                TEAM_ID,
            )
            if checkpoint is not None:
                break
            await asyncio.sleep(0.05)
    assert checkpoint is not None
    opened = open_checkpoint(bytes(checkpoint["signing_bytes"]), checkpoint["signature"])
    assert (opened.team_seq, opened.logs_origin, opened.kid) == (1, ORIGIN, _chain_kid())


def test_logs_does_not_start_without_its_chain_key(tmp_path: Path) -> None:
    settings = _deployment(tmp_path, "postgresql://localhost/logs")
    files = dict(settings.app_key_files)
    del files[_chain_kid()]
    with pytest.raises(AppKeyError):
        _app(settings.model_copy(update={"app_key_files": files}))


def test_logs_does_not_start_with_a_key_for_a_kid_its_template_does_not_declare(
    tmp_path: Path,
) -> None:
    settings = _deployment(tmp_path, "postgresql://localhost/logs")
    files = {**settings.app_key_files, "logs-other": write_key_file(tmp_path / "other")}
    with pytest.raises(AppKeyError):
        _app(settings.model_copy(update={"app_key_files": files}))


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


def _mail_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    password = tmp_path / "smtp-password"
    password.write_text(secrets.token_hex(16))
    password.chmod(0o600)
    monkeypatch.setenv("LOGS_EMAIL_SMTP_HOST", "localhost")
    monkeypatch.setenv("LOGS_EMAIL_SMTP_PORT", "587")
    monkeypatch.setenv("LOGS_EMAIL_USERNAME", "logs")
    monkeypatch.setenv("LOGS_EMAIL_PASSWORD_FILE", str(password))
    monkeypatch.setenv("LOGS_EMAIL_FROM", "noreply@logs.example.test")


async def test_logs_starts_from_its_environment_and_serves_its_committed_template(
    tmp_path: Path, database, monkeypatch: pytest.MonkeyPatch
) -> None:
    key_files = write_key_files(tmp_path)
    monkeypatch.setenv("LOGS_DATABASE_URL", database.config.get_dsn())
    monkeypatch.setenv("LOGS_DB_SCHEMA", database.schema or "public")
    monkeypatch.setenv("LOGS_PUBLIC_ORIGIN", ORIGIN)
    monkeypatch.setenv("LOGS_CONSOLE_ORIGIN", CONSOLE)
    _mail_environment(tmp_path, monkeypatch)
    monkeypatch.setenv("LOGS_APP_ID", TEST_APP_ID)
    monkeypatch.setenv("LOGS_APP_KEY_FILES", json.dumps({kid: str(path) for kid, path in key_files.items()}))
    async with running(serve()) as client:
        catalog = (await client.get("/.well-known/aweb-app-versions.json")).json()
        served = await client.get(catalog["variants"][0]["url"])
    assert served.content == served_manifest(key_files, origin=ORIGIN)


def test_logs_does_not_start_without_its_mail_settings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LOGS_DATABASE_URL", "postgresql://localhost/logs")
    monkeypatch.setenv("LOGS_PUBLIC_ORIGIN", ORIGIN)
    monkeypatch.setenv("LOGS_CONSOLE_ORIGIN", CONSOLE)
    monkeypatch.setenv("LOGS_APP_ID", TEST_APP_ID)
    key_files = write_key_files(tmp_path)
    monkeypatch.setenv(
        "LOGS_APP_KEY_FILES", json.dumps({kid: str(path) for kid, path in key_files.items()})
    )
    _mail_environment(tmp_path, monkeypatch)
    monkeypatch.delenv("LOGS_EMAIL_SMTP_HOST")
    with pytest.raises(ValueError, match="LOGS_EMAIL_SMTP_HOST"):
        serve()


async def test_each_origin_serves_only_its_own_routes(tmp_path: Path, database) -> None:
    service = _app(_deployment_on(tmp_path, database))
    async with running(service) as public:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=service), base_url=CONSOLE
        ) as console:
            # The member tools are on the public origin, behind team-auth.
            for path in ("/v1/reader-slots", "/v1/reader-removals", "/v1/hooks/ingest"):
                assert (await public.post(path, json={})).status_code == 401, path
                assert (await console.post(path, json={})).status_code == 404, path
            # The reader's console is on the console origin only.
            page = await console.get("/login")
            assert page.status_code == 200
            assert page.headers["content-type"].startswith("text/html")
            assert (await public.get("/login")).status_code == 404
            assert (await public.get("/ready")).status_code == 200
            assert (await console.get("/ready")).status_code == 404
            assert (await console.get("/.well-known/aweb-app-versions.json")).status_code == 404
            # The console never takes team-auth.
            refused = await console.get("/login", headers={"Authorization": "x"})
            assert refused.status_code == 403


async def test_a_stopped_logs_starts_again_with_the_same_routes(tmp_path: Path, database) -> None:
    service = _app(_deployment_on(tmp_path, database))
    for _ in range(2):
        async with running(service) as public:
            assert (await public.post("/v1/reader-slots", json={})).status_code == 401
            assert (await public.get("/ready")).status_code == 200
    assert {route.path for route in service.console_app.routes} == set()
