"""The logs app on the shared naapp runtime (audit-substrate.md §B).

logs serves its manifest, health and hook-only ingest route. Its chain key, the
one key that signs receipts and checkpoints, is loaded at construction by the
shared app-key loader, so a deployment without it, or with a key the served
manifest does not declare, does not start. While it runs, every team whose
chain moved gets a checkpoint each ``checkpoint_interval_seconds``.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime

import httpx
from aweb_naapp.hooks.catalog import packaged_catalog
from aweb_naapp.manifest import Manifest
from aweb_naapp.runtime.app import NaappRuntime, mount_manifest_routes
from aweb_naapp.runtime.app_keys import AppKeyError, load_app_key
from aweb_naapp.runtime.health import mount_health
from awid.registry import RegistryClient
from fastapi import FastAPI, HTTPException, Request
from pgdbm import AsyncDatabaseManager

from aweb_logs import MANIFEST_PATH, MIGRATIONS_MODULE, MIGRATIONS_PATH
from aweb_logs.chain import CHECKPOINT_PURPOSE, RECEIPT_PURPOSE
from aweb_logs.config import LogsSettings
from aweb_logs.ingest import Ingestor, IngestRefused
from aweb_logs.ledger import LogsSigner, checkpoint_moved_heads

logger = logging.getLogger(__name__)


def chain_signer(settings: LogsSettings, manifest: Manifest) -> LogsSigner:
    """The signer of this deployment's receipts and checkpoints, or :class:`AppKeyError`."""
    receipt = load_app_key(settings, manifest, RECEIPT_PURPOSE)
    checkpoint = load_app_key(settings, manifest, CHECKPOINT_PURPOSE)
    if checkpoint.kid != receipt.kid:
        raise AppKeyError(f"{RECEIPT_PURPOSE} and {CHECKPOINT_PURPOSE} must be one app key")
    return LogsSigner(
        logs_origin=settings.public_origin, kid=receipt.kid, signing_key=receipt.signing_key
    )


async def run_checkpoints(
    db: AsyncDatabaseManager,
    signer: LogsSigner,
    *,
    interval_seconds: float,
    stop: asyncio.Event,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> None:
    """Checkpoint the moved heads every ``interval_seconds`` until ``stop`` is
    set. A failing pass is logged and tried again at the next interval."""
    while not stop.is_set():
        try:
            await checkpoint_moved_heads(db, signer, issued_at=now())
        except Exception:
            logger.exception("Checkpoint pass failed")
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval_seconds)
        except TimeoutError:
            pass


def create_app(
    settings: LogsSettings,
    *,
    awid_transport: httpx.AsyncBaseTransport | None = None,
    team_server_transport: httpx.AsyncBaseTransport | None = None,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> FastAPI:
    runtime = NaappRuntime(
        settings,
        module_name=MIGRATIONS_MODULE,
        migrations_path=MIGRATIONS_PATH,
        manifest_path=MANIFEST_PATH,
        awid_transport=awid_transport,
        team_server_transport=team_server_transport,
    )
    signer = chain_signer(settings, runtime.manifest)

    async def configured_registry(domain: str) -> str:
        # Match the runtime verifier's configured authority; no event selects a registry.
        return settings.awid_registry_url

    registry = RegistryClient(
        registry_url=settings.awid_registry_url, service_token=settings.awid_service_token,
        transport=awid_transport, domain_registry_resolver=configured_registry,
    )
    ingestor = Ingestor(runtime, signer, packaged_catalog(), settings.client_quota, registry=registry)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        try:
            async with runtime.lifespan(app):
                stop = asyncio.Event()
                checkpoints = asyncio.create_task(
                    run_checkpoints(
                        runtime.db(),
                        signer,
                        interval_seconds=settings.checkpoint_interval_seconds,
                        stop=stop,
                    )
                )
                try:
                    yield
                finally:
                    stop.set()
                    await checkpoints
        finally:
            await registry.aclose()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    mount_manifest_routes(app, runtime=runtime)
    mount_health(app, settings, checks=runtime.health_checks())

    @app.post("/v1/hooks/ingest")
    async def ingest(request: Request) -> dict:
        try:
            return await ingestor.admit(request, received_at=now())
        except IngestRefused as refused:
            raise HTTPException(status_code=refused.status, detail={"code": refused.code}) from refused

    return app


def serve() -> FastAPI:
    """The app for this deployment, configured from its ``LOGS_`` environment:
    ``uvicorn aweb_logs.app:serve --factory``."""
    return create_app(LogsSettings())
