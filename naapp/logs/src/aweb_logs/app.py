"""The logs app on the shared naapp runtime (audit-substrate.md §B).

logs is one service on two origins. Its public origin serves the manifest,
health, the hook-only ingest route and the member tools that manage the team's
readers. Its console origin serves designated readers in a browser: enrolment,
passkey login and reading the team's log. Its chain key, the one key that signs
receipts and checkpoints, is loaded at construction by the shared app-key
loader, so a deployment without it, or with a key the served manifest does not
declare, does not start. While it runs, every team whose chain moved gets a
checkpoint each ``checkpoint_interval_seconds``.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

import httpx
from aweb_naapp.egress.send import Resolver
from aweb_naapp.email import EmailSettings, Mailer
from aweb_naapp.hooks.catalog import packaged_catalog
from aweb_naapp.manifest import Manifest
from aweb_naapp.runtime.app import NaappRuntime, mount_manifest_routes
from aweb_naapp.runtime.app_keys import AppKeyError, load_app_key
from aweb_naapp.runtime.authorization import DeclaredTool
from aweb_naapp.runtime.health import mount_health
from aweb_naapp.runtime.hook_egress import HookEgress
from aweb_naapp.runtime.origins import OriginApps
from aweb_naapp.runtime.passkeys.email import PasskeyEmailDelivery
from aweb_naapp.runtime.team_auth import Principal
from awid.registry import RegistryClient
from fastapi import FastAPI, HTTPException, Request
from pgdbm import AsyncDatabaseManager

from aweb_logs import MANIFEST_PATH, MIGRATIONS_MODULE, MIGRATIONS_PATH
from aweb_logs.chain import CHECKPOINT_PURPOSE, RECEIPT_PURPOSE
from aweb_logs.config import LogsSettings
from aweb_logs.ingest import Ingestor, IngestRefused
from aweb_logs.ledger import LogsSigner, checkpoint_moved_heads
from aweb_logs.reader_service import reader_service

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


async def admit_members(request: Request, principal: Principal, tool: DeclaredTool) -> bool:
    """logs' member tools are open to every member the shared admission admits:
    team-auth, a declared tool and the team's grant of its scopes. Each reader
    operation keeps its own rules, such as never removing the last reader."""
    return True


def create_app(
    settings: LogsSettings,
    *,
    email: EmailSettings,
    awid_transport: httpx.AsyncBaseTransport | None = None,
    team_server_transport: httpx.AsyncBaseTransport | None = None,
    resolver: Resolver | None = None,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> OriginApps:
    """logs on its public origin and its console origin. ``email`` sends the
    enrolment links of designated readers. Hook events leave through the guard
    the settings configure; ``resolver`` replaces its DNS resolver."""
    hooks = HookEgress.from_settings(settings, resolver=resolver)
    runtime = NaappRuntime(
        settings,
        module_name=MIGRATIONS_MODULE,
        migrations_path=MIGRATIONS_PATH,
        manifest_path=MANIFEST_PATH,
        awid_transport=awid_transport,
        team_server_transport=team_server_transport,
        hook_egress=hooks.egress,
        hook_internal_cidr=hooks.internal_cidr,
        hook_internal_origins=hooks.internal_origins,
    )
    signer = chain_signer(settings, runtime.manifest)
    authorized = runtime.authorized(grants=runtime.installation_grants(), policy=admit_members)
    delivery = PasskeyEmailDelivery(
        mailer=Mailer(email),
        console_origin=settings.console_origin,
        product="Logs",
        link_text="Open Logs",
    )

    async def configured_registry(domain: str) -> str:
        # Match the runtime verifier's configured authority; no event selects a registry.
        return settings.awid_registry_url

    registry = RegistryClient(
        registry_url=settings.awid_registry_url, service_token=settings.awid_service_token,
        transport=awid_transport, domain_registry_resolver=configured_registry,
    )
    ingestor = Ingestor(runtime, signer, packaged_catalog(), settings.client_quota, registry=registry)
    console = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @asynccontextmanager
    async def lifespan(api: FastAPI) -> AsyncIterator[None]:
        api_routes, console_routes = list(api.routes), list(console.routes)
        try:
            await hooks.preflight()
            async with runtime.lifespan(api):
                readers = await reader_service(
                    runtime,
                    signer=signer,
                    console_origin=settings.console_origin,
                    delivery=delivery,
                    backlog_age=timedelta(seconds=settings.hook_events_stalled_after_seconds),
                )
                api.include_router(readers.agent_router(authorized))
                console.include_router(readers.console_router)
                runtime.check_authorized_routes(api)
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
            api.router.routes[:] = api_routes
            console.router.routes[:] = console_routes
            await registry.aclose()

    api = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    mount_manifest_routes(api, runtime=runtime)
    mount_health(api, settings, checks=runtime.health_checks())

    @api.post("/v1/hooks/ingest")
    async def ingest(request: Request) -> dict:
        try:
            return await ingestor.admit(request, received_at=now())
        except IngestRefused as refused:
            raise HTTPException(status_code=refused.status, detail={"code": refused.code}) from refused

    return OriginApps(
        api, console, agent_origin=settings.public_origin, human_origin=settings.console_origin
    )


def serve() -> OriginApps:
    """The service for this deployment, configured from its ``LOGS_`` environment,
    its mail from ``LOGS_EMAIL_*``: ``uvicorn aweb_logs.app:serve --factory``."""
    return create_app(LogsSettings(), email=EmailSettings.from_env("LOGS_"))
