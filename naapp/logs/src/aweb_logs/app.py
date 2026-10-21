"""The logs app on the shared naapp runtime (audit-substrate.md §B).

logs serves its manifest and health and no docs surface. Its chain key, the
one key that signs receipts and checkpoints, is loaded at construction by the
shared app-key loader, so a deployment without it, or with a key the served
manifest does not declare, does not start.
"""

from __future__ import annotations

from pathlib import Path

import httpx
from aweb_naapp.manifest import Manifest
from aweb_naapp.runtime.app import NaappRuntime, mount_manifest_routes
from aweb_naapp.runtime.app_keys import AppKeyError, load_app_key
from aweb_naapp.runtime.health import mount_health
from fastapi import FastAPI

from aweb_logs import MANIFEST_PATH, MIGRATIONS_MODULE, MIGRATIONS_PATH
from aweb_logs.chain import CHECKPOINT_PURPOSE, RECEIPT_PURPOSE
from aweb_logs.config import LogsSettings
from aweb_logs.ledger import LogsSigner


def chain_signer(settings: LogsSettings, manifest: Manifest) -> LogsSigner:
    """The signer of this deployment's receipts and checkpoints, or :class:`AppKeyError`."""
    receipt = load_app_key(settings, manifest, RECEIPT_PURPOSE)
    checkpoint = load_app_key(settings, manifest, CHECKPOINT_PURPOSE)
    if checkpoint.kid != receipt.kid:
        raise AppKeyError(f"{RECEIPT_PURPOSE} and {CHECKPOINT_PURPOSE} must be one app key")
    return LogsSigner(
        logs_origin=settings.public_origin, kid=receipt.kid, signing_key=receipt.signing_key
    )


def create_app(
    settings: LogsSettings,
    *,
    manifest_path: Path = MANIFEST_PATH,
    awid_transport: httpx.AsyncBaseTransport | None = None,
) -> FastAPI:
    runtime = NaappRuntime(
        settings,
        module_name=MIGRATIONS_MODULE,
        migrations_path=MIGRATIONS_PATH,
        manifest_path=manifest_path,
        awid_transport=awid_transport,
    )
    chain_signer(settings, runtime.manifest)

    app = FastAPI(lifespan=runtime.lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    mount_manifest_routes(app, runtime=runtime)
    mount_health(app, settings, checks=runtime.health_checks())
    return app
