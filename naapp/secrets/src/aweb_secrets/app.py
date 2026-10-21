"""The secrets service: one process on two origins, on the shared naapp runtime.

The agent API origin (``public_origin``) serves the manifest, health and the
manifest's tools. Every tool route is admitted only through the runtime's
team-auth guard (B1): signed by a team member, declared by the served
manifest, covered by the team's installed grant and allowed by secrets'
policy. The origin carries no cookies in either direction.

The console origin (``console_origin``) serves people in a browser and never
accepts team-auth. It serves no tool.
"""

from __future__ import annotations

from pathlib import Path

import httpx
from aweb_naapp.idempotency import apply_idempotency_migrations
from aweb_naapp.ratelimit import apply_ratelimit_migrations
from aweb_naapp.roles import apply_roles_migrations, purge_team
from aweb_naapp.runtime.app import NaappRuntime, mount_manifest_routes
from aweb_naapp.runtime.authorization import ActionPolicy, GrantSource
from aweb_naapp.runtime.health import HealthCheck, mount_health
from aweb_naapp.runtime.installation import (
    InstallationFence,
    InstallationGrantSource,
    apply_installation_migrations,
)
from aweb_naapp.runtime.origins import split_origins
from fastapi import Depends, FastAPI, HTTPException
from pgdbm import AsyncDatabaseManager
from starlette.types import Receive, Scope, Send

from aweb_secrets.config import SecretsSettings
from aweb_secrets.manifest import MANIFEST_PATH
from aweb_secrets.revisions import apply_revision_migrations

MIGRATIONS_PATH = Path(__file__).resolve().parent / "migrations"
MODULE_NAME = "aweb_secrets"


class SecretsService:
    """The ASGI app serving both origins, with the runtime and the app of each."""

    def __init__(self, runtime: NaappRuntime, api_app: FastAPI, console_app: FastAPI) -> None:
        self.runtime = runtime
        self.api_app = api_app
        self.console_app = console_app
        settings = runtime.settings
        assert isinstance(settings, SecretsSettings)
        self._asgi = split_origins(
            api_app,
            console_app,
            agent_origin=settings.public_origin,
            human_origin=settings.console_origin,
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await self._asgi(scope, receive, send)


async def not_implemented() -> None:
    raise HTTPException(
        status_code=501,
        detail={"code": "not_implemented", "message": "This tool is not available yet"},
    )


# The shared table sets admission reads: request ids, role assignments, the
# installation fence, the configuration revision and the rate buckets.
STORES = (
    apply_idempotency_migrations,
    apply_roles_migrations,
    apply_installation_migrations,
    apply_revision_migrations,
    apply_ratelimit_migrations,
)


def installation_fence(
    db: AsyncDatabaseManager, *, app_id: str, grants: InstallationGrantSource
) -> InstallationFence:
    """The service's installation fence.

    Retiring an installation, on a confirmed uninstall or when a new
    installation id is admitted, purges the team's role assignments in the
    same transaction, so a reinstall starts with no roles (decision 48b).
    """
    return InstallationFence(db, app_id=app_id, grants=grants, on_retire=purge_team)


def create_app(
    settings: SecretsSettings,
    *,
    grants: GrantSource,
    policy: ActionPolicy,
    kms: HealthCheck,
    awid_transport: httpx.AsyncBaseTransport | None = None,
) -> SecretsService:
    """The secrets service. ``grants`` is the team-server grant authority,
    ``policy`` secrets' admission policy and ``kms`` its KMS canary."""
    runtime = NaappRuntime(
        settings,
        module_name=MODULE_NAME,
        migrations_path=MIGRATIONS_PATH,
        manifest_path=MANIFEST_PATH,
        awid_transport=awid_transport,
        stores=STORES,
    )
    checks = {**runtime.health_checks(), "kms": kms}

    api = FastAPI(lifespan=runtime.lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    mount_manifest_routes(api, runtime=runtime)
    mount_health(api, settings, checks=checks)
    authorized = runtime.authorized(grants=grants, policy=policy)
    for tool in runtime.declared_tools:
        api.add_api_route(
            tool.path,
            not_implemented,
            methods=[tool.method],
            name=tool.name,
            dependencies=[Depends(authorized)],
        )

    console = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    mount_health(console, settings, checks=checks)
    return SecretsService(runtime, api, console)
