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

from collections.abc import Awaitable, Callable, Sequence
from contextlib import AbstractAsyncContextManager, AsyncExitStack, asynccontextmanager
from pathlib import Path

import httpx
from aweb_naapp.idempotency import apply_idempotency_migrations
from aweb_naapp.ratelimit import apply_ratelimit_migrations
from aweb_naapp.roles import apply_roles_migrations, purge_team
from aweb_naapp.runtime.app import NaappRuntime, mount_manifest_routes
from aweb_naapp.runtime.authorization import ActionPolicy, Authorization, GrantSource
from aweb_naapp.runtime.health import HealthCheck, mount_health
from aweb_naapp.runtime.installation import (
    InstallationFence,
    InstallationGrantSource,
    apply_installation_migrations,
)
from aweb_naapp.runtime.origins import split_origins
from fastapi import APIRouter, Depends, FastAPI, HTTPException
from fastapi.routing import APIRoute
from pgdbm import AsyncDatabaseManager
from starlette.types import Receive, Scope, Send

from aweb_secrets.config import SecretsSettings
from aweb_secrets.manifest import MANIFEST_PATH
from aweb_secrets.revisions import apply_revision_migrations

MIGRATIONS_PATH = Path(__file__).resolve().parent / "migrations"
MODULE_NAME = "aweb_secrets"

Authorized = Callable[..., Awaitable[Authorization]]
ToolRouter = Callable[[NaappRuntime, Authorized], APIRouter]
ConsoleRouter = Callable[[NaappRuntime], APIRouter]
RunnerRouter = Callable[[NaappRuntime], APIRouter]
Prepare = Callable[[NaappRuntime], AbstractAsyncContextManager[None]]


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
    tool_routers: Sequence[ToolRouter] = (),
    prepare: Prepare | None = None,
    console_routers: Sequence[ConsoleRouter] = (),
    runner_routers: Sequence[RunnerRouter] = (),
) -> SecretsService:
    """The secrets service. ``grants`` is the team-server grant authority,
    ``policy`` secrets' admission policy and ``kms`` its KMS canary.

    Preparation runs inside the runtime lifespan, once its database is ready.
    All router factories then receive that same runtime; tool factories also
    receive its exact B1 dependency. Composition guards every included tool;
    unavailable declared tools retain 501. Runner factories mount HTTP POST
    adapters under /runner/v1/ on the API origin outside B1; their existing
    protocol validates runner authority. Prepared services close before the
    database disconnects; composed routes are removed on failure and shutdown.
    """
    runtime = NaappRuntime(
        settings,
        module_name=MODULE_NAME,
        migrations_path=MIGRATIONS_PATH,
        manifest_path=MANIFEST_PATH,
        awid_transport=awid_transport,
        stores=STORES,
    )
    checks = {**runtime.health_checks(), "kms": kms}

    authorized = runtime.authorized(grants=grants, policy=policy)

    console = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    mount_health(console, settings, checks=checks)

    @asynccontextmanager
    async def lifespan(api: FastAPI):
        api_routes, console_routes = list(api.routes), list(console.routes)
        try:
            async with runtime.lifespan(api):
                async with AsyncExitStack() as services:
                    if prepare is not None:
                        await services.enter_async_context(prepare(runtime))
                    implemented = set()
                    for factory in tool_routers:
                        router = factory(runtime, authorized)
                        for route in router.routes:
                            if not isinstance(route, APIRoute) or not route.methods:
                                raise ValueError("tool routers contain only HTTP tool routes")
                            for method in route.methods:
                                key = (method, route.path)
                                if key in implemented:
                                    raise ValueError("a tool route is composed more than once")
                                implemented.add(key)
                        api.include_router(router, dependencies=[Depends(authorized)])
                    for tool in runtime.declared_tools:
                        if (tool.method, tool.path) in implemented:
                            continue
                        api.add_api_route(
                            tool.path,
                            not_implemented,
                            methods=[tool.method],
                            name=tool.name,
                            dependencies=[Depends(authorized)],
                        )
                    runner_paths = set()
                    for runner_factory in runner_routers:
                        router = runner_factory(runtime)
                        for route in router.routes:
                            if (
                                not isinstance(route, APIRoute)
                                or route.methods != {"POST"}
                                or not route.path.startswith("/runner/v1/")
                                or route.path != route.path_format
                            ):
                                raise ValueError(
                                    "runner routers contain only HTTP POST /runner/v1/ routes"
                                )
                            # Placeholder names do not distinguish external
                            # paths; including the same route twice refuses.
                            runner_path = tuple(
                                "{}" if part.startswith("{") and part.endswith("}") else part
                                for part in route.path_format.split("/")
                            )
                            if runner_path in runner_paths:
                                raise ValueError("a runner route is composed more than once")
                            runner_paths.add(runner_path)
                        api.include_router(router)
                    for console_factory in console_routers:
                        console.include_router(console_factory(runtime))
                    # The runtime validates its static routes before opening
                    # the database; validate the final composed routes too.
                    runtime.check_authorized_routes(api)
                    yield
        finally:
            api.router.routes[:] = api_routes
            console.router.routes[:] = console_routes

    api = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    mount_manifest_routes(api, runtime=runtime)
    mount_health(api, settings, checks=checks)
    return SecretsService(runtime, api, console)
