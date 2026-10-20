"""The wiring and public surface every naapp shares.

An app creates a :class:`NaappRuntime`, builds its FastAPI app with the
runtime's lifespan, and calls :func:`mount_naapp_routes` for the standard public
surface. An app without the docs surface calls :func:`mount_manifest_routes`
and :func:`aweb_naapp.runtime.health.mount_health` instead.

The runtime reads the app's manifest once, at construction, for its configured
public origin: :attr:`NaappRuntime.manifest_bytes` are the bytes served at the
manifest routes, and the tools authorization checks against are parsed from
those same bytes, never from the app's authoring dict or a later file.

Member operations are guarded with ``Depends(runtime.authorized(grants=...,
policy=...))``. It admits a request only when it is signed by a team member,
declared by the served manifest, covered by the team's installed grant, and
allowed by the app's policy. ``Depends(runtime.principal)`` only
authenticates: it says who signed the request, never that they may act, so it
is for routes that need nothing more than the signer's identity.

The font files under ``/fonts/`` are the app's: this package names the fonts
its stylesheet loads and serves them from the app's directory, but does not
ship them.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.dependencies.models import Dependant
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from fastapi.routing import APIRoute
from pgdbm import AsyncDatabaseManager
from starlette.routing import BaseRoute, Host, Mount

from aweb_naapp.css import FONT_NAMES, aweb_css
from aweb_naapp.manifest import read_manifest_bytes
from aweb_naapp.outbox import outbox_status, run_drain
from aweb_naapp.robots import robots_txt
from aweb_naapp.runtime.authorization import (
    ActionPolicy,
    Authorization,
    DeclaredTools,
    GrantSource,
    authorize_request,
    is_placeholder,
)
from aweb_naapp.runtime.db import NaappDatabase
from aweb_naapp.runtime.event_emit import AppEvents
from aweb_naapp.runtime.health import CheckResult, HealthCheck, mount_health
from aweb_naapp.runtime.settings import NaappSettings
from aweb_naapp.runtime.team_auth import (
    AWIDTeamCache,
    Principal,
    authenticate_request,
    record_observed_principal,
)
from aweb_naapp.skills import Skills

NOINDEX_ROBOTS_HEADER = "noindex, nofollow, noarchive"
_NOSNIFF = {"X-Content-Type-Options": "nosniff"}


class NaappRuntime:
    """A naapp's database and AWID team cache, open for the app's lifespan.

    ``root_path`` is the external prefix the server serves the app under, if
    any. Declared tool paths are external paths, so it is part of them.

    ``manifest_path`` is the app's committed manifest file. It is read here,
    once per process, for ``settings.public_origin`` (configuration, never a
    request): ``manifest_bytes`` are served verbatim, and ``manifest`` and
    ``declared_tools`` are parsed from them. The app-event key the manifest
    declares is loaded here too, so a missing or wrong key stops the app
    before it serves anything, and ``app_events`` emits through it.
    """

    def __init__(
        self,
        settings: NaappSettings,
        *,
        module_name: str,
        migrations_path: Path,
        manifest_path: Path,
        root_path: str = "",
        awid_transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.settings = settings
        # The external prefix the server serves the app under (its ASGI root path).
        self.root_path = root_path.rstrip("/")
        self.module_name = module_name
        self.migrations_path = migrations_path
        self._awid_transport = awid_transport
        self._database: NaappDatabase | None = None
        self._team_cache: AWIDTeamCache | None = None
        self._manifest_bytes = read_manifest_bytes(manifest_path, settings.public_origin)
        self._manifest: Mapping[str, Any] = json.loads(self._manifest_bytes)
        self._declared_tools = DeclaredTools.from_manifest(self._manifest)
        self._app_events = AppEvents.from_settings(settings, self._manifest)
        self._guards: set[Callable[..., object]] = set()

    @property
    def manifest_bytes(self) -> bytes:
        """The manifest bytes served at the manifest routes, fixed at construction."""
        return self._manifest_bytes

    @property
    def manifest(self) -> Mapping[str, Any]:
        """The served manifest, parsed."""
        return self._manifest

    @property
    def declared_tools(self) -> DeclaredTools:
        """The tools authorization checks against, parsed from the served bytes."""
        return self._declared_tools

    @property
    def app_events(self) -> AppEvents:
        """The app's app-event emits, drained by the lifespan."""
        return self._app_events

    @asynccontextmanager
    async def lifespan(self, app: FastAPI) -> AsyncIterator[None]:
        self.check_authorized_routes(app)
        database = NaappDatabase(
            self.settings, module_name=self.module_name, migrations_path=self.migrations_path
        )
        await database.connect()
        self._database = database
        self._team_cache = AWIDTeamCache(
            registry_url=self.settings.awid_registry_url,
            ttl_seconds=self.settings.auth_cache_ttl_seconds,
            service_token=self.settings.awid_service_token,
            transport=self._awid_transport,
        )
        stop = asyncio.Event()
        client = httpx.AsyncClient(timeout=self.settings.app_emit_timeout_seconds)
        app_events_drain = (
            asyncio.create_task(
                run_drain(database.db, stop=stop, **self._app_events.drain_options(client))
            )
            if self._app_events.key is not None
            else None
        )
        try:
            yield
        finally:
            stop.set()
            if app_events_drain is not None:
                await app_events_drain
            await client.aclose()
            self._database = None
            self._team_cache = None
            await database.disconnect()

    def connected_db(self) -> AsyncDatabaseManager | None:
        """The database while the app is running, or None, for surfaces that
        must render without it."""
        return self._database.db if self._database is not None else None

    def db(self) -> AsyncDatabaseManager:
        """FastAPI dependency: the app's database."""
        if self._database is None:
            raise RuntimeError("naapp database is not initialized")
        return self._database.db

    def health_checks(self) -> dict[str, HealthCheck]:
        """The runtime's dependencies for the health routes: the database, and
        the age of the oldest outbox event not yet delivered (``None`` when
        every event is delivered). Neither is healthy outside the lifespan."""

        async def database() -> CheckResult:
            db = self.connected_db()
            if db is None:
                return CheckResult(ok=False)
            await db.fetch_value("SELECT 1")
            return CheckResult(ok=True)

        async def outbox() -> CheckResult:
            db = self.connected_db()
            if db is None:
                return CheckResult(ok=False)
            status = await outbox_status(db)
            ages = [
                target.oldest_undelivered_age_seconds
                for target in status.targets.values()
                if target.oldest_undelivered_age_seconds is not None
            ] + [team.oldest_age_seconds for team in status.unmaterialized.values()]
            return CheckResult(
                ok=True, detail={"oldest_undelivered_age_seconds": max(ages, default=None)}
            )

        return {"database": database, "outbox": outbox}

    def team_cache(self) -> AWIDTeamCache:
        if self._team_cache is None:
            raise RuntimeError("naapp auth cache is not initialized")
        return self._team_cache

    async def principal(self, request: Request) -> Principal:
        """FastAPI dependency: the team member who signed this request.

        Authentication only: any certified member of any team passes. Guard
        member operations with :meth:`authorized` instead.
        """
        return await authenticate_request(
            request,
            public_origin=self.settings.public_origin,
            team_cache=self.team_cache(),
            timestamp_skew_seconds=self.settings.timestamp_skew_seconds,
            did_aw_profile=self.settings.did_aw_profile,
        )

    def authorized(
        self, *, grants: GrantSource, policy: ActionPolicy
    ) -> Callable[[Request], Awaitable[Authorization]]:
        """A FastAPI dependency admitting only authorized member requests.

        It authenticates the request, then authorizes it against the tools of
        the served manifest, the team's grant from ``grants`` and the app's
        ``policy``. Only an admitted member is recorded as observed, so
        refused requests never write to the app's database.
        """

        async def authorized_request(request: Request) -> Authorization:
            principal = await self.principal(request)
            authorization = await authorize_request(
                request,
                principal=principal,
                tools=self.declared_tools,
                grants=grants,
                policy=policy,
            )
            await record_observed_principal(self.db(), principal)
            return authorization

        self._guards.add(authorized_request)
        return authorized_request

    def check_authorized_routes(self, app: FastAPI) -> None:
        """Refuse to start unless every route guarded by :meth:`authorized` is
        exactly one of its declared tools.

        The route's method and external path template (``root_path`` plus the
        route's path, placeholders compared by position, not by name) must
        equal a declared tool's. A route that merely matches a declared template,
        such as ``/v1/things/purge`` under a declared ``/v1/things/{id}``, would
        otherwise run its own handler while being authorized as the declared
        tool. Path converters are refused, because they change which requests a
        placeholder matches. Guarded routes must be declared on the runtime's
        own app: one inside a mounted or host-routed application is refused.
        The lifespan runs this check before anything else.
        """
        for route in app.routes:
            if isinstance(route, Mount | Host):
                if self._contains_guards(route.routes):
                    raise RuntimeError(
                        "authorized routes must be declared on the runtime's own app, "
                        f"not inside a mounted application ({route!r})"
                    )
                continue
            if not isinstance(route, APIRoute):
                continue
            if self._is_guarded(route.dependant):
                path = self.root_path + route.path_format
                if route.path != route.path_format:
                    raise RuntimeError(
                        f"authorized route {route.path} uses a path converter; declare it plainly"
                    )
                template = _template(path.split("/"))
                for method in sorted(route.methods or ()):
                    if not any(
                        tool.method == method and _template(tool.segments) == template
                        for tool in self.declared_tools
                    ):
                        raise RuntimeError(
                            f"authorized route {method} {path} is not exactly a declared manifest tool"
                        )

    def _contains_guards(self, routes: Sequence[BaseRoute]) -> bool:
        for route in routes:
            if isinstance(route, Mount | Host) and self._contains_guards(route.routes):
                return True
            if isinstance(route, APIRoute) and self._is_guarded(route.dependant):
                return True
        return False

    def _is_guarded(self, dependant: Dependant) -> bool:
        return any(
            dependency.call in self._guards or self._is_guarded(dependency)
            for dependency in dependant.dependencies
        )


def _template(segments: Sequence[str]) -> tuple[str, ...]:
    return tuple("{}" if is_placeholder(segment) else segment for segment in segments)


def mount_manifest_routes(app: FastAPI, *, runtime: NaappRuntime) -> None:
    """Serve the runtime's ``manifest_bytes`` verbatim, for an app with or
    without the docs surface."""
    manifest_bytes = runtime.manifest_bytes

    async def _manifest_response() -> Response:
        return Response(
            content=manifest_bytes,
            media_type="application/json",
            headers=_NOSNIFF,
        )

    # Served at the RFC 8615 well-known path the dispatcher and gateway fetch,
    # plus the bare path the docs surface links. Both return the same bytes.
    @app.get("/.well-known/aweb-app.json")
    async def well_known_manifest_route() -> Response:
        return await _manifest_response()

    @app.get("/aweb-app.json")
    async def aweb_app_manifest_route() -> Response:
        return await _manifest_response()


def mount_naapp_routes(
    app: FastAPI,
    *,
    runtime: NaappRuntime,
    skills: Skills,
    landing: Callable[[], Awaitable[str]],
    reference_html: str,
    llms_txt: str,
    og_card_png: bytes,
    fonts_dir: Path,
    robots_disallow: Sequence[str] = (),
    noindex_paths: Sequence[str] = (),
    health_checks: Mapping[str, HealthCheck] | None = None,
) -> None:
    """Serve the standard naapp public surface.

    ``fonts_dir`` holds the app's copies of the fonts the stylesheet loads
    (``FONT_NAMES``); only those names are served, and a directory missing one
    is refused here.

    The landing page, robots rules and noindex paths are the app's: ``landing``
    renders the front door on each request, ``robots_disallow`` lists the paths
    crawlers must skip, and every response under ``noindex_paths`` (found or
    not) carries ``X-Robots-Tag``. The manifest routes serve the runtime's
    ``manifest_bytes`` verbatim. The health routes check the runtime's
    dependencies plus the app's own ``health_checks``.
    """
    settings = runtime.settings
    noindex_prefixes = tuple(noindex_paths)

    if noindex_prefixes:

        @app.middleware("http")
        async def noindex(
            request: Request, call_next: Callable[[Request], Awaitable[Response]]
        ) -> Response:
            response = await call_next(request)
            if request.url.path.startswith(noindex_prefixes):
                response.headers["X-Robots-Tag"] = NOINDEX_ROBOTS_HEADER
            return response

    @app.get("/", response_class=HTMLResponse)
    async def landing_route() -> HTMLResponse:
        return HTMLResponse(await landing())

    def _aweb_css_response(immutable: bool) -> Response:
        # The fingerprinted URL is content-addressed, so it can be cached forever;
        # the legacy /css/aweb.css keeps a short TTL.
        cache = "public, max-age=31536000, immutable" if immutable else "public, max-age=3600"
        return Response(
            content=aweb_css(),
            media_type="text/css",
            headers={**_NOSNIFF, "Cache-Control": cache},
        )

    @app.get("/css/aweb.css")
    async def aweb_css_route() -> Response:
        return _aweb_css_response(immutable=False)

    @app.get("/css/aweb.{fingerprint}.css")
    async def aweb_css_fingerprinted_route(fingerprint: str) -> Response:
        return _aweb_css_response(immutable=True)

    fonts = {name: (fonts_dir / name).read_bytes() for name in sorted(FONT_NAMES)}

    @app.get("/fonts/{font_name}")
    async def font_route(font_name: str) -> Response:
        font = fonts.get(font_name)
        if font is None:
            raise HTTPException(status_code=404, detail="Font not found")
        return Response(
            content=font,
            media_type="font/woff2",
            headers={**_NOSNIFF, "Cache-Control": "public, max-age=31536000, immutable"},
        )

    @app.get("/og-card.png")
    async def og_card_route() -> Response:
        return Response(
            content=og_card_png,
            media_type="image/png",
            headers={"Cache-Control": "public, max-age=86400"},
        )

    @app.get("/reference", response_class=HTMLResponse)
    async def reference_route() -> HTMLResponse:
        return HTMLResponse(reference_html)

    @app.get("/llms.txt", response_class=PlainTextResponse)
    async def llms_route() -> PlainTextResponse:
        return PlainTextResponse(llms_txt, headers=_NOSNIFF)

    @app.get("/robots.txt", response_class=PlainTextResponse)
    async def robots_route() -> PlainTextResponse:
        return PlainTextResponse(robots_txt(robots_disallow), headers=_NOSNIFF)

    @app.get("/skills/", response_class=PlainTextResponse)
    async def skills_index_route() -> PlainTextResponse:
        return PlainTextResponse(skills.index(), headers=_NOSNIFF)

    @app.get("/skills/{skill_name}/SKILL.md", response_class=PlainTextResponse)
    async def skill_route(skill_name: str) -> PlainTextResponse:
        skill = skills.read(skill_name)
        if skill is None:
            raise HTTPException(status_code=404, detail="Skill not found")
        return PlainTextResponse(skill, headers=_NOSNIFF)

    mount_manifest_routes(app, runtime=runtime)
    mount_health(app, settings, checks={**runtime.health_checks(), **(health_checks or {})})
