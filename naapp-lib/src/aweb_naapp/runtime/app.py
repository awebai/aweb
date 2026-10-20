"""The wiring and public surface every naapp shares.

An app creates a :class:`NaappRuntime`, builds its FastAPI app with the
runtime's lifespan, and calls :func:`mount_naapp_routes` for the standard public
surface.

Member operations are guarded with ``Depends(runtime.authorized(tools=...,
grants=..., policy=...))``. It admits a request only when it is signed by a
team member, declared by the app's manifest, covered by the team's installed
grant, and allowed by the app's policy. ``Depends(runtime.principal)`` only
authenticates: it says who signed the request, never that they may act, so it
is for routes that need nothing more than the signer's identity.

The ``/fonts/`` route is not part of the shared surface yet: it waits on
whether the font files may ship inside this package.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.dependencies.models import Dependant
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from fastapi.routing import APIRoute
from pgdbm import AsyncDatabaseManager

from aweb_naapp.css import aweb_css
from aweb_naapp.manifest import read_manifest_bytes
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
from aweb_naapp.runtime.health import mount_health
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
    """

    def __init__(
        self,
        settings: NaappSettings,
        *,
        module_name: str,
        migrations_path: Path,
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
        self._guards: dict[Callable[..., object], DeclaredTools] = {}

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
        try:
            yield
        finally:
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
        )

    def authorized(
        self, *, tools: DeclaredTools, grants: GrantSource, policy: ActionPolicy
    ) -> Callable[[Request], Awaitable[Authorization]]:
        """A FastAPI dependency admitting only authorized member requests.

        It authenticates the request, then authorizes it against the app's
        declared ``tools``, the team's grant from ``grants`` and the app's
        ``policy``. Only an admitted member is recorded as observed, so
        refused requests never write to the app's database.
        """

        async def authorized_request(request: Request) -> Authorization:
            principal = await self.principal(request)
            authorization = await authorize_request(
                request, principal=principal, tools=tools, grants=grants, policy=policy
            )
            await record_observed_principal(self.db(), principal)
            return authorization

        self._guards[authorized_request] = tools
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
        placeholder matches. The lifespan runs this check before anything else.
        """
        for route in app.routes:
            if not isinstance(route, APIRoute):
                continue
            for tools in self._route_guards(route.dependant):
                path = self.root_path + route.path_format
                if route.path != route.path_format:
                    raise RuntimeError(
                        f"authorized route {route.path} uses a path converter; declare it plainly"
                    )
                template = _template(path.split("/"))
                for method in sorted(route.methods or ()):
                    if not any(
                        tool.method == method and _template(tool.segments) == template
                        for tool in tools
                    ):
                        raise RuntimeError(
                            f"authorized route {method} {path} is not exactly a declared manifest tool"
                        )

    def _route_guards(self, dependant: Dependant) -> list[DeclaredTools]:
        guards = []
        for dependency in dependant.dependencies:
            if dependency.call in self._guards:
                guards.append(self._guards[dependency.call])
            guards.extend(self._route_guards(dependency))
        return guards


def _template(segments: Sequence[str]) -> tuple[str, ...]:
    return tuple("{}" if is_placeholder(segment) else segment for segment in segments)


def mount_naapp_routes(
    app: FastAPI,
    *,
    runtime: NaappRuntime,
    manifest_path: Path,
    skills: Skills,
    landing: Callable[[], Awaitable[str]],
    reference_html: str,
    llms_txt: str,
    og_card_png: bytes,
    robots_disallow: Sequence[str] = (),
    noindex_paths: Sequence[str] = (),
) -> None:
    """Serve the standard naapp public surface.

    The landing page, robots rules and noindex paths are the app's: ``landing``
    renders the front door on each request, ``robots_disallow`` lists the paths
    crawlers must skip, and every response under ``noindex_paths`` (found or
    not) carries ``X-Robots-Tag``. The manifest is the committed file, adjusted
    for a deployment whose public origin is not the committed one.
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

    async def _manifest_response() -> Response:
        return Response(
            content=read_manifest_bytes(manifest_path, settings.public_origin),
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

    mount_health(app, settings)
