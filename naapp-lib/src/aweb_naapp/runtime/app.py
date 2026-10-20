"""The wiring and public surface every naapp shares.

An app creates a :class:`NaappRuntime`, builds its FastAPI app with the
runtime's lifespan, calls :func:`mount_naapp_routes` for the standard public
surface, and declares its own operations with ``Depends(runtime.principal)``
and ``Depends(runtime.db)``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from pgdbm import AsyncDatabaseManager

from aweb_naapp.css import aweb_css
from aweb_naapp.manifest import read_manifest_bytes
from aweb_naapp.robots import robots_txt
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
    """A naapp's database and AWID team cache, open for the app's lifespan."""

    def __init__(
        self,
        settings: NaappSettings,
        *,
        module_name: str,
        migrations_path: Path,
        awid_transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.settings = settings
        self.module_name = module_name
        self.migrations_path = migrations_path
        self._awid_transport = awid_transport
        self._database: NaappDatabase | None = None
        self._team_cache: AWIDTeamCache | None = None

    @asynccontextmanager
    async def lifespan(self, _app: FastAPI) -> AsyncIterator[None]:
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
        """FastAPI dependency: the team member who signed this request, recorded
        as observed by the app."""
        principal = await authenticate_request(
            request,
            public_origin=self.settings.public_origin,
            team_cache=self.team_cache(),
            timestamp_skew_seconds=self.settings.timestamp_skew_seconds,
        )
        await record_observed_principal(self.db(), principal)
        return principal


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
