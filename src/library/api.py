from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from pgdbm import AsyncDatabaseManager

from library.auth import AWIDTeamCache, Principal, authenticate_request
from library.aweb_manifest import read_manifest_bytes
from library.config import Settings, get_settings
from library.db import LibraryDatabase
from library.surfaces import (
    llms_txt,
    read_skill,
    render_landing_page,
    robots_txt,
    skills_index,
)

_SCAFFOLD_DETAIL = "Not implemented in the library scaffold (default-aaas.14.1)"


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved = settings or get_settings()
    holder: dict[str, object] = {}

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        database = LibraryDatabase(resolved)
        await database.connect()
        holder["db"] = database
        holder["team_cache"] = AWIDTeamCache(
            registry_url=resolved.awid_registry_url,
            ttl_seconds=resolved.auth_cache_ttl_seconds,
        )
        try:
            yield
        finally:
            await database.disconnect()

    app = FastAPI(title="library", version="0.1.0", lifespan=lifespan)

    def db() -> AsyncDatabaseManager:
        database = holder.get("db")
        if not isinstance(database, LibraryDatabase):
            raise RuntimeError("library database is not initialized")
        return database.db

    def team_cache() -> AWIDTeamCache:
        cache = holder.get("team_cache")
        if not isinstance(cache, AWIDTeamCache):
            raise RuntimeError("library auth cache is not initialized")
        return cache

    async def principal(
        request: Request,
        database: Annotated[AsyncDatabaseManager, Depends(db)],
        cache: Annotated[AWIDTeamCache, Depends(team_cache)],
    ) -> Principal:
        return await authenticate_request(request, settings=resolved, team_cache=cache, db=database)

    # --- Public, no-auth surfaces -------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    async def landing_route() -> HTMLResponse:
        return HTMLResponse(render_landing_page(public_origin=resolved.public_origin))

    @app.get("/llms.txt", response_class=PlainTextResponse)
    async def llms_route() -> PlainTextResponse:
        return PlainTextResponse(
            llms_txt(public_origin=resolved.public_origin),
            headers={"X-Content-Type-Options": "nosniff"},
        )

    @app.get("/robots.txt", response_class=PlainTextResponse)
    async def robots_route() -> PlainTextResponse:
        return PlainTextResponse(robots_txt(), headers={"X-Content-Type-Options": "nosniff"})

    @app.get("/skills/", response_class=PlainTextResponse)
    async def skills_index_route() -> PlainTextResponse:
        return PlainTextResponse(skills_index(), headers={"X-Content-Type-Options": "nosniff"})

    @app.get("/skills/{skill_name}/SKILL.md", response_class=PlainTextResponse)
    async def skill_route(skill_name: str) -> PlainTextResponse:
        skill = read_skill(skill_name)
        if skill is None:
            raise HTTPException(status_code=404, detail="Skill not found")
        return PlainTextResponse(skill, headers={"X-Content-Type-Options": "nosniff"})

    async def _manifest_response() -> Response:
        return Response(
            content=read_manifest_bytes(),
            media_type="application/json",
            headers={"X-Content-Type-Options": "nosniff"},
        )

    # Served at the RFC 8615 well-known path the dispatcher/gateway fetch, plus the
    # bare path the Library SOT lists. Both return the same raw committed bytes.
    @app.get("/.well-known/aweb-app.json")
    async def well_known_manifest_route() -> Response:
        return await _manifest_response()

    @app.get("/aweb-app.json")
    async def aweb_app_manifest_route() -> Response:
        return await _manifest_response()

    @app.get("/health")
    @app.get("/live")
    @app.get("/ready")
    async def health() -> dict[str, str]:
        return {"status": "ok", "service": "library"}

    # --- Public catalog reads (empty until the model task) ------------------------

    @app.get("/v1/profile-packs")
    async def list_profile_packs_route() -> list[dict]:
        return []

    @app.get("/v1/profile-packs/{pack_id}")
    async def get_profile_pack_route(pack_id: str) -> dict:
        raise HTTPException(status_code=404, detail="Profile pack not found")

    @app.get("/v1/profiles/{profile_id}")
    async def get_profile_route(profile_id: str) -> dict:
        raise HTTPException(status_code=404, detail="Profile not found")

    # --- Team-scoped, cert-auth-gated write stubs ---------------------------------
    # The principal dependency enforces AWID team-certificate auth (401 without a
    # valid certificate). Real bodies arrive in later tasks; for now each verb is a
    # 501 stub so the authenticated surface is present and testable.

    @app.post("/v1/profile-packs/import")
    async def import_profile_pack_route(actor: Annotated[Principal, Depends(principal)]) -> Response:
        raise HTTPException(status_code=501, detail=_SCAFFOLD_DETAIL)

    @app.post("/v1/agents/{agent_id}/profile-binding")
    async def set_profile_binding_route(
        agent_id: str, actor: Annotated[Principal, Depends(principal)]
    ) -> Response:
        raise HTTPException(status_code=501, detail=_SCAFFOLD_DETAIL)

    @app.get("/v1/agents/{agent_id}/profile-binding")
    async def get_profile_binding_route(
        agent_id: str, actor: Annotated[Principal, Depends(principal)]
    ) -> Response:
        raise HTTPException(status_code=501, detail=_SCAFFOLD_DETAIL)

    @app.post("/v1/materialize")
    async def materialize_route(actor: Annotated[Principal, Depends(principal)]) -> Response:
        raise HTTPException(status_code=501, detail=_SCAFFOLD_DETAIL)

    @app.post("/v1/proposals")
    async def create_proposal_route(actor: Annotated[Principal, Depends(principal)]) -> Response:
        raise HTTPException(status_code=501, detail=_SCAFFOLD_DETAIL)

    @app.get("/v1/proposals")
    async def list_proposals_route(actor: Annotated[Principal, Depends(principal)]) -> Response:
        raise HTTPException(status_code=501, detail=_SCAFFOLD_DETAIL)

    @app.post("/v1/proposals/{proposal_id}/approve")
    async def approve_proposal_route(
        proposal_id: str, actor: Annotated[Principal, Depends(principal)]
    ) -> Response:
        raise HTTPException(status_code=501, detail=_SCAFFOLD_DETAIL)

    @app.post("/v1/proposals/{proposal_id}/reject")
    async def reject_proposal_route(
        proposal_id: str, actor: Annotated[Principal, Depends(principal)]
    ) -> Response:
        raise HTTPException(status_code=501, detail=_SCAFFOLD_DETAIL)

    return app


app = create_app()
