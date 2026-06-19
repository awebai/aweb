import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from pgdbm import AsyncDatabaseManager

from library.auth import AWIDTeamCache, Principal, authenticate_request
from library.aweb_manifest import read_manifest_bytes
from library.config import Settings, get_settings
from library.db import LibraryDatabase
from library.models import (
    ImportToShelfRequest,
    MaterializeRequest,
    ProfileBindingRequest,
    ProfilePublishRequest,
    ProposalCreateRequest,
    SetTagsRequest,
    TeamRegisterRequest,
    UpdateFromSourceRequest,
)
from library.repository import (
    approve_proposal,
    create_proposal,
    create_shelf_profile,
    create_shelf_version,
    get_pack_profile,
    get_profile_binding,
    get_profile_pack,
    get_shelf_profile,
    import_to_shelf,
    list_profile_packs,
    list_proposals,
    list_shelf,
    materialize,
    publish_pack,
    publish_profile,
    register_team,
    reject_proposal,
    set_pack_tags,
    set_profile_binding,
    set_profile_tags,
    update_from_source,
)
from library.surfaces import (
    aweb_css,
    llms_txt,
    read_skill,
    render_landing_page,
    robots_txt,
    skills_index,
)


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

    @app.get("/css/aweb.css")
    async def aweb_css_route() -> Response:
        return Response(
            content=aweb_css(),
            media_type="text/css",
            headers={"X-Content-Type-Options": "nosniff", "Cache-Control": "public, max-age=3600"},
        )

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

    # --- Public catalog: packs are always public; ?tags filter -------------------

    @app.get("/v1/profile-packs")
    async def list_profile_packs_route(
        database: Annotated[AsyncDatabaseManager, Depends(db)],
        tags: Annotated[list[str] | None, Query()] = None,
    ) -> list[dict]:
        return await list_profile_packs(database, tags=tags)

    @app.get("/v1/profile-packs/{pack_id}")
    async def get_profile_pack_route(
        pack_id: str,
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        return await get_profile_pack(database, pack_ref=pack_id)

    @app.get("/v1/profile-packs/{pack_id}/profiles/{profile_id}")
    async def get_pack_profile_route(
        pack_id: str,
        profile_id: str,
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        return await get_pack_profile(database, pack_ref=pack_id, profile_ref=profile_id)

    # --- Team shelf reads (private; cert-gated) -----------------------------------

    @app.get("/v1/shelf")
    async def list_shelf_route(
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        return await list_shelf(database, principal=actor)

    @app.get("/v1/profiles/{profile_id}")
    async def get_shelf_profile_route(
        profile_id: str,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        return await get_shelf_profile(database, principal=actor, profile_ref=profile_id)

    @app.post("/v1/profiles")
    async def create_shelf_profile_route(
        request: Request,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        body = await request.json()
        return await create_shelf_profile(
            database, principal=actor, files=body.get("files", []), tags=body.get("tags", [])
        )

    @app.post("/v1/profiles/{profile_ref}/versions")
    async def create_shelf_version_route(
        profile_ref: str,
        request: Request,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        body = await request.json()
        return await create_shelf_version(
            database, principal=actor, profile_ref=profile_ref, files=body.get("files", [])
        )

    # update-from-source: per-part 3-way merge of a shelf profile against a newer
    # version of its source pack — pull upstream improvements into un-evolved parts,
    # keep local edits. A real merge mints target_version; nothing pullable is a no-op.
    @app.post("/v1/profiles/{profile_ref}/update-from-source")
    async def update_from_source_route(
        profile_ref: str,
        request: Request,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        raw = await request.body()
        payload = UpdateFromSourceRequest.model_validate(json.loads(raw) if raw.strip() else {})
        return await update_from_source(database, principal=actor, profile_ref=profile_ref, request=payload)

    # publish-profile: a team publishes a private shelf profile into a PUBLIC pack
    # (new pack, or a new version of an owned pack). pack.yaml is library-generated
    # and the profile set accumulates.
    @app.post("/v1/profiles/{profile_ref}/publish")
    async def publish_profile_route(
        profile_ref: str,
        request: Request,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        raw = await request.body()
        payload = ProfilePublishRequest.model_validate(json.loads(raw) if raw.strip() else {})
        return await publish_profile(database, principal=actor, profile_ref=profile_ref, request=payload)

    # --- Team-scoped, cert-auth-gated routes --------------------------------------
    # The principal dependency enforces AWID team-certificate auth (401 without a
    # valid certificate) and keys all state by the verified team_id.

    @app.post("/v1/team/register")
    async def register_team_route(
        request: Request,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        raw = await request.body()
        payload = TeamRegisterRequest.model_validate(json.loads(raw) if raw.strip() else {})
        return await register_team(database, principal=actor, owner=payload.owner, display_name=payload.display_name)

    # publish-pack: a producer uploads/updates a PUBLIC pack (the former import,
    # wire-unchanged: canonical import-payload -> import-return).
    @app.post("/v1/profile-packs/import")
    async def publish_pack_route(
        request: Request,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        return await publish_pack(database, principal=actor, payload=await request.json())

    # import-to-shelf: a team copies a public-pack profile onto its private shelf.
    # Idempotent keyed by (team, source pack, source profile): re-import is a pure
    # no-op returning the existing copy — never an update-from-source.
    @app.post("/v1/shelf/import")
    async def import_to_shelf_route(
        request: Request,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        raw = await request.body()
        payload = ImportToShelfRequest.model_validate(json.loads(raw) if raw.strip() else {})
        return await import_to_shelf(
            database,
            principal=actor,
            source_profile_pack_ref=payload.source_profile_pack_ref,
            source_profile_pack_version=payload.source_profile_pack_version,
            profile_ref=payload.profile_ref,
            tags=payload.tags,
        )

    @app.post("/v1/agents/{agent_id}/profile-binding")
    async def set_profile_binding_route(
        agent_id: str,
        request: Request,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        binding = ProfileBindingRequest.model_validate(await request.json())
        return await set_profile_binding(database, principal=actor, agent_id=agent_id, binding=binding)

    @app.get("/v1/agents/{agent_id}/profile-binding")
    async def get_profile_binding_route(
        agent_id: str,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        return await get_profile_binding(database, principal=actor, agent_id=agent_id)

    @app.post("/v1/materialize")
    async def materialize_route(
        request: Request,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        materialize_request = MaterializeRequest.model_validate(await request.json())
        return await materialize(database, principal=actor, request=materialize_request)

    # Mutable organizational tags (digest-unaffected); visibility is structural in v2.
    @app.put("/v1/profiles/{profile_ref}/tags")
    async def set_profile_tags_route(
        profile_ref: str,
        request: Request,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        payload = SetTagsRequest.model_validate(await request.json())
        return await set_profile_tags(database, principal=actor, profile_ref=profile_ref, tags=payload.tags)

    @app.put("/v1/profile-packs/{pack_ref}/tags")
    async def set_pack_tags_route(
        pack_ref: str,
        request: Request,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        payload = SetTagsRequest.model_validate(await request.json())
        return await set_pack_tags(database, principal=actor, pack_ref=pack_ref, tags=payload.tags)

    @app.post("/v1/proposals")
    async def create_proposal_route(
        request: Request,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        payload = ProposalCreateRequest.model_validate(await request.json())
        return await create_proposal(database, principal=actor, request=payload)

    @app.get("/v1/proposals")
    async def list_proposals_route(
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> list[dict]:
        return await list_proposals(database, principal=actor)

    @app.post("/v1/proposals/{proposal_id}/approve")
    async def approve_proposal_route(
        proposal_id: str,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        return await approve_proposal(database, principal=actor, proposal_id=proposal_id)

    @app.post("/v1/proposals/{proposal_id}/reject")
    async def reject_proposal_route(
        proposal_id: str,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        return await reject_proposal(database, principal=actor, proposal_id=proposal_id)

    return app


app = create_app()
