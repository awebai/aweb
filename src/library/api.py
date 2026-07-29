import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from pgdbm import AsyncDatabaseManager

from library import browse, browse_views
from library.auth import AWIDTeamCache, Principal, authenticate_request
from library.aweb_manifest import read_manifest_bytes
from library.build_identity import resolve_build_identity
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
    delete_blueprint,
    delete_shelf_profile,
    get_blueprint,
    get_blueprint_profile,
    get_profile_binding,
    get_shelf_profile,
    import_to_shelf,
    list_blueprints,
    list_proposals,
    list_shelf,
    materialize,
    publish_blueprint,
    publish_profile,
    register_team,
    reject_proposal,
    set_blueprint_tags,
    set_profile_binding,
    set_profile_tags,
    update_from_source,
)
from library.surfaces import (
    aweb_css,
    llms_txt,
    read_skill,
    render_landing_page,
    render_reference_page,
    robots_txt,
    skills_index,
)

_OG_CARD_BYTES = (Path(__file__).resolve().parent / "assets" / "og-card.png").read_bytes()
_FONTS_DIR = Path(__file__).resolve().parents[2] / "site" / "static" / "fonts"
_FONT_FILES = {
    name: _FONTS_DIR / name
    for name in (
        "BerkeleyMono-Light.woff2",
        "BerkeleyMono-Regular.woff2",
        "BerkeleyMono-SemiBold.woff2",
    )
}


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved = settings or get_settings()
    build_identity = resolve_build_identity()
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
        # The landing presents the first-party blueprint(s) from the live catalog
        # with their roles (catalog_view carries each blueprint's profiles). It is
        # a best-effort enhancement: the front door must render even when the
        # database is unavailable, so the read is soft.
        blueprints: list[dict] = []
        database = holder.get("db")
        if isinstance(database, LibraryDatabase):
            try:
                blueprints = await browse_views.catalog_view(database.db)
            except Exception:
                blueprints = []
        return HTMLResponse(
            render_landing_page(public_origin=resolved.public_origin, blueprints=blueprints)
        )

    def _aweb_css_response(immutable: bool) -> Response:
        # The fingerprinted URL is content-addressed, so it can be cached forever;
        # the legacy /css/aweb.css keeps a short TTL.
        cache = "public, max-age=31536000, immutable" if immutable else "public, max-age=3600"
        return Response(
            content=aweb_css(),
            media_type="text/css",
            headers={"X-Content-Type-Options": "nosniff", "Cache-Control": cache},
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
            content=_OG_CARD_BYTES,
            media_type="image/png",
            headers={"Cache-Control": "public, max-age=86400"},
        )

    @app.get("/fonts/{font_name}")
    async def font_route(font_name: str) -> Response:
        path = _FONT_FILES.get(font_name)
        if path is None or not path.is_file():
            raise HTTPException(status_code=404, detail="Font not found")
        return Response(
            content=path.read_bytes(),
            media_type="font/woff2",
            headers={
                "X-Content-Type-Options": "nosniff",
                "Cache-Control": "public, max-age=31536000, immutable",
            },
        )

    @app.get("/llms.txt", response_class=PlainTextResponse)
    async def llms_route() -> PlainTextResponse:
        return PlainTextResponse(
            llms_txt(public_origin=resolved.public_origin),
            headers={"X-Content-Type-Options": "nosniff"},
        )

    @app.get("/reference", response_class=HTMLResponse)
    async def reference_route() -> HTMLResponse:
        return HTMLResponse(render_reference_page(public_origin=resolved.public_origin))

    @app.get("/blueprints", response_class=HTMLResponse)
    async def browse_catalog_route(
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> HTMLResponse:
        blueprints = await browse_views.catalog_view(database)
        return HTMLResponse(
            browse.render_catalog_page(public_origin=resolved.public_origin, blueprints=blueprints)
        )

    @app.get("/blueprints/{blueprint_id}", response_class=HTMLResponse)
    async def browse_blueprint_route(
        blueprint_id: str,
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> HTMLResponse:
        blueprint = await browse_views.blueprint_view(database, blueprint_ref=blueprint_id)
        return HTMLResponse(
            browse.render_blueprint_page(public_origin=resolved.public_origin, blueprint=blueprint)
        )

    @app.get("/blueprints/{blueprint_id}/profiles/{profile_id}", response_class=HTMLResponse)
    async def browse_profile_route(
        blueprint_id: str,
        profile_id: str,
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> HTMLResponse:
        profile = await browse_views.profile_view(
            database, blueprint_ref=blueprint_id, profile_ref=profile_id
        )
        return HTMLResponse(
            browse.render_profile_page(public_origin=resolved.public_origin, profile=profile)
        )

    @app.get(
        "/blueprints/{blueprint_id}/profiles/{profile_id}/skills/{skill_name}",
        response_class=HTMLResponse,
    )
    async def browse_skill_route(
        blueprint_id: str,
        profile_id: str,
        skill_name: str,
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> HTMLResponse:
        skill = await browse_views.skill_view(
            database, blueprint_ref=blueprint_id, profile_ref=profile_id, skill_name=skill_name
        )
        return HTMLResponse(browse.render_skill_page(public_origin=resolved.public_origin, skill=skill))

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
            content=read_manifest_bytes(resolved.public_origin),
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
    async def health() -> dict[str, object]:
        return {"status": "ok", "service": "library", "build": build_identity}

    # --- Public catalog: blueprints are always public; ?tags filter -------------------

    @app.get("/v1/blueprints")
    async def list_blueprints_route(
        database: Annotated[AsyncDatabaseManager, Depends(db)],
        tags: Annotated[list[str] | None, Query()] = None,
    ) -> list[dict]:
        return await list_blueprints(database, tags=tags)

    @app.get("/v1/blueprints/{blueprint_id}")
    async def get_blueprint_route(
        blueprint_id: str,
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        return await get_blueprint(database, blueprint_ref=blueprint_id)

    @app.get("/v1/blueprints/{blueprint_id}/profiles/{profile_id}")
    async def get_blueprint_profile_route(
        blueprint_id: str,
        profile_id: str,
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        return await get_blueprint_profile(
            database, blueprint_ref=blueprint_id, profile_ref=profile_id
        )

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
        request: Request,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        # Default is the lighter summary; ?include=files adds the profile's
        # content (path/content_utf8/sha256) so a consumer can materialize the
        # shelf version locally. Opt-in keeps the summary contract back-compatible.
        include_files = request.query_params.get("include") == "files"
        return await get_shelf_profile(
            database, principal=actor, profile_ref=profile_id, include_files=include_files
        )

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
    # version of its source blueprint — pull upstream improvements into un-evolved parts,
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
        return await update_from_source(
            database, principal=actor, profile_ref=profile_ref, request=payload
        )

    # publish-profile: a team publishes a private shelf profile into a PUBLIC blueprint
    # (new blueprint, or a new version of an owned blueprint). blueprint.yaml is library-generated
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
        return await publish_profile(
            database, principal=actor, profile_ref=profile_ref, request=payload
        )

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
        return await register_team(
            database, principal=actor, owner=payload.owner, display_name=payload.display_name
        )

    # publish-blueprint: a producer uploads/updates a PUBLIC blueprint (the former import,
    # wire-unchanged: canonical import-payload -> import-return).
    @app.post("/v1/blueprints/import")
    async def publish_blueprint_route(
        request: Request,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        return await publish_blueprint(database, principal=actor, payload=await request.json())

    # import-to-shelf: a team copies a public-blueprint profile onto its private shelf.
    # Idempotent keyed by (team, source blueprint, source profile): re-import is a pure
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
            source_blueprint_ref=payload.source_blueprint_ref,
            source_blueprint_version=payload.source_blueprint_version,
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
        return await set_profile_binding(
            database, principal=actor, agent_id=agent_id, binding=binding
        )

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
        return await set_profile_tags(
            database, principal=actor, profile_ref=profile_ref, tags=payload.tags
        )

    @app.put("/v1/blueprints/{blueprint_ref}/tags")
    async def set_blueprint_tags_route(
        blueprint_ref: str,
        request: Request,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        payload = SetTagsRequest.model_validate(await request.json())
        return await set_blueprint_tags(
            database, principal=actor, blueprint_ref=blueprint_ref, tags=payload.tags
        )

    @app.delete("/v1/blueprints/{blueprint_ref}")
    async def delete_blueprint_route(
        blueprint_ref: str,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        return await delete_blueprint(database, principal=actor, blueprint_ref=blueprint_ref)

    @app.delete("/v1/profiles/{profile_id}")
    async def delete_shelf_profile_route(
        profile_id: str,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        return await delete_shelf_profile(database, principal=actor, profile_ref=profile_id)

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
