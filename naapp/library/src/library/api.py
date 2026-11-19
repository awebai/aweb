import json
import logging
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Annotated

from aweb_naapp.identity_assets import identity_asset
from aweb_naapp.runtime.app import InstalledMember, NaappRuntime, mount_naapp_routes
from aweb_naapp.runtime.authorization import DeclaredTool
from aweb_naapp.runtime.installation import (
    InstallationDatabase,
    InstallationRefused,
    apply_installation_migrations,
)
from aweb_naapp.runtime.team_auth import Principal
from awid.external_authority import TXTOutcomeResolver
from fastapi import Depends, FastAPI, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pgdbm import AsyncDatabaseManager

from library import browse, browse_views
from library.aweb_manifest import MANIFEST_PATH
from library.config import Settings, get_settings
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
    SKILLS,
    llms_txt,
    render_landing_page,
    render_reference_page,
)

_OG_CARD = identity_asset("library-card.png")
assert _OG_CARD is not None
_OG_CARD_BYTES = _OG_CARD[0]


_MIGRATIONS_DIR = Path(__file__).resolve().parent / "migrations"
_logger = logging.getLogger(__name__)


def create_app(
    settings: Settings | None = None, *, awid_txt_resolver: TXTOutcomeResolver | None = None
) -> FastAPI:
    """library's app. ``awid_txt_resolver`` answers the ``_awid`` records that
    name who may move a pinned team key (system DNS by default)."""
    resolved = settings or get_settings()
    runtime = NaappRuntime(
        resolved,
        module_name="library",
        migrations_path=_MIGRATIONS_DIR,
        manifest_path=MANIFEST_PATH,
        awid_txt_resolver=awid_txt_resolver,
        stores=(apply_installation_migrations,),
    )
    app = FastAPI(title="library", version="0.1.0", lifespan=runtime.lifespan)

    @app.exception_handler(InstallationRefused)
    async def installation_refused(_request: Request, error: InstallationRefused) -> JSONResponse:
        return JSONResponse(
            status_code=error.status,
            content={"detail": {"code": error.code, "message": str(error)}},
        )

    async def landing() -> str:
        # The front door must render even when the database is unavailable, so
        # the catalog teaser is a best-effort read.
        blueprints: list[dict] = []
        database = runtime.connected_db()
        if database is not None:
            try:
                blueprints = await browse_views.catalog_view(database)
            except Exception:
                _logger.exception("landing catalog read failed")
        return render_landing_page(public_origin=resolved.public_origin, blueprints=blueprints)

    mount_naapp_routes(
        app,
        runtime=runtime,
        skills=SKILLS,
        landing=landing,
        reference_html=render_reference_page(public_origin=resolved.public_origin),
        llms_txt=llms_txt(public_origin=resolved.public_origin),
        og_card_png=_OG_CARD_BYTES,
    )
    _mount_browse_routes(app, db=runtime.db, public_origin=resolved.public_origin)
    _mount_catalog_routes(app, db=runtime.db)
    installed_member = runtime.installed_member(policy=_member_policy)

    async def member(
        installed: Annotated[InstalledMember, Depends(installed_member)],
    ) -> Principal:
        return installed.principal

    async def member_db(
        installed: Annotated[InstalledMember, Depends(installed_member)],
    ) -> InstallationDatabase:
        return installed.permit.database()

    _mount_member_routes(app, principal=member, db=member_db)
    return app


async def _member_policy(request: Request, principal: Principal, tool: DeclaredTool) -> bool:
    """Library's domain rules (ownership, team keys) live in the repository; the
    runtime admits the declared tools, invocation contexts and installed scopes."""
    return True


def _mount_browse_routes(
    app: FastAPI, *, db: Callable[..., AsyncDatabaseManager], public_origin: str
) -> None:
    """The public HTML pages that browse the blueprint catalog."""

    @app.get("/blueprints", response_class=HTMLResponse)
    async def browse_catalog_route(
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> HTMLResponse:
        blueprints = await browse_views.catalog_view(database)
        return HTMLResponse(
            browse.render_catalog_page(public_origin=public_origin, blueprints=blueprints)
        )

    @app.get("/blueprints/{blueprint_id}", response_class=HTMLResponse)
    async def browse_blueprint_route(
        blueprint_id: str,
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> HTMLResponse:
        blueprint = await browse_views.blueprint_view(database, blueprint_ref=blueprint_id)
        return HTMLResponse(
            browse.render_blueprint_page(public_origin=public_origin, blueprint=blueprint)
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
            browse.render_profile_page(public_origin=public_origin, profile=profile)
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
        return HTMLResponse(browse.render_skill_page(public_origin=public_origin, skill=skill))


def _mount_catalog_routes(app: FastAPI, *, db: Callable[..., AsyncDatabaseManager]) -> None:
    """The public JSON catalog: blueprints and their profiles, readable by anyone."""
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


def _mount_member_routes(
    app: FastAPI,
    *,
    principal: Callable[..., Awaitable[Principal]],
    db: Callable[..., Awaitable[InstallationDatabase]],
) -> None:
    """The team-scoped routes, each admitted by ``principal``."""
    # --- Team shelf reads (private; cert-gated) -----------------------------------

    @app.get("/v1/shelf")
    async def list_shelf_route(
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[InstallationDatabase, Depends(db)],
    ) -> dict:
        return await list_shelf(database, principal=actor)

    @app.get("/v1/profiles/{profile_id}")
    async def get_shelf_profile_route(
        profile_id: str,
        request: Request,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[InstallationDatabase, Depends(db)],
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
        database: Annotated[InstallationDatabase, Depends(db)],
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
        database: Annotated[InstallationDatabase, Depends(db)],
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
        database: Annotated[InstallationDatabase, Depends(db)],
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
        database: Annotated[InstallationDatabase, Depends(db)],
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
        database: Annotated[InstallationDatabase, Depends(db)],
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
        database: Annotated[InstallationDatabase, Depends(db)],
    ) -> dict:
        return await publish_blueprint(database, principal=actor, payload=await request.json())

    # import-to-shelf: a team copies a public-blueprint profile onto its private shelf.
    # Idempotent keyed by (team, source blueprint, source profile): re-import is a pure
    # no-op returning the existing copy — never an update-from-source.
    @app.post("/v1/shelf/import")
    async def import_to_shelf_route(
        request: Request,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[InstallationDatabase, Depends(db)],
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
        database: Annotated[InstallationDatabase, Depends(db)],
    ) -> dict:
        binding = ProfileBindingRequest.model_validate(await request.json())
        return await set_profile_binding(
            database, principal=actor, agent_id=agent_id, binding=binding
        )

    @app.get("/v1/agents/{agent_id}/profile-binding")
    async def get_profile_binding_route(
        agent_id: str,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[InstallationDatabase, Depends(db)],
    ) -> dict:
        return await get_profile_binding(database, principal=actor, agent_id=agent_id)

    @app.post("/v1/materialize")
    async def materialize_route(
        request: Request,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[InstallationDatabase, Depends(db)],
    ) -> dict:
        materialize_request = MaterializeRequest.model_validate(await request.json())
        return await materialize(database, principal=actor, request=materialize_request)

    # Mutable organizational tags (digest-unaffected); visibility is structural in v2.
    @app.put("/v1/profiles/{profile_ref}/tags")
    async def set_profile_tags_route(
        profile_ref: str,
        request: Request,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[InstallationDatabase, Depends(db)],
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
        database: Annotated[InstallationDatabase, Depends(db)],
    ) -> dict:
        payload = SetTagsRequest.model_validate(await request.json())
        return await set_blueprint_tags(
            database, principal=actor, blueprint_ref=blueprint_ref, tags=payload.tags
        )

    @app.delete("/v1/blueprints/{blueprint_ref}")
    async def delete_blueprint_route(
        blueprint_ref: str,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[InstallationDatabase, Depends(db)],
    ) -> dict:
        return await delete_blueprint(database, principal=actor, blueprint_ref=blueprint_ref)

    @app.delete("/v1/profiles/{profile_id}")
    async def delete_shelf_profile_route(
        profile_id: str,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[InstallationDatabase, Depends(db)],
    ) -> dict:
        return await delete_shelf_profile(database, principal=actor, profile_ref=profile_id)

    @app.post("/v1/proposals")
    async def create_proposal_route(
        request: Request,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[InstallationDatabase, Depends(db)],
    ) -> dict:
        payload = ProposalCreateRequest.model_validate(await request.json())
        return await create_proposal(database, principal=actor, request=payload)

    @app.get("/v1/proposals")
    async def list_proposals_route(
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[InstallationDatabase, Depends(db)],
    ) -> list[dict]:
        return await list_proposals(database, principal=actor)

    @app.post("/v1/proposals/{proposal_id}/approve")
    async def approve_proposal_route(
        proposal_id: str,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[InstallationDatabase, Depends(db)],
    ) -> dict:
        return await approve_proposal(database, principal=actor, proposal_id=proposal_id)

    @app.post("/v1/proposals/{proposal_id}/reject")
    async def reject_proposal_route(
        proposal_id: str,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[InstallationDatabase, Depends(db)],
    ) -> dict:
        return await reject_proposal(database, principal=actor, proposal_id=proposal_id)


app = create_app()
