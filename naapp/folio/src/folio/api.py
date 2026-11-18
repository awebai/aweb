from pathlib import Path
from typing import Annotated

from aweb_naapp.identity_assets import identity_asset
from aweb_naapp.runtime.app import NaappRuntime, mount_naapp_routes
from aweb_naapp.runtime.authorization import Authorization
from aweb_naapp.runtime.installation import InstallationRefused, apply_installation_migrations
from aweb_naapp.runtime.team_auth import Principal
from fastapi import Depends, FastAPI, HTTPException, Request
from pgdbm import AsyncDatabaseManager

from folio.asset_routes import mount_asset_routes
from folio.aweb_manifest import MANIFEST_PATH
from folio.config import Settings, get_settings
from folio.models import (
    AppendTemplateVersionRequest,
    BillingResponse,
    CreateDocumentRequest,
    CreatePresentationRequest,
    DocumentResponse,
    DocumentSummary,
    DocumentVersion,
    LinkKind,
    PresentationResponse,
    ThemeRequest,
    ThemeResponse,
)
from folio.present_routes import mount_presentation_routes
from folio.presentation import theme_contrast_error
from folio.privacy import PresentationPrivacy, install_access_filter
from folio.repository import (
    append_version,
    create_document,
    get_billing_status,
    get_document,
    get_theme,
    list_documents,
    list_versions,
    mint_presentation_link,
    revoke_presentation_link,
    upsert_theme,
)
from folio.surfaces import (
    SKILLS,
    llms_txt,
    render_landing_page,
    render_reference_page,
)
from folio.templates import render_declarative_template

_PACKAGE_DIR = Path(__file__).resolve().parent
_OG_CARD = identity_asset("folio-card.png")
assert _OG_CARD is not None
_OG_CARD_BYTES = _OG_CARD[0]
_FONTS_DIR = _PACKAGE_DIR / "fonts"
_MIGRATIONS_DIR = _PACKAGE_DIR / "migrations"
# Present links and asset URLs are user content: crawlers skip them and every
# response under them carries a noindex header.
_USER_CONTENT_PATHS = ("/present/", "/assets/")


def create_app(settings: Settings | None = None) -> FastAPI:
    install_access_filter()
    resolved = settings or get_settings()
    runtime = NaappRuntime(
        resolved,
        module_name="folio",
        migrations_path=_MIGRATIONS_DIR,
        manifest_path=MANIFEST_PATH,
        stores=(apply_installation_migrations,),
    )
    app = FastAPI(title="folio", version="0.1.0", lifespan=runtime.lifespan)
    app.add_middleware(PresentationPrivacy)
    app.state.folio_runtime = runtime

    @app.exception_handler(InstallationRefused)
    async def installation_refused(request: Request, error: InstallationRefused):
        from fastapi.responses import JSONResponse

        return JSONResponse(status_code=error.status, content={"detail": {"code": error.code}})

    def db(request: Request):
        permit = getattr(request.state, "folio_installation", None)
        return permit.database() if permit is not None else runtime.db()

    # Folio's domain policy admits current members; the shared guard separately
    # enforces exact manifest tools, invocation contexts and installed scopes.
    async def member_policy(request, member, tool):
        return True

    member_authorized = runtime.authorized(
        grants=runtime.installation_grants(), policy=member_policy
    )

    async def principal(
        request: Request, authorization: Annotated[Authorization, Depends(member_authorized)]
    ) -> Principal:
        try:
            permit = await runtime.installation_fence().permit(authorization.principal.team_id)
            if (authorization.grant.installation_id, authorization.grant.generation) != (
                permit.admitted.installation_id,
                permit.admitted.generation,
            ):
                raise InstallationRefused(
                    "generation_superseded", 409, "Installation changed during admission"
                )
        except InstallationRefused as error:
            raise HTTPException(error.status, detail={"code": error.code}) from None
        request.state.folio_installation = permit
        return authorization.principal

    async def landing() -> str:
        return render_landing_page(public_origin=resolved.public_origin)

    mount_naapp_routes(
        app,
        runtime=runtime,
        skills=SKILLS,
        landing=landing,
        reference_html=render_reference_page(public_origin=resolved.public_origin),
        llms_txt=llms_txt(public_origin=resolved.public_origin),
        og_card_png=_OG_CARD_BYTES,
        fonts_dir=_FONTS_DIR,
        robots_disallow=_USER_CONTENT_PATHS,
        noindex_paths=_USER_CONTENT_PATHS,
    )

    @app.post("/v1/documents", response_model=DocumentResponse)
    async def create_document_route(
        payload: CreateDocumentRequest,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        has_body = "body" in payload.model_fields_set
        has_template = "template" in payload.model_fields_set
        if has_body == has_template:
            raise HTTPException(status_code=422, detail="Provide exactly one of body or template")
        if has_template:
            if payload.template is None:
                raise HTTPException(status_code=422, detail="template must be an object")
            body = render_declarative_template(payload.template.model_dump())
        else:
            if payload.body is None:
                raise HTTPException(status_code=422, detail="body must be a string")
            body = payload.body
        result = await create_document(
            database,
            principal=actor,
            events=runtime.app_events,
            slug=payload.slug,
            title=payload.title,
            body=body,
        )
        return result

    @app.get("/v1/documents", response_model=list[DocumentSummary])
    async def list_documents_route(
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> list[dict]:
        return await list_documents(database, principal=actor)

    @app.get("/v1/documents/{slug}", response_model=DocumentResponse)
    async def get_document_route(
        slug: str,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        return await get_document(database, principal=actor, slug=slug)

    @app.post("/v1/documents/{slug}/versions", response_model=DocumentResponse)
    async def append_version_route(
        slug: str,
        request: Request,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        try:
            body = (await request.body()).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise HTTPException(status_code=400, detail="Version body must be valid UTF-8") from exc
        result = await append_version(
            database, principal=actor, events=runtime.app_events, slug=slug, body=body
        )
        return result

    @app.post("/v1/documents/{slug}/versions/template", response_model=DocumentResponse)
    async def append_template_version_route(
        slug: str,
        payload: AppendTemplateVersionRequest,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        body = render_declarative_template(payload.model_dump())
        result = await append_version(
            database, principal=actor, events=runtime.app_events, slug=slug, body=body
        )
        return result

    @app.get("/v1/billing", response_model=BillingResponse)
    async def billing_route(
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        return await get_billing_status(database, principal=actor)

    @app.get("/v1/documents/{slug}/versions", response_model=list[DocumentVersion])
    async def list_versions_route(
        slug: str,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> list[dict]:
        return await list_versions(database, principal=actor, slug=slug)

    @app.post("/v1/present", response_model=PresentationResponse)
    async def create_presentation_route(
        request: Request,
        payload: CreatePresentationRequest,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        return await mint_presentation_link(
            database,
            installation_id=request.state.folio_installation.admitted.installation_id,
            principal=actor,
            settings=resolved,
            slug=payload.slug,
            version=payload.version,
            ttl_seconds=payload.ttl_seconds,
            kind=LinkKind.EDITABLE if payload.editable else LinkKind.READ_ONLY,
        )

    @app.post("/v1/present/{token}/revoke")
    async def revoke_presentation_route(
        token: str,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict[str, bool]:
        await revoke_presentation_link(database, principal=actor, token=token)
        return {"revoked": True}

    mount_asset_routes(app, settings=resolved, principal=principal, db=db)

    @app.get("/v1/theme", response_model=ThemeResponse)
    async def get_theme_route(
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        return await get_theme(database, principal=actor, settings=resolved)

    @app.put("/v1/theme", response_model=ThemeResponse)
    async def put_theme_route(
        payload: ThemeRequest,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        if "preset" in payload.tokens:
            raise HTTPException(
                status_code=422,
                detail="tokens may not contain a reserved 'preset' key; use the top-level preset field",
            )
        contrast_error = theme_contrast_error(payload.tokens, preset=payload.preset)
        if contrast_error is not None:
            raise HTTPException(status_code=422, detail=contrast_error)
        return await upsert_theme(
            database,
            principal=actor,
            settings=resolved,
            tokens=payload.tokens,
            preset=payload.preset,
            logo=payload.logo,
            clear_logo=payload.clear_logo,
            header=payload.header,
            footer=payload.footer,
        )

    mount_presentation_routes(app, runtime=runtime, settings=resolved, db=db)

    return app


app = create_app()
