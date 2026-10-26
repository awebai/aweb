import secrets
from contextlib import asynccontextmanager
from importlib.resources import files
from pathlib import Path
from typing import Annotated
from uuid import UUID

from aweb_naapp.page_store import StoreError
from aweb_naapp.ratelimit import apply_ratelimit_migrations
from aweb_naapp.runtime.app import NOINDEX_ROBOTS_HEADER, NaappRuntime, mount_naapp_routes
from aweb_naapp.runtime.authorization import Authorization
from aweb_naapp.runtime.capability_links import apply_capability_link_migrations
from aweb_naapp.runtime.installation import InstallationRefused, apply_installation_migrations
from aweb_naapp.runtime.team_auth import Principal
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, Response
from pgdbm import AsyncDatabaseManager

from folio import edit_sessions
from folio.aweb_manifest import MANIFEST_PATH
from folio.cloudflare_stream import stream_iframe_url
from folio.config import Settings, get_settings
from folio.document_record_host import DocumentRecordHost
from folio.document_widgets import document_segments
from folio.installation_access import presented_document
from folio.models import (
    AppendTemplateVersionRequest,
    AssetMetadataResponse,
    BillingResponse,
    CreateDocumentRequest,
    CreatePresentationRequest,
    DocumentResponse,
    DocumentSummary,
    DocumentVersion,
    ImageAssetResponse,
    ImageAssetUploadRequest,
    PresentationEditRequest,
    PresentationEditResponse,
    PresentationPreviewRequest,
    PresentationResponse,
    PresentationStateResponse,
    ThemeRequest,
    ThemeResponse,
    VideoDirectUploadRequest,
    VideoDirectUploadResponse,
)
from folio.presentation import (
    _theme_css,
    content_security_policy,
    render_editor_page,
    render_presented_markdown,
    render_presented_page,
    sanitize_layout_tokens,
    sanitize_theme_tokens,
    theme_contrast_error,
)
from folio.privacy import PresentationPrivacy, install_access_filter
from folio.record_host import RecordHost, store_http
from folio.record_storage import RecordStorage
from folio.repository import (
    _allowed_assets_for_body,
    _theme_from_row,
    append_presented_version,
    append_version,
    create_document,
    create_video_direct_upload,
    get_asset_metadata,
    get_billing_status,
    get_document,
    get_public_asset,
    get_theme,
    list_documents,
    list_versions,
    mint_presentation_link,
    revoke_presentation_link,
    upload_image_asset,
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
_OG_CARD_BYTES = (_PACKAGE_DIR / "assets" / "og-card.png").read_bytes()
_FONTS_DIR = _PACKAGE_DIR / "fonts"
_MIGRATIONS_DIR = _PACKAGE_DIR / "migrations"
# Present links and asset URLs are user content: crawlers skip them and every
# response under them carries a noindex header.
_USER_CONTENT_PATHS = ("/present/", "/assets/")


def create_app(
    settings: Settings | None = None, *, awid_transport=None, team_server_transport=None
) -> FastAPI:
    install_access_filter()
    resolved = settings or get_settings()
    record_storage = RecordStorage(resolved)
    runtime = NaappRuntime(
        resolved,
        module_name="folio",
        migrations_path=_MIGRATIONS_DIR,
        manifest_path=MANIFEST_PATH,
        awid_transport=awid_transport,
        team_server_transport=team_server_transport,
        stores=(
            apply_installation_migrations,
            apply_ratelimit_migrations,
            apply_capability_link_migrations,
            record_storage.connect,
        ),
    )
    records = RecordHost(runtime, record_storage)

    document_records = DocumentRecordHost(runtime, record_storage)

    @asynccontextmanager
    async def lifespan(app):
        try:
            async with runtime.lifespan(app):
                yield
        finally:
            await record_storage.disconnect()

    app = FastAPI(title="folio", version="0.1.0", lifespan=lifespan)
    app.state.folio_runtime = runtime
    app.state.folio_records = records
    app.add_middleware(PresentationPrivacy)

    @app.exception_handler(InstallationRefused)
    async def installation_refused(request: Request, error: InstallationRefused):
        from fastapi.responses import JSONResponse

        return JSONResponse(status_code=error.status, content={"detail": {"code": error.code}})

    def db(request: Request):
        permit = getattr(request.state, "folio_installation", None)
        return permit.database() if permit is not None else runtime.db()

    @app.get("/present/widgets/assets/{name}", include_in_schema=False)
    async def widget_asset(name: str) -> Response:
        shared = {"renderer.js": "page-renderer.js", "renderer.css": "page-renderer.css"}
        local = {"atomic-editor.mjs", "document-model.mjs", "folio-widget-host.mjs"}
        if name in shared:
            asset = files("aweb_naapp.pages").joinpath("assets", shared[name])
        elif name in local:
            asset = files("folio").joinpath("assets", name)
        else:
            raise HTTPException(404)
        return Response(
            asset.read_bytes(),
            media_type=("text/css" if name.endswith(".css") else "text/javascript"),
            headers={"X-Content-Type-Options": "nosniff"},
        )

    document_records.mount(app, db)

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
    records.mount(app)

    @app.post("/v1/documents", response_model=DocumentResponse)
    async def create_document_route(
        request: Request,
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
        result = await records.save_document(
            database,
            request.state.folio_installation.admitted,
            actor,
            operation=create_document,
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
        result = await records.save_document(
            database,
            request.state.folio_installation.admitted,
            actor,
            operation=append_version,
            slug=slug,
            body=body,
        )
        return result

    @app.post("/v1/documents/{slug}/versions/template", response_model=DocumentResponse)
    async def append_template_version_route(
        slug: str,
        request: Request,
        payload: AppendTemplateVersionRequest,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        body = render_declarative_template(payload.model_dump())
        result = await records.save_document(
            database,
            request.state.folio_installation.admitted,
            actor,
            operation=append_version,
            slug=slug,
            body=body,
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

        async def authority(tx, **kwargs):
            return await document_records.mint_authority_on(
                tx,
                installation=request.state.folio_installation.admitted,
                **kwargs,
            )

        try:
            async with database.transaction() as tx:
                return await mint_presentation_link(
                    tx,
                    installation_id=request.state.folio_installation.admitted.installation_id,
                    principal=actor,
                    settings=resolved,
                    slug=payload.slug,
                    version=payload.version,
                    ttl_seconds=payload.ttl_seconds,
                    editable=payload.editable,
                    record_authority=authority,
                )
        except StoreError as error:
            raise store_http(error) from None

    @app.post("/v1/present/{token}/revoke")
    async def revoke_presentation_route(
        token: str,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict[str, bool]:
        await revoke_presentation_link(database, principal=actor, token=token)
        return {"revoked": True}

    def presentation_asset_embeds(allowed_assets: object) -> dict[UUID, dict[str, str]]:
        if not isinstance(allowed_assets, dict):
            return {}
        embeds: dict[UUID, dict[str, str]] = {}
        for asset_id, raw in allowed_assets.items():
            if not isinstance(asset_id, UUID) or not isinstance(raw, dict):
                continue
            kind = str(raw.get("kind") or "")
            if kind == "image":
                embeds[asset_id] = {
                    "kind": "image",
                    "url": f"{resolved.public_origin.rstrip('/')}/assets/{asset_id}",
                }
            elif kind == "video":
                status = str(raw.get("stream_status") or "pending_upload")
                embed = {"kind": "video", "status": status}
                stream_uid = str(raw.get("stream_uid") or "").strip()
                if status == "ready" and stream_uid:
                    try:
                        embed["iframe_url"] = stream_iframe_url(
                            settings=resolved, stream_uid=stream_uid
                        )
                    except HTTPException:
                        embed["status"] = "unavailable"
                embeds[asset_id] = embed
        return embeds

    @app.post("/v1/assets", response_model=ImageAssetResponse)
    async def upload_asset_route(
        payload: ImageAssetUploadRequest,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        return await upload_image_asset(database, principal=actor, settings=resolved, image=payload)

    @app.post("/v1/assets/video/direct-upload", response_model=VideoDirectUploadResponse)
    async def create_video_direct_upload_route(
        payload: VideoDirectUploadRequest,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        return await create_video_direct_upload(
            database, principal=actor, settings=resolved, video=payload
        )

    @app.get("/v1/assets/{asset_id}", response_model=AssetMetadataResponse)
    async def get_asset_route(
        asset_id: UUID,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        return await get_asset_metadata(
            database, principal=actor, settings=resolved, asset_id=asset_id
        )

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

    @app.get("/assets/{asset_id}")
    async def asset_route(
        asset_id: UUID,
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> Response:
        asset = await get_public_asset(database, asset_id=asset_id)
        return Response(
            content=asset["bytes"],
            media_type=str(asset["content_type"]),
            headers={
                "X-Content-Type-Options": "nosniff",
                "X-Robots-Tag": NOINDEX_ROBOTS_HEADER,
            },
        )

    async def edit_snapshot(context, body: str, version_number: int) -> dict:
        database, team_id = context.tx, context.row["team_id"]
        assets = await _allowed_assets_for_body(database, team_id=team_id, body=body)
        tables = await document_records.snapshot(context)
        row = await database.fetch_one(
            "SELECT tokens,logo_asset_id,header,footer FROM {{tables.themes}} WHERE team_id=$1",
            team_id,
        )
        theme = _theme_from_row(row, public_origin=resolved.public_origin) if row else None
        return {
            "body": body,
            "version_number": version_number,
            "segments": document_segments(body),
            "widgets": tables["widgets"],
            "theme": {
                "css": _theme_css(sanitize_theme_tokens((theme or {}).get("tokens"))),
                "header": (theme or {}).get("header"),
                "footer": (theme or {}).get("footer"),
                "logo_url": (theme or {}).get("logo_url"),
            },
            "html": render_presented_markdown(
                body,
                public_origin=resolved.public_origin,
                asset_embeds=presentation_asset_embeds(assets),
            ),
        }

    @app.get("/present/edit/{link_id}", response_class=HTMLResponse)
    async def editor_shell(link_id: str) -> HTMLResponse:
        nonce = secrets.token_urlsafe(16)
        return HTMLResponse(
            render_editor_page(token=link_id, body="", version_number=1, nonce=nonce),
            headers={
                "Content-Security-Policy": f"default-src 'self'; img-src 'self'; script-src 'nonce-{nonce}' 'strict-dynamic'; connect-src 'self'; style-src 'unsafe-inline' 'self'; base-uri 'none'; frame-ancestors 'none'"
            },
        )

    @app.post("/present/edit/{link_id}/session")
    async def editor_exchange(
        link_id: str, request: Request, database: Annotated[AsyncDatabaseManager, Depends(db)]
    ) -> dict:
        # Fixed refusals, without validation errors echoing secret input.
        try:
            payload = await request.json()
        except (ValueError, UnicodeError):
            raise edit_sessions.unavailable() from None
        if not isinstance(payload, dict) or set(payload) != {"opener"}:
            raise edit_sessions.unavailable()
        credential, current = await edit_sessions.exchange(
            database,
            runtime,
            link_id=link_id,
            opener=payload["opener"],
        )
        async with edit_sessions.checked_access(
            database, runtime, link_id=link_id, credential=credential
        ) as context:
            current = await document_records.source(context)
            return {
                "session_secret": credential,
                **await edit_snapshot(context, current["body"], current["version_number"]),
            }

    @app.get(
        "/present/edit/{link_id}/state",
        response_model=PresentationStateResponse,
        response_model_exclude_none=True,
    )
    async def editor_state(
        link_id: str,
        request: Request,
        database: Annotated[AsyncDatabaseManager, Depends(db)],
        after_version: Annotated[int | None, Query(ge=1)] = None,
    ) -> dict:
        async with edit_sessions.checked_access(
            database,
            runtime,
            link_id=link_id,
            credential=request.headers.get(edit_sessions.SESSION_HEADER),
        ) as context:
            current = await document_records.source(context)
            if after_version == current["version_number"]:
                return {"version_number": current["version_number"]}
            return await edit_snapshot(context, current["body"], current["version_number"])

    @app.post("/present/edit/{link_id}/edit", response_model=PresentationEditResponse)
    async def editor_save(
        link_id: str,
        request: Request,
        payload: PresentationEditRequest,
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        async with edit_sessions.access(
            database,
            runtime,
            link_id=link_id,
            credential=request.headers.get(edit_sessions.SESSION_HEADER),
            write=True,
        ) as (tx, link):
            return await append_presented_version(
                tx,
                events=runtime.app_events,
                link=link,
                body=payload.body,
                base_version=payload.base_version,
                editor_name=payload.editor_name,
            )

    @app.post("/present/edit/{link_id}/preview", response_class=HTMLResponse)
    async def editor_preview(
        link_id: str,
        request: Request,
        payload: PresentationPreviewRequest,
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> HTMLResponse:
        async with edit_sessions.access(
            database,
            runtime,
            link_id=link_id,
            credential=request.headers.get(edit_sessions.SESSION_HEADER),
        ) as (_, link):
            team_id = link["team_id"]
        assets = await _allowed_assets_for_body(database, team_id=team_id, body=payload.body)
        html = render_presented_markdown(
            payload.body,
            public_origin=resolved.public_origin,
            asset_embeds=presentation_asset_embeds(assets),
        )
        return HTMLResponse(
            html,
            headers={
                "Content-Security-Policy": "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'"
            },
        )

    @app.get("/present/{token}", response_class=HTMLResponse)
    async def present_route(
        token: str,
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> HTMLResponse:
        presented = await presented_document(database, runtime=runtime, token=token)
        theme = presented.get("theme")
        if isinstance(theme, dict) and theme.get("logo_asset_id") is not None:
            theme["logo_url"] = (
                f"{resolved.public_origin.rstrip('/')}/assets/{theme['logo_asset_id']}"
            )
        if bool(presented.get("editable")):
            raise edit_sessions.unavailable()
        nonce = secrets.token_urlsafe(16)
        mode = sanitize_layout_tokens(theme.get("tokens") if isinstance(theme, dict) else None)[
            "mode"
        ]
        return HTMLResponse(
            render_presented_page(
                body=str(presented["body"]),
                theme=theme,
                public_origin=resolved.public_origin,
                asset_embeds=presentation_asset_embeds(presented.get("allowed_assets")),
                nonce=nonce,
                widget_token=token
                if any(
                    part["kind"] == "widget" for part in document_segments(str(presented["body"]))
                )
                else None,
            ),
            headers={
                "Content-Security-Policy": content_security_policy(
                    mode=mode,
                    nonce=nonce,
                    stream_host=resolved.cloudflare_stream_playback_host,
                    widgets=any(
                        part["kind"] == "widget"
                        for part in document_segments(str(presented["body"]))
                    ),
                ),
            },
        )

    return app


app = create_app()
