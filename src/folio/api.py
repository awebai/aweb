import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from pgdbm import AsyncDatabaseManager

from folio.auth import AWIDTeamCache, Principal, authenticate_request
from folio.aweb_manifest import read_manifest_bytes
from folio.cloudflare_stream import stream_iframe_url
from folio.config import Settings, get_settings
from folio.db import FolioDatabase
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
    content_security_policy,
    render_editor_page,
    render_presented_markdown,
    render_presented_page,
    sanitize_layout_tokens,
    theme_contrast_error,
)
from folio.repository import (
    append_version,
    create_document,
    create_video_direct_upload,
    edit_presented_document,
    get_asset_metadata,
    get_billing_status,
    get_document,
    get_presentation_state,
    get_presented_document,
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
    USER_CONTENT_ROBOTS_HEADER,
    llms_txt,
    read_skill,
    render_landing_page,
    robots_txt,
    skills_index,
)
from folio.templates import render_declarative_template


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved = settings or get_settings()
    holder: dict[str, object] = {}

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        database = FolioDatabase(resolved)
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

    app = FastAPI(title="folio", version="0.1.0", lifespan=lifespan)

    @app.middleware("http")
    async def user_content_noindex(request: Request, call_next):
        response = await call_next(request)
        if request.url.path.startswith(("/present/", "/assets/")):
            response.headers["X-Robots-Tag"] = USER_CONTENT_ROBOTS_HEADER
        return response

    def db() -> AsyncDatabaseManager:
        database = holder.get("db")
        if not isinstance(database, FolioDatabase):
            raise RuntimeError("folio database is not initialized")
        return database.db

    def team_cache() -> AWIDTeamCache:
        cache = holder.get("team_cache")
        if not isinstance(cache, AWIDTeamCache):
            raise RuntimeError("folio auth cache is not initialized")
        return cache

    async def principal(
        request: Request,
        database: Annotated[AsyncDatabaseManager, Depends(db)],
        cache: Annotated[AWIDTeamCache, Depends(team_cache)],
    ) -> Principal:
        return await authenticate_request(request, settings=resolved, team_cache=cache, db=database)

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
        return PlainTextResponse(
            robots_txt(),
            headers={"X-Content-Type-Options": "nosniff"},
        )

    @app.get("/skills/", response_class=PlainTextResponse)
    async def skills_index_route() -> PlainTextResponse:
        return PlainTextResponse(
            skills_index(),
            headers={"X-Content-Type-Options": "nosniff"},
        )

    @app.get("/skills/{skill_name}/SKILL.md", response_class=PlainTextResponse)
    async def skill_route(skill_name: str) -> PlainTextResponse:
        skill = read_skill(skill_name)
        if skill is None:
            raise HTTPException(status_code=404, detail="Skill not found")
        return PlainTextResponse(skill, headers={"X-Content-Type-Options": "nosniff"})

    @app.get("/.well-known/aweb-app.json")
    async def aweb_app_manifest_route() -> Response:
        return Response(
            content=read_manifest_bytes(),
            media_type="application/json",
            headers={"X-Content-Type-Options": "nosniff"},
        )

    @app.get("/health")
    @app.get("/live")
    @app.get("/ready")
    async def health() -> dict[str, str]:
        return {"status": "ok", "service": "folio"}

    @app.post("/v1/documents", response_model=DocumentResponse)
    async def create_document_route(
        request: Request,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        payload = CreateDocumentRequest.model_validate(await request.json())
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
        return await create_document(
            database,
            principal=actor,
            settings=resolved,
            slug=payload.slug,
            title=payload.title,
            body=body,
        )

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
        return await append_version(database, principal=actor, settings=resolved, slug=slug, body=body)

    @app.post("/v1/documents/{slug}/versions/template", response_model=DocumentResponse)
    async def append_template_version_route(
        slug: str,
        request: Request,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        payload = AppendTemplateVersionRequest.model_validate(await request.json())
        body = render_declarative_template(payload.model_dump())
        return await append_version(database, principal=actor, settings=resolved, slug=slug, body=body)

    @app.get("/v1/billing", response_model=BillingResponse)
    async def billing_route(
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        return await get_billing_status(database, principal=actor, settings=resolved)

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
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        payload = CreatePresentationRequest.model_validate(await request.json())
        return await mint_presentation_link(
            database,
            principal=actor,
            settings=resolved,
            slug=payload.slug,
            version=payload.version,
            ttl_seconds=payload.ttl_seconds,
            editable=payload.editable,
        )

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
                        embed["iframe_url"] = stream_iframe_url(settings=resolved, stream_uid=stream_uid)
                    except HTTPException:
                        embed["status"] = "unavailable"
                embeds[asset_id] = embed
        return embeds

    @app.post("/v1/assets", response_model=ImageAssetResponse)
    async def upload_asset_route(
        request: Request,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        payload = ImageAssetUploadRequest.model_validate(await request.json())
        return await upload_image_asset(database, principal=actor, settings=resolved, image=payload)

    @app.post("/v1/assets/video/direct-upload", response_model=VideoDirectUploadResponse)
    async def create_video_direct_upload_route(
        request: Request,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        payload = VideoDirectUploadRequest.model_validate(await request.json())
        return await create_video_direct_upload(database, principal=actor, settings=resolved, video=payload)

    @app.get("/v1/assets/{asset_id}", response_model=AssetMetadataResponse)
    async def get_asset_route(
        asset_id: UUID,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        return await get_asset_metadata(database, principal=actor, settings=resolved, asset_id=asset_id)

    @app.get("/v1/theme", response_model=ThemeResponse)
    async def get_theme_route(
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        return await get_theme(database, principal=actor, settings=resolved)

    @app.put("/v1/theme", response_model=ThemeResponse)
    async def put_theme_route(
        request: Request,
        actor: Annotated[Principal, Depends(principal)],
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        payload = ThemeRequest.model_validate(await request.json())
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
                "X-Robots-Tag": USER_CONTENT_ROBOTS_HEADER,
            },
        )

    @app.get("/present/{token}/state", response_model=PresentationStateResponse)
    async def presentation_state_route(
        token: str,
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        return await get_presentation_state(database, token=token)

    @app.post("/present/{token}/edit", response_model=PresentationEditResponse)
    async def presentation_edit_route(
        token: str,
        request: Request,
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> dict:
        payload = PresentationEditRequest.model_validate(await request.json())
        return await edit_presented_document(
            database,
            token=token,
            settings=resolved,
            body=payload.body,
            base_version=payload.base_version,
            editor_name=payload.editor_name,
        )

    @app.post("/present/{token}/preview", response_class=HTMLResponse)
    async def presentation_preview_route(
        token: str,
        request: Request,
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> HTMLResponse:
        payload = PresentationPreviewRequest.model_validate(await request.json())
        presented = await get_presented_document(database, token=token)
        if not bool(presented.get("editable")):
            raise HTTPException(status_code=404, detail="Presentation link not found")
        html = render_presented_markdown(
            payload.body,
            public_origin=resolved.public_origin,
            asset_embeds=presentation_asset_embeds(presented.get("allowed_assets")),
        )
        return HTMLResponse(
            html,
            headers={"Content-Security-Policy": "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'"},
        )

    @app.get("/present/{token}", response_class=HTMLResponse)
    async def present_route(
        token: str,
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> HTMLResponse:
        presented = await get_presented_document(database, token=token)
        theme = presented.get("theme")
        if isinstance(theme, dict) and theme.get("logo_asset_id") is not None:
            theme["logo_url"] = f"{resolved.public_origin.rstrip('/')}/assets/{theme['logo_asset_id']}"
        if bool(presented.get("editable")):
            nonce = secrets.token_urlsafe(16)
            return HTMLResponse(
                render_editor_page(
                    token=token,
                    body=str(presented["body"]),
                    version_number=int(presented["version_number"]),
                    theme=theme,
                    public_origin=resolved.public_origin,
                    asset_embeds=presentation_asset_embeds(presented.get("allowed_assets")),
                    nonce=nonce,
                ),
                headers={
                    "Content-Security-Policy": f"default-src 'self'; img-src 'self'; script-src 'nonce-{nonce}'; style-src 'unsafe-inline' 'self'; base-uri 'none'; frame-ancestors 'none'",
                },
            )
        nonce = secrets.token_urlsafe(16)
        mode = sanitize_layout_tokens(theme.get("tokens") if isinstance(theme, dict) else None)["mode"]
        return HTMLResponse(
            render_presented_page(
                body=str(presented["body"]),
                theme=theme,
                public_origin=resolved.public_origin,
                asset_embeds=presentation_asset_embeds(presented.get("allowed_assets")),
                nonce=nonce,
            ),
            headers={
                "Content-Security-Policy": content_security_policy(
                    mode=mode, nonce=nonce, stream_host=resolved.cloudflare_stream_playback_host
                ),
            },
        )

    return app


app = create_app()
