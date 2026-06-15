from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from pgdbm import AsyncDatabaseManager

from folio.auth import AWIDTeamCache, Principal, authenticate_request
from folio.cloudflare_stream import stream_iframe_url
from folio.config import Settings, get_settings
from folio.db import FolioDatabase
from folio.models import (
    AssetMetadataResponse,
    BillingResponse,
    CreateDocumentRequest,
    CreatePresentationRequest,
    DocumentResponse,
    DocumentSummary,
    DocumentVersion,
    ImageAssetResponse,
    ImageAssetUploadRequest,
    PresentationResponse,
    ThemeRequest,
    ThemeResponse,
    VideoDirectUploadRequest,
    VideoDirectUploadResponse,
)
from folio.presentation import render_presented_page
from folio.repository import (
    append_version,
    create_document,
    create_video_direct_upload,
    get_asset_metadata,
    get_billing_status,
    get_document,
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
        return await create_document(
            database,
            principal=actor,
            settings=resolved,
            slug=payload.slug,
            title=payload.title,
            body=payload.body,
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
        return await upsert_theme(
            database,
            principal=actor,
            settings=resolved,
            tokens=payload.tokens,
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

    @app.get("/present/{token}", response_class=HTMLResponse)
    async def present_route(
        token: str,
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> HTMLResponse:
        presented = await get_presented_document(database, token=token)
        theme = presented.get("theme")
        if isinstance(theme, dict) and theme.get("logo_asset_id") is not None:
            theme["logo_url"] = f"{resolved.public_origin.rstrip('/')}/assets/{theme['logo_asset_id']}"
        return HTMLResponse(
            render_presented_page(
                body=str(presented["body"]),
                theme=theme,
                public_origin=resolved.public_origin,
                asset_embeds=presentation_asset_embeds(presented.get("allowed_assets")),
            ),
            headers={"X-Robots-Tag": USER_CONTENT_ROBOTS_HEADER},
        )

    return app


app = create_app()
