"""Team members' asset routes: upload, video direct upload and metadata."""

from collections.abc import Callable
from typing import Annotated, Any
from uuid import UUID

from aweb_naapp.runtime.team_auth import Principal
from fastapi import Depends, FastAPI
from pgdbm import AsyncDatabaseManager

from folio.config import Settings
from folio.models import (
    AssetMetadataResponse,
    ImageAssetResponse,
    ImageAssetUploadRequest,
    VideoDirectUploadRequest,
    VideoDirectUploadResponse,
)
from folio.repository import create_video_direct_upload, get_asset_metadata, upload_image_asset


def mount_asset_routes(
    app: FastAPI,
    *,
    settings: Settings,
    principal: Callable[..., Any],
    db: Callable[..., Any],
) -> None:
    """Mount /v1/assets*; ``principal`` admits a current member of an installed team."""
    resolved = settings

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
