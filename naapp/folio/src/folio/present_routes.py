"""The human-facing presentation routes: read-only pages, the editor and its session.

Image bytes are served only under the capability that shows them (docs/sot.md
§1, Images): a live read-only link at /present/<token>/assets/<uuid>, an edit
session at /present/edit/<id>/assets/<uuid>. The Markdown reference
/assets/<uuid> names an image; nothing serves it.
"""

import secrets
from collections.abc import Callable
from typing import Annotated, Any
from uuid import UUID

from aweb_naapp.runtime.app import NaappRuntime
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, Response
from pgdbm import AsyncDatabaseManager

from folio import edit_sessions
from folio.cloudflare_stream import stream_iframe_url
from folio.config import Settings
from folio.images import image_response
from folio.installation_access import presented_document, presented_image
from folio.models import (
    AssetKind,
    PresentationEditRequest,
    PresentationEditResponse,
    PresentationPreviewRequest,
    PresentationStateResponse,
    StreamStatus,
)
from folio.presentation import (
    _editor_theme_css,
    content_security_policy,
    render_editor_page,
    render_presented_markdown,
    render_presented_page,
    sanitize_layout_tokens,
)
from folio.repository import (
    _allowed_assets_for_body,
    _theme_from_row,
    append_presented_version,
    get_team_image,
)

# The status a ready video's embed shows when its signed playback URL cannot be made.
PLAYBACK_UNAVAILABLE = "unavailable"


def mount_presentation_routes(
    app: FastAPI,
    *,
    runtime: NaappRuntime,
    settings: Settings,
    db: Callable[..., Any],
) -> None:
    """Mount /present/* and the image route its pages embed.

    ``db`` is the app's database dependency: the installation permit's database
    when one was admitted for the request, otherwise the runtime's.
    """
    resolved = settings

    origin = resolved.public_origin.rstrip("/")

    def presented_image_url(token: str) -> Callable[[UUID], str]:
        return lambda asset_id: f"{origin}/present/{token}/assets/{asset_id}"

    def session_image_url(link_id: str) -> Callable[[UUID], str]:
        return lambda asset_id: f"{origin}/present/edit/{link_id}/assets/{asset_id}"

    def presentation_asset_embeds(
        allowed_assets: object, *, image_url: Callable[[UUID], str]
    ) -> dict[UUID, dict[str, str]]:
        if not isinstance(allowed_assets, dict):
            return {}
        embeds: dict[UUID, dict[str, str]] = {}
        for asset_id, raw in allowed_assets.items():
            if not isinstance(asset_id, UUID) or not isinstance(raw, dict):
                continue
            kind = str(raw.get("kind") or "")
            if kind == AssetKind.IMAGE:
                embeds[asset_id] = {"kind": AssetKind.IMAGE, "url": image_url(asset_id)}
            elif kind == AssetKind.VIDEO:
                status = StreamStatus(raw.get("stream_status") or StreamStatus.PENDING_UPLOAD)
                embed: dict[str, str] = {"kind": AssetKind.VIDEO, "status": status}
                stream_uid = str(raw.get("stream_uid") or "").strip()
                if status == StreamStatus.READY and stream_uid:
                    try:
                        embed["iframe_url"] = stream_iframe_url(
                            settings=resolved, stream_uid=stream_uid
                        )
                    except HTTPException:
                        embed["status"] = PLAYBACK_UNAVAILABLE
                embeds[asset_id] = embed
        return embeds

    @app.get("/present/{token}/assets/{asset_id}")
    async def presented_image_route(
        token: str,
        asset_id: UUID,
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> Response:
        image = await presented_image(database, runtime=runtime, token=token, asset_id=asset_id)
        return image_response(image)

    @app.get("/present/edit/{link_id}/assets/{asset_id}")
    async def session_image_route(
        link_id: str,
        asset_id: UUID,
        request: Request,
        database: Annotated[AsyncDatabaseManager, Depends(db)],
    ) -> Response:
        # The editor previews unsaved drafts, so a session reads any of its team's images.
        async with edit_sessions.access(
            database,
            runtime,
            link_id=link_id,
            credential=request.headers.get(edit_sessions.SESSION_HEADER),
        ) as (tx, link):
            image = await get_team_image(tx, team_id=link["team_id"], asset_id=asset_id)
        return image_response(image)

    async def edit_snapshot(
        database: AsyncDatabaseManager,
        *,
        link_id: str,
        team_id: str,
        body: str,
        version_number: int,
        assets: dict,
    ) -> dict:
        row = await database.fetch_one(
            "SELECT tokens,logo_asset_id,header,footer FROM {{tables.themes}} WHERE team_id=$1",
            team_id,
        )
        theme = _theme_from_row(row, public_origin=None) if row else None
        image_url = session_image_url(link_id)
        logo_asset_id = (theme or {}).get("logo_asset_id")
        return {
            "body": body,
            "version_number": version_number,
            "theme": {
                "css": _editor_theme_css(theme),
                "header": (theme or {}).get("header"),
                "footer": (theme or {}).get("footer"),
                "logo_url": image_url(logo_asset_id) if logo_asset_id is not None else None,
            },
            "html": render_presented_markdown(
                body,
                public_origin=resolved.public_origin,
                asset_embeds=presentation_asset_embeds(assets, image_url=image_url),
            ),
        }

    @app.get("/present/edit/{link_id}", response_class=HTMLResponse)
    async def editor_shell(link_id: str) -> HTMLResponse:
        nonce = secrets.token_urlsafe(16)
        return HTMLResponse(
            render_editor_page(
                token=link_id,
                body="",
                version_number=1,
                nonce=nonce,
                public_origin=resolved.public_origin,
            ),
            headers={
                "Content-Security-Policy": f"default-src 'self'; img-src 'self' blob:; script-src 'nonce-{nonce}'; style-src 'unsafe-inline' 'self'; base-uri 'none'; frame-ancestors 'none'"
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
        assets = await _allowed_assets_for_body(
            database, team_id=current["team_id"], body=current["body"]
        )
        return {
            "session_secret": credential,
            **await edit_snapshot(
                database,
                link_id=link_id,
                team_id=current["team_id"],
                body=current["body"],
                version_number=current["version_number"],
                assets=assets,
            ),
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
        async with edit_sessions.access(
            database,
            runtime,
            link_id=link_id,
            credential=request.headers.get(edit_sessions.SESSION_HEADER),
        ) as (tx, link):
            current = await tx.fetch_one(
                "SELECT body,version_number FROM {{tables.document_versions}} WHERE document_id=$1 ORDER BY version_number DESC LIMIT 1",
                link["document_id"],
            )
            if current is None:
                raise edit_sessions.unavailable()
            state = dict(current)
        if after_version == state["version_number"]:
            return {"version_number": state["version_number"]}
        assets = await _allowed_assets_for_body(
            database, team_id=link["team_id"], body=state["body"]
        )
        return await edit_snapshot(
            database,
            link_id=link_id,
            team_id=link["team_id"],
            body=state["body"],
            version_number=state["version_number"],
            assets=assets,
        )

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
            asset_embeds=presentation_asset_embeds(assets, image_url=session_image_url(link_id)),
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
        image_url = presented_image_url(token)
        if isinstance(theme, dict) and theme.get("logo_asset_id") is not None:
            theme["logo_url"] = image_url(theme["logo_asset_id"])
        nonce = secrets.token_urlsafe(16)
        mode = sanitize_layout_tokens(theme.get("tokens") if isinstance(theme, dict) else None)[
            "mode"
        ]
        return HTMLResponse(
            render_presented_page(
                body=str(presented["body"]),
                theme=theme,
                public_origin=resolved.public_origin,
                asset_embeds=presentation_asset_embeds(
                    presented.get("allowed_assets"), image_url=image_url
                ),
                nonce=nonce,
            ),
            headers={
                "Content-Security-Policy": content_security_policy(
                    mode=mode, nonce=nonce, stream_host=resolved.cloudflare_stream_playback_host
                ),
            },
        )
