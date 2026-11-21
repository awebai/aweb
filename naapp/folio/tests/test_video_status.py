"""A video's Cloudflare Stream state reaches assets.stream_status only as a StreamStatus.

The parser, the upload owner and the database are real; only Cloudflare's replies
are supplied, since the tests do not reach Cloudflare. test_cloudflare_stream covers every
documented state; here one of them, and an unrecognized one, go through the
stored column and its CHECK.
"""

from __future__ import annotations

import pytest
from fastapi import HTTPException
from test_present_privacy import OWNER, present_world

from folio import cloudflare_stream
from folio.cloudflare_stream import StreamDirectUpload, video_status_from_cloudflare
from folio.models import StreamStatus, VideoDirectUploadRequest
from folio.repository import create_video_direct_upload, get_asset_metadata

__all__ = ["present_world"]


def _cloudflare_result(state: str) -> dict:
    return {"uid": "stream-uid", "readyToStream": False, "status": {"state": state}}


async def _video(db, settings, monkeypatch) -> object:
    """A video asset created through Folio's direct upload, pending its upload."""

    async def create_direct_upload(self, *, max_duration_seconds: int, expires_at):
        return StreamDirectUpload(
            uid="stream-uid", upload_url="https://upload.example/stream-uid", expires_at=expires_at
        )

    monkeypatch.setattr(
        cloudflare_stream.CloudflareStreamClient, "create_direct_upload", create_direct_upload
    )
    upload = await create_video_direct_upload(
        db,
        principal=OWNER,
        settings=settings,
        video=VideoDirectUploadRequest(content_type="video/mp4"),
    )
    return upload["asset_id"]


def _cloudflare_reports(monkeypatch, state: str) -> None:
    async def get_video_status(self, *, stream_uid: str):
        return video_status_from_cloudflare(_cloudflare_result(state))

    monkeypatch.setattr(
        cloudflare_stream.CloudflareStreamClient, "get_video_status", get_video_status
    )


async def _stored_status(db, asset_id) -> str:
    row = await db.fetch_one(
        "SELECT stream_status FROM {{tables.assets}} WHERE asset_id=$1", asset_id
    )
    return row["stream_status"]


async def test_a_documented_cloudflare_state_is_stored(present_world, monkeypatch):
    _, db, settings = present_world
    asset_id = await _video(db, settings, monkeypatch)
    assert await _stored_status(db, asset_id) == StreamStatus.PENDING_UPLOAD
    _cloudflare_reports(monkeypatch, "downloading")

    metadata = await get_asset_metadata(db, principal=OWNER, settings=settings, asset_id=asset_id)

    assert await _stored_status(db, asset_id) == StreamStatus.QUEUED
    assert metadata["stream_status"] == StreamStatus.QUEUED


async def test_an_unrecognized_cloudflare_state_is_refused_before_it_is_written(
    present_world, monkeypatch
):
    _, db, settings = present_world
    asset_id = await _video(db, settings, monkeypatch)
    _cloudflare_reports(monkeypatch, "inprogress")
    await get_asset_metadata(db, principal=OWNER, settings=settings, asset_id=asset_id)
    assert await _stored_status(db, asset_id) == StreamStatus.PROCESSING
    _cloudflare_reports(monkeypatch, "melting")

    with pytest.raises(HTTPException) as refused:
        await get_asset_metadata(db, principal=OWNER, settings=settings, asset_id=asset_id)

    assert refused.value.status_code == 502
    assert await _stored_status(db, asset_id) == StreamStatus.PROCESSING
