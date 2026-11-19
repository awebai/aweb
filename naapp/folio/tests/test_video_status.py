"""A video's Cloudflare Stream state reaches assets.stream_status only as a StreamStatus.

The parser and the database are real; only Cloudflare's reply is supplied, since
the tests do not reach Cloudflare. test_cloudflare_stream covers every
documented state; here one of them, and an unrecognized one, go through the
stored column and its CHECK.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import HTTPException
from test_present_privacy import OWNER, present_world

from folio import cloudflare_stream
from folio.cloudflare_stream import video_status_from_cloudflare
from folio.models import StreamStatus
from folio.repository import get_asset_metadata

__all__ = ["present_world"]


def _cloudflare_result(state: str) -> dict:
    return {"uid": "stream-uid", "readyToStream": False, "status": {"state": state}}


async def _video(db, *, status: StreamStatus) -> object:
    asset_id = uuid4()
    await db.execute(
        """INSERT INTO {{tables.assets}} (asset_id, team_id, kind, content_type, stream_uid, stream_status)
        VALUES ($1, $2, 'video', 'video/mp4', 'stream-uid', $3)""",
        asset_id,
        OWNER.team_id,
        status,
    )
    return asset_id


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
    asset_id = await _video(db, status=StreamStatus.PENDING_UPLOAD)
    _cloudflare_reports(monkeypatch, "downloading")

    metadata = await get_asset_metadata(db, principal=OWNER, settings=settings, asset_id=asset_id)

    assert await _stored_status(db, asset_id) == StreamStatus.QUEUED
    assert metadata["stream_status"] == StreamStatus.QUEUED


async def test_an_unrecognized_cloudflare_state_is_refused_before_it_is_written(
    present_world, monkeypatch
):
    _, db, settings = present_world
    asset_id = await _video(db, status=StreamStatus.PROCESSING)
    _cloudflare_reports(monkeypatch, "melting")

    with pytest.raises(HTTPException) as refused:
        await get_asset_metadata(db, principal=OWNER, settings=settings, asset_id=asset_id)

    assert refused.value.status_code == 502
    assert await _stored_status(db, asset_id) == StreamStatus.PROCESSING
