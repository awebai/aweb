from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import jwt
from fastapi import HTTPException

from folio.config import Settings


@dataclass(frozen=True)
class StreamDirectUpload:
    uid: str
    upload_url: str
    expires_at: datetime
    status: str = "pending_upload"


@dataclass(frozen=True)
class StreamVideoStatus:
    uid: str
    status: str
    ready_to_stream: bool
    duration_seconds: float | None = None


class CloudflareStreamClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def _require_api_config(self) -> tuple[str, str]:
        account_id = (self.settings.cloudflare_account_id or "").strip()
        token = (self.settings.cloudflare_stream_api_token or "").strip()
        if not account_id or not token:
            raise HTTPException(status_code=503, detail="Cloudflare Stream is not configured")
        return account_id, token

    def _url(self, path: str) -> str:
        account_id, _token = self._require_api_config()
        return f"{self.settings.cloudflare_api_base.rstrip('/')}/accounts/{account_id}/stream{path}"

    def _headers(self) -> dict[str, str]:
        _account_id, token = self._require_api_config()
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    async def create_direct_upload(self, *, max_duration_seconds: int, expires_at: datetime) -> StreamDirectUpload:
        payload = {
            "maxDurationSeconds": max_duration_seconds,
            "expiry": expires_at.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "requireSignedURLs": True,
            "allowedOrigins": [self.settings.public_origin.rstrip("/")],
        }
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.post(self._url("/direct_upload"), headers=self._headers(), json=payload)
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=503, detail="Cloudflare Stream direct upload unavailable") from exc
        data = _cloudflare_json(response, context="Cloudflare Stream direct upload")
        result = data.get("result") if isinstance(data, dict) else None
        if not isinstance(result, dict):
            raise HTTPException(status_code=503, detail="Cloudflare Stream direct upload response was invalid")
        uid = str(result.get("uid") or "").strip()
        upload_url = str(result.get("uploadURL") or "").strip()
        if not uid or not upload_url:
            raise HTTPException(status_code=503, detail="Cloudflare Stream direct upload response was incomplete")
        return StreamDirectUpload(uid=uid, upload_url=upload_url, expires_at=expires_at)

    async def get_video_status(self, *, stream_uid: str) -> StreamVideoStatus:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.get(self._url(f"/{stream_uid}"), headers=self._headers())
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=503, detail="Cloudflare Stream status unavailable") from exc
        data = _cloudflare_json(response, context="Cloudflare Stream status")
        result = data.get("result") if isinstance(data, dict) else None
        if not isinstance(result, dict):
            raise HTTPException(status_code=503, detail="Cloudflare Stream status response was invalid")
        ready = bool(result.get("readyToStream"))
        status_data = result.get("status")
        state = "ready" if ready else "processing"
        if isinstance(status_data, dict) and status_data.get("state"):
            state = str(status_data["state"]).strip().lower()
        if state == "pendingupload":
            state = "pending_upload"
        if state == "inprogress":
            state = "processing"
        duration = result.get("duration")
        try:
            duration_seconds = float(duration) if duration is not None else None
        except (TypeError, ValueError):
            duration_seconds = None
        return StreamVideoStatus(
            uid=str(result.get("uid") or stream_uid),
            status="ready" if ready else state,
            ready_to_stream=ready,
            duration_seconds=duration_seconds,
        )


def _cloudflare_json(response: httpx.Response, *, context: str) -> dict[str, Any]:
    if response.status_code >= 400:
        raise HTTPException(status_code=503, detail=f"{context} failed with HTTP {response.status_code}")
    try:
        data = response.json()
    except ValueError as exc:
        raise HTTPException(status_code=503, detail=f"{context} returned non-JSON") from exc
    if not isinstance(data, dict) or data.get("success") is not True:
        raise HTTPException(status_code=503, detail=f"{context} was not successful")
    return data


def stream_direct_upload_expires_at(settings: Settings) -> datetime:
    return datetime.now(UTC) + timedelta(seconds=settings.cloudflare_stream_direct_upload_ttl_seconds)


def sign_stream_playback_token(*, settings: Settings, stream_uid: str) -> str:
    key_id = (settings.cloudflare_stream_signing_key_id or "").strip()
    private_key = (settings.cloudflare_stream_signing_key_pem or "").strip()
    if not key_id or not private_key:
        raise HTTPException(status_code=503, detail="Cloudflare Stream signing key is not configured")
    now = int(time.time())
    payload = {
        "sub": stream_uid,
        "kid": key_id,
        "nbf": now - 10,
        "exp": now + settings.cloudflare_stream_signed_playback_ttl_seconds,
    }
    return jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": key_id})


def stream_iframe_url(*, settings: Settings, stream_uid: str) -> str:
    token = sign_stream_playback_token(settings=settings, stream_uid=stream_uid)
    host = settings.cloudflare_stream_playback_host.strip().removeprefix("https://").removeprefix("http://").rstrip("/")
    if not host:
        raise HTTPException(status_code=503, detail="Cloudflare Stream playback host is not configured")
    return f"https://{host}/{token}/iframe"
