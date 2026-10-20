"""Hook resolution: where a team's hook events go, who may produce them, and the core producer's keys."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter
from pydantic import BaseModel

from aweb.config import get_app_grant_max_age_seconds, get_hook_producer_keys

router = APIRouter(tags=["hooks"])


class HookProducerKeyResponse(BaseModel):
    kid: str
    did_key: str
    valid_from: str
    # Null while the key has no end, never omitted.
    valid_until: str | None


class HookProducerKeysResponse(BaseModel):
    keys: list[HookProducerKeyResponse]
    as_of: str
    max_age_seconds: int


def _as_of() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@router.get("/v1/hooks/producer-keys", response_model=HookProducerKeysResponse)
async def hook_producer_keys_route() -> HookProducerKeysResponse:
    """The core hook producer's public keys, retired ones included. Anyone may
    read them; a consumer reaches this server only through the team's anchored
    server record."""
    return HookProducerKeysResponse(
        keys=[
            HookProducerKeyResponse(
                kid=key.kid,
                did_key=key.did_key,
                valid_from=key.valid_from,
                valid_until=key.valid_until,
            )
            for key in get_hook_producer_keys()
        ],
        as_of=_as_of(),
        max_age_seconds=get_app_grant_max_age_seconds(),
    )
