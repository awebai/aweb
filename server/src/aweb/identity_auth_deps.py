from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request

from awid.dns_auth import enforce_timestamp_skew, parse_didkey_auth, require_timestamp
from awid.signing import canonical_json_bytes, verify_did_key_signature
from aweb.deps import get_db
from aweb.team_auth_deps import TeamIdentity, _aweb_db, get_team_identity

logger = logging.getLogger(__name__)

IDENTITY_DID_AW_HEADER = "X-AWEB-DID-AW"


@dataclass(frozen=True)
class IdentityAuth:
    did_key: str
    did_aw: str | None
    address: str | None


@dataclass(frozen=True)
class MessagingAuth:
    did_key: str
    did_aw: str | None
    address: str | None
    team_id: str | None = None
    alias: str | None = None
    agent_id: str | None = None
    lifetime: str | None = None
    certificate_id: str | None = None


def auth_dids(identity: IdentityAuth | MessagingAuth) -> list[str]:
    dids: list[str] = []
    for value in ((getattr(identity, "did_aw", None) or "").strip(), (getattr(identity, "did_key", None) or "").strip()):
        if value and value not in dids:
            dids.append(value)
    return dids


def _get_body_sha256(request: Request) -> str:
    body_sha256 = getattr(request.state, "body_sha256", None)
    if body_sha256 is not None:
        return body_sha256
    return hashlib.sha256(b"").hexdigest()


async def resolve_identity_auth(request: Request) -> IdentityAuth:
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    did_key, signature_b64 = parse_didkey_auth(auth_header)
    timestamp = require_timestamp(request)
    enforce_timestamp_skew(timestamp)

    did_aw = (request.headers.get(IDENTITY_DID_AW_HEADER) or "").strip()
    payload = canonical_json_bytes(
        {
            "body_sha256": _get_body_sha256(request),
            "did_aw": did_aw,
            "timestamp": timestamp,
        }
    )
    try:
        verify_did_key_signature(did_key=did_key, payload=payload, signature_b64=signature_b64)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="Invalid DIDKey signature") from exc

    if not did_aw:
        return IdentityAuth(did_key=did_key, did_aw=None, address=None)

    registry_client = getattr(request.app.state, "awid_registry_client", None)
    if registry_client is None:
        raise HTTPException(status_code=503, detail="AWID registry client not configured")

    try:
        resolution = await registry_client.resolve_key(did_aw)
    except Exception as exc:
        logger.warning("AWID registry unavailable for did:aw resolution: %s", did_aw, exc_info=True)
        raise HTTPException(status_code=503, detail="AWID registry unavailable") from exc

    if not resolution or resolution.current_did_key != did_key:
        raise HTTPException(status_code=401, detail="did:aw does not match Authorization did:key")

    address = None
    try:
        addresses = await registry_client.list_did_addresses(did_aw)
    except Exception:
        addresses = []
    if addresses:
        first = addresses[0]
        address = f"{first.domain}/{first.name}"

    return IdentityAuth(did_key=did_key, did_aw=did_aw, address=address)


async def get_identity_auth(request: Request, db=Depends(get_db)) -> IdentityAuth:
    del db
    return await resolve_identity_auth(request)


async def get_messaging_auth(request: Request, db=Depends(get_db)) -> MessagingAuth:
    if request.headers.get("X-AWID-Team-Certificate"):
        team_identity: TeamIdentity = await get_team_identity(request, db)
        aweb_db = _aweb_db(db)
        row = await aweb_db.fetch_one(
            """
            SELECT did_aw, address
            FROM {{tables.agents}}
            WHERE agent_id = $1 AND deleted_at IS NULL
            """,
            team_identity.agent_id,
        )
        row_did_aw = (row.get("did_aw") if row else None) or None
        row_address = (row.get("address") if row else None) or None
        return MessagingAuth(
            did_key=team_identity.did_key,
            did_aw=team_identity.did_aw or row_did_aw,
            address=team_identity.address or row_address,
            team_id=team_identity.team_id,
            alias=team_identity.alias,
            agent_id=team_identity.agent_id,
            lifetime=team_identity.lifetime,
            certificate_id=team_identity.certificate_id,
        )

    identity = await resolve_identity_auth(request)
    return MessagingAuth(
        did_key=identity.did_key,
        did_aw=identity.did_aw,
        address=identity.address,
    )
