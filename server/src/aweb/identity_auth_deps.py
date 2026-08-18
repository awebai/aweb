from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request

from awid.dns_auth import enforce_timestamp_skew, parse_didkey_auth, require_timestamp
from awid.signing import canonical_json_bytes, verify_did_key_signature
from aweb.awid_error_handling import (
    AWID_DEPENDENCY_ERRORS,
    awid_dependency_http_exception,
    awid_registry_not_configured_exception,
)
from aweb.config import require_registered_certificates
from aweb.deps import get_db
from aweb.team_auth_deps import (
    TeamIdentity,
    _aweb_db,
    _get_registered_certificates,
    _get_revoked_certificates,
    get_team_identity,
)

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
    identity_scope: str | None = None
    certificate_id: str | None = None
    verified_team_id: str | None = None


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
        raise awid_registry_not_configured_exception(operation="AWID did:aw resolution")

    try:
        resolution = await registry_client.resolve_key(did_aw)
    except AWID_DEPENDENCY_ERRORS as exc:
        logger.warning("AWID registry dependency failed for did:aw resolution: %s", did_aw, exc_info=True)
        raise awid_dependency_http_exception(exc, operation="AWID did:aw resolution") from exc
    except Exception as exc:
        logger.exception("Unexpected AWID registry dependency error for did:aw resolution: %s", did_aw)
        raise awid_dependency_http_exception(exc, operation="AWID did:aw resolution") from exc

    if resolution and resolution.current_did_key != did_key and hasattr(registry_client, "resolve_key_fresh"):
        try:
            resolution = await registry_client.resolve_key_fresh(did_aw)
        except Exception:
            logger.warning("AWID fresh did:aw resolution failed for %s", did_aw, exc_info=True)

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


async def lookup_identity_agent_context(
    db,
    *,
    did_key: str,
    did_aw: str | None = None,
    allow_ambiguous_global_identity: bool = False,
) -> dict | None:
    did_aw_value = (did_aw or "").strip()
    aweb_db = _aweb_db(db)
    rows = await aweb_db.fetch_all(
        """
        SELECT agent_id, team_id, alias, did_aw, address, identity_scope, certificate_id
        FROM {{tables.agents}}
        WHERE deleted_at IS NULL
          AND (did_key = $1 OR ($2 <> '' AND did_aw = $2))
        ORDER BY created_at DESC
        LIMIT 2
        """,
        did_key,
        did_aw_value,
    )
    if not rows:
        return None
    if len(rows) > 1:
        if allow_ambiguous_global_identity and did_aw_value:
            return None
        raise HTTPException(status_code=409, detail="Authenticated DID matches multiple active local agents")
    return dict(rows[0])


async def _enforce_current_membership(request: Request, row: dict | None) -> dict | None:
    """Refuse team context derived from a projection whose admitting
    certificate is revoked (aweb-abfn).

    Identity-only auth proves key possession; the team_id/alias it inherits
    from the agents projection is only as current as that row. A revoked
    member whose projection survived — the split-state family recorded on
    aweb-aaum.9 — would otherwise keep sending under its team alias forever by
    omitting the certificate header. This applies the same registry revocation
    check the certificate-presenting path performs, with the same fail-closed
    503 on registry unavailability.

    Revocation ends membership, not the identity: the row's team_id, alias,
    and agent_id are stripped, while the DID-scoped facts stand, so the
    identity keeps reading its own mailbox and loses only team attribution
    and team-gated behavior. A row with no recorded certificate predates the
    recording (migration 017) and passes unchanged; it heals at the next
    certificate-authenticated connect or request.
    """
    if not row:
        return row
    team_id = (row.get("team_id") or "").strip()
    certificate_id = (row.get("certificate_id") or "").strip()
    if not team_id or not certificate_id:
        return row
    revoked = await _get_revoked_certificates(request, team_id)
    if certificate_id not in revoked:
        # Staged existence requirement (default OFF): an unregistered
        # certificate can never appear in the revocation set, so once
        # AWEB_REQUIRE_REGISTERED_CERTIFICATES is on the recorded
        # certificate must also exist at the registry or team context is
        # stripped — otherwise omitting the certificate header would
        # bypass the existence check the presenting path enforces. Same
        # remedy as revocation here: strip membership, keep the identity.
        if not require_registered_certificates():
            return row
        registered = await _get_registered_certificates(request, team_id)
        if certificate_id in registered:
            return row
        logger.warning(
            "identity-auth team context stripped: certificate %s for alias %r in %s "
            "is not registered at the AWID registry",
            certificate_id,
            row.get("alias"),
            team_id,
        )
    else:
        logger.warning(
            "identity-auth team context stripped: certificate %s for alias %r in %s is revoked",
            certificate_id,
            row.get("alias"),
            team_id,
        )
    stripped = dict(row)
    stripped["team_id"] = None
    stripped["alias"] = None
    stripped["agent_id"] = None
    return stripped


async def get_messaging_auth(request: Request, db=Depends(get_db)) -> MessagingAuth:
    if (request.headers.get("Authorization") or "").lstrip().startswith("AWEB-Grant "):
        # Imported lazily: identity_grant_auth imports MessagingAuth from here.
        from aweb.identity_grant_auth import verify_identity_grant_auth

        return await verify_identity_grant_auth(request, db)

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
            identity_scope=team_identity.identity_scope,
            certificate_id=team_identity.certificate_id,
            verified_team_id=team_identity.team_id,
        )

    identity = await resolve_identity_auth(request)
    # Identity-scoped messaging routes by DID/address; a global identity may
    # have multiple local team rows, so ambiguity must not force a team choice.
    row = await lookup_identity_agent_context(
        db,
        did_key=identity.did_key,
        did_aw=identity.did_aw,
        allow_ambiguous_global_identity=True,
    )
    row = await _enforce_current_membership(request, row)
    return MessagingAuth(
        did_key=identity.did_key,
        did_aw=identity.did_aw or ((row or {}).get("did_aw") or None),
        address=identity.address or ((row or {}).get("address") or None),
        team_id=(row or {}).get("team_id") or None,
        alias=(row or {}).get("alias") or None,
        agent_id=(str((row or {}).get("agent_id")) if (row or {}).get("agent_id") else None),
        identity_scope=(row or {}).get("identity_scope") or None,
    )
