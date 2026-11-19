from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field, replace
from enum import StrEnum

from awid.dns_auth import enforce_timestamp_skew, parse_didkey_auth, require_timestamp
from awid.signing import verify_did_key_signature
from fastapi import Depends, HTTPException, Request

from aweb.auth_context import GrantContext
from aweb.auth_metrics import count_legacy_request_auth
from aweb.certificate_registration import (
    configured_registration_mode,
    read_certificate_registration,
    RegistrationState,
)
from aweb.deps import get_db
from aweb.id_chain_auth import authenticate_id_chain
from aweb.identity_address import AddressResolution, AddressResolutionState
from aweb.identity_binding import (
    IdentityBinding,
    refresh_projection_binding,
    verified_projection,
    verify_identity_binding,
)
from aweb.member_team_key import (
    current_member,
    member_projection_columns_sql,
)
from aweb.team_auth_deps import (
    TeamIdentity,
    _aweb_db,
    _team_auth_allowed_audiences,
    get_team_identity,
    revoked_certificates,
)
from aweb.team_auth_envelope import identity_auth_signature_payload

logger = logging.getLogger(__name__)

IDENTITY_DID_AW_HEADER = "X-AWEB-DID-AW"


@dataclass(frozen=True)
class IdentityAuth:
    did_key: str
    did_aw: str | None
    address: str | None
    address_resolution: AddressResolution = field(default_factory=AddressResolution)


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
    grant: GrantContext | None = None
    id_chain: dict | None = None
    address_resolution: AddressResolution = field(default_factory=AddressResolution)


def auth_dids(identity: IdentityAuth | MessagingAuth) -> list[str]:
    dids: list[str] = []
    for value in (
        (getattr(identity, "did_aw", None) or "").strip(),
        (getattr(identity, "did_key", None) or "").strip(),
    ):
        if value and value not in dids:
            dids.append(value)
    return dids


def participant_dids(identity: IdentityAuth | MessagingAuth) -> list[str]:
    """One participant identity: global did:aw, otherwise local did:key.

    auth_dids additionally includes the signing key for cryptographic checks;
    that key is not a second global participant or continuation authority.
    """
    return auth_dids(identity)[:1]


def _get_body_sha256(request: Request) -> str:
    body_sha256 = getattr(request.state, "body_sha256", None)
    if body_sha256 is not None:
        return body_sha256
    return hashlib.sha256(b"").hexdigest()


async def resolve_identity_auth(request: Request, *, db=None) -> IdentityAuth:
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(status_code=401, detail="Missing Authorization header")

    did_key, signature_b64 = parse_didkey_auth(auth_header)
    timestamp = require_timestamp(request)
    enforce_timestamp_skew(timestamp)

    did_aw = (request.headers.get(IDENTITY_DID_AW_HEADER) or "").strip()
    try:
        envelope = identity_auth_signature_payload(
            request,
            did_aw=did_aw,
            timestamp=timestamp,
            body_sha256=_get_body_sha256(request),
            allowed_audiences=_team_auth_allowed_audiences(request)
            if request.headers.get("X-AWEB-Signed-Payload")
            else [],
        )
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    try:
        verify_did_key_signature(
            did_key=did_key,
            payload=envelope.canonical_payload,
            signature_b64=signature_b64,
        )
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="Invalid DIDKey signature") from exc

    if not did_aw:
        await authenticate_id_chain(request, IdentityBinding(did_key=did_key))
        if envelope.version == 1:
            count_legacy_request_auth(request, "identity")
        return IdentityAuth(did_key=did_key, did_aw=None, address=None)

    registry_client = getattr(request.app.state, "awid_registry_client", None)
    try:
        binding = await verify_identity_binding(request, did_key=did_key, did_aw=did_aw)
    except HTTPException as exc:
        if exc.status_code == 403:
            raise HTTPException(
                status_code=401, detail="did:aw does not match Authorization did:key"
            ) from exc
        raise

    key_binding = binding
    address = None
    try:
        addresses = await registry_client.list_did_addresses(did_aw)
    except Exception as exc:
        # Retain the typed cause in request-local evidence; log no URL, name,
        # exception message or credentials. Failed discovery grants no fact.
        outcome = AddressResolution("unknown", cause=exc)
        logger.warning("Identity address evidence unavailable: %s", type(exc).__name__)
    else:
        outcome = AddressResolution("empty")
        if len(addresses) == 1:
            first = addresses[0]
            address = f"{first.domain}/{first.name}"
            binding = await verify_identity_binding(
                request, did_key=did_key, did_aw=did_aw, address=address
            )
            outcome = AddressResolution("verified")
    request.state.identity_address_resolution = outcome

    await authenticate_id_chain(request, binding)
    binding_db = db if db is not None else getattr(request.app.state, "db", None)
    if binding_db is not None and outcome.state != "unknown":
        await refresh_projection_binding(
            _aweb_db(binding_db),
            agent_id=None,
            did_key=did_key,
            binding=key_binding if key_binding.fresh_observation else binding,
        )
    if envelope.version == 1:
        count_legacy_request_auth(request, "identity")
    return IdentityAuth(
        did_key=did_key, did_aw=did_aw, address=address, address_resolution=outcome
    )


class IdentityContextSelection(StrEnum):
    REQUIRE_UNIQUE = "require_unique"
    IDENTITY_ONLY = "identity_only"


async def lookup_identity_agent_context(
    db,
    *,
    did_key: str,
    did_aw: str | None = None,
    selection: IdentityContextSelection = IdentityContextSelection.REQUIRE_UNIQUE,
    request: Request | None = None,
) -> dict | None:
    did_aw_value = (did_aw or "").strip()
    aweb_db = _aweb_db(db)
    rows = await aweb_db.fetch_all(
        """
        SELECT """
        + member_projection_columns_sql("a")
        + """
        FROM {{tables.agents}} AS a
        WHERE a.deleted_at IS NULL
          AND a.did_key = $1
        ORDER BY a.created_at DESC
        """,
        did_key,
    )
    if not rows:
        return None
    outcome = (
        getattr(request.state, "identity_address_resolution", None)
        if request is not None
        else None
    )
    if outcome is not None and outcome.state == "unknown":
        # Key possession/current DID binding was authenticated above. During an
        # address outage, retain previously verified projections, including
        # verified-empty; never mint a marker from a key-only observation.
        request.state.identity_address_resolution = outcome.with_stored_bindings(
            rows,
            did_key=did_key,
            did_aw=did_aw_value,
        )
    elif request is not None:
        for row in rows:
            binding = await verify_identity_binding(
                request,
                did_key=did_key,
                did_aw=row.get("did_aw") or "",
                address=row.get("address") or "",
            )
            await refresh_projection_binding(
                aweb_db, agent_id=row["agent_id"], did_key=did_key, binding=binding
            )
        rows = [{**dict(row), "did_aw_verified_key": did_key} for row in rows]
    rows = [verified_projection(row) for row in rows]
    if request is not None and selection is IdentityContextSelection.IDENTITY_ONLY:
        registry = getattr(request.app.state, "awid_registry_client", None)
        eligible = []
        for row in rows:
            member = await current_membership(registry, row, request=request)
            if member and member.get("team_id"):
                eligible.append(member)
        rows = eligible
        if len(rows) > 1:
            outcome = getattr(
                request.state, "identity_address_resolution", AddressResolution()
            )
            request.state.identity_address_resolution = replace(
                outcome, state=AddressResolutionState.CONTEXT_REQUIRED
            )
        if not rows:
            return None
    if len(rows) > 1:
        if selection is IdentityContextSelection.IDENTITY_ONLY and did_aw_value:
            return None
        raise HTTPException(
            status_code=409,
            detail="Authenticated DID matches multiple active local agents",
        )
    return dict(rows[0])


async def _enforce_current_membership(
    request: Request, row: dict | None
) -> dict | None:
    """Keep identity access while rechecking membership under identity.md:569-585.

    Registry revocation or an enforced missing registration removes team
    attribution; identity-only inbox and history remain scoped to the DID.
    """
    return await current_membership(
        getattr(request.app.state, "awid_registry_client", None), row, request=request
    )


async def current_membership(
    registry_client, row: dict | None, *, request: Request | None = None
) -> dict | None:
    """The row with its team context, or stripped of it when the admitting
    certificate is revoked or unregistered, as this registry client reports it."""
    if not row:
        return row
    team_id = (row.get("team_id") or "").strip()
    certificate_id = (row.get("certificate_id") or "").strip()
    if not team_id:
        return row
    if not current_member(row):
        logger.warning(
            "identity-auth team context stripped: alias %r in %s was accepted under "
            "a team key that is not the team's current key",
            row.get("alias"),
            team_id,
        )
        return _without_team_context(row)
    if not certificate_id:
        return row
    revoked = await revoked_certificates(
        registry_client, team_id, certificate_ids=[certificate_id]
    )
    if certificate_id not in revoked:
        decision = await read_certificate_registration(
            registry_client=registry_client,
            team_id=team_id,
            certificate_id=certificate_id,
            mode=configured_registration_mode(),
            request=request,
        )
        if decision.allows_registration:
            return row
        if decision.state is RegistrationState.UNAVAILABLE:
            raise HTTPException(
                status_code=503,
                detail="Certificate registration is unavailable. Retry in a moment.",
            ) from decision.unavailable_cause
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
    return _without_team_context(row)


def _without_team_context(row: dict) -> dict:
    """The row with its team context removed and its DID-scoped facts kept."""
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
        return MessagingAuth(
            did_key=team_identity.did_key,
            did_aw=team_identity.did_aw or None,
            address=team_identity.address or None,
            team_id=team_identity.team_id,
            alias=team_identity.alias,
            agent_id=team_identity.agent_id,
            identity_scope=team_identity.identity_scope,
            certificate_id=team_identity.certificate_id,
            verified_team_id=team_identity.team_id,
            id_chain=getattr(request.state, "id_chain", None),
            address_resolution=team_identity.address_resolution,
        )

    identity = await resolve_identity_auth(request)
    # Identity-scoped messaging routes by DID/address; a global identity may
    # have multiple local team rows, so ambiguity must not force a team choice.
    row = await lookup_identity_agent_context(
        db,
        did_key=identity.did_key,
        did_aw=identity.did_aw,
        selection=IdentityContextSelection.IDENTITY_ONLY,
        request=request,
    )
    outcome = getattr(
        request.state, "identity_address_resolution", identity.address_resolution
    )
    if outcome.state is AddressResolutionState.UNKNOWN:
        address = outcome.stored_address
    elif row:
        address = row.get("address") or None
    else:
        address = identity.address
    return MessagingAuth(
        did_key=identity.did_key,
        did_aw=identity.did_aw or ((row or {}).get("did_aw") or None),
        address=address,
        team_id=(row or {}).get("team_id") or None,
        alias=(row or {}).get("alias") or None,
        agent_id=(
            str((row or {}).get("agent_id")) if (row or {}).get("agent_id") else None
        ),
        identity_scope=(row or {}).get("identity_scope") or None,
        id_chain=getattr(request.state, "id_chain", None),
        address_resolution=outcome,
    )
