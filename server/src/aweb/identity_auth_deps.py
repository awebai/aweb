from __future__ import annotations

import logging
from dataclasses import replace

from awid.dns_auth import enforce_timestamp_skew, parse_didkey_auth, require_timestamp
from awid.signing import verify_did_key_signature
from fastapi import Depends, HTTPException, Request

from aweb.application_state import application_registry_client
from aweb.auth_context import GrantContext as GrantContext
from aweb.auth_context import IdentityAuth, MessagingAuth, TeamIdentity
from aweb.auth_metrics import count_legacy_request_auth
from aweb.certificate_registration import (
    RegistrationState,
    configured_registration_mode,
    read_certificate_registration,
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
from aweb.request_body import request_body_sha256
from aweb.service_errors import IdentityBindingError
from aweb.team_auth_deps import get_team_identity
from aweb.team_auth_envelope import identity_auth_signature_payload
from aweb.team_registry import (
    native_database_manager,
    request_auth_audiences,
    revoked_certificates,
)

logger = logging.getLogger(__name__)

IDENTITY_DID_AW_HEADER = "X-AWEB-DID-AW"


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


async def resolve_identity_auth(request: Request, *, db=None) -> IdentityAuth:
    """Verify request-bound key possession and stable identity before membership selection."""
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
            body_sha256=request_body_sha256(request),
            allowed_audiences=request_auth_audiences(request)
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

    try:
        binding = await verify_identity_binding(request, did_key=did_key, did_aw=did_aw)
    except IdentityBindingError as exc:
        if exc.status_code == 403:
            raise HTTPException(
                status_code=401, detail="did:aw does not match Authorization did:key"
            ) from exc
        raise

    registry_client = application_registry_client(request.app.state)
    key_binding = binding
    address = None
    try:
        addresses = await registry_client.list_did_addresses(did_aw)
    except Exception as exc:
        # Retain the typed cause in request-local evidence; log no URL, name,
        # exception message or credentials. Failed discovery grants no fact.
        outcome = AddressResolution(AddressResolutionState.UNKNOWN, cause=exc)
        logger.warning("Identity address evidence unavailable: %s", type(exc).__name__)
    else:
        outcome = AddressResolution(AddressResolutionState.EMPTY)
        if len(addresses) == 1:
            first = addresses[0]
            address = f"{first.domain}/{first.name}"
            binding = await verify_identity_binding(
                request, did_key=did_key, did_aw=did_aw, address=address
            )
            outcome = AddressResolution(AddressResolutionState.VERIFIED)
        elif addresses:
            # Discovery is known, but listing order does not select a From.
            outcome = AddressResolution(AddressResolutionState.UNSELECTED)
    request.state.identity_address_resolution = outcome

    await authenticate_id_chain(request, binding)
    binding_db = db if db is not None else getattr(request.app.state, "db", None)
    if binding_db is not None and outcome.state is not AddressResolutionState.UNKNOWN:
        await refresh_projection_binding(
            native_database_manager(binding_db),
            agent_id=None,
            did_key=did_key,
            binding=key_binding if key_binding.fresh_observation else binding,
        )
    if envelope.version == 1:
        count_legacy_request_auth(request, "identity")
    return IdentityAuth(
        did_key=did_key, did_aw=did_aw, address=address, address_resolution=outcome
    )


async def lookup_identity_agent_context(
    db,
    *,
    did_key: str,
    did_aw: str | None = None,
    request: Request,
) -> dict | None:
    """Select one current member context, preserving identity-only reads on ambiguity.

    trust-model.md:186-191 permits a unique current row to supply its exact
    verified address; address-dependent effects require an explicit credential
    when several rows remain. No newest-row winner establishes authority.
    """
    did_aw_value = (did_aw or "").strip()
    aweb_db = native_database_manager(db)
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
    prior_resolution = getattr(request.state, "identity_address_resolution", None)
    if (
        prior_resolution is not None
        and prior_resolution.state is AddressResolutionState.UNKNOWN
    ):
        # Key possession/current DID binding was authenticated above. During an
        # address outage, retain previously verified projections, including
        # verified-empty; never mint a marker from a key-only observation.
        request.state.identity_address_resolution = (
            prior_resolution.with_stored_bindings(
                rows,
                did_key=did_key,
                did_aw=did_aw_value,
            )
        )
    else:
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
    registry = application_registry_client(request.app.state)
    eligible = []
    for row in rows:
        member = await current_membership(registry, row, request=request)
        if member and member.get("team_id"):
            eligible.append(member)
    rows = eligible
    outcome = getattr(request.state, "identity_address_resolution", AddressResolution())
    if len(rows) > 1:
        request.state.identity_address_resolution = replace(
            outcome,
            state=AddressResolutionState.CONTEXT_REQUIRED,
        )
        if did_aw_value:
            return None
        raise HTTPException(
            status_code=409,
            detail=(
                "Authenticated DID matches multiple active local agents. "
                "Select the intended team with a current team certificate."
            ),
        )
    if not rows:
        return None
    if outcome.state is AddressResolutionState.UNKNOWN:
        request.state.identity_address_resolution = outcome.with_stored_bindings(
            rows,
            did_key=did_key,
            did_aw=did_aw_value,
        )
    elif outcome.state is AddressResolutionState.UNSELECTED:
        state = (
            AddressResolutionState.VERIFIED
            if rows[0].get("address")
            else AddressResolutionState.EMPTY
        )
        request.state.identity_address_resolution = replace(outcome, state=state)
    return dict(rows[0])


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
    """Resolve one original messaging principal for HTTP and native MCP consumers."""
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
