"""FastAPI dependencies for team certificate authentication.

Provides TeamIdentity — the authenticated context for all routes
in the team-based architecture. Every authenticated endpoint resolves
a TeamIdentity from the request's certificate headers.
"""

from __future__ import annotations

import logging

from awid.dns_auth import enforce_timestamp_skew, parse_didkey_auth, require_timestamp
from awid.signing import verify_did_key_signature
from awid.team_certificate import TeamCertificateError, decode_team_certificate, verify_team_certificate_claims
from fastapi import Depends, HTTPException, Request
from pgdbm import AsyncDatabaseManager

from aweb.application_state import application_registry_client
from aweb.audit import AuditActor, is_operator_audit_request, set_verified_audit_actor
from aweb.auth_context import GRANT_SCOPE_ANY, GRANT_SCOPES, NativeCertificateIdentity, TeamIdentity
from aweb.auth_metrics import count_legacy_request_auth
from aweb.certificate_evidence import EvidenceMode
from aweb.deps import get_db
from aweb.id_chain_auth import authenticate_id_chain
from aweb.identity_binding import (
    IdentityBinding,
    refresh_projection_binding,
    verify_identity_binding,
)
from aweb.identity_scope import normalize_identity_scope
from aweb.member_team_key import (
    CURRENT_MEMBERSHIP_REQUIRED_DETAIL,
    CurrentMembershipRequired,
    MemberProjection,
    MemberReadLock,
    current_member,
    member_row_active,
    read_certificate_standings,
    read_member_projection,
)
from aweb.request_body import request_body_sha256
from aweb.service_errors import CurrentMembershipRefusal
from aweb.team_auth import certificate_refusal, project_verified_team_certificate
from aweb.team_auth_envelope import team_auth_signature_payload
from aweb.team_key_pins import AdmittedTeamKeys
from aweb.team_registry import (
    native_database_manager as _aweb_db,
)
from aweb.team_registry import (
    request_auth_audiences as _team_auth_allowed_audiences,
)
from aweb.team_registry import (
    resolve_team_key as _resolve_team_key,
)

logger = logging.getLogger(__name__)


def _superseded_team_key() -> HTTPException:
    return HTTPException(
        status_code=401,
        detail={
            "code": "team_key_not_current",
            "message": "The team certificate is under a superseded team key",
        },
    )


async def resolve_team_identity(
    db: AsyncDatabaseManager,
    cert_info: dict,
    *,
    request: Request | None = None,
) -> TeamIdentity:
    """Resolve a TeamIdentity from verified certificate info.

    Looks up the agent row by (team_id, did_key). The agent must
    already exist (created via POST /v1/connect).

    Args:
        db: The aweb database manager.
        cert_info: Verified certificate fields and native standing evidence.

    Returns:
        TeamIdentity with resolved agent_id.

    Raises:
        ValueError: If the native member is absent, deleted or inactive.
    """
    team_id = cert_info["team_id"]
    did_key = cert_info["did_key"]

    # A host that already read this member's agent row while verifying the
    # same request passes it as cert_info["agent_row"]; it is used only for the
    # exact (team_id, did_key) this certificate verified.
    row = cert_info.get("agent_row")
    if isinstance(row, dict):
        try:
            row = MemberProjection.from_row(row)
        except ValueError:
            # A partial row cannot answer native eligibility. Read the missing
            # authority facts through their owner, without inventing NULL values.
            logger.warning(
                "Invalid host member snapshot; reading the canonical native projection",
                exc_info=True,
            )
            row = None
    if not (
        isinstance(row, MemberProjection)
        and row["team_id"] == team_id
        and row["did_key"] == did_key
    ):
        row = await read_member_projection(db, team_id=team_id, did_key=did_key)

    if not row or row["deleted_at"] is not None:
        raise CurrentMembershipRequired(
            f"Agent not connected: no agent with did_key {did_key[:20]}... in team {team_id}. "
            + CURRENT_MEMBERSHIP_REQUIRED_DETAIL
        )

    if not member_row_active(row):
        raise CurrentMembershipRequired()

    # Only the key checked by the certificate verifier may reaccept a member.
    # A stored accepted key is attribution, not a substitute for that proof.
    verified_team_did_key = str(cert_info.get("verified_team_did_key") or "").strip()
    if not verified_team_did_key:
        raise CurrentMembershipRequired()

    binding = cert_info.get("identity_binding")
    if not isinstance(binding, IdentityBinding):
        binding = IdentityBinding()
        if request is not None:
            binding = await verify_identity_binding(
                request,
                did_key=did_key,
                did_aw=cert_info.get("member_did_aw") or "",
                address=cert_info.get("member_address") or "",
            )
    if request is not None and not binding.did_aw and (row.get("did_aw") or row.get("address")):
        # A claimless certificate cannot inherit stored global identity
        # metadata without independently proving that row's exact binding.
        binding = await verify_identity_binding(
            request,
            did_key=did_key,
            did_aw=row.get("did_aw") or "",
            address=row.get("address") or "",
        )
    # identity.md:807-811: later grants must retain the exact certificate that
    # this verified request makes current for its subject.
    presented_certificate_id = (cert_info.get("certificate_id") or "").strip()
    # A worker may still hold a verified old key in its memo, or a host may
    # have read its snapshot before rotation. Recheck under the same locks
    # that protect acceptance and binding writes; no registry read occurs here.
    # A reader with cached/local binding evidence and the same credential
    # does not write acceptance. Share its membership lock with delivery's
    # policy locks, while retaining the transactional current-key check.
    # If the credential changed, release SHARE before taking UPDATE so two
    # readers never deadlock while upgrading their locks. Reread and validate
    # again in that transaction; the earlier row grants no authority.
    read_locks = (
        (MemberReadLock.UPDATE,)
        if binding.fresh_observation or (
            presented_certificate_id and (
                presented_certificate_id != (row.get("certificate_id") or "").strip()
                or verified_team_did_key != (row.get("accepted_team_did_key") or "").strip()
            )
        )
        else (MemberReadLock.SHARE, MemberReadLock.UPDATE)
    )
    for read_lock in read_locks:
        async with db.transaction() as tx:
            row = await read_member_projection(
                tx, team_id=team_id, did_key=did_key, read_lock=read_lock
            )
            if row is None or not current_member(row, checked_key=verified_team_did_key):
                raise CurrentMembershipRequired()
            update_certificate = presented_certificate_id and (
                presented_certificate_id != (row.get("certificate_id") or "").strip()
                or verified_team_did_key != (row.get("accepted_team_did_key") or "").strip()
            )
            if read_lock is MemberReadLock.SHARE and update_certificate:
                continue
            await refresh_projection_binding(
                tx, agent_id=row["agent_id"], did_key=did_key, binding=binding
            )
            if update_certificate:
                await tx.execute(
                    "UPDATE {{tables.agents}} SET certificate_id = $2, accepted_team_did_key = $3 WHERE agent_id = $1",
                    row["agent_id"], presented_certificate_id, verified_team_did_key,
                )
            break

    return NativeCertificateIdentity(
        team_id=team_id,
        alias=cert_info["alias"],
        did_key=did_key,
        did_aw=binding.did_aw,
        address=binding.address,
        agent_id=str(row["agent_id"]),
        identity_scope=normalize_identity_scope(cert_info.get("identity_scope")),
        certificate_id=cert_info.get("certificate_id", ""),
        verified_team_did_key=verified_team_did_key,
    )


# ---------------------------------------------------------------------------
# Shared certificate verification (steps 1-5, no agent lookup)
# ---------------------------------------------------------------------------


async def verify_request_certificate(request: Request, db, *, fresh: bool = False) -> dict:
    """Verify a request's DIDKey signature and team certificate.

    Steps 1-5 of the auth pipeline:
    1. Parse Authorization: DIDKey <did:key> <signature>
    2. Verify Ed25519 signature over canonical JSON payload + timestamp
    3. Parse and verify team certificate (X-AWID-Team-Certificate)
    4. Resolve team public key from awid registry
    5. Check revocation list from awid registry

    Returns cert_info dict (team_id, alias, did_key, identity_scope,
    certificate_id, member_did_aw, member_address, identity_binding). The member claims are
    empty strings for local certificates. Does NOT look up the agent
    in the local DB — suitable for /v1/connect where the agent may not
    exist yet.

    Raises HTTPException on any failure.
    """
    # -- Step 1: Extract DIDKey auth header --
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    did_key, signature_b64 = parse_didkey_auth(auth_header)

    # -- Step 2: Verify the request envelope using the cached body hash. --
    timestamp = require_timestamp(request)
    enforce_timestamp_skew(timestamp)

    cert_header = request.headers.get("X-AWID-Team-Certificate")
    if not cert_header:
        raise HTTPException(status_code=401, detail="Missing X-AWID-Team-Certificate header")

    try:
        cert_data = decode_team_certificate(cert_header)
    except TeamCertificateError as e:
        raise certificate_refusal(e) from None

    cert_team_id = cert_data.get("team_id")
    if not isinstance(cert_team_id, str) or not cert_team_id.strip():
        raise certificate_refusal(TeamCertificateError("invalid_field", "team_id"))

    # Verify Ed25519 signature over the team-auth request envelope.
    # Legacy clients sign compact v1: {team_id, timestamp, body_sha256}.
    # Current clients sign request-bound v2 in X-AWEB-Signed-Payload.
    body_sha256 = request_body_sha256(request)
    allowed_audiences = (
        _team_auth_allowed_audiences(request)
        if str(request.headers.get("X-AWEB-Signed-Payload") or "").strip()
        else []
    )
    try:
        envelope = team_auth_signature_payload(
            request,
            team_id=cert_team_id,
            timestamp=timestamp,
            body_sha256=body_sha256,
            allowed_audiences=allowed_audiences,
        )
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    try:
        verify_did_key_signature(
            did_key=did_key,
            payload=envelope.canonical_payload,
            signature_b64=signature_b64,
        )
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid DIDKey signature")

    cert_info, team_did_key = await _verify_admitting_certificate(
        request,
        db=db,
        cert_team_id=cert_team_id,
        cert_header=cert_header,
        cert_data=cert_data,
        did_key=did_key,
    )

    # Team authority does not establish the member's stable identity/address.
    binding = await verify_identity_binding(
        request,
        did_key=did_key,
        did_aw=cert_info.get("member_did_aw", ""),
        address=cert_info.get("member_address", ""),
        fresh=fresh,
    )
    await authenticate_id_chain(request, binding)
    cert_info["identity_kind"] = getattr(request.state, "identity_kind", None)
    cert_info["identity_binding"] = binding
    cert_info["identity_binding_fresh"] = binding.fresh_observation
    cert_info["verified_member_did_aw"] = binding.did_aw
    cert_info["verified_member_address"] = binding.address
    cert_info["did_aw_verified_key"] = did_key if binding.did_aw else ""
    # Include the registry-resolved team key (not the certificate's claim)
    cert_info["verified_team_did_key"] = team_did_key
    if envelope.version == 1:
        count_legacy_request_auth(request, "certificate")
    set_verified_audit_actor(
        request,
        AuditActor(
            team_id=cert_info["team_id"],
            principal_type="c",
            auth_mode="team_auth_v2" if envelope.version == 2 else "team_auth_v1",
            did_key=cert_info["did_key"],
            did_aw=binding.did_aw or None,
        ),
    )
    return cert_info


async def _verify_admitting_certificate(
    request: Request,
    *,
    db,
    cert_team_id: str,
    cert_header: str,
    cert_data: dict,
    did_key: str,
) -> tuple[dict, str]:
    """Verify the certificate against the admitted key and registry records."""
    # -- Step 4: Resolve team public key from awid --
    team_did_key = await _resolve_team_key(request, cert_team_id, db=_aweb_db(db))
    if not team_did_key:
        raise HTTPException(status_code=401, detail="unknown_team")

    # Only a valid certificate may spend the registration-miss budget. A
    # certificate signature failure alone may spend the team-key refresh.
    evidence = EvidenceMode.CACHED
    try:
        try:
            checked = verify_team_certificate_claims(
                cert_header, subject_did_key=did_key, team_did_key=team_did_key,
            )
        except TeamCertificateError as exc:
            if exc.reason != "bad_signature":
                raise
            refreshed_key = await _resolve_team_key(
                request, cert_team_id, db=_aweb_db(db), rejected_key=team_did_key,
            )
            if not refreshed_key:
                raise
            team_did_key = refreshed_key
            checked = verify_team_certificate_claims(
                cert_header, subject_did_key=did_key, team_did_key=team_did_key,
            )
            evidence = EvidenceMode.FRESH

        certificate_id = checked.claims["certificate_id"]
        standings = await read_certificate_standings(
            application_registry_client(request.app.state), cert_team_id, [certificate_id],
            request=request, revocation_evidence=evidence,
        )
        standing = standings[certificate_id]
        standing.require_active()
        if standing.refreshed_after_miss:
            pin = await AdmittedTeamKeys(_aweb_db(db)).pin(cert_team_id)
            if pin is not None and pin.team_did_key != team_did_key:
                raise _superseded_team_key()
    except TeamCertificateError as exc:
        if (
            exc.reason == "bad_signature"
            and str(cert_data.get("team_did_key") or "").strip() != team_did_key
        ):
            raise _superseded_team_key() from None
        if exc.reason == "unregistered":
            logger.warning(
                "certificate existence check failed: a certificate presented for team %s "
                "is not registered at the AWID registry",
                cert_team_id,
            )
        raise certificate_refusal(exc) from None
    cert_info = project_verified_team_certificate(checked.claims)
    cert_info["registration_decision"] = standing.registration
    return cert_info, team_did_key


async def resolve_team_identity_with_grant_scope(
    request: Request,
    db,
    *,
    grant_scope: str | None,
    membership_refusal_detail: str | None = None,
) -> TeamIdentity:
    """Resolve native certificate/grant authority under a declared grant scope.

    docs/identity.md:770-781: delegation cannot widen the operation's scope.
    Embedding hosts apply their own account fences to this same native result.
    """
    if (request.headers.get("Authorization") or "").lstrip().startswith("AWEB-Grant "):
        from aweb.identity_grant_auth import verify_identity_grant_team_identity

        if grant_scope is None:
            if is_operator_audit_request(request):
                # Verify solely to attribute the refusal, never to grant the
                # operation. The subject, not the session key, is the actor.
                identity = await verify_identity_grant_team_identity(
                    request, db, required_scope=GRANT_SCOPE_ANY
                )
                assert identity.grant is not None
                set_verified_audit_actor(
                    request,
                    AuditActor(
                        team_id=identity.team_id,
                        principal_type="c",
                        auth_mode="identity_grant",
                        did_key=identity.did_key,
                        did_aw=identity.did_aw or None,
                        grant_id=identity.grant.grant_id,
                    ),
                )
            raise HTTPException(status_code=403, detail="outside grant scope")

        return await verify_identity_grant_team_identity(request, db, required_scope=grant_scope)

    cert_info = await verify_request_certificate(request, db)

    aweb_db = _aweb_db(db)
    try:
        return await resolve_team_identity(aweb_db, cert_info, request=request)
    except CurrentMembershipRequired as e:
        logger.warning("Native membership refusal: %s", e)
        if membership_refusal_detail is not None:
            raise CurrentMembershipRefusal(membership_refusal_detail) from e
        raise HTTPException(status_code=403, detail=str(e)) from e
    except ValueError as e:
        raise HTTPException(status_code=403, detail=str(e))


# Existing embedding callers and the public API share one implementation.
_get_team_identity_with_grant_scope = resolve_team_identity_with_grant_scope


async def get_team_identity(request: Request, db=Depends(get_db)) -> TeamIdentity:
    """FastAPI dependency: authenticate request via team certificate.

    Full auth pipeline (steps 1-6): verifies the certificate and resolves the
    agent from the local DB. Grant principals are denied here unless a route
    opts in through team_identity_with_grant_scope(...); undeclared routes fail
    closed for grants.
    """
    return await resolve_team_identity_with_grant_scope(request, db, grant_scope=None)


def team_identity_with_grant_scope(scope: str, *, membership_refusal_detail: str | None = None):
    """Return a dependency that accepts either root team auth or a scoped grant."""
    if scope != GRANT_SCOPE_ANY and scope not in GRANT_SCOPES:
        raise AssertionError(f"unknown grant scope declaration: {scope}")

    async def dependency(request: Request, db=Depends(get_db)) -> TeamIdentity:
        return await resolve_team_identity_with_grant_scope(
            request,
            db,
            grant_scope=scope,
            membership_refusal_detail=membership_refusal_detail,
        )

    dependency._aweb_grant_scope = scope  # type: ignore[attr-defined]
    return dependency


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------
