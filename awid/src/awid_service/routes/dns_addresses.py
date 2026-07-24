"""Public address management under DNS-backed namespaces."""

from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Literal

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from awid.atomic_claim import (
    CUSTODY_HOSTED,
    CUSTODY_SELF,
    ATOMIC_ADDRESS_CLAIM_OPERATION,
    AtomicAddressClaimFields,
    atomic_address_claim_identity_canonical,
    atomic_address_claim_identity_proof_hash,
    atomic_address_claim_namespace_canonical,
    normalize_atomic_address_claim_fields,
)
from awid.did import public_key_from_did, stable_id_from_did_key, stable_id_from_public_key, validate_stable_id
from awid.dns_verify import DomainVerifier
from awid.dns_auth import validate_did_key as _validate_dns_did_key
from awid.dns_auth import verify_signed_json_request
from awid.dns_auth import enforce_timestamp_skew
from awid.log import (
    identity_state_hash as awid_identity_state_hash,
    log_entry_payload as awid_log_entry_payload,
    sha256_hex as awid_sha256_hex,
)
from awid.pagination import encode_cursor, validate_pagination_params
from awid.ratelimit import rate_limit_dep
from awid.signing import verify_did_key_signature
from awid_service.deps import get_db, get_domain_verifier
from awid_service.routes.dns_namespace_reverify import reverify_namespace_row

_ADDRESS_ALREADY_BOUND_DETAIL = "address already bound to a different did_aw"
_DID_CURRENT_KEY_MISMATCH_DETAIL = "did_aw current key does not match"
router = APIRouter(prefix="/v1/namespaces/{domain}/addresses", tags=["addresses"])
logger = logging.getLogger(__name__)

_STALE_THRESHOLD = timedelta(hours=24)
_ATOMIC_CLAIM_ENABLED_ENV = "AWID_ENABLE_ATOMIC_CLAIM"

_CLAIM_ADDRESS_TAKEN = "address_taken_different_owner"
_CLAIM_DID_TAKEN_DIFFERENT_KEY = "did_taken_different_key"
_CLAIM_NAMESPACE_AUTHORITY_INVALID = "namespace_authority_invalid"
_CLAIM_IDENTITY_SIGNATURE_INVALID = "identity_signature_invalid"
_CLAIM_TIMESTAMP_STALE = "timestamp_stale"
_CLAIM_NAMESPACE_NOT_REGISTERED = "namespace_not_registered"
_CLAIM_PAYLOAD_CANONICALIZATION_MISMATCH = "payload_canonicalization_mismatch"
_CLAIM_CUSTODY_UNSUPPORTED = "custody_combination_unsupported"
_CLAIM_PRIMITIVE_DISABLED = "primitive_disabled"
_CLAIM_PRIMITIVE_NOT_SUPPORTED = "primitive_not_supported"
_CLAIM_DID_LOG_PROOF_REQUIRED = "did_log_proof_required"
_CLAIM_DID_LOG_PROOF_INVALID = "did_log_proof_invalid"
_ATOMIC_CLAIM_CONFLICT_CODES = (
    _CLAIM_ADDRESS_TAKEN,
    _CLAIM_DID_TAKEN_DIFFERENT_KEY,
    _CLAIM_NAMESPACE_AUTHORITY_INVALID,
    _CLAIM_IDENTITY_SIGNATURE_INVALID,
    _CLAIM_TIMESTAMP_STALE,
    _CLAIM_NAMESPACE_NOT_REGISTERED,
    _CLAIM_PAYLOAD_CANONICALIZATION_MISMATCH,
    _CLAIM_CUSTODY_UNSUPPORTED,
    _CLAIM_PRIMITIVE_DISABLED,
    _CLAIM_PRIMITIVE_NOT_SUPPORTED,
    _CLAIM_DID_LOG_PROOF_REQUIRED,
    _CLAIM_DID_LOG_PROOF_INVALID,
)


def _verify_address_signature(
    request: Request,
    *,
    domain: str,
    name: str,
    operation: str,
    signed_preconditions: dict[str, str] | None = None,
) -> str:
    payload = {
        "domain": domain,
        "name": name,
        "operation": operation,
    }
    payload.update(signed_preconditions or {})
    return verify_signed_json_request(request, payload_dict=payload)


# ---------------------------------------------------------------------------
# Namespace lookup + stale verification
# ---------------------------------------------------------------------------


async def _require_namespace(db, domain: str):
    """Fetch the active namespace row or raise 404."""
    row = await db.fetch_one(
        """
        SELECT namespace_id, domain, controller_did, verification_status,
               default_delivery_origin, last_verified_at, created_at
        FROM {{tables.dns_namespaces}}
        WHERE domain = $1 AND deleted_at IS NULL
        """,
        domain,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Namespace not found")
    return row


async def _ensure_fresh_verification(db, ns_row, domain: str, verify_domain: DomainVerifier):
    """Re-verify DNS if the namespace verification is stale (>24h).

    Returns the current namespace row. Raises 403 on DNS failure without
    mutating namespace verification state.
    """
    # A revoked namespace always requires re-verification, regardless of timestamp
    if ns_row["verification_status"] == "verified":
        last_verified = ns_row["last_verified_at"]
        if last_verified is not None:
            if last_verified.tzinfo is None:
                last_verified = last_verified.replace(tzinfo=timezone.utc)
            else:
                last_verified = last_verified.astimezone(timezone.utc)
            age = datetime.now(timezone.utc) - last_verified
            if age <= _STALE_THRESHOLD:
                return ns_row

    result = await reverify_namespace_row(
        db,
        ns_row,
        domain=domain,
        verify_domain=verify_domain,
        allow_local_bypass=True,
        dns_failure_status=403,
        dns_failure_detail="Namespace DNS verification failed",
    )
    return result.row


def _require_controller(caller_did: str, ns_row) -> None:
    """Raise 403 if the caller is not the namespace controller."""
    if caller_did != ns_row["controller_did"]:
        raise HTTPException(
            status_code=403,
            detail="Only the namespace controller can manage addresses",
        )


async def _require_registered_did(tx, *, did_aw: str, current_did_key: str):
    row = await tx.fetch_one(
        """
        SELECT current_did_key
        FROM {{tables.did_aw_mappings}}
        WHERE did_aw = $1
        FOR SHARE
        """,
        did_aw,
    )
    if row is None:
        raise HTTPException(
            status_code=409,
            detail="did_aw must be registered before address assignment",
        )
    if row["current_did_key"] != current_did_key:
        raise HTTPException(status_code=409, detail=_DID_CURRENT_KEY_MISMATCH_DETAIL)
    return row


async def _lock_address_registration_key(tx, *, namespace_id, name: str) -> None:
    await tx.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 0::bigint))",
        f"public_addresses:{namespace_id}:{name}",
    )


async def _lock_did_registration_key(tx, *, did_aw: str) -> None:
    await tx.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended($1, 0::bigint))",
        f"did_aw_mappings:{did_aw}",
    )


async def _fetch_active_address_for_registration(tx, *, namespace_id, name: str):
    return await tx.fetch_one(
        """
        SELECT pa.address_id, pa.name, pa.did_aw, m.current_did_key,
               ns.default_delivery_origin, pa.created_at
        FROM {{tables.public_addresses}} pa
        JOIN {{tables.did_aw_mappings}} m ON m.did_aw = pa.did_aw
        JOIN {{tables.dns_namespaces}} ns ON ns.namespace_id = pa.namespace_id
        WHERE pa.namespace_id = $1 AND pa.name = $2 AND pa.deleted_at IS NULL
        FOR SHARE OF pa, m, ns
        """,
        namespace_id,
        name,
    )


def _raise_address_registration_conflict(row, *, did_aw: str, current_did_key: str) -> None:
    if row["did_aw"] != did_aw:
        raise HTTPException(status_code=409, detail=_ADDRESS_ALREADY_BOUND_DETAIL)
    if row["current_did_key"] != current_did_key:
        raise HTTPException(status_code=409, detail=_DID_CURRENT_KEY_MISMATCH_DETAIL)


# ---------------------------------------------------------------------------
# Request/response models
# ---------------------------------------------------------------------------


def _validate_did_aw(v: str) -> str:
    return validate_stable_id(v)


def _validate_did_key(v: str) -> str:
    return _validate_dns_did_key(v)


class AddressRegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=256)
    did_aw: str = Field(..., min_length=1)
    current_did_key: str = Field(..., min_length=1)
    # Deprecated compatibility fields. They are accepted but ignored; all new
    # address writes use neutral global metadata (public, visible_to_team_id=NULL).
    reachability: str | None = Field(default=None, max_length=32)
    visible_to_team_id: str | None = Field(default=None, max_length=512)

    _check_did_aw = field_validator("did_aw")(_validate_did_aw)
    _check_did_key = field_validator("current_did_key")(_validate_did_key)


class AddressUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Deprecated compatibility fields. They are accepted but ignored; update
    # normalizes address metadata to the neutral global state.
    reachability: str | None = Field(default=None, max_length=32)
    visible_to_team_id: str | None = Field(default=None, max_length=512)


class AddressReassignRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    did_aw: str = Field(..., min_length=1)
    current_did_key: str = Field(..., min_length=1)

    _check_did_aw = field_validator("did_aw")(_validate_did_aw)
    _check_did_key = field_validator("current_did_key")(_validate_did_key)


class AddressDeleteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str | None = Field(default=None, max_length=512)
    expected_address_id: str | None = Field(default=None, max_length=64)
    expected_did_aw: str | None = Field(default=None, max_length=256)
    expected_current_did_key: str | None = Field(default=None, max_length=256)


class AtomicClaimDidLogProof(BaseModel):
    model_config = ConfigDict(extra="forbid")

    did_aw: str = Field(..., max_length=256)
    seq: int = Field(..., ge=1)
    operation: Literal["register_did", "rotate_key"]
    previous_did_key: str | None = Field(..., max_length=256)
    new_did_key: str = Field(..., max_length=256)
    prev_entry_hash: str | None
    state_hash: str = Field(..., max_length=128)
    authorized_by: str = Field(..., max_length=256)
    timestamp: str = Field(..., max_length=64)
    signature: str = Field(..., max_length=2048)


class AtomicAddressClaimRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operation: Literal["claim_identity_address"] = ATOMIC_ADDRESS_CLAIM_OPERATION
    address_name: str = Field(..., min_length=1, max_length=256)
    did_aw: str = Field(..., max_length=256)
    current_did_key: str = Field(..., max_length=256)
    registry_url: str = Field(..., max_length=512)
    timestamp: str = Field(..., max_length=64)
    dry_run: bool = False
    identity_custody: Literal["self", "hosted_custodial"]
    namespace_custody: Literal["self", "hosted_custodial"]
    identity_signature: str = Field(..., max_length=2048)
    namespace_signature: str = Field(..., max_length=2048)
    did_log_proof: AtomicClaimDidLogProof | None = None


class AddressDeliveryResponse(BaseModel):
    origin: str | None = None
    source: str = "identity"


class AddressResponse(BaseModel):
    address_id: str
    domain: str
    name: str
    did_aw: str
    current_did_key: str
    delivery: AddressDeliveryResponse
    created_at: str


class AddressListResponse(BaseModel):
    addresses: list[AddressResponse]
    has_more: bool = False
    next_cursor: str | None = None


class AtomicAddressClaimResponse(BaseModel):
    status: str
    dry_run: bool
    domain: str
    name: str
    did_aw: str
    current_did_key: str
    identity_custody: str
    namespace_custody: str
    did_status: str
    address_status: str
    address: AddressResponse | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _validate_domain(domain: str) -> str:
    domain = domain.lower().rstrip(".")
    if not domain or len(domain) > 256:
        raise HTTPException(status_code=400, detail="Invalid domain")
    return domain


def _address_response(row, domain: str) -> AddressResponse:
    return AddressResponse(
        address_id=str(row["address_id"]),
        domain=domain,
        name=row["name"],
        did_aw=row["did_aw"],
        current_did_key=row["current_did_key"],
        delivery=AddressDeliveryResponse(origin=row.get("default_delivery_origin"), source="namespace"),
        created_at=row["created_at"].isoformat(),
    )


def _atomic_claim_enabled() -> bool:
    value = os.getenv(_ATOMIC_CLAIM_ENABLED_ENV, "true").strip().lower()
    return value not in {"0", "false", "no", "off", "disabled"}


def _claim_error(status_code: int, code: str, message: str) -> HTTPException:
    return HTTPException(status_code=status_code, detail={"code": code, "message": message})


def _claim_request_id(request: Request) -> str:
    return request.headers.get("X-Request-ID") or request.headers.get("X-AWEB-Request-ID") or uuid.uuid4().hex


def _normalize_address_claim_fields(domain: str, body: AtomicAddressClaimRequest) -> AtomicAddressClaimFields:
    try:
        validate_stable_id(body.did_aw)
        _validate_did_key(body.current_did_key)
        fields = normalize_atomic_address_claim_fields(
            AtomicAddressClaimFields(
                operation=body.operation,
                domain=domain,
                address_name=body.address_name,
                did_aw=body.did_aw,
                current_did_key=body.current_did_key,
                registry_url=body.registry_url,
                timestamp=body.timestamp,
                dry_run=body.dry_run,
                identity_custody=body.identity_custody,
                namespace_custody=body.namespace_custody,
            )
        )
    except ValueError as exc:
        raise _claim_error(422, _CLAIM_PAYLOAD_CANONICALIZATION_MISMATCH, str(exc)) from exc
    return fields


def _verify_atomic_claim_signatures(
    *,
    fields: AtomicAddressClaimFields,
    identity_signature: str,
    namespace_signature: str,
    namespace_controller_did: str,
) -> tuple[bytes, str, bytes]:
    try:
        enforce_timestamp_skew(fields.timestamp)
    except HTTPException as exc:
        raise _claim_error(401, _CLAIM_TIMESTAMP_STALE, "timestamp outside allowed skew window") from exc

    try:
        identity_canonical = atomic_address_claim_identity_canonical(fields)
    except ValueError as exc:
        raise _claim_error(422, _CLAIM_PAYLOAD_CANONICALIZATION_MISMATCH, str(exc)) from exc
    try:
        verify_did_key_signature(
            did_key=fields.current_did_key,
            payload=identity_canonical,
            signature_b64=identity_signature,
        )
    except Exception as exc:
        raise _claim_error(401, _CLAIM_IDENTITY_SIGNATURE_INVALID, "identity signature invalid") from exc

    try:
        identity_proof_hash = atomic_address_claim_identity_proof_hash(
            identity_canonical,
            identity_signature,
        )
        namespace_canonical = atomic_address_claim_namespace_canonical(
            fields,
            identity_proof_hash,
        )
    except ValueError as exc:
        raise _claim_error(422, _CLAIM_PAYLOAD_CANONICALIZATION_MISMATCH, str(exc)) from exc
    try:
        verify_did_key_signature(
            did_key=namespace_controller_did,
            payload=namespace_canonical,
            signature_b64=namespace_signature,
        )
    except Exception as exc:
        raise _claim_error(
            403,
            _CLAIM_NAMESPACE_AUTHORITY_INVALID,
            "namespace authority signature invalid for the namespace controller",
        ) from exc
    return identity_canonical, identity_proof_hash, namespace_canonical


def _validated_did_log_proof(
    proof: AtomicClaimDidLogProof | None,
    *,
    fields: AtomicAddressClaimFields,
) -> tuple[bytes, str, str] | None:
    if proof is None:
        return None
    try:
        validate_stable_id(proof.did_aw)
        _validate_did_key(proof.new_did_key)
        _validate_did_key(proof.authorized_by)
    except ValueError as exc:
        raise _claim_error(422, _CLAIM_DID_LOG_PROOF_INVALID, str(exc)) from exc
    if proof.did_aw != fields.did_aw:
        raise _claim_error(422, _CLAIM_DID_LOG_PROOF_INVALID, "did_log_proof did_aw mismatch")
    if proof.new_did_key != fields.current_did_key:
        raise _claim_error(422, _CLAIM_DID_LOG_PROOF_INVALID, "did_log_proof new_did_key mismatch")

    if proof.seq == 1:
        if proof.operation != "register_did":
            raise _claim_error(422, _CLAIM_DID_LOG_PROOF_INVALID, "seq=1 proof must register_did")
        if proof.previous_did_key is not None or proof.prev_entry_hash is not None:
            raise _claim_error(422, _CLAIM_DID_LOG_PROOF_INVALID, "register_did proof must not carry previous key state")
        if proof.authorized_by != fields.current_did_key:
            raise _claim_error(422, _CLAIM_DID_LOG_PROOF_INVALID, "register_did proof must be authorized by current did:key")
        try:
            enforce_timestamp_skew(proof.timestamp)
            derived = stable_id_from_public_key(public_key_from_did(proof.new_did_key))
        except HTTPException as exc:
            raise _claim_error(401, _CLAIM_TIMESTAMP_STALE, "did_log_proof timestamp outside allowed skew window") from exc
        except Exception as exc:
            raise _claim_error(422, _CLAIM_DID_LOG_PROOF_INVALID, str(exc)) from exc
        if derived != proof.did_aw:
            raise _claim_error(422, _CLAIM_DID_LOG_PROOF_INVALID, "did_log_proof did_aw does not match key derivation")
        proof_signer = proof.new_did_key
    else:
        if proof.operation != "rotate_key":
            raise _claim_error(422, _CLAIM_DID_LOG_PROOF_INVALID, "seq>1 proof must rotate_key")
        if proof.previous_did_key is None or proof.prev_entry_hash is None:
            raise _claim_error(422, _CLAIM_DID_LOG_PROOF_INVALID, "rotate_key proof requires previous key state")
        try:
            _validate_did_key(proof.previous_did_key)
            if len(proof.prev_entry_hash) != 64:
                raise ValueError("rotate_key proof prev_entry_hash must be 64 hex characters")
            int(proof.prev_entry_hash, 16)
        except ValueError as exc:
            raise _claim_error(422, _CLAIM_DID_LOG_PROOF_INVALID, str(exc)) from exc
        if proof.authorized_by != proof.previous_did_key:
            raise _claim_error(422, _CLAIM_DID_LOG_PROOF_INVALID, "rotate_key proof must be authorized by previous did:key")
        # A rotation log head is historical registry evidence, so its timestamp
        # need not be fresh. The outer atomic claim signatures still carry and
        # enforce a fresh request timestamp.
        proof_signer = proof.previous_did_key

    state_hash = awid_identity_state_hash(
        did_aw=proof.did_aw,
        current_did_key=proof.new_did_key,
    )
    if proof.state_hash != state_hash:
        raise _claim_error(422, _CLAIM_DID_LOG_PROOF_INVALID, "did_log_proof state_hash mismatch")
    payload = awid_log_entry_payload(
        did_aw=proof.did_aw,
        seq=proof.seq,
        operation=proof.operation,
        previous_did_key=proof.previous_did_key,
        new_did_key=proof.new_did_key,
        prev_entry_hash=proof.prev_entry_hash,
        state_hash=state_hash,
        authorized_by=proof.authorized_by,
        timestamp=proof.timestamp,
    )
    try:
        verify_did_key_signature(
            did_key=proof_signer,
            payload=payload,
            signature_b64=proof.signature,
        )
    except Exception as exc:
        raise _claim_error(401, _CLAIM_DID_LOG_PROOF_INVALID, "did_log_proof signature invalid") from exc
    return payload, awid_sha256_hex(payload), state_hash


async def _resolve_caller_did_aw(db, caller_did_key: str | None) -> str | None:
    caller_did_key = (caller_did_key or "").strip()
    if not caller_did_key:
        return None
    row = await db.fetch_one(
        """
        SELECT did_aw
        FROM {{tables.did_aw_mappings}}
        WHERE current_did_key = $1
        """,
        caller_did_key,
    )
    if row is None:
        try:
            return stable_id_from_did_key(caller_did_key)
        except Exception:
            return None
    return row["did_aw"]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post(
    "",
    response_model=AddressResponse,
    dependencies=[Depends(rate_limit_dep("address_register"))],
)
async def register_address(
    request: Request,
    domain: str,
    body: AddressRegisterRequest,
    db_infra=Depends(get_db),
    verify_domain: DomainVerifier = Depends(get_domain_verifier),
) -> AddressResponse:
    """Register an external address under a DNS-backed namespace."""
    db = db_infra.get_manager("aweb")
    domain = _validate_domain(domain)

    caller_did = _verify_address_signature(
        request, domain=domain, name=body.name, operation="register_address",
    )

    # Verify namespace + controller outside transaction (read-only checks).
    # The namespace is re-fetched with FOR SHARE inside the transaction to
    # prevent concurrent soft-delete from invalidating these checks.
    ns_row = await _require_namespace(db, domain)
    ns_row = await _ensure_fresh_verification(db, ns_row, domain, verify_domain)
    _require_controller(caller_did, ns_row)

    async with db.transaction() as tx:
        # Re-fetch namespace with lock to prevent concurrent deletion
        ns_locked = await tx.fetch_one(
            """
            SELECT namespace_id FROM {{tables.dns_namespaces}}
            WHERE namespace_id = $1 AND deleted_at IS NULL
            FOR SHARE
            """,
            ns_row["namespace_id"],
        )
        if ns_locked is None:
            raise HTTPException(status_code=404, detail="Namespace not found")

        did_row = await _require_registered_did(
            tx,
            did_aw=body.did_aw,
            current_did_key=body.current_did_key,
        )

        await _lock_address_registration_key(
            tx,
            namespace_id=ns_row["namespace_id"],
            name=body.name,
        )
        existing = await _fetch_active_address_for_registration(
            tx,
            namespace_id=ns_row["namespace_id"],
            name=body.name,
        )
        if existing is not None:
            _raise_address_registration_conflict(
                existing,
                did_aw=body.did_aw,
                current_did_key=body.current_did_key,
            )
            return _address_response(existing, domain)

        addr_id = uuid.uuid4()
        now = datetime.now(timezone.utc)
        try:
            await tx.execute(
                """
                INSERT INTO {{tables.public_addresses}}
                    (address_id, namespace_id, name, did_aw, created_at)
                VALUES ($1, $2, $3, $4, $5)
                """,
                addr_id,
                ns_row["namespace_id"],
                body.name,
                body.did_aw,
                now,
            )
        except asyncpg.UniqueViolationError as e:
            detail = str(e)
            if "did_aw" in detail:
                raise HTTPException(
                    status_code=409,
                    detail="Identity already has an active address",
                )
            raise HTTPException(status_code=409, detail=_ADDRESS_ALREADY_BOUND_DETAIL)

    return AddressResponse(
        address_id=str(addr_id),
        domain=domain,
        name=body.name,
        did_aw=body.did_aw,
        current_did_key=body.current_did_key,
        delivery=AddressDeliveryResponse(origin=ns_row.get("default_delivery_origin"), source="namespace"),
        created_at=now.isoformat(),
    )


@router.post(
    "/claims",
    response_model=AtomicAddressClaimResponse,
    response_model_exclude_none=True,
    dependencies=[Depends(rate_limit_dep("address_atomic_claim"))],
)
async def claim_identity_address(
    request: Request,
    domain: str,
    body: AtomicAddressClaimRequest,
    db_infra=Depends(get_db),
) -> AtomicAddressClaimResponse:
    """Atomically preflight/apply did:aw registration and namespace address claim."""
    request_id = _claim_request_id(request)
    if not _atomic_claim_enabled():
        logger.info("atomic_address_claim disabled request_id=%s", request_id)
        raise _claim_error(
            404,
            _CLAIM_PRIMITIVE_DISABLED,
            "atomic address claim primitive is disabled on this AWID server",
        )

    db = db_infra.get_manager("aweb")
    domain = _validate_domain(domain)
    if body.identity_custody == CUSTODY_HOSTED and body.namespace_custody == CUSTODY_SELF:
        raise _claim_error(
            422,
            _CLAIM_CUSTODY_UNSUPPORTED,
            "hosted-custodial DID with self-custodial namespace is unsupported in v1",
        )
    fields = _normalize_address_claim_fields(domain, body)

    ns_row = await db.fetch_one(
        """
        SELECT namespace_id, domain, controller_did, verification_status,
               default_delivery_origin, created_at
        FROM {{tables.dns_namespaces}}
        WHERE domain = $1 AND deleted_at IS NULL
        """,
        fields.domain,
    )
    if ns_row is None:
        raise _claim_error(
            404,
            _CLAIM_NAMESPACE_NOT_REGISTERED,
            "namespace must be registered before an atomic address claim",
        )
    if not ns_row["controller_did"]:
        raise _claim_error(
            409,
            _CLAIM_NAMESPACE_AUTHORITY_INVALID,
            "namespace has no controller did:key registered",
        )

    identity_canonical, identity_proof_hash, namespace_canonical = _verify_atomic_claim_signatures(
        fields=fields,
        identity_signature=body.identity_signature,
        namespace_signature=body.namespace_signature,
        namespace_controller_did=ns_row["controller_did"],
    )
    did_log_proof = _validated_did_log_proof(body.did_log_proof, fields=fields)

    logger.info(
        "atomic_address_claim verified request_id=%s dry_run=%s domain=%s address=%s did_hash=%s "
        "identity_custody=%s namespace_custody=%s did_log_proof_present=%s",
        request_id,
        fields.dry_run,
        fields.domain,
        fields.address_name,
        awid_sha256_hex(fields.did_aw.encode("utf-8"))[:12],
        fields.identity_custody,
        fields.namespace_custody,
        did_log_proof is not None,
    )

    async with db.transaction() as tx:
        ns_locked = await tx.fetch_one(
            """
            SELECT namespace_id, default_delivery_origin
            FROM {{tables.dns_namespaces}}
            WHERE namespace_id = $1 AND deleted_at IS NULL
            FOR SHARE
            """,
            ns_row["namespace_id"],
        )
        if ns_locked is None:
            raise _claim_error(
                404,
                _CLAIM_NAMESPACE_NOT_REGISTERED,
                "namespace disappeared before claim transaction",
            )

        await _lock_did_registration_key(tx, did_aw=fields.did_aw)
        await _lock_address_registration_key(
            tx,
            namespace_id=ns_row["namespace_id"],
            name=fields.address_name,
        )

        did_row = await tx.fetch_one(
            """
            SELECT did_aw, current_did_key
            FROM {{tables.did_aw_mappings}}
            WHERE did_aw = $1
            FOR UPDATE
            """,
            fields.did_aw,
        )
        if did_row is not None and did_row["current_did_key"] != fields.current_did_key:
            raise _claim_error(
                409,
                _CLAIM_DID_TAKEN_DIFFERENT_KEY,
                "did:aw is already registered to a different current did:key",
            )
        if did_row is not None and body.did_log_proof is not None and body.did_log_proof.seq > 1:
            registered_head = await tx.fetch_one(
                """
                SELECT seq, operation, previous_did_key, new_did_key,
                       prev_entry_hash, state_hash, authorized_by, signature, timestamp
                FROM {{tables.did_aw_log}}
                WHERE did_aw = $1
                ORDER BY seq DESC
                LIMIT 1
                """,
                fields.did_aw,
            )
            proof = body.did_log_proof
            if registered_head is None or any(
                (
                    registered_head["seq"] != proof.seq,
                    registered_head["operation"] != proof.operation,
                    registered_head["previous_did_key"] != proof.previous_did_key,
                    registered_head["new_did_key"] != proof.new_did_key,
                    registered_head["prev_entry_hash"] != proof.prev_entry_hash,
                    registered_head["state_hash"] != proof.state_hash,
                    registered_head["authorized_by"] != proof.authorized_by,
                    registered_head["signature"] != proof.signature,
                    registered_head["timestamp"] != proof.timestamp,
                )
            ):
                raise _claim_error(
                    409,
                    _CLAIM_DID_LOG_PROOF_INVALID,
                    "rotate_key proof does not match the registered did log head",
                )
        did_status = "existing" if did_row is not None else "would_create"
        if did_row is None and (
            did_log_proof is None
            or body.did_log_proof is None
            or body.did_log_proof.seq != 1
            or body.did_log_proof.operation != "register_did"
        ):
            raise _claim_error(
                409,
                _CLAIM_DID_LOG_PROOF_REQUIRED,
                "a genesis register_did proof is required when the did:aw is not already registered",
            )

        existing = await _fetch_active_address_for_registration(
            tx,
            namespace_id=ns_row["namespace_id"],
            name=fields.address_name,
        )
        if existing is not None:
            if existing["did_aw"] != fields.did_aw:
                raise _claim_error(
                    409,
                    _CLAIM_ADDRESS_TAKEN,
                    "address is already bound to a different did:aw",
                )
            if existing["current_did_key"] != fields.current_did_key:
                raise _claim_error(
                    409,
                    _CLAIM_DID_TAKEN_DIFFERENT_KEY,
                    "address owner did:aw is registered to a different current did:key",
                )
            return AtomicAddressClaimResponse(
                status="already_applied",
                dry_run=fields.dry_run,
                domain=fields.domain,
                name=fields.address_name,
                did_aw=fields.did_aw,
                current_did_key=fields.current_did_key,
                identity_custody=fields.identity_custody,
                namespace_custody=fields.namespace_custody,
                did_status=did_status,
                address_status="existing",
                address=_address_response(existing, fields.domain),
            )

        if fields.dry_run:
            return AtomicAddressClaimResponse(
                status="available",
                dry_run=True,
                domain=fields.domain,
                name=fields.address_name,
                did_aw=fields.did_aw,
                current_did_key=fields.current_did_key,
                identity_custody=fields.identity_custody,
                namespace_custody=fields.namespace_custody,
                did_status=did_status,
                address_status="would_create",
            )

        now = datetime.now(timezone.utc)
        if did_row is None:
            proof_payload, proof_entry_hash, proof_state_hash = did_log_proof
            # Keep the stored DID log compatible with the stock verifier. This
            # should be impossible after _validated_did_log_proof, but check
            # before any insert so a future refactor cannot create partial rows.
            if awid_sha256_hex(proof_payload) != proof_entry_hash:
                raise _claim_error(500, _CLAIM_DID_LOG_PROOF_INVALID, "did_log_proof hash mismatch")
            await tx.execute(
                """
                INSERT INTO {{tables.did_aw_mappings}}
                    (did_aw, current_did_key, created_at, updated_at)
                VALUES ($1, $2, $3, $4)
                """,
                fields.did_aw,
                fields.current_did_key,
                now,
                now,
            )
            await tx.execute(
                """
                INSERT INTO {{tables.did_aw_log}}
                    (did_aw, seq, operation, previous_did_key, new_did_key,
                     prev_entry_hash, entry_hash, state_hash, authorized_by, signature,
                     timestamp, created_at)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
                """,
                fields.did_aw,
                1,
                "register_did",
                None,
                fields.current_did_key,
                None,
                proof_entry_hash,
                proof_state_hash,
                fields.current_did_key,
                body.did_log_proof.signature,
                body.did_log_proof.timestamp,
                now,
            )
            did_status = "created"

        addr_id = uuid.uuid4()
        await tx.execute(
            """
            INSERT INTO {{tables.public_addresses}}
                (address_id, namespace_id, name, did_aw, created_at)
            VALUES ($1, $2, $3, $4, $5)
            """,
            addr_id,
            ns_row["namespace_id"],
            fields.address_name,
            fields.did_aw,
            now,
        )

    logger.info(
        "atomic_address_claim applied request_id=%s dry_run=%s outcome=claimed identity_proof_hash=%s "
        "identity_payload_len=%s namespace_payload_len=%s",
        request_id,
        fields.dry_run,
        identity_proof_hash,
        len(identity_canonical),
        len(namespace_canonical),
    )
    return AtomicAddressClaimResponse(
        status="claimed",
        dry_run=False,
        domain=fields.domain,
        name=fields.address_name,
        did_aw=fields.did_aw,
        current_did_key=fields.current_did_key,
        identity_custody=fields.identity_custody,
        namespace_custody=fields.namespace_custody,
        did_status=did_status,
        address_status="created",
        address=AddressResponse(
            address_id=str(addr_id),
            domain=fields.domain,
            name=fields.address_name,
            did_aw=fields.did_aw,
            current_did_key=fields.current_did_key,
            delivery=AddressDeliveryResponse(origin=ns_row.get("default_delivery_origin"), source="namespace"),
            created_at=now.isoformat(),
        ),
    )


@router.get(
    "/{name}",
    response_model=AddressResponse,
    dependencies=[Depends(rate_limit_dep("address_get"))],
)
async def get_address(
    request: Request,
    domain: str,
    name: str,
    db_infra=Depends(get_db),
) -> AddressResponse:
    """Resolve an external address by name."""
    db = db_infra.get_manager("aweb")
    domain = _validate_domain(domain)
    ns_row = await _require_namespace(db, domain)
    row = await db.fetch_one(
        """
        SELECT pa.address_id, pa.name, pa.did_aw, m.current_did_key,
               ns.default_delivery_origin, pa.created_at
        FROM {{tables.public_addresses}} pa
        JOIN {{tables.did_aw_mappings}} m ON m.did_aw = pa.did_aw
        JOIN {{tables.dns_namespaces}} ns ON ns.namespace_id = pa.namespace_id
        WHERE pa.namespace_id = $1
          AND pa.name = $2
          AND pa.deleted_at IS NULL
          AND ns.deleted_at IS NULL
        """,
        ns_row["namespace_id"],
        name,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Address not found")
    return _address_response(row, domain)


@router.get(
    "",
    response_model=AddressListResponse,
    dependencies=[Depends(rate_limit_dep("address_list"))],
)
async def list_addresses(
    request: Request,
    domain: str,
    limit: int | None = Query(default=None, ge=1),
    cursor: str | None = Query(default=None),
    db_infra=Depends(get_db),
) -> AddressListResponse:
    """List active addresses under a namespace with cursor pagination."""
    db = db_infra.get_manager("aweb")
    domain = _validate_domain(domain)
    ns_row = await _require_namespace(db, domain)

    try:
        validated_limit, decoded_cursor = validate_pagination_params(limit, cursor)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    params: list[object] = [ns_row["namespace_id"]]
    where_clauses = [
        "pa.namespace_id = $1",
        "pa.deleted_at IS NULL",
        "ns.deleted_at IS NULL",
    ]
    if decoded_cursor is not None:
        cursor_name = decoded_cursor.get("name")
        if not isinstance(cursor_name, str):
            raise HTTPException(status_code=400, detail="Invalid cursor: missing name")
        params.append(cursor_name)
        where_clauses.append(f"pa.name > ${len(params)}")
    params.append(validated_limit + 1)
    query = (
        "SELECT pa.address_id, pa.name, pa.did_aw, m.current_did_key,"
        " ns.default_delivery_origin, pa.created_at"
        " FROM {{tables.public_addresses}} pa"
        " JOIN {{tables.did_aw_mappings}} m ON m.did_aw = pa.did_aw"
        " JOIN {{tables.dns_namespaces}} ns ON ns.namespace_id = pa.namespace_id"
        " WHERE " + " AND ".join(where_clauses)
        + f" ORDER BY pa.name LIMIT ${len(params)}"
    )
    rows = await db.fetch_all(query, *params)
    has_more = len(rows) > validated_limit
    page_rows = rows[:validated_limit]
    next_cursor = None
    if has_more and page_rows:
        next_cursor = encode_cursor({"name": page_rows[-1]["name"]})
    return AddressListResponse(
        addresses=[_address_response(r, domain) for r in page_rows],
        has_more=has_more,
        next_cursor=next_cursor,
    )


@router.put(
    "/{name}",
    response_model=AddressResponse,
    dependencies=[Depends(rate_limit_dep("address_update"))],
)
async def update_address(
    request: Request,
    domain: str,
    name: str,
    body: AddressUpdateRequest,
    db_infra=Depends(get_db),
    verify_domain: DomainVerifier = Depends(get_domain_verifier),
) -> AddressResponse:
    """Normalize legacy address metadata under a DNS-backed namespace.

    Deprecated `reachability` and `visible_to_team_id` request fields are
    ignored. The address is forced to neutral global metadata.
    """
    db = db_infra.get_manager("aweb")
    domain = _validate_domain(domain)

    caller_did = _verify_address_signature(
        request, domain=domain, name=name, operation="update_address",
    )

    ns_row = await _require_namespace(db, domain)
    ns_row = await _ensure_fresh_verification(db, ns_row, domain, verify_domain)
    _require_controller(caller_did, ns_row)

    async with db.transaction() as tx:
        # Lock namespace to prevent concurrent deletion
        ns_locked = await tx.fetch_one(
            """
            SELECT namespace_id FROM {{tables.dns_namespaces}}
            WHERE namespace_id = $1 AND deleted_at IS NULL
            FOR SHARE
            """,
            ns_row["namespace_id"],
        )
        if ns_locked is None:
            raise HTTPException(status_code=404, detail="Namespace not found")

        row = await tx.fetch_one(
            """
            SELECT pa.address_id, pa.name, pa.did_aw, m.current_did_key,
                   ns.default_delivery_origin, pa.created_at
            FROM {{tables.public_addresses}} pa
            JOIN {{tables.did_aw_mappings}} m ON m.did_aw = pa.did_aw
            JOIN {{tables.dns_namespaces}} ns ON ns.namespace_id = pa.namespace_id
            WHERE pa.namespace_id = $1 AND pa.name = $2 AND pa.deleted_at IS NULL
            FOR UPDATE OF pa
            """,
            ns_row["namespace_id"],
            name,
        )
        if row is None:
            raise HTTPException(status_code=404, detail="Address not found")

    return AddressResponse(
        address_id=str(row["address_id"]),
        domain=domain,
        name=row["name"],
        did_aw=row["did_aw"],
        current_did_key=row["current_did_key"],
        delivery=AddressDeliveryResponse(origin=row.get("default_delivery_origin"), source="namespace"),
        created_at=row["created_at"].isoformat(),
    )


@router.delete("/{name}", dependencies=[Depends(rate_limit_dep("address_delete"))])
async def delete_address(
    request: Request,
    domain: str,
    name: str,
    body: AddressDeleteRequest | None = None,
    db_infra=Depends(get_db),
) -> dict:
    """Soft-delete an address. Must be signed by the controller.

    Does not require fresh DNS verification — the controller should always be
    able to delete addresses, even if DNS has lapsed or been revoked.
    """
    db = db_infra.get_manager("aweb")
    domain = _validate_domain(domain)

    signed_preconditions = {}
    if body is not None:
        for field in ("expected_address_id", "expected_did_aw", "expected_current_did_key"):
            if value := getattr(body, field):
                signed_preconditions[field] = value
    caller_did = _verify_address_signature(
        request,
        domain=domain,
        name=name,
        operation="delete_address",
        signed_preconditions=signed_preconditions,
    )

    ns_row = await _require_namespace(db, domain)
    _require_controller(caller_did, ns_row)

    async with db.transaction() as tx:
        row = await tx.fetch_one(
            """
            SELECT pa.address_id, pa.did_aw, m.current_did_key
            FROM {{tables.public_addresses}} pa
            JOIN {{tables.did_aw_mappings}} m ON m.did_aw = pa.did_aw
            WHERE pa.namespace_id = $1 AND pa.name = $2 AND pa.deleted_at IS NULL
            FOR UPDATE OF pa
            """,
            ns_row["namespace_id"],
            name,
        )
        if row is None:
            raise HTTPException(status_code=404, detail="Address not found")
        if body is not None and any(
            (
                body.expected_address_id is not None
                and body.expected_address_id != str(row["address_id"]),
                body.expected_did_aw is not None and body.expected_did_aw != row["did_aw"],
                body.expected_current_did_key is not None
                and body.expected_current_did_key != row["current_did_key"],
            )
        ):
            raise HTTPException(status_code=409, detail="Address changed since it was claimed")

        active_cert = await tx.fetch_one(
            """
            SELECT tc.certificate_id
            FROM {{tables.team_certificates}} tc
            JOIN {{tables.teams}} t ON t.team_uuid = tc.team_uuid
            WHERE t.domain = $1
              AND t.deleted_at IS NULL
              AND tc.revoked_at IS NULL
              AND tc.member_address = $2
            LIMIT 1
            """,
            domain,
            f"{domain}/{name}",
        )
        if active_cert is not None:
            raise HTTPException(status_code=409, detail="Address has active certificates")

        await tx.execute(
            "UPDATE {{tables.public_addresses}} SET deleted_at = NOW() WHERE address_id = $1",
            row["address_id"],
        )

    return {
        "deleted": True,
        "address_id": str(row["address_id"]),
        "domain": domain,
        "name": name,
    }


@router.post(
    "/{name}/reassign",
    response_model=AddressResponse,
    dependencies=[Depends(rate_limit_dep("address_reassign"))],
)
async def reassign_address(
    request: Request,
    domain: str,
    name: str,
    body: AddressReassignRequest,
    db_infra=Depends(get_db),
    verify_domain: DomainVerifier = Depends(get_domain_verifier),
) -> AddressResponse:
    """Reassign an address to a new identity (new did_aw + current_did_key)."""
    db = db_infra.get_manager("aweb")
    domain = _validate_domain(domain)

    caller_did = _verify_address_signature(
        request, domain=domain, name=name, operation="reassign_address",
    )

    ns_row = await _require_namespace(db, domain)
    ns_row = await _ensure_fresh_verification(db, ns_row, domain, verify_domain)
    _require_controller(caller_did, ns_row)

    async with db.transaction() as tx:
        # Lock namespace to prevent concurrent deletion
        ns_locked = await tx.fetch_one(
            """
            SELECT namespace_id FROM {{tables.dns_namespaces}}
            WHERE namespace_id = $1 AND deleted_at IS NULL
            FOR SHARE
            """,
            ns_row["namespace_id"],
        )
        if ns_locked is None:
            raise HTTPException(status_code=404, detail="Namespace not found")

        row = await tx.fetch_one(
            """
            SELECT address_id, name, created_at
            FROM {{tables.public_addresses}}
            WHERE namespace_id = $1 AND name = $2 AND deleted_at IS NULL
            FOR UPDATE
            """,
            ns_row["namespace_id"],
            name,
        )
        if row is None:
            raise HTTPException(status_code=404, detail="Address not found")

        did_row = await _require_registered_did(
            tx,
            did_aw=body.did_aw,
            current_did_key=body.current_did_key,
        )

        try:
            await tx.execute(
                """
                UPDATE {{tables.public_addresses}}
                SET did_aw = $1
                WHERE address_id = $2
                """,
                body.did_aw,
                row["address_id"],
            )
        except asyncpg.UniqueViolationError:
            raise HTTPException(
                status_code=409,
                detail="New identity already has an active address",
            )

    return AddressResponse(
        address_id=str(row["address_id"]),
        domain=domain,
        name=row["name"],
        did_aw=body.did_aw,
        current_did_key=body.current_did_key,
        delivery=AddressDeliveryResponse(origin=ns_row.get("default_delivery_origin"), source="namespace"),
        created_at=row["created_at"].isoformat(),
    )
