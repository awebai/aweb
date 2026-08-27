"""DNS-backed namespace registration and management."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator

from awid.delegation import (
    DelegationAssertion,
    DelegationPayload,
    parse_delegation_assertion,
    verify_delegation_signature,
)
from awid.dns_verify import DomainVerifier, verify_domain_with_authoritative_ttl
from awid_service.deps import get_db, get_domain_verifier
from awid.dns_verify import DnsVerificationError
from awid.pagination import encode_cursor, validate_pagination_params
from awid_service.delivery_origin import validate_delivery_origin
from awid.ratelimit import rate_limit_dep
from awid.dns_auth import validate_did_key as _validate_did_key
from awid.dns_auth import verify_signed_json_request
from awid.signing import canonical_json_bytes
import awid_service.routes.dns_namespace_reverify as dns_namespace_reverify_routes
from awid_service.delegation_state import (
    DelegationStateError,
    append_transition,
    delegation_head,
    stored_assertion,
    stored_delegation_chain,
)
from awid_service.routes.dns_namespace_reverify import (
    is_reserved_local_domain,
    reverify_namespace_row,
)

router = APIRouter(prefix="/v1/namespaces", tags=["namespaces"])
logger = logging.getLogger(__name__)

_MAX_DOMAIN_LENGTH = 256
_PARENT_AUTH_HEADER = "X-AWEB-Parent-Authorization"
_PARENT_TIMESTAMP_HEADER = "X-AWEB-Parent-Timestamp"
_NEW_CONTROLLER_AUTH_HEADER = "X-AWEB-New-Controller-Authorization"
_NEW_CONTROLLER_TIMESTAMP_HEADER = "X-AWEB-New-Controller-Timestamp"


def _verify_controller_signature(
    request: Request,
    *,
    domain: str,
    operation: str,
    extra_payload: dict[str, str] | None = None,
    authorization_header: str = "Authorization",
    timestamp_header: str = "X-AWEB-Timestamp",
) -> str:
    payload_dict = {
        "domain": domain,
        "operation": operation,
    }
    if extra_payload:
        payload_dict.update(extra_payload)
    return verify_signed_json_request(
        request,
        payload_dict=payload_dict,
        authorization_header=authorization_header,
        timestamp_header=timestamp_header,
    )


def _validate_domain(domain: str) -> str:
    """Validate and canonicalize a domain string."""
    domain = domain.lower().rstrip(".")
    if not domain or len(domain) > _MAX_DOMAIN_LENGTH:
        raise HTTPException(status_code=400, detail="Invalid domain")
    return domain


def _verify_controller_rotation_signature(
    request: Request,
    *,
    domain: str,
    new_controller_did: str,
    delegation_entry_hash: str | None = None,
    rollover_id: str | None = None,
) -> None:
    """Require proof that the caller controls the new controller key."""
    extra_payload = {"new_controller_did": new_controller_did}
    if delegation_entry_hash is not None:
        extra_payload["delegation_entry_hash"] = delegation_entry_hash
    if rollover_id is not None:
        extra_payload["rollover_id"] = rollover_id
    did_key = _verify_controller_signature(
        request,
        domain=domain,
        operation="rotate_controller",
        extra_payload=extra_payload,
    )
    if did_key != new_controller_did:
        raise HTTPException(status_code=401, detail="Authorization DID must match new_controller_did")


async def _find_parent_namespace(db, *, domain: str, lock_for_share: bool = False):
    query = """
        SELECT namespace_id, domain, controller_did
        FROM {{tables.dns_namespaces}}
        WHERE deleted_at IS NULL
          AND verification_status = 'verified'
          AND domain <> $1
          AND $1 LIKE ('%.' || domain)
        ORDER BY LENGTH(domain) DESC
        LIMIT 1
    """
    if lock_for_share:
        query += "\n        FOR SHARE"
    return await db.fetch_one(query, domain)


def _verify_parent_namespace_authorization(
    request: Request,
    *,
    child_domain: str,
    controller_did: str | None = None,
    new_controller_did: str | None = None,
    delegation_entry_hash: str | None = None,
    rollover_id: str | None = None,
) -> str:
    extra_payload = {"child_domain": child_domain}
    operation = "authorize_subdomain_registration"
    if new_controller_did is not None:
        operation = "authorize_subdomain_rotation"
        extra_payload["new_controller_did"] = new_controller_did
    elif controller_did is not None:
        extra_payload["controller_did"] = controller_did
    if delegation_entry_hash is not None:
        extra_payload["delegation_entry_hash"] = delegation_entry_hash
    if rollover_id is not None:
        extra_payload["rollover_id"] = rollover_id

    return _verify_controller_signature(
        request,
        domain=child_domain,
        operation=operation,
        extra_payload=extra_payload,
        authorization_header=_PARENT_AUTH_HEADER,
        timestamp_header=_PARENT_TIMESTAMP_HEADER,
    )


# ---------------------------------------------------------------------------
# Request/response models
# ---------------------------------------------------------------------------


class NamespaceRegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain: str = Field(..., min_length=1, max_length=256)
    controller_did: str | None = Field(default=None, min_length=1, max_length=256)
    default_delivery_origin: str | None = Field(default=None, min_length=1, max_length=512)
    delegation_assertion: DelegationAssertion | None = None

    @field_validator("controller_did")
    @classmethod
    def validate_controller_did(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _validate_did_key(value)

    @field_validator("default_delivery_origin")
    @classmethod
    def validate_default_delivery_origin(cls, value: str | None) -> str | None:
        return validate_delivery_origin(value)


class NamespaceRotateControllerRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    new_controller_did: str = Field(..., min_length=1, max_length=256)
    delegation_assertion: DelegationAssertion | None = None
    rollover_id: uuid.UUID | None = None

    @field_validator("new_controller_did")
    @classmethod
    def validate_did_key(cls, value: str) -> str:
        return _validate_did_key(value)


class NamespaceReverifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rollover_id: uuid.UUID | None = None


class NamespaceUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    default_delivery_origin: str | None = Field(..., max_length=512)

    @field_validator("default_delivery_origin")
    @classmethod
    def validate_default_delivery_origin(cls, value: str | None) -> str | None:
        return validate_delivery_origin(value)


class NamespaceResponse(BaseModel):
    namespace_id: str
    domain: str
    controller_did: str | None = None
    verification_status: str
    default_delivery_origin: str | None = None
    last_verified_at: Optional[str] = None
    created_at: str
    delegation_chain: list[DelegationAssertion] = Field(default_factory=list)


class NamespaceReverifyResponse(NamespaceResponse):
    old_controller_did: str | None = None
    new_controller_did: str | None = None


class NamespaceListResponse(BaseModel):
    namespaces: list[NamespaceResponse]
    has_more: bool
    next_cursor: str | None = None


class NamespaceDeleteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str | None = Field(default=None, max_length=512)
    delegation_assertion: DelegationAssertion | None = None


class NamespaceDelegationBackfillRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    delegation_assertion: DelegationAssertion


class ControllerRolloverStartRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    new_controller_did: str = Field(min_length=1, max_length=256)
    recovery_mode: Literal["none", "exact_dns", "delegated"] = "none"
    recovery_assertion: DelegationAssertion | None = None

    @field_validator("new_controller_did")
    @classmethod
    def validate_new_controller(cls, value: str) -> str:
        return _validate_did_key(value)


class ControllerRolloverSignatureItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    child_domain: str = Field(min_length=1, max_length=253)
    head_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    signature: str = Field(min_length=86, max_length=86)


class ControllerRolloverSignaturesRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    signatures: list[ControllerRolloverSignatureItem] = Field(min_length=1, max_length=100)


class ControllerRolloverResponse(BaseModel):
    rollover_id: uuid.UUID
    parent_domain: str
    old_controller_did: str
    new_controller_did: str
    recovery_mode: Literal["none", "exact_dns", "delegated"]
    recovery_assertion: DelegationAssertion | None = None
    state: Literal[
        "preparing", "ready", "overlap", "recovery_overlap_unbounded",
        "overlap_risk_accepted", "completed", "canceled",
    ]
    total_children: int = Field(ge=0)
    signed_children: int = Field(ge=0)
    started_at: datetime
    cutover_at: datetime | None = None
    complete_after: datetime | None = None


class ControllerRolloverChildResponse(BaseModel):
    child_domain: str
    head_hash: str
    payload: DelegationPayload


class ControllerRolloverChildrenResponse(BaseModel):
    children: list[ControllerRolloverChildResponse]
    has_more: bool
    next_cursor: str | None = None


class NamespaceDelegationLogResponse(BaseModel):
    entries: list[DelegationAssertion] = Field(max_length=100)
    has_more: bool
    next_sequence: int = Field(ge=0)
    next_cursor: str | None = Field(default=None, max_length=256)
    head_sequence: int = Field(gt=0)
    head_hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


def _raise_delegation_error(exc: DelegationStateError) -> None:
    raise HTTPException(
        status_code=exc.status_code,
        detail={"code": exc.code, "message": exc.message, "retryable": exc.retryable},
    ) from exc


async def _lock_namespace_authority_admission(tx) -> None:
    await tx.fetch_value(
        "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
        "namespace-authority-admission",
    )


async def _check_registry_cutover_fence(tx, domain: str) -> None:
    cutover = await tx.fetch_one(
        """
        SELECT cutover_id FROM {{tables.registry_migration_cutovers}}
        WHERE state NOT IN ('completed','canceled')
          AND (root_domain=$1 OR root_domain LIKE ('%.' || $1)
               OR $1 LIKE ('%.' || root_domain))
        LIMIT 1
        """,
        domain,
    )
    if cutover is not None:
        _raise_delegation_error(
            DelegationStateError(
                "registry_migration_fenced",
                "registry cutover fences controller rollover",
                retryable=True,
            )
        )


async def _check_parent_rollover_fence(tx, parent_domain: str) -> None:
    active = await tx.fetch_one(
        """
        SELECT rollover_id FROM {{tables.namespace_controller_rollovers}}
        WHERE parent_domain = $1 AND state NOT IN ('completed', 'canceled')
        """,
        parent_domain,
    )
    if active is not None:
        _raise_delegation_error(
            DelegationStateError(
                "namespace_delegation_fenced",
                "parent controller rollover temporarily fences child mutations",
                retryable=True,
            )
        )


async def _validated_rollover_children(tx, parent_domain: str):
    orphan = await tx.fetch_one(
        """
        SELECT h.child_domain
        FROM {{tables.namespace_delegation_heads}} h
        LEFT JOIN {{tables.dns_namespaces}} ns
          ON ns.domain=h.child_domain AND ns.deleted_at IS NULL
        WHERE h.parent_domain=$1 AND h.head_operation <> 'revoke'
          AND ns.namespace_id IS NULL
        LIMIT 1
        FOR SHARE OF h
        """,
        parent_domain,
    )
    if orphan is not None:
        _raise_delegation_error(
            DelegationStateError(
                "delegation_chain_inconsistent",
                "non-revoked rollover child has no active namespace row",
            )
        )
    descendants = await tx.fetch_all(
        """
        SELECT ns.domain AS child_domain,ns.controller_did,ns.active_delegation_hash,
               h.parent_domain,h.head_hash,h.head_operation,h.head_controller_did,
               h.head_sequence,e.canonical_payload
        FROM {{tables.dns_namespaces}} ns
        LEFT JOIN {{tables.namespace_delegation_heads}} h ON h.child_domain=ns.domain
        LEFT JOIN {{tables.namespace_delegation_entries}} e
          ON e.child_domain=h.child_domain AND e.sequence=h.head_sequence
        WHERE ns.deleted_at IS NULL AND ns.domain LIKE ('%.' || $1)
          AND (h.parent_domain=$1 OR (ns.active_delegation_hash IS NOT NULL AND h.child_domain IS NULL))
        ORDER BY ns.domain COLLATE "C"
        FOR SHARE OF ns
        """,
        parent_domain,
    )
    children = []
    for row in descendants:
        if row["active_delegation_hash"] is not None:
            if (
                row["head_hash"] is None
                or row["parent_domain"] != parent_domain
                or row["head_operation"] == "revoke"
                or row["active_delegation_hash"] != row["head_hash"]
                or row["controller_did"] != row["head_controller_did"]
            ):
                _raise_delegation_error(
                    DelegationStateError(
                        "delegation_chain_inconsistent",
                        "active inherited child is inconsistent with its delegation head",
                    )
                )
        if row["parent_domain"] == parent_domain and row["head_operation"] != "revoke":
            if row["canonical_payload"] is None:
                _raise_delegation_error(
                    DelegationStateError(
                        "delegation_chain_inconsistent", "rollover child head entry is missing"
                    )
                )
            children.append(row)
    return children


async def _rollover_response(tx, row) -> ControllerRolloverResponse:
    counts = await tx.fetch_one(
        """
        SELECT COUNT(*)::int AS total,
               COUNT(new_signature)::int AS signed
        FROM {{tables.namespace_controller_rollover_children}}
        WHERE rollover_id = $1
        """,
        row["rollover_id"],
    )
    return ControllerRolloverResponse(
        rollover_id=str(row["rollover_id"]),
        parent_domain=row["parent_domain"],
        old_controller_did=row["old_controller_did"],
        new_controller_did=row["new_controller_did"],
        recovery_mode=row["recovery_mode"],
        recovery_assertion=(
            None
            if row["recovery_assertion"] is None
            else DelegationAssertion.model_validate_json(
                bytes(row["recovery_assertion"])
            )
        ),
        state=row["state"],
        total_children=counts["total"],
        signed_children=counts["signed"],
        started_at=row["started_at"].isoformat(),
        cutover_at=None if row["cutover_at"] is None else row["cutover_at"].isoformat(),
        complete_after=None if row["complete_after"] is None else row["complete_after"].isoformat(),
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post(
    "",
    response_model=NamespaceResponse,
    dependencies=[Depends(rate_limit_dep("namespace_register"))],
)
async def register_namespace(
    request: Request,
    body: NamespaceRegisterRequest,
    db_infra=Depends(get_db),
    verify_domain: DomainVerifier = Depends(get_domain_verifier),
) -> NamespaceResponse:
    """Register a DNS-backed namespace.

    The caller must prove control of the child controller key via the main
    Authorization header. Registration authority then comes from either the
    domain TXT record or a verified parent namespace authorization header.
    """
    db = db_infra.get_manager("aweb")
    domain = _validate_domain(body.domain)
    assertion = body.delegation_assertion
    register_extra_payload: dict[str, str] = {}
    if body.default_delivery_origin is not None:
        register_extra_payload["default_delivery_origin"] = body.default_delivery_origin
    if assertion is not None:
        register_extra_payload.update(
            {
                "controller_did": body.controller_did or assertion.payload.child_controller_did,
                "delegation_entry_hash": assertion.entry_hash,
            }
        )
    caller_did = _verify_controller_signature(
        request,
        domain=domain,
        operation="register",
        extra_payload=register_extra_payload or None,
    )
    requested_controller_did = body.controller_did or caller_did
    if body.controller_did is not None and body.controller_did != caller_did:
        raise HTTPException(status_code=403, detail="controller_did must match the signing key")

    skip_dns = os.environ.get("AWID_SKIP_DNS_VERIFY", "").strip() == "1"
    parent_auth_present = request.headers.get(_PARENT_AUTH_HEADER) is not None
    domain_is_local = is_reserved_local_domain(domain)
    if assertion is not None and not parent_auth_present:
        raise HTTPException(status_code=400, detail="delegation_assertion requires parent authorization")
    if not skip_dns and not parent_auth_present and not domain_is_local:
        try:
            dns_authority = await verify_domain(domain)
        except DnsVerificationError as e:
            raise HTTPException(status_code=422, detail=str(e))
        if dns_authority.controller_did != caller_did:
            raise HTTPException(status_code=403, detail="Signing key does not match DNS controller")

    async with db.transaction() as tx:
        parent_namespace = None
        if parent_auth_present:
            parent_namespace = await _find_parent_namespace(tx, domain=domain, lock_for_share=True)
            if parent_namespace is None:
                raise HTTPException(status_code=401, detail="Invalid parent authorization")
            await _check_parent_rollover_fence(tx, parent_namespace["domain"])
            parent_signer = _verify_parent_namespace_authorization(
                request,
                child_domain=domain,
                controller_did=requested_controller_did,
                delegation_entry_hash=None if assertion is None else assertion.entry_hash,
            )
            if parent_signer != parent_namespace["controller_did"]:
                raise HTTPException(status_code=401, detail="Invalid parent authorization")

        existing = await tx.fetch_one(
            """
            SELECT namespace_id, domain, controller_did, verification_status,
                   default_delivery_origin, last_verified_at, created_at,
                   active_delegation_hash
            FROM {{tables.dns_namespaces}}
            WHERE domain = $1 AND deleted_at IS NULL
            FOR UPDATE
            """,
            domain,
        )
        head = await delegation_head(tx, domain)
        if head is not None:
            await _check_parent_rollover_fence(tx, head["parent_domain"])
        if existing is not None:
            if (
                existing["controller_did"] != requested_controller_did
                or existing["default_delivery_origin"] != body.default_delivery_origin
            ):
                _raise_delegation_error(
                    DelegationStateError(
                        "namespace_delegation_conflict",
                        "existing namespace differs from registration retry",
                    )
                )
            if head is None:
                if assertion is not None:
                    _raise_delegation_error(
                        DelegationStateError(
                            "namespace_delegation_required",
                            "existing no-history namespace must use delegation backfill",
                        )
                    )
                return _namespace_response(existing)
            if assertion is None:
                _raise_delegation_error(
                    DelegationStateError(
                        "namespace_delegation_required",
                        "history-backed namespace cannot be retried without its original assertion",
                    )
                )
            if (
                head["head_sequence"] != 1
                or head["head_operation"] != "delegate"
                or head["head_hash"] != assertion.entry_hash
                or head["head_controller_did"] != existing["controller_did"]
                or existing["active_delegation_hash"] != head["head_hash"]
            ):
                _raise_delegation_error(
                    DelegationStateError(
                        "namespace_delegation_conflict",
                        "POST is only valid as the exact original delegated-create retry",
                    )
                )
            try:
                await append_transition(
                    tx,
                    assertion.model_dump(mode="json"),
                    authority_did=parent_namespace["controller_did"],
                    expected_child_domain=domain,
                    expected_child_controller_did=requested_controller_did,
                    expected_operation="delegate",
                )
            except DelegationStateError as exc:
                _raise_delegation_error(exc)
            chain = await stored_delegation_chain(tx, domain)
            return _namespace_response(existing, delegation_chain=chain)
        if (
            parent_auth_present
            and assertion is None
            and (
                head is not None
                or os.environ.get("AWID_REQUIRE_DELEGATION_ASSERTION", "").strip() == "1"
            )
        ):
            _raise_delegation_error(
                DelegationStateError(
                    "namespace_delegation_required",
                    "history-backed inherited namespace requires delegation_assertion",
                )
            )

        if existing is None:
            ns_id = uuid.uuid4()
            now = datetime.now(timezone.utc)
            await tx.execute(
                """
                INSERT INTO {{tables.dns_namespaces}}
                    (namespace_id, domain, controller_did, verification_status,
                     default_delivery_origin, last_verified_at, created_at)
                VALUES ($1, $2, $3, 'verified', $4, $5, $5)
                """,
                ns_id,
                domain,
                requested_controller_did,
                body.default_delivery_origin,
                now,
            )

        if assertion is not None:
            if assertion.payload.parent_domain != parent_namespace["domain"]:
                _raise_delegation_error(
                    DelegationStateError(
                        "namespace_delegation_transition_invalid",
                        "delegation parent_domain does not equal the selected parent namespace",
                    )
                )
            try:
                stored = await append_transition(
                    tx,
                    assertion.model_dump(mode="json"),
                    authority_did=parent_namespace["controller_did"],
                    expected_child_domain=domain,
                    expected_child_controller_did=requested_controller_did,
                    expected_operation="delegate",
                )
            except DelegationStateError as exc:
                _raise_delegation_error(exc)
            await tx.execute(
                """
                UPDATE {{tables.dns_namespaces}}
                SET active_delegation_hash = $2
                WHERE namespace_id = $1 AND deleted_at IS NULL
                """,
                ns_id,
                stored["entry_hash"],
            )
        row = await tx.fetch_one(
            """
            SELECT namespace_id, domain, controller_did, verification_status,
                   default_delivery_origin, last_verified_at, created_at
            FROM {{tables.dns_namespaces}} WHERE namespace_id = $1
            """,
            ns_id,
        )
        try:
            chain = await stored_delegation_chain(tx, domain)
        except DelegationStateError as exc:
            _raise_delegation_error(exc)
        return _namespace_response(row, delegation_chain=chain)


@router.post(
    "/{domain}/controller-rollovers",
    response_model=ControllerRolloverResponse,
)
async def start_controller_rollover(
    request: Request,
    domain: str,
    body: ControllerRolloverStartRequest,
    db_infra=Depends(get_db),
    verify_domain: DomainVerifier = Depends(get_domain_verifier),
) -> ControllerRolloverResponse:
    db = db_infra.get_manager("aweb")
    domain = _validate_domain(domain)
    if body.recovery_mode not in {"none", "exact_dns", "delegated"}:
        raise HTTPException(status_code=400, detail="invalid recovery_mode")
    if body.recovery_mode == "delegated" and body.recovery_assertion is None:
        raise HTTPException(status_code=400, detail="delegated recovery requires recovery_assertion")
    if body.recovery_mode != "delegated" and body.recovery_assertion is not None:
        raise HTTPException(status_code=400, detail="recovery_assertion is only valid for delegated recovery")
    admission_extra = {
        "new_controller_did": body.new_controller_did,
        "recovery_mode": body.recovery_mode,
    }
    if body.recovery_assertion is not None:
        admission_extra["recovery_entry_hash"] = body.recovery_assertion.entry_hash
    caller = _verify_controller_signature(
        request,
        domain=domain,
        operation=(
            "start_controller_rollover"
            if body.recovery_mode == "none"
            else "recover_controller_rollover"
        ),
        extra_payload=admission_extra,
    )
    new_controller = _verify_controller_signature(
        request,
        domain=domain,
        operation="prove_controller_rollover_key",
        extra_payload=admission_extra,
        authorization_header=_NEW_CONTROLLER_AUTH_HEADER,
        timestamp_header=_NEW_CONTROLLER_TIMESTAMP_HEADER,
    )
    if new_controller != body.new_controller_did:
        raise HTTPException(status_code=401, detail="new controller proof does not match")

    async with db.transaction() as tx:
        await _lock_namespace_authority_admission(tx)
        await _check_registry_cutover_fence(tx, domain)
        parent = await tx.fetch_one(
            """
            SELECT namespace_id, domain, controller_did, active_delegation_hash
            FROM {{tables.dns_namespaces}}
            WHERE domain = $1 AND deleted_at IS NULL
            FOR UPDATE
            """,
            domain,
        )
        if parent is None:
            raise HTTPException(status_code=404, detail="Namespace not found")
        expected_caller = (
            parent["controller_did"]
            if body.recovery_mode == "none"
            else body.new_controller_did
        )
        if caller != expected_caller:
            raise HTTPException(status_code=403, detail="Rollover admission signer is not authorized")
        if body.new_controller_did == parent["controller_did"]:
            raise HTTPException(status_code=409, detail="new controller must differ")

        recovery_bytes = None
        existing_rollover = await tx.fetch_one(
            """
            SELECT * FROM {{tables.namespace_controller_rollovers}}
            WHERE parent_domain=$1 AND state NOT IN ('completed','canceled')
            FOR UPDATE
            """,
            domain,
        )
        if existing_rollover is not None:
            requested_recovery = (
                None
                if body.recovery_assertion is None
                else canonical_json_bytes(body.recovery_assertion.model_dump(mode="json"))
            )
            stored_recovery = existing_rollover["recovery_assertion"]
            if (
                existing_rollover["old_controller_did"] == parent["controller_did"]
                and existing_rollover["new_controller_did"] == body.new_controller_did
                and existing_rollover["recovery_mode"] == body.recovery_mode
                and (None if stored_recovery is None else bytes(stored_recovery)) == requested_recovery
            ):
                return await _rollover_response(tx, existing_rollover)
            raise HTTPException(status_code=409, detail="conflicting controller rollover already exists")

        ttl_seconds = None
        previous_evidence = None
        if parent["active_delegation_hash"] is None:
            if body.recovery_mode == "delegated":
                raise HTTPException(status_code=409, detail="delegated recovery requires inherited parent state")
            authority = await verify_domain(domain)
            expected_dns_controller = (
                parent["controller_did"]
                if body.recovery_mode == "none"
                else body.new_controller_did
            )
            if authority.inherited or authority.controller_did != expected_dns_controller:
                raise HTTPException(status_code=403, detail="live exact DNS does not name required controller")
            if body.recovery_mode == "none":
                if authority.authoritative_ttl_seconds is None:
                    authority = await verify_domain_with_authoritative_ttl(domain)
                    if authority.controller_did != parent["controller_did"] or authority.inherited:
                        raise HTTPException(status_code=403, detail="authoritative DNS changed during rollover preparation")
                if (
                    authority.authoritative_ttl_seconds is None
                    or authority.authoritative_ttl_seconds <= 0
                ):
                    raise HTTPException(
                        status_code=422,
                        detail={"code": "controller_rollover_previous_ttl_unknown", "message": "old live DNS TTL unavailable", "retryable": False},
                    )
                ttl_seconds = authority.authoritative_ttl_seconds
                previous_evidence = {
                    "dns_name": authority.dns_name,
                    "controller_did": authority.controller_did,
                    "registry_origin": authority.registry_url,
                    "ttl_seconds": ttl_seconds,
                    "observed_at": datetime.now(timezone.utc).isoformat(),
                }
        elif body.recovery_mode == "exact_dns":
            raise HTTPException(status_code=409, detail="exact-DNS recovery requires a direct parent")
        elif body.recovery_mode == "delegated":
            head = await delegation_head(tx, domain, for_update=True)
            if (
                head is None
                or head["head_operation"] == "revoke"
                or parent["active_delegation_hash"] != head["head_hash"]
                or parent["controller_did"] != head["head_controller_did"]
            ):
                _raise_delegation_error(
                    DelegationStateError(
                        "delegation_chain_inconsistent",
                        "delegated parent row/head is inconsistent",
                    )
                )
            try:
                parsed = parse_delegation_assertion(
                    body.recovery_assertion.model_dump(mode="json")
                )
            except Exception as exc:
                _raise_delegation_error(
                    DelegationStateError(
                        "controller_rollover_recovery_invalid",
                        str(exc),
                        status_code=422,
                    )
                )
            grandparent = await tx.fetch_one(
                """
                SELECT controller_did FROM {{tables.dns_namespaces}}
                WHERE domain=$1 AND deleted_at IS NULL AND verification_status='verified'
                FOR SHARE
                """,
                head["parent_domain"],
            )
            if (
                grandparent is None
                or parsed.payload.operation != "rotate"
                or parsed.payload.parent_domain != head["parent_domain"]
                or parsed.payload.child_domain != domain
                or parsed.payload.child_controller_did != body.new_controller_did
                or parsed.payload.sequence != head["head_sequence"] + 1
                or parsed.payload.previous_delegation_hash != head["head_hash"]
                or len(parsed.signatures) != 1
                or parsed.signatures[0].controller_did != grandparent["controller_did"]
            ):
                _raise_delegation_error(
                    DelegationStateError(
                        "controller_rollover_recovery_invalid",
                        "grandparent recovery assertion does not extend the delegated parent",
                        status_code=403,
                    )
                )
            recovery_bytes = canonical_json_bytes(parsed.model_dump(mode="json"))

        children = await _validated_rollover_children(tx, domain)
        rollover_id = uuid.uuid4()
        state = "ready" if not children else "preparing"
        row = await tx.fetch_one(
            """
            INSERT INTO {{tables.namespace_controller_rollovers}}
                (rollover_id, parent_domain, old_controller_did, new_controller_did,
                 state, recovery_mode, recovery_assertion,
                 previous_dns_ttl_seconds, previous_dns_evidence)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)
            RETURNING *
            """,
            rollover_id,
            domain,
            parent["controller_did"],
            body.new_controller_did,
            state,
            body.recovery_mode,
            recovery_bytes,
            ttl_seconds,
            None if previous_evidence is None else json.dumps(previous_evidence),
        )
        for ordinal, child in enumerate(children):
            await tx.execute(
                """
                INSERT INTO {{tables.namespace_controller_rollover_children}}
                    (rollover_id, child_domain, head_hash, canonical_payload, ordinal)
                VALUES ($1, $2, $3, $4, $5)
                """,
                rollover_id,
                child["child_domain"],
                child["head_hash"],
                child["canonical_payload"],
                ordinal,
            )
        return await _rollover_response(tx, row)


@router.get(
    "/{domain}/controller-rollovers/{rollover_id}",
    response_model=ControllerRolloverResponse,
)
async def get_controller_rollover(
    domain: str, rollover_id: uuid.UUID, db_infra=Depends(get_db)
) -> ControllerRolloverResponse:
    db = db_infra.get_manager("aweb")
    row = await db.fetch_one(
        """
        SELECT * FROM {{tables.namespace_controller_rollovers}}
        WHERE rollover_id = $1::uuid AND parent_domain = $2
        """,
        rollover_id,
        _validate_domain(domain),
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Controller rollover not found")
    return await _rollover_response(db, row)


@router.get(
    "/{domain}/controller-rollovers/{rollover_id}/children",
    response_model=ControllerRolloverChildrenResponse,
)
async def get_controller_rollover_children(
    domain: str,
    rollover_id: uuid.UUID,
    limit: int = Query(default=100, ge=1, le=100),
    cursor: str | None = Query(default=None),
    db_infra=Depends(get_db),
) -> ControllerRolloverChildrenResponse:
    db = db_infra.get_manager("aweb")
    domain = _validate_domain(domain)
    async with db.transaction() as tx:
        page_row = None
        token_hash = None
        if cursor is not None:
            token_hash = "sha256:" + hashlib.sha256(cursor.encode()).hexdigest()
            page_row = await tx.fetch_one(
                """
                SELECT p.*,r.parent_domain
                FROM {{tables.namespace_controller_rollover_read_pages}} p
                JOIN {{tables.namespace_controller_rollovers}} r ON r.rollover_id=p.rollover_id
                WHERE p.token_hash=$1
                FOR UPDATE OF p
                """,
                token_hash,
            )
            if (
                page_row is None
                or str(page_row["rollover_id"]) != str(rollover_id)
                or page_row["parent_domain"] != domain
                or page_row["expires_at"] <= datetime.now(timezone.utc)
            ):
                raise HTTPException(status_code=400, detail="invalid rollover cursor")
            if page_row["response_projection"] is not None:
                stored = page_row["response_projection"]
                return ControllerRolloverChildrenResponse.model_validate(
                    json.loads(stored) if isinstance(stored, str) else dict(stored)
                )
            start = page_row["page_start_ordinal"]
            limit = page_row["page_limit"]
        else:
            await tx.fetch_value(
                "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                f"rollover-first:{rollover_id}:{limit}",
            )
            first = await tx.fetch_one(
                """
                SELECT * FROM {{tables.namespace_controller_rollover_first_pages}}
                WHERE rollover_id=$1::uuid AND page_limit=$2
                FOR UPDATE
                """,
                rollover_id,
                limit,
            )
            if first is not None and first["expires_at"] > datetime.now(timezone.utc):
                stored = first["response_projection"]
                return ControllerRolloverChildrenResponse.model_validate(
                    json.loads(stored) if isinstance(stored, str) else dict(stored)
                )
            if first is not None:
                await tx.execute(
                    "DELETE FROM {{tables.namespace_controller_rollover_read_pages}} WHERE rollover_id=$1::uuid AND page_limit=$2",
                    rollover_id,
                    limit,
                )
                await tx.execute(
                    "DELETE FROM {{tables.namespace_controller_rollover_first_pages}} WHERE rollover_id=$1::uuid AND page_limit=$2",
                    rollover_id,
                    limit,
                )
            exists = await tx.fetch_one(
                "SELECT 1 FROM {{tables.namespace_controller_rollovers}} WHERE rollover_id=$1::uuid AND parent_domain=$2",
                rollover_id,
                domain,
            )
            if exists is None:
                raise HTTPException(status_code=404, detail="Controller rollover not found")
            start = 0

        rows = await tx.fetch_all(
            """
            SELECT c.child_domain, c.head_hash, c.canonical_payload, c.ordinal
            FROM {{tables.namespace_controller_rollover_children}} c
            WHERE c.rollover_id = $1::uuid AND c.ordinal >= $2
            ORDER BY c.ordinal LIMIT $3
            """,
            rollover_id,
            start,
            limit + 1,
        )
        has_more = len(rows) > limit
        page = rows[:limit]
        next_cursor = None
        if has_more:
            next_cursor = secrets.token_urlsafe(32)
            await tx.execute(
                """
                INSERT INTO {{tables.namespace_controller_rollover_read_pages}}
                    (token_hash,rollover_id,page_start_ordinal,page_limit,expires_at)
                VALUES ($1,$2::uuid,$3,$4,$5)
                """,
                "sha256:" + hashlib.sha256(next_cursor.encode()).hexdigest(),
                rollover_id,
                page[-1]["ordinal"] + 1,
                limit,
                datetime.now(timezone.utc) + timedelta(minutes=10),
            )
        projection = {
            "children": [
                {
                    "child_domain": row["child_domain"],
                    "head_hash": row["head_hash"],
                    "payload": json.loads(bytes(row["canonical_payload"]).decode()),
                }
                for row in page
            ],
            "has_more": has_more,
            "next_cursor": next_cursor,
        }
        projection_json = json.dumps(projection, sort_keys=True, separators=(",", ":"))
        if cursor is not None:
            await tx.execute(
                """
                UPDATE {{tables.namespace_controller_rollover_read_pages}}
                SET response_projection=$2::jsonb
                WHERE token_hash=$1 AND response_projection IS NULL
                """,
                token_hash,
                projection_json,
            )
        else:
            await tx.execute(
                """
                INSERT INTO {{tables.namespace_controller_rollover_first_pages}}
                    (rollover_id,page_limit,response_projection,expires_at)
                VALUES ($1::uuid,$2,$3::jsonb,$4)
                """,
                rollover_id,
                limit,
                projection_json,
                datetime.now(timezone.utc) + timedelta(minutes=10),
            )
        return ControllerRolloverChildrenResponse.model_validate(projection)


@router.put(
    "/{domain}/controller-rollovers/{rollover_id}/signatures",
    response_model=ControllerRolloverResponse,
)
async def attach_controller_rollover_signatures(
    request: Request,
    domain: str,
    rollover_id: uuid.UUID,
    body: ControllerRolloverSignaturesRequest,
    db_infra=Depends(get_db),
) -> ControllerRolloverResponse:
    domain = _validate_domain(domain)
    canonical_batch = canonical_json_bytes(body.model_dump(mode="json"))
    batch_hash = "sha256:" + hashlib.sha256(canonical_batch).hexdigest()
    caller = _verify_controller_signature(
        request,
        domain=domain,
        operation="attach_controller_rollover_signatures",
        extra_payload={"rollover_id": str(rollover_id), "batch_hash": batch_hash},
    )
    db = db_infra.get_manager("aweb")
    async with db.transaction() as tx:
        rollover = await tx.fetch_one(
            """
            SELECT * FROM {{tables.namespace_controller_rollovers}}
            WHERE rollover_id = $1::uuid AND parent_domain = $2
            FOR UPDATE
            """,
            rollover_id,
            domain,
        )
        if rollover is None:
            raise HTTPException(status_code=404, detail="Controller rollover not found")
        if caller != rollover["new_controller_did"]:
            raise HTTPException(status_code=403, detail="Only the new parent controller can attach signatures")
        if rollover["state"] not in {"preparing", "ready"}:
            raise HTTPException(status_code=409, detail="Controller rollover no longer accepts signatures")

        prepared = []
        for item in body.signatures:
            child = await tx.fetch_one(
                """
                SELECT c.child_domain, c.head_hash, c.canonical_payload, c.new_signature,
                       h.head_sequence
                FROM {{tables.namespace_controller_rollover_children}} c
                JOIN {{tables.namespace_delegation_heads}} h ON h.child_domain = c.child_domain
                WHERE c.rollover_id = $1::uuid AND c.child_domain = $2
                FOR UPDATE OF c
                """,
                rollover_id,
                _validate_domain(item.child_domain),
            )
            if child is None or child["head_hash"] != item.head_hash:
                raise HTTPException(status_code=409, detail="Rollover child head mismatch")
            if child["new_signature"] is not None and child["new_signature"] != item.signature:
                raise HTTPException(status_code=409, detail="Rollover signature conflict")
            stored_signature = await tx.fetch_value(
                """
                SELECT signature FROM {{tables.namespace_delegation_signatures}}
                WHERE child_domain=$1 AND sequence=$2 AND controller_did=$3
                """,
                child["child_domain"],
                child["head_sequence"],
                rollover["new_controller_did"],
            )
            if stored_signature is not None and stored_signature != item.signature:
                raise HTTPException(status_code=409, detail="Stored rollover signature conflict")
            try:
                verify_delegation_signature(
                    controller_did=rollover["new_controller_did"],
                    signature=item.signature,
                    canonical_payload=bytes(child["canonical_payload"]),
                )
            except Exception as exc:
                raise HTTPException(status_code=422, detail="Invalid rollover child signature") from exc
            prepared.append((child, item))

        for child, item in prepared:
            await tx.execute(
                """
                INSERT INTO {{tables.namespace_delegation_signatures}}
                    (child_domain, sequence, controller_did, signature)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (child_domain, sequence, controller_did) DO NOTHING
                """,
                child["child_domain"],
                child["head_sequence"],
                rollover["new_controller_did"],
                item.signature,
            )
            await tx.execute(
                """
                UPDATE {{tables.namespace_controller_rollover_children}}
                SET new_signature = $3
                WHERE rollover_id = $1::uuid AND child_domain = $2
                  AND (new_signature IS NULL OR new_signature = $3)
                """,
                rollover_id,
                child["child_domain"],
                item.signature,
            )
        readback = await tx.fetch_all(
            """
            SELECT c.child_domain,c.canonical_payload,c.new_signature,s.signature AS stored_signature
            FROM {{tables.namespace_controller_rollover_children}} c
            LEFT JOIN {{tables.namespace_delegation_heads}} h ON h.child_domain=c.child_domain
            LEFT JOIN {{tables.namespace_delegation_signatures}} s
              ON s.child_domain=c.child_domain AND s.sequence=h.head_sequence
             AND s.controller_did=$2
            WHERE c.rollover_id=$1::uuid
            ORDER BY c.child_domain COLLATE "C"
            """,
            rollover_id,
            rollover["new_controller_did"],
        )
        complete = True
        for item in readback:
            if item["new_signature"] is None or item["stored_signature"] != item["new_signature"]:
                complete = False
                break
            try:
                verify_delegation_signature(
                    controller_did=rollover["new_controller_did"],
                    signature=item["stored_signature"],
                    canonical_payload=bytes(item["canonical_payload"]),
                )
            except Exception as exc:
                raise HTTPException(status_code=409, detail="Stored rollover signature readback invalid") from exc
        if complete:
            rollover = await tx.fetch_one(
                """
                UPDATE {{tables.namespace_controller_rollovers}}
                SET state = 'ready', updated_at = NOW()
                WHERE rollover_id = $1::uuid
                RETURNING *
                """,
                rollover_id,
            )
        return await _rollover_response(tx, rollover)


@router.post(
    "/{domain}/controller-rollovers/{rollover_id}/complete",
    response_model=ControllerRolloverResponse,
)
async def complete_controller_rollover(
    request: Request,
    domain: str,
    rollover_id: uuid.UUID,
    db_infra=Depends(get_db),
) -> ControllerRolloverResponse:
    domain = _validate_domain(domain)
    caller = _verify_controller_signature(
        request,
        domain=domain,
        operation="complete_controller_rollover",
        extra_payload={"rollover_id": str(rollover_id)},
    )
    db = db_infra.get_manager("aweb")
    async with db.transaction() as tx:
        rollover = await tx.fetch_one(
            """
            SELECT * FROM {{tables.namespace_controller_rollovers}}
            WHERE rollover_id = $1::uuid AND parent_domain = $2
            FOR UPDATE
            """,
            rollover_id,
            domain,
        )
        if rollover is None:
            raise HTTPException(status_code=404, detail="Controller rollover not found")
        if caller != rollover["new_controller_did"]:
            raise HTTPException(status_code=403, detail="Only the new controller can complete rollover")
        if rollover["state"] == "completed":
            return await _rollover_response(tx, rollover)
        if rollover["state"] not in {"overlap", "overlap_risk_accepted"} or rollover["complete_after"] is None:
            raise HTTPException(status_code=409, detail="Controller rollover is not in bounded overlap")
        if datetime.now(timezone.utc) < rollover["complete_after"]:
            _raise_delegation_error(
                DelegationStateError(
                    "controller_rollover_overlap_pending",
                    "controller rollover overlap has not elapsed",
                    retryable=True,
                )
            )
        rollover = await tx.fetch_one(
            """
            UPDATE {{tables.namespace_controller_rollovers}}
            SET state = 'completed', updated_at = NOW()
            WHERE rollover_id = $1::uuid
            RETURNING *
            """,
            rollover_id,
        )
        return await _rollover_response(tx, rollover)


@router.delete(
    "/{domain}/controller-rollovers/{rollover_id}",
    response_model=ControllerRolloverResponse,
)
async def cancel_controller_rollover(
    request: Request,
    domain: str,
    rollover_id: uuid.UUID,
    db_infra=Depends(get_db),
) -> ControllerRolloverResponse:
    domain = _validate_domain(domain)
    caller = _verify_controller_signature(
        request,
        domain=domain,
        operation="cancel_controller_rollover",
        extra_payload={"rollover_id": str(rollover_id)},
    )
    db = db_infra.get_manager("aweb")
    async with db.transaction() as tx:
        rollover = await tx.fetch_one(
            """
            SELECT * FROM {{tables.namespace_controller_rollovers}}
            WHERE rollover_id = $1::uuid AND parent_domain = $2
            FOR UPDATE
            """,
            rollover_id,
            domain,
        )
        if rollover is None:
            raise HTTPException(status_code=404, detail="Controller rollover not found")
        if caller != rollover["old_controller_did"]:
            raise HTTPException(status_code=403, detail="Only the old controller can cancel rollover")
        if rollover["state"] not in {"preparing", "ready"}:
            raise HTTPException(status_code=409, detail="Controller rollover cannot be canceled after cutover")
        rollover = await tx.fetch_one(
            """
            UPDATE {{tables.namespace_controller_rollovers}}
            SET state = 'canceled', updated_at = NOW()
            WHERE rollover_id = $1::uuid RETURNING *
            """,
            rollover_id,
        )
        return await _rollover_response(tx, rollover)


@router.post(
    "/{domain}/delegation/backfill",
    response_model=NamespaceResponse,
)
async def backfill_namespace_delegation(
    request: Request,
    domain: str,
    body: NamespaceDelegationBackfillRequest,
    db_infra=Depends(get_db),
) -> NamespaceResponse:
    db = db_infra.get_manager("aweb")
    domain = _validate_domain(domain)
    assertion = body.delegation_assertion
    caller_did = _verify_controller_signature(
        request,
        domain=domain,
        operation="backfill_namespace_delegation",
        extra_payload={"delegation_entry_hash": assertion.entry_hash},
    )
    async with db.transaction() as tx:
        row = await tx.fetch_one(
            """
            SELECT namespace_id, domain, controller_did, verification_status,
                   default_delivery_origin, last_verified_at, created_at,
                   active_delegation_hash
            FROM {{tables.dns_namespaces}}
            WHERE domain = $1 AND deleted_at IS NULL
            FOR UPDATE
            """,
            domain,
        )
        if row is None:
            raise HTTPException(status_code=404, detail="Namespace not found")
        if caller_did != row["controller_did"]:
            raise HTTPException(status_code=403, detail="Only the namespace controller can backfill")
        if await delegation_head(tx, domain, for_update=True) is not None:
            _raise_delegation_error(
                DelegationStateError("namespace_delegation_conflict", "delegation history already exists")
            )
        parent = await _find_parent_namespace(tx, domain=domain, lock_for_share=True)
        if parent is None:
            raise HTTPException(status_code=401, detail="Invalid parent authorization")
        await _check_parent_rollover_fence(tx, parent["domain"])
        parent_signer = _verify_controller_signature(
            request,
            domain=domain,
            operation="authorize_subdomain_backfill",
            extra_payload={
                "child_domain": domain,
                "controller_did": row["controller_did"],
                "delegation_entry_hash": assertion.entry_hash,
            },
            authorization_header=_PARENT_AUTH_HEADER,
            timestamp_header=_PARENT_TIMESTAMP_HEADER,
        )
        if parent_signer != parent["controller_did"]:
            raise HTTPException(status_code=401, detail="Invalid parent authorization")
        if assertion.payload.parent_domain != parent["domain"]:
            _raise_delegation_error(
                DelegationStateError(
                    "namespace_delegation_transition_invalid",
                    "delegation parent_domain does not equal the selected parent namespace",
                )
            )
        try:
            stored = await append_transition(
                tx,
                assertion.model_dump(mode="json"),
                authority_did=parent["controller_did"],
                expected_child_domain=domain,
                expected_child_controller_did=row["controller_did"],
                expected_operation="delegate",
            )
        except DelegationStateError as exc:
            _raise_delegation_error(exc)
        updated = await tx.fetch_one(
            """
            UPDATE {{tables.dns_namespaces}}
            SET active_delegation_hash = $2
            WHERE namespace_id = $1 AND active_delegation_hash IS NULL
            RETURNING namespace_id, domain, controller_did, verification_status,
                      default_delivery_origin, last_verified_at, created_at
            """,
            row["namespace_id"],
            stored["entry_hash"],
        )
        if updated is None:
            _raise_delegation_error(
                DelegationStateError("namespace_delegation_conflict", "namespace synchronization changed")
            )
        chain = await stored_delegation_chain(tx, domain)
        return _namespace_response(updated, delegation_chain=chain)


@router.get(
    "/{domain}/delegation-log",
    response_model=NamespaceDelegationLogResponse,
    dependencies=[Depends(rate_limit_dep("namespace_delegation_log"))],
)
async def get_namespace_delegation_log(
    domain: str,
    after_sequence: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=100),
    cursor: str | None = Query(default=None),
    db_infra=Depends(get_db),
) -> NamespaceDelegationLogResponse:
    db = db_infra.get_manager("aweb")
    domain = _validate_domain(domain)

    if cursor is None:
        async with db.transaction() as tx:
            await tx.fetch_value(
                "SELECT pg_advisory_xact_lock(hashtextextended($1,0))",
                f"delegation-first:{domain}:{after_sequence}:{limit}",
            )
            head = await tx.fetch_one(
                """
                SELECT child_domain, head_sequence, head_hash
                FROM {{tables.namespace_delegation_heads}}
                WHERE child_domain = $1
                FOR SHARE
                """,
                domain,
            )
            if head is None:
                raise HTTPException(
                    status_code=404,
                    detail={"code": "delegation_log_not_found", "message": "delegation log not found", "retryable": False},
                )
            if after_sequence > head["head_sequence"]:
                raise HTTPException(status_code=400, detail="after_sequence exceeds head")
            rows = await tx.fetch_all(
                """
                SELECT sequence FROM {{tables.namespace_delegation_entries}}
                WHERE child_domain = $1 AND sequence > $2 AND sequence <= $3
                ORDER BY sequence LIMIT $4
                """,
                domain,
                after_sequence,
                head["head_sequence"],
                limit + 1,
            )
            has_more = len(rows) > limit
            page = rows[:limit]
            entries = [await stored_assertion(tx, domain, row["sequence"]) for row in page]
            next_sequence = after_sequence if not page else page[-1]["sequence"]
            next_cursor = None
            snapshot_id = None
            if has_more:
                existing_snapshot = await tx.fetch_one(
                    """
                    SELECT snapshot_id,expires_at,invalidated_at,first_response_projection
                    FROM {{tables.namespace_delegation_read_snapshots}}
                    WHERE child_domain=$1 AND head_sequence=$2 AND head_hash=$3
                      AND original_after=$4 AND page_limit=$5
                    FOR UPDATE
                    """,
                    domain, head["head_sequence"], head["head_hash"], after_sequence, limit,
                )
                if (
                    existing_snapshot is not None
                    and existing_snapshot["expires_at"] > datetime.now(timezone.utc)
                    and existing_snapshot["invalidated_at"] is None
                    and existing_snapshot["first_response_projection"] is not None
                ):
                    stored = existing_snapshot["first_response_projection"]
                    return NamespaceDelegationLogResponse.model_validate(
                        json.loads(stored) if isinstance(stored, str) else dict(stored)
                    )
                next_cursor = secrets.token_urlsafe(32)
                if existing_snapshot is None:
                    snapshot_id = uuid.uuid4()
                    await tx.execute(
                        """
                        INSERT INTO {{tables.namespace_delegation_read_snapshots}}
                            (snapshot_id, child_domain, head_sequence, head_hash,
                             original_after, page_limit, expires_at)
                        VALUES ($1, $2, $3, $4, $5, $6, $7)
                        """,
                        snapshot_id, domain, head["head_sequence"], head["head_hash"],
                        after_sequence, limit,
                        datetime.now(timezone.utc) + timedelta(minutes=10),
                    )
                else:
                    snapshot_id = existing_snapshot["snapshot_id"]
                    await tx.execute(
                        "DELETE FROM {{tables.namespace_delegation_read_pages}} WHERE snapshot_id=$1",
                        snapshot_id,
                    )
                    await tx.execute(
                        """
                        UPDATE {{tables.namespace_delegation_read_snapshots}}
                        SET expires_at=$2,invalidated_at=NULL,
                            first_response_projection=NULL
                        WHERE snapshot_id=$1
                        """,
                        snapshot_id, datetime.now(timezone.utc) + timedelta(minutes=10),
                    )
                await tx.execute(
                    """
                    INSERT INTO {{tables.namespace_delegation_read_pages}}
                        (token_hash, snapshot_id, page_start_sequence, page_limit)
                    VALUES ($1, $2, $3, $4)
                    """,
                    "sha256:" + hashlib.sha256(next_cursor.encode()).hexdigest(),
                    snapshot_id, next_sequence + 1, limit,
                )
            projection = {
                "entries": entries,
                "has_more": has_more,
                "next_sequence": next_sequence,
                "next_cursor": next_cursor,
                "head_sequence": head["head_sequence"],
                "head_hash": head["head_hash"],
            }
            if snapshot_id is not None:
                await tx.execute(
                    """
                    UPDATE {{tables.namespace_delegation_read_snapshots}}
                    SET first_response_projection=$2::jsonb
                    WHERE snapshot_id=$1
                    """,
                    snapshot_id,
                    json.dumps(projection, sort_keys=True, separators=(",", ":")),
                )
            return NamespaceDelegationLogResponse.model_validate(projection)

    token_hash = "sha256:" + hashlib.sha256(cursor.encode()).hexdigest()
    changed = False
    projection = None
    preliminary = await db.fetch_one(
        """
        SELECT p.snapshot_id,s.child_domain
        FROM {{tables.namespace_delegation_read_pages}} p
        JOIN {{tables.namespace_delegation_read_snapshots}} s
          ON s.snapshot_id=p.snapshot_id
        WHERE p.token_hash=$1
        """,
        token_hash,
    )
    if preliminary is None or preliminary["child_domain"] != domain:
        raise HTTPException(
            status_code=400,
            detail={"code": "delegation_cursor_invalid", "message": "cursor is invalid", "retryable": False},
        )
    async with db.transaction() as tx:
        live_head = await tx.fetch_one(
            """
            SELECT head_sequence,head_hash FROM {{tables.namespace_delegation_heads}}
            WHERE child_domain=$1 FOR SHARE
            """,
            preliminary["child_domain"],
        )
        page_row = await tx.fetch_one(
            """
            SELECT p.snapshot_id, p.page_start_sequence, p.page_limit,
                   p.response_projection,
                   s.child_domain, s.head_sequence, s.head_hash,
                   s.expires_at, s.invalidated_at
            FROM {{tables.namespace_delegation_read_pages}} p
            JOIN {{tables.namespace_delegation_read_snapshots}} s
              ON s.snapshot_id = p.snapshot_id
            WHERE p.token_hash = $1
            FOR UPDATE OF p, s
            """,
            token_hash,
        )
        if (
            page_row is None
            or page_row["snapshot_id"] != preliminary["snapshot_id"]
            or page_row["child_domain"] != preliminary["child_domain"]
            or page_row["child_domain"] != domain
            or page_row["expires_at"] <= datetime.now(timezone.utc)
            or page_row["invalidated_at"] is not None
        ):
            raise HTTPException(
                status_code=400,
                detail={"code": "delegation_cursor_invalid", "message": "cursor is invalid", "retryable": False},
            )
        if (
            live_head is None
            or live_head["head_sequence"] != page_row["head_sequence"]
            or live_head["head_hash"] != page_row["head_hash"]
        ):
            await tx.execute(
                """
                UPDATE {{tables.namespace_delegation_read_snapshots}}
                SET invalidated_at = NOW() WHERE snapshot_id = $1
                """,
                page_row["snapshot_id"],
            )
            changed = True
        elif page_row["response_projection"] is not None:
            stored_projection = page_row["response_projection"]
            projection = (
                json.loads(stored_projection)
                if isinstance(stored_projection, str)
                else dict(stored_projection)
            )
        else:
            rows = await tx.fetch_all(
                """
                SELECT sequence FROM {{tables.namespace_delegation_entries}}
                WHERE child_domain = $1 AND sequence >= $2 AND sequence <= $3
                ORDER BY sequence LIMIT $4
                """,
                domain,
                page_row["page_start_sequence"],
                page_row["head_sequence"],
                page_row["page_limit"] + 1,
            )
            has_more = len(rows) > page_row["page_limit"]
            page = rows[: page_row["page_limit"]]
            entries = [await stored_assertion(tx, domain, row["sequence"]) for row in page]
            next_sequence = page_row["page_start_sequence"] - 1 if not page else page[-1]["sequence"]
            next_cursor = None
            if has_more:
                next_cursor = secrets.token_urlsafe(32)
                await tx.execute(
                    """
                    INSERT INTO {{tables.namespace_delegation_read_pages}}
                        (token_hash, snapshot_id, page_start_sequence, page_limit)
                    VALUES ($1, $2, $3, $4)
                    """,
                    "sha256:" + hashlib.sha256(next_cursor.encode()).hexdigest(),
                    page_row["snapshot_id"],
                    next_sequence + 1,
                    page_row["page_limit"],
                )
            projection = {
                "entries": entries,
                "has_more": has_more,
                "next_sequence": next_sequence,
                "next_cursor": next_cursor,
                "head_sequence": page_row["head_sequence"],
                "head_hash": page_row["head_hash"],
            }
            await tx.execute(
                """
                UPDATE {{tables.namespace_delegation_read_pages}}
                SET response_projection = $2::jsonb
                WHERE token_hash = $1 AND response_projection IS NULL
                """,
                token_hash,
                json.dumps(projection, sort_keys=True, separators=(",", ":")),
            )
    if changed:
        raise HTTPException(
            status_code=409,
            detail={"code": "delegation_log_snapshot_changed", "message": "delegation log head changed", "retryable": True},
        )
    return NamespaceDelegationLogResponse.model_validate(projection)


@router.post(
    "/{domain}/reverify",
    response_model=NamespaceReverifyResponse,
    dependencies=[Depends(rate_limit_dep("namespace_reverify"))],
)
async def reverify_namespace(
    domain: str,
    body: NamespaceReverifyRequest | None = None,
    db_infra=Depends(get_db),
    verify_domain: DomainVerifier = Depends(get_domain_verifier),
) -> NamespaceReverifyResponse:
    """Reverify namespace control from live DNS and refresh stored authority."""
    db = db_infra.get_manager("aweb")
    domain = _validate_domain(domain)
    ns_row = await db.fetch_one(
        """
        SELECT namespace_id, domain, controller_did, verification_status,
               default_delivery_origin, last_verified_at, created_at
        FROM {{tables.dns_namespaces}}
        WHERE domain = $1 AND deleted_at IS NULL
        """,
        domain,
    )
    if ns_row is None:
        raise HTTPException(status_code=404, detail="Namespace not found")

    try:
        authority = await verify_domain(domain)
    except DnsVerificationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if not authority.inherited and authority.controller_did != ns_row["controller_did"]:
        async with db.transaction() as tx:
            locked = await tx.fetch_one(
                """
                SELECT namespace_id,domain,controller_did,verification_status,
                       default_delivery_origin,last_verified_at,created_at,
                       active_delegation_hash
                FROM {{tables.dns_namespaces}}
                WHERE domain=$1 AND deleted_at IS NULL
                FOR UPDATE
                """,
                domain,
            )
            if locked is None:
                raise HTTPException(status_code=404, detail="Namespace not found")
            if locked["controller_did"] != ns_row["controller_did"]:
                raise HTTPException(status_code=409, detail="Namespace controller changed during reverify")
            head = await delegation_head(tx, domain, for_update=True)
            if head is not None:
                await _check_parent_rollover_fence(tx, head["parent_domain"])
            child = await tx.fetch_one(
                """
                SELECT child_domain FROM {{tables.namespace_delegation_heads}}
                WHERE parent_domain=$1 AND head_operation <> 'revoke' LIMIT 1
                FOR SHARE
                """,
                domain,
            )
            rollover = None
            if child is not None:
                rollover_id = None if body is None else body.rollover_id
                if rollover_id is not None:
                    rollover = await tx.fetch_one(
                        """
                        SELECT * FROM {{tables.namespace_controller_rollovers}}
                        WHERE rollover_id=$1::uuid AND parent_domain=$2
                          AND old_controller_did=$3 AND new_controller_did=$4
                        FOR UPDATE
                        """,
                        rollover_id,
                        domain,
                        locked["controller_did"],
                        authority.controller_did,
                    )
                if rollover is None or rollover["state"] != "ready":
                    _raise_delegation_error(
                        DelegationStateError(
                            "controller_rollover_not_ready",
                            "DNS reverify controller change requires a ready rollover",
                        )
                    )
            now = datetime.now(timezone.utc)
            updated = await tx.fetch_one(
                """
                UPDATE {{tables.dns_namespaces}}
                SET controller_did=$2,verification_status='verified',
                    last_verified_at=$3,active_delegation_hash=NULL,
                    last_verified_dns_ttl_seconds=$4
                WHERE namespace_id=$1 AND controller_did=$5
                RETURNING namespace_id,domain,controller_did,verification_status,
                          default_delivery_origin,last_verified_at,created_at
                """,
                locked["namespace_id"],
                authority.controller_did,
                now,
                authority.ttl_seconds,
                locked["controller_did"],
            )
            if updated is None:
                raise HTTPException(status_code=409, detail="Namespace controller changed during reverify")
            if rollover is not None:
                if rollover["recovery_mode"] == "exact_dns" and rollover["previous_dns_ttl_seconds"] is None:
                    await tx.execute(
                        """
                        UPDATE {{tables.namespace_controller_rollovers}}
                        SET state='recovery_overlap_unbounded',cutover_at=$2,
                            first_new_dns_observed_at=$2,complete_after=NULL,updated_at=NOW()
                        WHERE rollover_id=$1
                        """,
                        rollover["rollover_id"], now,
                    )
                else:
                    if rollover["previous_dns_ttl_seconds"] is None:
                        raise HTTPException(status_code=422, detail="Old DNS TTL unavailable")
                    await tx.execute(
                        """
                        UPDATE {{tables.namespace_controller_rollovers}}
                        SET state='overlap',cutover_at=$2,
                            complete_after=$2::timestamptz + ($3::double precision * INTERVAL '1 second'),
                            updated_at=NOW()
                        WHERE rollover_id=$1
                        """,
                        rollover["rollover_id"], now, rollover["previous_dns_ttl_seconds"],
                    )
            dns_namespace_reverify_routes.logger.warning(
                "Namespace controller rotated: domain=%s old_controller_did=%s new_controller_did=%s",
                domain,
                locked["controller_did"],
                authority.controller_did,
            )
            response = _namespace_response(updated)
            return NamespaceReverifyResponse(
                **response.model_dump(),
                old_controller_did=locked["controller_did"],
                new_controller_did=authority.controller_did,
            )

    async def verified_authority(_domain: str):
        return authority

    result = await reverify_namespace_row(
        db,
        ns_row,
        domain=domain,
        verify_domain=verified_authority,
        allow_local_bypass=False,
        dns_failure_status=422,
    )
    return _namespace_reverify_response(result)


@router.get(
    "/{domain}",
    response_model=NamespaceResponse,
    dependencies=[Depends(rate_limit_dep("namespace_get"))],
)
async def get_namespace(domain: str, db_infra=Depends(get_db)) -> NamespaceResponse:
    """Query a namespace's status by domain."""
    db = db_infra.get_manager("aweb")
    domain = _validate_domain(domain)
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
    try:
        chain = await stored_delegation_chain(db, domain)
    except DelegationStateError as exc:
        _raise_delegation_error(exc)
    return _namespace_response(row, delegation_chain=chain)


@router.patch(
    "/{domain}",
    response_model=NamespaceResponse,
    dependencies=[Depends(rate_limit_dep("namespace_update"))],
)
async def update_namespace(
    request: Request,
    domain: str,
    body: NamespaceUpdateRequest,
    db_infra=Depends(get_db),
) -> NamespaceResponse:
    """Update namespace metadata authorized by the current namespace controller."""
    db = db_infra.get_manager("aweb")
    domain = _validate_domain(domain)
    signed_origin = body.default_delivery_origin or ""
    caller_did = _verify_controller_signature(
        request,
        domain=domain,
        operation="update_namespace",
        extra_payload={"default_delivery_origin": signed_origin},
    )

    async with db.transaction() as tx:
        existing = await tx.fetch_one(
            """
            SELECT namespace_id, controller_did
            FROM {{tables.dns_namespaces}}
            WHERE domain = $1 AND deleted_at IS NULL
            FOR UPDATE
            """,
            domain,
        )
        if existing is None:
            raise HTTPException(status_code=404, detail="Namespace not found")
        if caller_did != existing["controller_did"]:
            raise HTTPException(
                status_code=403,
                detail="Only the namespace controller can update namespace metadata",
            )

        row = await tx.fetch_one(
            """
            UPDATE {{tables.dns_namespaces}}
            SET default_delivery_origin = $2
            WHERE namespace_id = $1 AND deleted_at IS NULL
            RETURNING namespace_id, domain, controller_did, verification_status,
                      default_delivery_origin, last_verified_at, created_at
            """,
            existing["namespace_id"],
            body.default_delivery_origin,
        )
        if row is None:
            raise HTTPException(status_code=404, detail="Namespace not found")
    return _namespace_response(row)


@router.put(
    "/{domain}",
    response_model=NamespaceResponse,
    dependencies=[Depends(rate_limit_dep("namespace_rotate"))],
)
async def rotate_namespace_controller(
    request: Request,
    domain: str,
    body: NamespaceRotateControllerRequest,
    db_infra=Depends(get_db),
    verify_domain: DomainVerifier = Depends(get_domain_verifier),
) -> NamespaceResponse:
    """Rotate a namespace controller with new-key proof plus DNS or parent auth.

    This is intentional key-loss recovery: the old controller key may be gone.
    The caller must prove possession of the new controller key, and authority
    then comes from either DNS re-verification or parent-domain authorization
    for registered subdomains.
    """
    db = db_infra.get_manager("aweb")
    domain = _validate_domain(domain)
    new_controller_did = body.new_controller_did
    assertion = body.delegation_assertion
    _verify_controller_rotation_signature(
        request,
        domain=domain,
        new_controller_did=new_controller_did,
        delegation_entry_hash=None if assertion is None else assertion.entry_hash,
        rollover_id=None if body.rollover_id is None else str(body.rollover_id),
    )
    skip_dns = os.environ.get("AWID_SKIP_DNS_VERIFY", "").strip() == "1"
    parent_auth_present = request.headers.get(_PARENT_AUTH_HEADER) is not None
    domain_is_local = is_reserved_local_domain(domain)
    delegated_recovery_requested = (
        assertion is not None and body.rollover_id is not None and not parent_auth_present
    )
    if assertion is not None and not parent_auth_present and not delegated_recovery_requested:
        raise HTTPException(status_code=400, detail="delegation_assertion requires parent authorization")
    if not skip_dns and not parent_auth_present and not domain_is_local and not delegated_recovery_requested:
        try:
            dns_authority = await verify_domain(domain)
        except DnsVerificationError as e:
            raise HTTPException(status_code=422, detail=str(e))
        if dns_authority.controller_did != new_controller_did:
            raise HTTPException(status_code=403, detail="DNS controller does not match new_controller_did")

    now = datetime.now(timezone.utc)
    async with db.transaction() as tx:
        parent_namespace = None
        if parent_auth_present:
            parent_namespace = await _find_parent_namespace(tx, domain=domain, lock_for_share=True)
            if parent_namespace is None:
                raise HTTPException(status_code=401, detail="Invalid parent authorization")
            await _check_parent_rollover_fence(tx, parent_namespace["domain"])
            parent_signer = _verify_parent_namespace_authorization(
                request,
                child_domain=domain,
                new_controller_did=new_controller_did,
                delegation_entry_hash=None if assertion is None else assertion.entry_hash,
                rollover_id=None if body.rollover_id is None else str(body.rollover_id),
            )
            if parent_signer != parent_namespace["controller_did"]:
                raise HTTPException(status_code=401, detail="Invalid parent authorization")
        existing = await tx.fetch_one(
            """
            SELECT namespace_id, controller_did, active_delegation_hash
            FROM {{tables.dns_namespaces}}
            WHERE domain = $1 AND deleted_at IS NULL
            FOR UPDATE
            """,
            domain,
        )
        if existing is None:
            raise HTTPException(status_code=404, detail="Namespace not found")
        head = await delegation_head(tx, domain, for_update=True)
        if head is not None:
            await _check_parent_rollover_fence(tx, head["parent_domain"])
        nonrevoked_child = await tx.fetch_one(
            """
            SELECT child_domain FROM {{tables.namespace_delegation_heads}}
            WHERE parent_domain = $1 AND head_operation <> 'revoke' LIMIT 1
            """,
            domain,
        )
        own_rollover = None
        if body.rollover_id is not None:
            own_rollover = await tx.fetch_one(
                """
                SELECT * FROM {{tables.namespace_controller_rollovers}}
                WHERE rollover_id = $1::uuid AND parent_domain = $2
                FOR UPDATE
                """,
                body.rollover_id,
                domain,
            )
            if (
                own_rollover is None
                or own_rollover["state"] != "ready"
                or own_rollover["old_controller_did"] != existing["controller_did"]
                or own_rollover["new_controller_did"] != new_controller_did
            ):
                _raise_delegation_error(
                    DelegationStateError(
                        "controller_rollover_not_ready",
                        "rollover is not ready for this controller change",
                    )
                )
        elif nonrevoked_child is not None:
            _raise_delegation_error(
                DelegationStateError(
                    "controller_rollover_not_ready",
                    "parent controller change requires a ready rollover",
                )
            )

        if parent_auth_present:
            if assertion is None and (
                head is not None
                or os.environ.get("AWID_REQUIRE_DELEGATION_ASSERTION", "").strip() == "1"
            ):
                _raise_delegation_error(
                    DelegationStateError(
                        "namespace_delegation_required",
                        "history-backed inherited namespace requires delegation_assertion",
                    )
                )
        elif delegated_recovery_requested:
            submitted_recovery = canonical_json_bytes(assertion.model_dump(mode="json"))
            if (
                own_rollover is None
                or own_rollover["recovery_mode"] != "delegated"
                or own_rollover["recovery_assertion"] is None
                or bytes(own_rollover["recovery_assertion"]) != submitted_recovery
                or head is None
            ):
                _raise_delegation_error(
                    DelegationStateError(
                        "controller_rollover_recovery_invalid",
                        "submitted recovery assertion differs from prepared evidence",
                        status_code=403,
                    )
                )
            grandparent = await tx.fetch_one(
                """
                SELECT domain,controller_did FROM {{tables.dns_namespaces}}
                WHERE domain=$1 AND deleted_at IS NULL AND verification_status='verified'
                FOR SHARE
                """,
                head["parent_domain"],
            )
            if grandparent is None:
                _raise_delegation_error(
                    DelegationStateError(
                        "controller_rollover_recovery_invalid",
                        "delegated recovery grandparent is unavailable",
                        status_code=403,
                    )
                )
            parent_namespace = grandparent

        marker = None
        if assertion is not None:
            expected_operation = "delegate" if head is not None and head["head_operation"] == "revoke" else "rotate"
            try:
                stored = await append_transition(
                    tx,
                    assertion.model_dump(mode="json"),
                    authority_did=parent_namespace["controller_did"],
                    expected_child_domain=domain,
                    expected_child_controller_did=new_controller_did,
                    expected_operation=expected_operation,
                )
            except DelegationStateError as exc:
                _raise_delegation_error(exc)
            marker = stored["entry_hash"]

        row = await tx.fetch_one(
            """
            UPDATE {{tables.dns_namespaces}}
            SET controller_did = $2, verification_status = 'verified',
                last_verified_at = $3, active_delegation_hash = $4
            WHERE domain = $1 AND deleted_at IS NULL
            RETURNING namespace_id, domain, controller_did, verification_status,
                      default_delivery_origin, last_verified_at, created_at
            """,
            domain,
            new_controller_did,
            now,
            marker,
        )
        if row is None:
            raise HTTPException(status_code=404, detail="Namespace not found")
        if own_rollover is not None:
            if own_rollover["recovery_mode"] == "exact_dns" and own_rollover["previous_dns_ttl_seconds"] is None:
                await tx.execute(
                    """
                    UPDATE {{tables.namespace_controller_rollovers}}
                    SET state = 'recovery_overlap_unbounded', cutover_at = $2,
                        first_new_dns_observed_at = $2, complete_after = NULL,
                        updated_at = NOW()
                    WHERE rollover_id = $1
                    """,
                    own_rollover["rollover_id"],
                    now,
                )
            else:
                overlap_seconds = (
                    60
                    if existing["active_delegation_hash"] is not None
                    else own_rollover["previous_dns_ttl_seconds"]
                )
                if overlap_seconds is None:
                    _raise_delegation_error(
                        DelegationStateError(
                            "controller_rollover_previous_ttl_unknown",
                            "old live DNS TTL unavailable",
                            status_code=422,
                        )
                    )
                await tx.execute(
                    """
                    UPDATE {{tables.namespace_controller_rollovers}}
                    SET state = 'overlap', cutover_at = $2::timestamptz,
                        complete_after = $2::timestamptz + ($3::double precision * INTERVAL '1 second'),
                        updated_at = NOW()
                    WHERE rollover_id = $1
                    """,
                    own_rollover["rollover_id"],
                    now,
                    overlap_seconds,
                )
        try:
            chain = await stored_delegation_chain(tx, domain)
        except DelegationStateError as exc:
            _raise_delegation_error(exc)
    if existing["controller_did"] != new_controller_did:
        logger.warning(
            "Namespace controller rotated: domain=%s old_controller_did=%s new_controller_did=%s",
            domain,
            existing["controller_did"],
            new_controller_did,
        )
    return _namespace_response(row, delegation_chain=chain)


@router.get(
    "",
    response_model=NamespaceListResponse,
    dependencies=[Depends(rate_limit_dep("namespace_list"))],
)
async def list_namespaces(
    controller_did: Optional[str] = Query(default=None),
    limit: int | None = Query(default=None, ge=1),
    cursor: str | None = Query(default=None),
    db_infra=Depends(get_db),
) -> NamespaceListResponse:
    """List registered namespaces, optionally filtered by controller DID."""
    db = db_infra.get_manager("aweb")
    try:
        validated_limit, decoded_cursor = validate_pagination_params(limit, cursor)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    where_clauses = ["deleted_at IS NULL"]
    params: list[object] = []
    if controller_did:
        params.append(controller_did)
        where_clauses.append(f"controller_did = ${len(params)}")
    if decoded_cursor is not None:
        cursor_created_at = decoded_cursor.get("created_at")
        cursor_namespace_id = decoded_cursor.get("namespace_id")
        if not isinstance(cursor_created_at, str) or not isinstance(cursor_namespace_id, str):
            raise HTTPException(status_code=400, detail="Invalid cursor: missing pagination fields")
        try:
            cursor_created_at_value = datetime.fromisoformat(
                cursor_created_at.replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid cursor: bad created_at") from exc
        params.extend([cursor_created_at_value, cursor_namespace_id])
        where_clauses.append(
            f"(created_at, namespace_id) > (${len(params) - 1}::timestamptz, ${len(params)}::uuid)"
        )
    params.append(validated_limit + 1)
    query = (
        """
        SELECT namespace_id, domain, controller_did, verification_status,
               default_delivery_origin, last_verified_at, created_at
        FROM {{tables.dns_namespaces}}
        WHERE """
        + " AND ".join(where_clauses)
        + f"""
        ORDER BY created_at, namespace_id
        LIMIT ${len(params)}
        """
    )
    rows = await db.fetch_all(query, *params)
    has_more = len(rows) > validated_limit
    page_rows = rows[:validated_limit]
    next_cursor = None
    if has_more and page_rows:
        last_row = page_rows[-1]
        next_cursor = encode_cursor(
            {
                "created_at": last_row["created_at"].isoformat(),
                "namespace_id": str(last_row["namespace_id"]),
            }
        )
    return NamespaceListResponse(
        namespaces=[_namespace_response(r) for r in page_rows],
        has_more=has_more,
        next_cursor=next_cursor,
    )


@router.delete("/{domain}", dependencies=[Depends(rate_limit_dep("namespace_delete"))])
async def delete_namespace(
    request: Request,
    domain: str,
    body: NamespaceDeleteRequest | None = None,
    db_infra=Depends(get_db),
) -> dict:
    """Delete a namespace after verifying it has no active certificates."""
    db = db_infra.get_manager("aweb")
    domain = _validate_domain(domain)
    assertion = None if body is None else body.delegation_assertion
    delete_extra = None if assertion is None else {"delegation_entry_hash": assertion.entry_hash}
    caller_did = _verify_controller_signature(
        request, domain=domain, operation="delete_namespace", extra_payload=delete_extra
    )

    async with db.transaction() as tx:
        row = await tx.fetch_one(
            """
            SELECT namespace_id, controller_did, active_delegation_hash
            FROM {{tables.dns_namespaces}}
            WHERE domain = $1 AND deleted_at IS NULL
            FOR UPDATE
            """,
            domain,
        )
        if row is None:
            raise HTTPException(status_code=404, detail="Namespace not found")
        if caller_did != row["controller_did"]:
            raise HTTPException(status_code=403, detail="Only the namespace controller can delete")

        child_head = await tx.fetch_one(
            """
            SELECT child_domain
            FROM {{tables.namespace_delegation_heads}}
            WHERE parent_domain = $1 AND head_operation <> 'revoke'
            LIMIT 1
            """,
            domain,
        )
        if child_head is not None:
            _raise_delegation_error(
                DelegationStateError(
                    "namespace_has_nonrevoked_child_delegations",
                    "namespace has non-revoked child delegation history",
                )
            )

        head = await delegation_head(tx, domain, for_update=True)
        if head is not None:
            await _check_parent_rollover_fence(tx, head["parent_domain"])
            if (
                assertion is None
                or head["head_operation"] == "revoke"
                or head["head_controller_did"] != row["controller_did"]
            ):
                _raise_delegation_error(
                    DelegationStateError(
                        "namespace_delegation_sync_required",
                        "delegation history must be synchronized before namespace deletion",
                    )
                )
            try:
                await append_transition(
                    tx,
                    assertion.model_dump(mode="json"),
                    authority_did=row["controller_did"],
                    expected_child_domain=domain,
                    expected_child_controller_did=row["controller_did"],
                    expected_operation="revoke",
                )
            except DelegationStateError as exc:
                _raise_delegation_error(exc)
        elif assertion is not None:
            _raise_delegation_error(
                DelegationStateError(
                    "namespace_delegation_transition_invalid",
                    "cannot revoke a namespace without delegation history",
                )
            )

        active_cert = await tx.fetch_one(
            """
            SELECT tc.certificate_id
            FROM {{tables.teams}} t
            JOIN {{tables.team_certificates}} tc ON tc.team_uuid = t.team_uuid
            WHERE t.domain = $1
              AND t.deleted_at IS NULL
              AND tc.revoked_at IS NULL
            LIMIT 1
            """,
            domain,
        )
        if active_cert is not None:
            raise HTTPException(status_code=409, detail="Namespace has active certificates")

        now = datetime.now(timezone.utc)
        await tx.execute(
            """
            DELETE FROM {{tables.team_certificates}} tc
            USING {{tables.teams}} t
            WHERE tc.team_uuid = t.team_uuid
              AND t.domain = $1
            """,
            domain,
        )
        await tx.execute(
            """
            UPDATE {{tables.teams}}
            SET deleted_at = $2
            WHERE domain = $1 AND deleted_at IS NULL
            """,
            domain,
            now,
        )
        await tx.execute(
            """
            UPDATE {{tables.public_addresses}}
            SET deleted_at = $2
            WHERE namespace_id = $1 AND deleted_at IS NULL
            """,
            row["namespace_id"],
            now,
        )
        await tx.execute(
            """
            UPDATE {{tables.dns_namespaces}}
            SET deleted_at = $2
            WHERE namespace_id = $1 AND deleted_at IS NULL
            """,
            row["namespace_id"],
            now,
        )

    return {"deleted": True, "namespace_id": str(row["namespace_id"]), "domain": domain}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _namespace_response(
    row, *, delegation_chain: list[dict] | None = None
) -> NamespaceResponse:
    return NamespaceResponse(
        namespace_id=str(row["namespace_id"]),
        domain=row["domain"],
        controller_did=row["controller_did"],
        verification_status=row["verification_status"],
        default_delivery_origin=row.get("default_delivery_origin"),
        last_verified_at=row["last_verified_at"].isoformat() if row["last_verified_at"] else None,
        created_at=row["created_at"].isoformat(),
        delegation_chain=[
            DelegationAssertion.model_validate(assertion)
            for assertion in (delegation_chain or [])
        ],
    )


def _namespace_reverify_response(result) -> NamespaceReverifyResponse:
    response = _namespace_response(result.row)
    return NamespaceReverifyResponse(
        namespace_id=response.namespace_id,
        domain=response.domain,
        controller_did=response.controller_did,
        verification_status=response.verification_status,
        default_delivery_origin=response.default_delivery_origin,
        last_verified_at=response.last_verified_at,
        created_at=response.created_at,
        old_controller_did=result.old_controller_did,
        new_controller_did=result.new_controller_did,
    )
