"""DNS-backed namespace registration and management."""

from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_serializer

from awid.dns_verify import DomainVerifier
from awid_service.deps import get_db, get_domain_verifier
from awid.dns_verify import DnsVerificationError
from awid.pagination import encode_cursor, validate_pagination_params
from awid_service.delivery_origin import validate_delivery_origin
from awid.ratelimit import rate_limit_dep
from awid.dns_auth import enforce_timestamp_skew, require_timestamp, validate_did_key as _validate_did_key
from awid.id_certificates import IDCertificateError, strict_did_key
from awid_service.id_tree_gate import strict_json_object
from awid.controller_request import ControllerAuthRoute, verify_controller_json_request
from awid_service.id_tree_clock import app_clock
from awid_service.namespace_epochs import (
    REPLACED,
    ROTATED,
    proves_root,
    has_epoch_history,
    is_exact,
    open_epoch,
    open_epoch_of,
    retire_namespace_controller,
    record_delegation,
    delegation_of,
    advance_delegated_children,
)
from awid_service.routes.dns_namespace_reverify import (
    is_reserved_local_domain,
    reverify_namespace_row,
)

router = APIRouter(prefix="/v1/namespaces", tags=["namespaces"], route_class=ControllerAuthRoute)
logger = logging.getLogger(__name__)

_MAX_DOMAIN_LENGTH = 256
_PARENT_AUTH_HEADER = "X-AWEB-Parent-Authorization"
_PARENT_TIMESTAMP_HEADER = "X-AWEB-Parent-Timestamp"
_NEW_KEY_AUTH_HEADER = "X-AWEB-New-Key-Authorization"
_ROTATION_FIELDS = frozenset({"domain", "operation", "from_seq", "previous_did_key", "new_did_key"})


async def _verify_controller_signature(
    request: Request,
    *,
    domain: str,
    operation: str,
    extra_payload: dict[str, str] | None = None,
    authorization_header: str = "Authorization",
    timestamp_header: str = "X-AWEB-Timestamp",
    signed_payload_header: str = "X-AWEB-Signed-Payload",
) -> str:
    payload_dict = {
        "domain": domain,
        "operation": operation,
    }
    if extra_payload:
        payload_dict.update(extra_payload)
    return await verify_controller_json_request(
        request,
        payload_dict=payload_dict,
        authorization_header=authorization_header,
        timestamp_header=timestamp_header,
        signed_payload_header=signed_payload_header,
    )


def _validate_domain(domain: str) -> str:
    """Validate and canonicalize a domain string."""
    domain = domain.lower().rstrip(".")
    if not domain or len(domain) > _MAX_DOMAIN_LENGTH:
        raise HTTPException(status_code=400, detail="Invalid domain")
    return domain


async def _verify_controller_rotation_signature(
    request: Request,
    *,
    domain: str,
    new_controller_did: str,
) -> None:
    """Require proof that the caller controls the new controller key."""
    did_key = await _verify_controller_signature(
        request,
        domain=domain,
        operation="rotate_controller",
        extra_payload={"new_controller_did": new_controller_did},
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


async def _verify_parent_namespace_authorization(
    request: Request,
    *,
    child_domain: str,
    controller_did: str | None = None,
    new_controller_did: str | None = None,
) -> str:
    extra_payload = {"child_domain": child_domain}
    operation = "authorize_subdomain_registration"
    if new_controller_did is not None:
        operation = "authorize_subdomain_rotation"
        extra_payload["new_controller_did"] = new_controller_did
    elif controller_did is not None:
        extra_payload["controller_did"] = controller_did

    return await _verify_controller_signature(
        request,
        domain=child_domain,
        operation=operation,
        extra_payload=extra_payload,
        authorization_header=_PARENT_AUTH_HEADER,
        timestamp_header=_PARENT_TIMESTAMP_HEADER,
        signed_payload_header="X-AWEB-Parent-Signed-Payload",
    )


async def _open_first_epoch_for_existing_namespace(tx, *, domain: str, caller_did: str, clock) -> None:
    """Open epoch 1 for a namespace registered before epoch history existed.

    Only its stored controller, with exact DNS or verified parent proof, may do
    so, and only while the domain has no epoch at all; the conditions are
    rechecked under the namespace row lock so concurrent requests open one.
    """
    locked = await tx.fetch_one(
        """
        SELECT controller_did
        FROM {{tables.dns_namespaces}}
        WHERE domain = $1 AND deleted_at IS NULL
        FOR UPDATE
        """,
        domain,
    )
    if locked is None or locked["controller_did"] != caller_did:
        return
    if await has_epoch_history(tx, domain):
        return
    await open_epoch(tx, domain=domain, did_key=caller_did, continuity=REPLACED, clock=clock)


def _coded(code: str, status: int) -> HTTPException:
    return HTTPException(status_code=status, detail={"code": code, "message": code.replace("_", " ")})


def _rotation_body(raw: bytes, domain: str) -> dict:
    try:
        body = strict_json_object(raw)
    except IDCertificateError as exc:
        raise _coded("invalid_shape", 400) from exc
    if (
        set(body) != _ROTATION_FIELDS
        or body["domain"] != domain
        or body["operation"] != "rotate_namespace_controller"
        or type(body["from_seq"]) is not int
        or body["from_seq"] < 1
        or not strict_did_key(body["previous_did_key"])
        or not strict_did_key(body["new_did_key"])
        or body["previous_did_key"] == body["new_did_key"]
    ):
        raise _coded("invalid_shape", 400)
    return body


async def _verify_rotation_proofs(request: Request, body: dict) -> None:
    """Both keys sign the same covering-v2 request; there is no legacy form."""
    if request.headers.get("X-AWEB-Signed-Payload") is None:
        raise _coded("invalid_signature", 401)
    try:
        previous = await verify_controller_json_request(request, payload_dict=body)
        new = await verify_controller_json_request(
            request, payload_dict=body, authorization_header=_NEW_KEY_AUTH_HEADER,
        )
    except HTTPException as exc:
        if exc.status_code != 401:
            raise
        raise _coded("invalid_signature", 401) from exc
    if previous != body["previous_did_key"] or new != body["new_did_key"]:
        raise _coded("invalid_signature", 401)


# ---------------------------------------------------------------------------
# Request/response models
# ---------------------------------------------------------------------------


class NamespaceRegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain: str = Field(..., min_length=1, max_length=256)
    controller_did: str | None = Field(default=None, min_length=1, max_length=256)
    default_delivery_origin: str | None = Field(default=None, min_length=1, max_length=512)

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

    @field_validator("new_controller_did")
    @classmethod
    def validate_did_key(cls, value: str) -> str:
        return _validate_did_key(value)


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
    delegation: dict[str, str] | None = None

    @model_serializer(mode="wrap")
    def serialize(self, handler):
        result = handler(self)
        if self.delegation is None:
            result.pop("delegation", None)
        return result


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


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post(
    "",
    response_model=NamespaceResponse,
    dependencies=[Depends(rate_limit_dep("namespace_register", allow_trusted_service=True))],
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
    register_extra_payload = (
        {"default_delivery_origin": body.default_delivery_origin}
        if body.default_delivery_origin is not None
        else None
    )
    caller_did = await _verify_controller_signature(
        request,
        domain=domain,
        operation="register",
        extra_payload=register_extra_payload,
    )
    requested_controller_did = body.controller_did or caller_did
    if body.controller_did is not None and body.controller_did != caller_did:
        raise HTTPException(
            status_code=403,
            detail="controller_did must match the signing key",
        )

    skip_dns = os.environ.get("AWID_SKIP_DNS_VERIFY", "").strip() == "1"
    parent_auth_present = request.headers.get(_PARENT_AUTH_HEADER) is not None
    domain_is_local = is_reserved_local_domain(domain)
    dns_authority = None
    if not skip_dns and not parent_auth_present and not domain_is_local:
        try:
            dns_authority = await verify_domain(domain)
        except DnsVerificationError as e:
            raise HTTPException(status_code=422, detail=str(e))

        if dns_authority.controller_did != caller_did:
            raise HTTPException(
                status_code=403,
                detail="Signing key does not match DNS controller",
            )

    # Parent proof and child-row mutation share one transaction.
    async with db.transaction() as tx:
        parent_namespace = None
        if parent_auth_present:
            parent_namespace = await _find_parent_namespace(tx, domain=domain, lock_for_share=True)
            if parent_namespace is None:
                raise HTTPException(status_code=401, detail="Invalid parent authorization")
            parent_signer = await _verify_parent_namespace_authorization(
                request, child_domain=domain, controller_did=requested_controller_did,
            )
            if parent_signer != parent_namespace["controller_did"]:
                raise HTTPException(status_code=401, detail="Invalid parent authorization")
        existing = await tx.fetch_one(
            """SELECT namespace_id, domain, controller_did, verification_status,
                      default_delivery_origin, last_verified_at, created_at, parent_domain, parent_controller_key
               FROM {{tables.dns_namespaces}} WHERE domain = $1 AND deleted_at IS NULL
               FOR UPDATE""", domain,
        )
        if existing is not None:
            if parent_namespace is not None:
                if existing["controller_did"] != requested_controller_did:
                    raise HTTPException(status_code=403, detail="Signing key does not match namespace controller")
                await record_delegation(tx, domain=domain, parent=parent_namespace)
                existing = dict(existing, parent_domain=parent_namespace["domain"],
                                parent_controller_key=parent_namespace["controller_did"])
            if proves_root(dns_authority, caller_did) or parent_namespace is not None:
                await _open_first_epoch_for_existing_namespace(
                    tx, domain=domain, caller_did=caller_did, clock=app_clock(request.app),
                )
            return _namespace_response(existing)
        controller_did = requested_controller_did
        ns_id = uuid.uuid4()
        now = datetime.now(timezone.utc)
        await tx.execute(
            """
            INSERT INTO {{tables.dns_namespaces}}
                (namespace_id, domain, controller_did, verification_status, default_delivery_origin, last_verified_at, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            """,
            ns_id,
            domain,
            controller_did,
            "verified",
            body.default_delivery_origin,
            now,
            now,
        )
        if parent_namespace is not None:
            await record_delegation(tx, domain=domain, parent=parent_namespace)
        if proves_root(dns_authority, controller_did) or parent_namespace is not None:
            await open_epoch(
                tx, domain=domain, did_key=controller_did, continuity=REPLACED, clock=app_clock(request.app),
            )

    return NamespaceResponse(
        namespace_id=str(ns_id),
        domain=domain,
        controller_did=controller_did,
        verification_status="verified",
        default_delivery_origin=body.default_delivery_origin,
        last_verified_at=now.isoformat(),
        created_at=now.isoformat(),
        delegation={"parent_domain": parent_namespace["domain"], "parent_controller_key": parent_namespace["controller_did"], "controller_key": controller_did} if parent_namespace is not None else None,
    )


@router.post(
    "/{domain}/reverify",
    response_model=NamespaceReverifyResponse,
    dependencies=[Depends(rate_limit_dep("namespace_reverify"))],
)
async def reverify_namespace(
    domain: str,
    db_infra=Depends(get_db),
    verify_domain: DomainVerifier = Depends(get_domain_verifier),
) -> NamespaceReverifyResponse:
    """Reverify namespace control from live DNS and refresh stored authority."""
    db = db_infra.get_manager("aweb")
    domain = _validate_domain(domain)
    ns_row = await db.fetch_one(
        """
        SELECT namespace_id, domain, controller_did, verification_status,
               default_delivery_origin, last_verified_at, created_at, parent_domain, parent_controller_key
        FROM {{tables.dns_namespaces}}
        WHERE domain = $1 AND deleted_at IS NULL
        """,
        domain,
    )
    if ns_row is None:
        raise HTTPException(status_code=404, detail="Namespace not found")

    result = await reverify_namespace_row(
        db,
        ns_row,
        domain=domain,
        verify_domain=verify_domain,
        allow_local_bypass=False,
        dns_failure_status=422,
    )
    return _namespace_reverify_response(result)


@router.get(
    "/{domain}",
    response_model=NamespaceResponse,
    dependencies=[Depends(rate_limit_dep("namespace_get", allow_trusted_service=True))],
)
async def get_namespace(domain: str, db_infra=Depends(get_db)) -> NamespaceResponse:
    """Query a namespace's status by domain."""
    db = db_infra.get_manager("aweb")
    domain = _validate_domain(domain)
    row = await db.fetch_one(
        """
        SELECT namespace_id, domain, controller_did, verification_status,
               default_delivery_origin, last_verified_at, created_at, parent_domain, parent_controller_key
        FROM {{tables.dns_namespaces}}
        WHERE domain = $1 AND deleted_at IS NULL
        """,
        domain,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Namespace not found")
    return _namespace_response(row)


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
    caller_did = await _verify_controller_signature(
        request,
        domain=domain,
        operation="update_namespace",
        extra_payload={"default_delivery_origin": signed_origin},
    )

    async with db.transaction() as tx:
        existing = await tx.fetch_one(
            """
            SELECT namespace_id, controller_did, parent_domain, parent_controller_key
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
                      default_delivery_origin, last_verified_at, created_at, parent_domain, parent_controller_key
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
    await _verify_controller_rotation_signature(
        request,
        domain=domain,
        new_controller_did=new_controller_did,
    )
    skip_dns = os.environ.get("AWID_SKIP_DNS_VERIFY", "").strip() == "1"
    parent_auth_present = request.headers.get(_PARENT_AUTH_HEADER) is not None
    domain_is_local = is_reserved_local_domain(domain)
    dns_authority = None
    if not skip_dns and not parent_auth_present and not domain_is_local:
        try:
            dns_authority = await verify_domain(domain)
        except DnsVerificationError as e:
            raise HTTPException(status_code=422, detail=str(e))

        if dns_authority.controller_did != new_controller_did:
            raise HTTPException(
                status_code=403,
                detail="DNS controller does not match new_controller_did",
            )

    now = datetime.now(timezone.utc)
    async with db.transaction() as tx:
        parent_namespace = None
        if parent_auth_present:
            parent_namespace = await _find_parent_namespace(tx, domain=domain, lock_for_share=True)
            if parent_namespace is None:
                raise HTTPException(status_code=401, detail="Invalid parent authorization")
            parent_signer = await _verify_parent_namespace_authorization(
                request,
                child_domain=domain,
                new_controller_did=new_controller_did,
            )
            if parent_signer != parent_namespace["controller_did"]:
                raise HTTPException(status_code=401, detail="Invalid parent authorization")


        existing = await tx.fetch_one(
            """
            SELECT namespace_id, controller_did, parent_domain, parent_controller_key
            FROM {{tables.dns_namespaces}}
            WHERE domain = $1 AND deleted_at IS NULL
            FOR UPDATE
            """,
            domain,
        )
        if existing is None:
            raise HTTPException(status_code=404, detail="Namespace not found")

        if parent_namespace is not None:
            await record_delegation(tx, domain=domain, parent=parent_namespace)
        row = await tx.fetch_one(
            """
            UPDATE {{tables.dns_namespaces}}
            SET controller_did = $2,
                verification_status = 'verified',
                last_verified_at = $3
            WHERE domain = $1 AND deleted_at IS NULL
            RETURNING namespace_id, domain, controller_did, verification_status,
                      default_delivery_origin, last_verified_at, created_at, parent_domain, parent_controller_key
            """,
            domain,
            new_controller_did,
            now,
        )
        if row is None:
            raise HTTPException(status_code=404, detail="Namespace not found")
        if proves_root(dns_authority, new_controller_did) or parent_namespace is not None:
            # Recovery compares against the open epoch, not the stored row,
            # which reverify may already have moved to this key.
            epoch = await open_epoch_of(tx, domain, for_update=True)
            if epoch is None or epoch["did_key"] != new_controller_did:
                await open_epoch(
                    tx, domain=domain, did_key=new_controller_did, continuity=REPLACED,
                    clock=app_clock(request.app),
                )
        if proves_root(dns_authority, new_controller_did) or parent_namespace is not None:
            await advance_delegated_children(tx, domain=domain, controller_key=new_controller_did)
    if existing["controller_did"] != new_controller_did:
        logger.warning(
            "Namespace controller rotated: domain=%s old_controller_did=%s new_controller_did=%s",
            domain,
            existing["controller_did"],
            new_controller_did,
        )
    return _namespace_response(row)


@router.post(
    "/{domain}/rotate",
    response_model=NamespaceResponse,
    dependencies=[Depends(rate_limit_dep("namespace_rotate"))],
)
async def rotate_namespace_with_previous_key(
    request: Request,
    domain: str,
    db_infra=Depends(get_db),
    verify_domain: DomainVerifier = Depends(get_domain_verifier),
) -> NamespaceResponse:
    """Rotate the controller with the previous key's consent, keeping the tree.

    The previous and new keys sign the request. Exact DNS proves the new key,
    or an inherited TXT and the parent record establish the old child key. Under the namespace lock the open epoch must still be the one
    the request names, so a replayed or stale request refuses head_conflict;
    the open epoch is retired and its `rotated` successor opened at one
    witness time, which keeps registrations under the previous key valid.
    """
    db = db_infra.get_manager("aweb")
    domain = _validate_domain(domain)
    body = _rotation_body(await request.body(), domain)
    await _verify_rotation_proofs(request, body)
    try:
        authority = await verify_domain(domain)
    except DnsVerificationError:
        authority = None
    if authority is None or (is_exact(authority) and authority.controller_did != body["new_did_key"]):
        raise _coded("evidence_unavailable", 503)

    async with db.transaction() as tx:
        existing = await tx.fetch_one(
            """
            SELECT namespace_id, controller_did, parent_domain, parent_controller_key
            FROM {{tables.dns_namespaces}}
            WHERE domain = $1 AND deleted_at IS NULL
            FOR UPDATE
            """,
            domain,
        )
        if existing is None:
            raise HTTPException(status_code=404, detail="Namespace not found")
        if authority.inherited and not proves_root(authority, body["previous_did_key"], domain=domain, namespace=existing):
            raise _coded("evidence_unavailable", 503)
        try:
            enforce_timestamp_skew(require_timestamp(request))
        except HTTPException as exc:
            raise _coded("invalid_signature", 401) from exc
        epoch = await open_epoch_of(tx, domain, for_update=True)
        if epoch is None or (epoch["seq"], epoch["did_key"]) != (body["from_seq"], body["previous_did_key"]):
            raise _coded("head_conflict", 409)
        row = await tx.fetch_one(
            """
            UPDATE {{tables.dns_namespaces}}
            SET controller_did = $2,
                verification_status = 'verified',
                last_verified_at = $3
            WHERE domain = $1 AND deleted_at IS NULL
            RETURNING namespace_id, domain, controller_did, verification_status,
                      default_delivery_origin, last_verified_at, created_at, parent_domain, parent_controller_key
            """,
            domain,
            body["new_did_key"],
            datetime.now(timezone.utc),
        )
        await open_epoch(
            tx, domain=domain, did_key=body["new_did_key"], continuity=ROTATED, clock=app_clock(request.app),
        )
        await advance_delegated_children(tx, domain=domain, controller_key=body["new_did_key"])
    logger.warning(
        "Namespace controller rotated with previous-key consent: domain=%s from_seq=%s new_controller_did=%s",
        domain, body["from_seq"], body["new_did_key"],
    )
    return _namespace_response(row)


@router.get(
    "",
    response_model=NamespaceListResponse,
    dependencies=[Depends(rate_limit_dep("namespace_list", allow_trusted_service=True))],
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
               default_delivery_origin, last_verified_at, created_at, parent_domain, parent_controller_key
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

    # Verify the caller's signature first (fail fast on bad auth)
    caller_did = await _verify_controller_signature(request, domain=domain, operation="delete_namespace")

    # Transactional: lock the row, verify ownership, then delete
    async with db.transaction() as tx:
        row = await tx.fetch_one(
            """
            SELECT namespace_id, controller_did, parent_domain, parent_controller_key
            FROM {{tables.dns_namespaces}}
            WHERE domain = $1 AND deleted_at IS NULL
            FOR UPDATE
            """,
            domain,
        )
        if row is None:
            raise HTTPException(status_code=404, detail="Namespace not found")

        if caller_did != row["controller_did"]:
            raise HTTPException(
                status_code=403,
                detail="Only the namespace controller can delete",
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
        await retire_namespace_controller(tx, domain=domain, clock=app_clock(request.app))

    return {"deleted": True, "namespace_id": str(row["namespace_id"]), "domain": domain}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _namespace_response(row) -> NamespaceResponse:
    return NamespaceResponse(
        namespace_id=str(row["namespace_id"]),
        domain=row["domain"],
        controller_did=row["controller_did"],
        verification_status=row["verification_status"],
        default_delivery_origin=row.get("default_delivery_origin"),
        last_verified_at=row["last_verified_at"].isoformat() if row["last_verified_at"] else None,
        created_at=row["created_at"].isoformat(),
        delegation=delegation_of(row),
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
