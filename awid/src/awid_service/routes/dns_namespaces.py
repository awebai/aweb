"""DNS-backed namespace registration and management."""

from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator

from awid.dns_verify import DomainVerifier
from awid_service.deps import get_db, get_domain_verifier
from awid.dns_verify import DnsVerificationError
from awid.pagination import encode_cursor, validate_pagination_params
from awid.ratelimit import rate_limit_dep
from awid.dns_auth import validate_did_key as _validate_did_key
from awid.dns_auth import verify_signed_json_request
from awid_service.routes.dns_namespace_reverify import (
    is_reserved_local_domain,
    reverify_namespace_row,
)

router = APIRouter(prefix="/v1/namespaces", tags=["namespaces"])
logger = logging.getLogger(__name__)

_MAX_DOMAIN_LENGTH = 256
_PARENT_AUTH_HEADER = "X-AWEB-Parent-Authorization"
_PARENT_TIMESTAMP_HEADER = "X-AWEB-Parent-Timestamp"
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
) -> None:
    """Require proof that the caller controls the new controller key."""
    did_key = _verify_controller_signature(
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


def _verify_parent_namespace_authorization(
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

    @field_validator("controller_did")
    @classmethod
    def validate_controller_did(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _validate_did_key(value)


class NamespaceRotateControllerRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    new_controller_did: str = Field(..., min_length=1, max_length=256)

    @field_validator("new_controller_did")
    @classmethod
    def validate_did_key(cls, value: str) -> str:
        return _validate_did_key(value)


class NamespaceResponse(BaseModel):
    namespace_id: str
    domain: str
    controller_did: str | None = None
    verification_status: str
    last_verified_at: Optional[str] = None
    created_at: str


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
    caller_did = _verify_controller_signature(request, domain=domain, operation="register")
    requested_controller_did = body.controller_did or caller_did
    if body.controller_did is not None and body.controller_did != caller_did:
        raise HTTPException(
            status_code=403,
            detail="controller_did must match the signing key",
        )

    skip_dns = os.environ.get("AWID_SKIP_DNS_VERIFY", "").strip() == "1"
    parent_auth_present = request.headers.get(_PARENT_AUTH_HEADER) is not None
    domain_is_local = is_reserved_local_domain(domain)
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

    # Transactional: check-then-insert to prevent duplicate races
    async with db.transaction() as tx:
        existing = await tx.fetch_one(
            """
            SELECT namespace_id, domain, controller_did, verification_status,
                   last_verified_at, created_at
            FROM {{tables.dns_namespaces}}
            WHERE domain = $1 AND deleted_at IS NULL
            """,
            domain,
        )

        if existing is not None:
            return _namespace_response(existing)

        controller_did = requested_controller_did
        if parent_auth_present:
            parent_namespace = await _find_parent_namespace(tx, domain=domain, lock_for_share=True)
            if parent_namespace is None:
                raise HTTPException(status_code=401, detail="Invalid parent authorization")
            parent_signer = _verify_parent_namespace_authorization(
                request,
                child_domain=domain,
                controller_did=requested_controller_did,
            )
            if parent_signer != parent_namespace["controller_did"]:
                raise HTTPException(status_code=401, detail="Invalid parent authorization")

        ns_id = uuid.uuid4()
        now = datetime.now(timezone.utc)
        await tx.execute(
            """
            INSERT INTO {{tables.dns_namespaces}}
                (namespace_id, domain, controller_did, verification_status, last_verified_at, created_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            """,
            ns_id,
            domain,
            controller_did,
            "verified",
            now,
            now,
        )

    return NamespaceResponse(
        namespace_id=str(ns_id),
        domain=domain,
        controller_did=controller_did,
        verification_status="verified",
        last_verified_at=now.isoformat(),
        created_at=now.isoformat(),
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
               last_verified_at, created_at
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
    dependencies=[Depends(rate_limit_dep("namespace_get"))],
)
async def get_namespace(domain: str, db_infra=Depends(get_db)) -> NamespaceResponse:
    """Query a namespace's status by domain."""
    db = db_infra.get_manager("aweb")
    domain = _validate_domain(domain)
    row = await db.fetch_one(
        """
        SELECT namespace_id, domain, controller_did, verification_status,
               last_verified_at, created_at
        FROM {{tables.dns_namespaces}}
        WHERE domain = $1 AND deleted_at IS NULL
        """,
        domain,
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
    _verify_controller_rotation_signature(
        request,
        domain=domain,
        new_controller_did=new_controller_did,
    )
    skip_dns = os.environ.get("AWID_SKIP_DNS_VERIFY", "").strip() == "1"
    parent_auth_present = request.headers.get(_PARENT_AUTH_HEADER) is not None
    domain_is_local = is_reserved_local_domain(domain)
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

        if parent_auth_present:
            parent_namespace = await _find_parent_namespace(tx, domain=domain, lock_for_share=True)
            if parent_namespace is None:
                raise HTTPException(status_code=401, detail="Invalid parent authorization")
            parent_signer = _verify_parent_namespace_authorization(
                request,
                child_domain=domain,
                new_controller_did=new_controller_did,
            )
            if parent_signer != parent_namespace["controller_did"]:
                raise HTTPException(status_code=401, detail="Invalid parent authorization")

        row = await tx.fetch_one(
            """
            UPDATE {{tables.dns_namespaces}}
            SET controller_did = $2,
                verification_status = 'verified',
                last_verified_at = $3
            WHERE domain = $1 AND deleted_at IS NULL
            RETURNING namespace_id, domain, controller_did, verification_status,
                      last_verified_at, created_at
            """,
            domain,
            new_controller_did,
            now,
        )
        if row is None:
            raise HTTPException(status_code=404, detail="Namespace not found")
    if existing["controller_did"] != new_controller_did:
        logger.warning(
            "Namespace controller rotated: domain=%s old_controller_did=%s new_controller_did=%s",
            domain,
            existing["controller_did"],
            new_controller_did,
        )
    return _namespace_response(row)


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
               last_verified_at, created_at
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
    caller_did = _verify_controller_signature(request, domain=domain, operation="delete_namespace")

    # Transactional: lock the row, verify ownership, then delete
    async with db.transaction() as tx:
        row = await tx.fetch_one(
            """
            SELECT namespace_id, controller_did
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
        last_verified_at=row["last_verified_at"].isoformat() if row["last_verified_at"] else None,
        created_at=row["created_at"].isoformat(),
    )


def _namespace_reverify_response(result) -> NamespaceReverifyResponse:
    response = _namespace_response(result.row)
    return NamespaceReverifyResponse(
        namespace_id=response.namespace_id,
        domain=response.domain,
        controller_did=response.controller_did,
        verification_status=response.verification_status,
        last_verified_at=response.last_verified_at,
        created_at=response.created_at,
        old_controller_did=result.old_controller_did,
        new_controller_did=result.new_controller_did,
    )
