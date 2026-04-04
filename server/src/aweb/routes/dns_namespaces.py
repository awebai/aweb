"""DNS-backed namespace registration and management."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator

from aweb.deps import DomainVerifier, get_db, get_domain_verifier
from aweb.dns_verify import DnsVerificationError
from aweb.ratelimit import rate_limit_dep
from aweb.routes.dns_auth import validate_did_key as _validate_did_key
from aweb.routes.dns_auth import verify_signed_json_request

router = APIRouter(prefix="/v1/namespaces", tags=["namespaces"])

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


class NamespaceListResponse(BaseModel):
    namespaces: list[NamespaceResponse]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post(
    "",
    response_model=NamespaceResponse,
    dependencies=[Depends(rate_limit_dep("did_register"))],
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

    parent_auth_present = request.headers.get(_PARENT_AUTH_HEADER) is not None
    if not parent_auth_present:
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


@router.get("/{domain}", response_model=NamespaceResponse)
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


@router.put("/{domain}", response_model=NamespaceResponse)
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
    parent_auth_present = request.headers.get(_PARENT_AUTH_HEADER) is not None
    if not parent_auth_present:
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
    return _namespace_response(row)


@router.get("", response_model=NamespaceListResponse)
async def list_namespaces(
    controller_did: Optional[str] = Query(default=None),
    db_infra=Depends(get_db),
) -> NamespaceListResponse:
    """List registered namespaces, optionally filtered by controller DID."""
    db = db_infra.get_manager("aweb")
    if controller_did:
        rows = await db.fetch_all(
            """
            SELECT namespace_id, domain, controller_did, verification_status,
                   last_verified_at, created_at
            FROM {{tables.dns_namespaces}}
            WHERE controller_did = $1 AND deleted_at IS NULL
            ORDER BY created_at
            """,
            controller_did,
        )
    else:
        rows = await db.fetch_all(
            """
            SELECT namespace_id, domain, controller_did, verification_status,
                   last_verified_at, created_at
            FROM {{tables.dns_namespaces}}
            WHERE deleted_at IS NULL
            ORDER BY created_at
            """,
        )
    return NamespaceListResponse(
        namespaces=[_namespace_response(r) for r in rows],
    )


@router.delete("/{domain}")
async def delete_namespace(
    request: Request,
    domain: str,
    db_infra=Depends(get_db),
) -> dict:
    """Soft-delete a namespace. Must be signed by the controller key."""
    db = db_infra.get_manager("aweb")
    domain = _validate_domain(domain)

    # Verify the caller's signature first (fail fast on bad auth)
    caller_did = _verify_controller_signature(request, domain=domain, operation="delete")

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

        await tx.execute(
            "UPDATE {{tables.dns_namespaces}} SET deleted_at = NOW() WHERE namespace_id = $1",
            row["namespace_id"],
        )

    return {"status": "deleted", "domain": domain}


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
