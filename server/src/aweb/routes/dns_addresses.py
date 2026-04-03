"""Public address management under DNS-backed namespaces."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator

from aweb.address_reachability import normalize_address_reachability
from aweb.deps import DomainVerifier, get_db, get_domain_verifier
from aweb.dns_verify import DnsVerificationError
from aweb.awid.signing import canonical_json_bytes, verify_did_key_signature

router = APIRouter(prefix="/v1/namespaces/{domain}/addresses", tags=["addresses"])

_STALE_THRESHOLD = timedelta(hours=24)


# ---------------------------------------------------------------------------
# Auth helpers (shared pattern with dns_namespaces)
# ---------------------------------------------------------------------------


def _parse_didkey_auth(authorization: str | None) -> tuple[str, str]:
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    parts = authorization.split(" ")
    if len(parts) != 3 or parts[0] != "DIDKey":
        raise HTTPException(
            status_code=401,
            detail="Authorization must be: DIDKey <did:key> <signature>",
        )
    return parts[1], parts[2]


def _require_timestamp(request: Request) -> str:
    value = request.headers.get("X-AWEB-Timestamp")
    if not value:
        raise HTTPException(status_code=401, detail="Missing X-AWEB-Timestamp header")
    return value


def _enforce_timestamp_skew(ts: str) -> None:
    try:
        ts = ts.strip()
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            raise HTTPException(status_code=401, detail="Timestamp must include timezone")
        dt = dt.astimezone(timezone.utc)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="Malformed timestamp")
    delta = abs((datetime.now(timezone.utc) - dt).total_seconds())
    if delta > 300:
        raise HTTPException(status_code=401, detail="Timestamp outside allowed skew window")


def _verify_address_signature(
    request: Request,
    *,
    domain: str,
    name: str,
    operation: str,
) -> str:
    """Parse auth headers, verify signature, return the signing did:key."""
    did_key, sig = _parse_didkey_auth(request.headers.get("Authorization"))
    timestamp = _require_timestamp(request)
    _enforce_timestamp_skew(timestamp)

    payload = canonical_json_bytes({
        "domain": domain,
        "name": name,
        "operation": operation,
        "timestamp": timestamp,
    })

    try:
        verify_did_key_signature(did_key=did_key, payload=payload, signature_b64=sig)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid signature")

    return did_key


# ---------------------------------------------------------------------------
# Namespace lookup + stale verification
# ---------------------------------------------------------------------------


async def _require_namespace(db, domain: str):
    """Fetch the active namespace row or raise 404."""
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
    return row


async def _ensure_fresh_verification(db, ns_row, domain: str, verify_domain: DomainVerifier) -> None:
    """Re-verify DNS if the namespace verification is stale (>24h).

    Updates the namespace record on success. Raises 403 on failure or
    controller mismatch.
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
                return

    # Stale, revoked, or never verified — re-check DNS
    try:
        dns_controller = await verify_domain(domain)
    except DnsVerificationError:
        await db.execute(
            """
            UPDATE {{tables.dns_namespaces}}
            SET verification_status = 'revoked'
            WHERE namespace_id = $1 AND deleted_at IS NULL
            """,
            ns_row["namespace_id"],
        )
        raise HTTPException(
            status_code=403,
            detail="Namespace DNS verification failed — namespace revoked",
        )

    if dns_controller != ns_row["controller_did"]:
        await db.execute(
            """
            UPDATE {{tables.dns_namespaces}}
            SET verification_status = 'revoked'
            WHERE namespace_id = $1 AND deleted_at IS NULL
            """,
            ns_row["namespace_id"],
        )
        raise HTTPException(
            status_code=403,
            detail="DNS controller has changed — namespace revoked",
        )

    # Verification passed — refresh timestamp
    await db.execute(
        """
        UPDATE {{tables.dns_namespaces}}
        SET last_verified_at = NOW(), verification_status = 'verified'
        WHERE namespace_id = $1 AND deleted_at IS NULL
        """,
        ns_row["namespace_id"],
    )


def _require_controller(caller_did: str, ns_row) -> None:
    """Raise 403 if the caller is not the namespace controller."""
    if caller_did != ns_row["controller_did"]:
        raise HTTPException(
            status_code=403,
            detail="Only the namespace controller can manage addresses",
        )


# ---------------------------------------------------------------------------
# Request/response models
# ---------------------------------------------------------------------------


def _validate_did_aw(v: str) -> str:
    if not v.startswith("did:aw:"):
        raise ValueError("must start with 'did:aw:'")
    return v


def _validate_did_key(v: str) -> str:
    if not v.startswith("did:key:z"):
        raise ValueError("must start with 'did:key:z'")
    return v


class AddressRegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=256)
    did_aw: str = Field(..., min_length=1)
    current_did_key: str = Field(..., min_length=1)
    reachability: str = Field(default="private", max_length=32)

    _check_did_aw = field_validator("did_aw")(_validate_did_aw)
    _check_did_key = field_validator("current_did_key")(_validate_did_key)

    @field_validator("reachability")
    @classmethod
    def _validate_reachability(cls, value: str) -> str:
        return normalize_address_reachability(value)


class AddressUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reachability: str | None = Field(default=None, max_length=32)

    @field_validator("reachability")
    @classmethod
    def _validate_reachability(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return normalize_address_reachability(value)


class AddressReassignRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    did_aw: str = Field(..., min_length=1)
    current_did_key: str = Field(..., min_length=1)

    _check_did_aw = field_validator("did_aw")(_validate_did_aw)
    _check_did_key = field_validator("current_did_key")(_validate_did_key)


class AddressResponse(BaseModel):
    address_id: str
    domain: str
    name: str
    did_aw: str
    current_did_key: str
    reachability: str
    created_at: str


class AddressListResponse(BaseModel):
    addresses: list[AddressResponse]


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
        reachability=str(row.get("reachability") or "private"),
        created_at=row["created_at"].isoformat(),
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("", response_model=AddressResponse)
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
    _require_controller(caller_did, ns_row)
    await _ensure_fresh_verification(db, ns_row, domain, verify_domain)

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

        addr_id = uuid.uuid4()
        now = datetime.now(timezone.utc)
        try:
            await tx.execute(
                """
                INSERT INTO {{tables.public_addresses}}
                    (address_id, namespace_id, name, did_aw, current_did_key, reachability, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                """,
                addr_id,
                ns_row["namespace_id"],
                body.name,
                body.did_aw,
                body.current_did_key,
                body.reachability,
                now,
            )
        except asyncpg.UniqueViolationError as e:
            detail = str(e)
            if "did_aw" in detail:
                raise HTTPException(
                    status_code=409,
                    detail="Identity already has an active address",
                )
            raise HTTPException(status_code=409, detail="Address name already registered")

    return AddressResponse(
        address_id=str(addr_id),
        domain=domain,
        name=body.name,
        did_aw=body.did_aw,
        current_did_key=body.current_did_key,
        reachability=body.reachability,
        created_at=now.isoformat(),
    )


@router.get("/{name}", response_model=AddressResponse)
async def get_address(
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
        SELECT address_id, name, did_aw, current_did_key, reachability, created_at
        FROM {{tables.public_addresses}}
        WHERE namespace_id = $1 AND name = $2 AND deleted_at IS NULL
        """,
        ns_row["namespace_id"],
        name,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Address not found")
    return _address_response(row, domain)


@router.get("", response_model=AddressListResponse)
async def list_addresses(
    domain: str,
    db_infra=Depends(get_db),
) -> AddressListResponse:
    """List all active addresses under a namespace."""
    db = db_infra.get_manager("aweb")
    domain = _validate_domain(domain)
    ns_row = await _require_namespace(db, domain)

    rows = await db.fetch_all(
        """
        SELECT address_id, name, did_aw, current_did_key, reachability, created_at
        FROM {{tables.public_addresses}}
        WHERE namespace_id = $1 AND deleted_at IS NULL
        ORDER BY name
        """,
        ns_row["namespace_id"],
    )
    return AddressListResponse(
        addresses=[_address_response(r, domain) for r in rows],
    )


@router.put("/{name}", response_model=AddressResponse)
async def update_address(
    request: Request,
    domain: str,
    name: str,
    body: AddressUpdateRequest,
    db_infra=Depends(get_db),
    verify_domain: DomainVerifier = Depends(get_domain_verifier),
) -> AddressResponse:
    """Update address metadata under a DNS-backed namespace.

    When `reachability` is omitted, this is a no-op that returns the current
    address state unchanged.
    """
    db = db_infra.get_manager("aweb")
    domain = _validate_domain(domain)

    caller_did = _verify_address_signature(
        request, domain=domain, name=name, operation="update_address",
    )

    ns_row = await _require_namespace(db, domain)
    _require_controller(caller_did, ns_row)
    await _ensure_fresh_verification(db, ns_row, domain, verify_domain)

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
            SELECT address_id, name, did_aw, current_did_key, reachability, created_at
            FROM {{tables.public_addresses}}
            WHERE namespace_id = $1 AND name = $2 AND deleted_at IS NULL
            FOR UPDATE
            """,
            ns_row["namespace_id"],
            name,
        )
        if row is None:
            raise HTTPException(status_code=404, detail="Address not found")

        next_reachability = body.reachability
        if next_reachability is not None:
            row = await tx.fetch_one(
                """
                UPDATE {{tables.public_addresses}}
                SET reachability = $1
                WHERE address_id = $2
                RETURNING address_id, name, did_aw, current_did_key, reachability, created_at
                """,
                next_reachability,
                row["address_id"],
            )
            if row is None:
                raise HTTPException(status_code=404, detail="Address not found")

    return AddressResponse(
        address_id=str(row["address_id"]),
        domain=domain,
        name=row["name"],
        did_aw=row["did_aw"],
        current_did_key=row["current_did_key"],
        reachability=str(row.get("reachability") or "private"),
        created_at=row["created_at"].isoformat(),
    )


@router.delete("/{name}")
async def delete_address(
    request: Request,
    domain: str,
    name: str,
    db_infra=Depends(get_db),
) -> dict:
    """Soft-delete an address. Must be signed by the controller.

    Does not require fresh DNS verification — the controller should always be
    able to delete addresses, even if DNS has lapsed or been revoked.
    """
    db = db_infra.get_manager("aweb")
    domain = _validate_domain(domain)

    caller_did = _verify_address_signature(
        request, domain=domain, name=name, operation="delete_address",
    )

    ns_row = await _require_namespace(db, domain)
    _require_controller(caller_did, ns_row)

    async with db.transaction() as tx:
        row = await tx.fetch_one(
            """
            SELECT address_id
            FROM {{tables.public_addresses}}
            WHERE namespace_id = $1 AND name = $2 AND deleted_at IS NULL
            FOR UPDATE
            """,
            ns_row["namespace_id"],
            name,
        )
        if row is None:
            raise HTTPException(status_code=404, detail="Address not found")

        await tx.execute(
            "UPDATE {{tables.public_addresses}} SET deleted_at = NOW() WHERE address_id = $1",
            row["address_id"],
        )

    return {"status": "deleted", "domain": domain, "name": name}


@router.post("/{name}/reassign", response_model=AddressResponse)
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
    _require_controller(caller_did, ns_row)
    await _ensure_fresh_verification(db, ns_row, domain, verify_domain)

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
            SELECT address_id, name, reachability, created_at
            FROM {{tables.public_addresses}}
            WHERE namespace_id = $1 AND name = $2 AND deleted_at IS NULL
            FOR UPDATE
            """,
            ns_row["namespace_id"],
            name,
        )
        if row is None:
            raise HTTPException(status_code=404, detail="Address not found")

        try:
            await tx.execute(
                """
                UPDATE {{tables.public_addresses}}
                SET did_aw = $1, current_did_key = $2
                WHERE address_id = $3
                """,
                body.did_aw,
                body.current_did_key,
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
        reachability=str(row.get("reachability") or "private"),
        created_at=row["created_at"].isoformat(),
    )
