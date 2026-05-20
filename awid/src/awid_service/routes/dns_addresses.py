"""Public address management under DNS-backed namespaces."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from awid.did import stable_id_from_did_key, validate_stable_id
from awid.dns_verify import DomainVerifier
from awid.dns_auth import validate_did_key as _validate_dns_did_key
from awid.dns_auth import verify_signed_json_request
from awid.pagination import encode_cursor, validate_pagination_params
from awid.ratelimit import rate_limit_dep
from awid_service.deps import get_db, get_domain_verifier
from awid_service.routes.dns_namespace_reverify import reverify_namespace_row

_ADDRESS_ALREADY_BOUND_DETAIL = "address already bound to a different did_aw"
_DID_CURRENT_KEY_MISMATCH_DETAIL = "did_aw current key does not match"
_NEUTRAL_REACHABILITY = "public"
_MIGRATION_REQUIRED_DETAIL = (
    "Address blocked by legacy migration state; normalize reachability to public "
    "and visible_to_team_id to null before public resolution"
)

router = APIRouter(prefix="/v1/namespaces/{domain}/addresses", tags=["addresses"])
logger = logging.getLogger(__name__)

_STALE_THRESHOLD = timedelta(hours=24)


def _verify_address_signature(
    request: Request,
    *,
    domain: str,
    name: str,
    operation: str,
) -> str:
    return verify_signed_json_request(
        request,
        payload_dict={
            "domain": domain,
            "name": name,
            "operation": operation,
        },
    )


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


async def _fetch_active_address_for_registration(tx, *, namespace_id, name: str):
    return await tx.fetch_one(
        """
        SELECT pa.address_id, pa.name, pa.did_aw, m.current_did_key, pa.reachability,
               pa.visible_to_team_id, ns.default_delivery_origin, pa.created_at
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


class AddressDeliveryResponse(BaseModel):
    origin: str | None = None
    source: str = "identity"


class AddressResponse(BaseModel):
    address_id: str
    domain: str
    name: str
    did_aw: str
    current_did_key: str
    reachability: str
    visible_to_team_id: str | None = None
    delivery: AddressDeliveryResponse
    created_at: str


class AddressListResponse(BaseModel):
    addresses: list[AddressResponse]
    has_more: bool = False
    next_cursor: str | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _validate_domain(domain: str) -> str:
    domain = domain.lower().rstrip(".")
    if not domain or len(domain) > 256:
        raise HTTPException(status_code=400, detail="Invalid domain")
    return domain


def _is_neutral_address_row(row) -> bool:
    return (
        str(row.get("reachability") or "nobody") == _NEUTRAL_REACHABILITY
        and row.get("visible_to_team_id") is None
    )


def _raise_if_legacy_migration_blocked(row) -> None:
    if not _is_neutral_address_row(row):
        raise HTTPException(status_code=409, detail=_MIGRATION_REQUIRED_DETAIL)


def _address_response(row, domain: str) -> AddressResponse:
    return AddressResponse(
        address_id=str(row["address_id"]),
        domain=domain,
        name=row["name"],
        did_aw=row["did_aw"],
        current_did_key=row["current_did_key"],
        reachability=str(row.get("reachability") or "nobody"),
        visible_to_team_id=row.get("visible_to_team_id"),
        delivery=AddressDeliveryResponse(origin=row.get("default_delivery_origin"), source="namespace"),
        created_at=row["created_at"].isoformat(),
    )


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
        reachability = _NEUTRAL_REACHABILITY
        visible_to_team_id = None
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
                    (address_id, namespace_id, name, did_aw, reachability, visible_to_team_id, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                """,
                addr_id,
                ns_row["namespace_id"],
                body.name,
                body.did_aw,
                reachability,
                visible_to_team_id,
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
        reachability=reachability,
        visible_to_team_id=visible_to_team_id,
        delivery=AddressDeliveryResponse(origin=ns_row.get("default_delivery_origin"), source="namespace"),
        created_at=now.isoformat(),
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
        SELECT pa.address_id, pa.name, pa.did_aw, m.current_did_key, pa.reachability,
               pa.visible_to_team_id, ns.default_delivery_origin, pa.created_at
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
    _raise_if_legacy_migration_blocked(row)
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
        "pa.reachability = 'public'",
        "pa.visible_to_team_id IS NULL",
    ]
    if decoded_cursor is not None:
        cursor_name = decoded_cursor.get("name")
        if not isinstance(cursor_name, str):
            raise HTTPException(status_code=400, detail="Invalid cursor: missing name")
        params.append(cursor_name)
        where_clauses.append(f"pa.name > ${len(params)}")
    params.append(validated_limit + 1)
    query = (
        "SELECT pa.address_id, pa.name, pa.did_aw, m.current_did_key, pa.reachability,"
        " pa.visible_to_team_id, ns.default_delivery_origin, pa.created_at"
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
            SELECT pa.address_id, pa.name, pa.did_aw, m.current_did_key, pa.reachability,
                   pa.visible_to_team_id, ns.default_delivery_origin, pa.created_at
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

        next_reachability = _NEUTRAL_REACHABILITY
        next_visible_to_team_id = None
        if next_reachability != row["reachability"] or row.get("visible_to_team_id") is not None:
            row = await tx.fetch_one(
                """
                UPDATE {{tables.public_addresses}} pa
                SET reachability = $1,
                    visible_to_team_id = $2
                FROM {{tables.did_aw_mappings}} m,
                     {{tables.dns_namespaces}} ns
                WHERE pa.address_id = $3
                  AND m.did_aw = pa.did_aw
                  AND ns.namespace_id = pa.namespace_id
                RETURNING pa.address_id, pa.name, pa.did_aw, m.current_did_key, pa.reachability,
                          pa.visible_to_team_id, ns.default_delivery_origin, pa.created_at
                """,
                next_reachability,
                next_visible_to_team_id,
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
        reachability=str(row.get("reachability") or "nobody"),
        visible_to_team_id=row.get("visible_to_team_id"),
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
            SELECT address_id, name, reachability, visible_to_team_id, created_at
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
                SET did_aw = $1,
                    reachability = 'public',
                    visible_to_team_id = NULL
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
        reachability=_NEUTRAL_REACHABILITY,
        visible_to_team_id=None,
        delivery=AddressDeliveryResponse(origin=ns_row.get("default_delivery_origin"), source="namespace"),
        created_at=row["created_at"].isoformat(),
    )
