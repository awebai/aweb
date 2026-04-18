from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Literal

logger = logging.getLogger(__name__)

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, model_validator

from awid_service.deps import get_db as get_db_infra
from awid.ratelimit import rate_limit_dep
from awid.did import (
    public_key_from_did,
    stable_id_from_public_key,
    validate_stable_id,
)
from awid.log import (
    identity_state_hash as awid_identity_state_hash,
    log_entry_payload as awid_log_entry_payload,
    register_did_entry_payload as awid_register_did_entry_payload,
    require_canonical_server_origin,
    sha256_hex as awid_sha256_hex,
    state_hash as awid_state_hash,
)
from awid.signing import verify_did_key_signature
from awid.pagination import encode_cursor, validate_pagination_params
from awid_service.routes.dns_addresses import AddressListResponse, AddressResponse
from awid.dns_auth import enforce_timestamp_skew, parse_didkey_auth, require_timestamp

router = APIRouter(prefix="/v1/did", tags=["did"])


class DidRegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    did_aw: str = Field(..., max_length=256)
    did_key: str = Field(..., max_length=256)
    operation: Literal["register_did"]
    prev_entry_hash: str | None
    seq: int = Field(..., ge=1)
    authorized_by: str = Field(..., max_length=256)
    timestamp: str = Field(..., max_length=64)
    proof: str = Field(..., max_length=2048)

    @model_validator(mode="before")
    @classmethod
    def reject_legacy_bundled_fields(cls, data):
        if isinstance(data, dict):
            legacy_fields = {"address", "server", "handle", "state_hash"} & set(data)
            if legacy_fields:
                fields = ", ".join(sorted(legacy_fields))
                raise ValueError(
                    f"legacy bundled DID payload fields are not accepted ({fields}); "
                    "see awid-sot.md#identity-operations"
                )
        return data


class DidKeyEvidence(BaseModel):
    seq: int
    operation: str
    previous_did_key: str | None
    new_did_key: str
    prev_entry_hash: str | None
    entry_hash: str
    state_hash: str
    authorized_by: str
    signature: str
    timestamp: str


class DidKeyResponse(BaseModel):
    did_aw: str
    current_did_key: str
    log_head: DidKeyEvidence | None = None


class DidHeadResponse(BaseModel):
    did_aw: str
    current_did_key: str
    seq: int
    entry_hash: str
    state_hash: str
    timestamp: str
    updated_at: datetime


class DidFullResponse(BaseModel):
    did_aw: str
    current_did_key: str
    server: str
    address: str
    handle: str | None
    created_at: datetime
    updated_at: datetime


class DidUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operation: Literal["rotate_key"] = "rotate_key"
    new_did_key: str = Field(..., max_length=256)
    seq: int = Field(..., ge=1)
    prev_entry_hash: str = Field(..., max_length=128)
    state_hash: str = Field(..., max_length=128)
    authorized_by: str = Field(..., max_length=256)
    timestamp: str = Field(..., max_length=64)
    signature: str = Field(..., max_length=2048)


class DidLogEntry(BaseModel):
    did_aw: str
    seq: int
    operation: str
    previous_did_key: str | None
    new_did_key: str
    prev_entry_hash: str | None
    entry_hash: str
    state_hash: str
    authorized_by: str
    signature: str
    timestamp: str


def _db(request: Request):
    return get_db_infra(request).get_manager("aweb")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_mapping_server(server: str | None) -> str:
    if server is None:
        return ""
    if not server.strip():
        return ""
    return require_canonical_server_origin(server)


def _normalize_mapping_address(address: str | None) -> str:
    if address is None:
        return ""
    return address.strip()


@router.post("", dependencies=[Depends(rate_limit_dep("did_register"))])
async def register_did(request: Request, req: DidRegisterRequest) -> dict:
    try:
        validate_stable_id(req.did_aw)
        enforce_timestamp_skew(req.timestamp)
        if req.seq != 1 or req.prev_entry_hash is not None:
            raise ValueError("seq must be 1 and prev_entry_hash must be null on register_did")
        if req.authorized_by != req.did_key:
            raise ValueError("authorized_by must equal did_key on register_did")
        public_key = public_key_from_did(req.did_key)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    entry_payload = awid_register_did_entry_payload(
        did_aw=req.did_aw,
        did_key=req.did_key,
        prev_entry_hash=req.prev_entry_hash,
        seq=req.seq,
        authorized_by=req.authorized_by,
        timestamp=req.timestamp,
    )
    entry_hash = awid_sha256_hex(entry_payload)
    state_hash = awid_identity_state_hash(did_aw=req.did_aw, current_did_key=req.did_key)

    db = _db(request)
    created_at = _now()
    updated_at = created_at

    async with db.transaction() as tx:
        existing = await tx.fetch_one(
            """
            SELECT did_aw, current_did_key
            FROM {{tables.did_aw_mappings}}
            WHERE did_aw = $1
            """,
            req.did_aw,
        )
        if existing is not None:
            if existing["current_did_key"] == req.did_key:
                return {
                    "registered": True,
                    "did_aw": existing["did_aw"],
                    "current_did_key": existing["current_did_key"],
                }
            raise HTTPException(status_code=409, detail="did_aw already registered")

        derived = stable_id_from_public_key(public_key)
        if derived != req.did_aw:
            raise HTTPException(status_code=400, detail="did_aw does not match did_key derivation")

        try:
            verify_did_key_signature(
                did_key=req.did_key, payload=entry_payload, signature_b64=req.proof
            )
        except Exception as exc:
            raise HTTPException(status_code=401, detail="invalid proof") from exc

        await tx.execute(
            """
            INSERT INTO {{tables.did_aw_mappings}}
                (did_aw, current_did_key, server_url, address, handle, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            """,
            req.did_aw,
            req.did_key,
            "",
            "",
            None,
            created_at,
            updated_at,
        )

        await tx.execute(
            """
            INSERT INTO {{tables.did_aw_log}}
                (did_aw, seq, operation, previous_did_key, new_did_key,
                 prev_entry_hash, entry_hash, state_hash, authorized_by, signature,
                 timestamp, created_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
            """,
            req.did_aw,
            1,
            "register_did",
            None,
            req.did_key,
            None,
            entry_hash,
            state_hash,
            req.did_key,
            req.proof,
            req.timestamp,
            created_at,
        )

    return {
        "registered": True,
        "did_aw": req.did_aw,
        "current_did_key": req.did_key,
    }


@router.get(
    "/{did_aw}/key",
    response_model=DidKeyResponse,
    dependencies=[Depends(rate_limit_dep("did_key"))],
)
async def get_key(request: Request, did_aw: str) -> DidKeyResponse:
    try:
        did_aw = validate_stable_id(did_aw)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    db = _db(request)
    row = await db.fetch_one(
        """
        SELECT did_aw, current_did_key
        FROM {{tables.did_aw_mappings}}
        WHERE did_aw = $1
        """,
        did_aw,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="not found")

    head = await db.fetch_one(
        """
        SELECT seq, operation, previous_did_key, new_did_key,
               prev_entry_hash, entry_hash, state_hash, authorized_by, signature,
               timestamp
        FROM {{tables.did_aw_log}}
        WHERE did_aw = $1
        ORDER BY seq DESC
        LIMIT 1
        """,
        did_aw,
    )
    if head is None:
        raise HTTPException(status_code=500, detail="log missing for did_aw")
    if head["new_did_key"] != row["current_did_key"]:
        raise HTTPException(status_code=500, detail="mapping/log inconsistency")

    return DidKeyResponse(
        did_aw=row["did_aw"],
        current_did_key=row["current_did_key"],
        log_head=DidKeyEvidence(
            seq=head["seq"],
            operation=head["operation"],
            previous_did_key=head["previous_did_key"],
            new_did_key=head["new_did_key"],
            prev_entry_hash=head["prev_entry_hash"],
            entry_hash=head["entry_hash"],
            state_hash=head["state_hash"],
            authorized_by=head["authorized_by"],
            signature=head["signature"],
            timestamp=head["timestamp"],
        ),
    )


@router.get(
    "/{did_aw}/addresses",
    response_model=AddressListResponse,
    dependencies=[Depends(rate_limit_dep("did_addresses"))],
)
async def list_did_addresses(
    request: Request,
    did_aw: str,
    limit: int | None = Query(default=None, ge=1),
    cursor: str | None = Query(default=None),
) -> AddressListResponse:
    try:
        did_aw = validate_stable_id(did_aw)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        validated_limit, decoded_cursor = validate_pagination_params(limit, cursor)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    db = _db(request)
    params: list[object] = [did_aw]
    where_clauses = ["pa.did_aw = $1", "pa.deleted_at IS NULL", "ns.deleted_at IS NULL"]
    if decoded_cursor is not None:
        cursor_domain = decoded_cursor.get("domain")
        cursor_name = decoded_cursor.get("name")
        if not isinstance(cursor_domain, str) or not isinstance(cursor_name, str):
            raise HTTPException(status_code=400, detail="Invalid cursor")
        params.append(cursor_domain)
        params.append(cursor_name)
        where_clauses.append(f"(ns.domain, pa.name) > (${len(params) - 1}, ${len(params)})")
    params.append(validated_limit + 1)
    query = (
        "SELECT pa.address_id, ns.domain, pa.name, pa.did_aw, pa.current_did_key,"
        " pa.reachability, pa.visible_to_team_id, pa.created_at"
        " FROM {{tables.public_addresses}} pa"
        " JOIN {{tables.dns_namespaces}} ns ON ns.namespace_id = pa.namespace_id"
        " WHERE " + " AND ".join(where_clauses)
        + f" ORDER BY ns.domain ASC, pa.name ASC LIMIT ${len(params)}"
    )
    rows = await db.fetch_all(query, *params)
    has_more = len(rows) > validated_limit
    page_rows = rows[:validated_limit]
    next_cursor = None
    if has_more and page_rows:
        next_cursor = encode_cursor({"domain": page_rows[-1]["domain"], "name": page_rows[-1]["name"]})
    return AddressListResponse(
        addresses=[
            AddressResponse(
                address_id=str(row["address_id"]),
                domain=row["domain"],
                name=row["name"],
                did_aw=row["did_aw"],
                current_did_key=row["current_did_key"],
                reachability=str(row.get("reachability") or "nobody"),
                visible_to_team_id=row.get("visible_to_team_id"),
                created_at=row["created_at"].isoformat(),
            )
            for row in page_rows
        ],
        has_more=has_more,
        next_cursor=next_cursor,
    )


@router.get(
    "/{did_aw}/head",
    response_model=DidHeadResponse,
    dependencies=[Depends(rate_limit_dep("did_head"))],
)
async def get_head(request: Request, did_aw: str) -> DidHeadResponse:
    try:
        did_aw = validate_stable_id(did_aw)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    db = _db(request)
    row = await db.fetch_one(
        """
        SELECT did_aw, current_did_key, updated_at
        FROM {{tables.did_aw_mappings}}
        WHERE did_aw = $1
        """,
        did_aw,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="not found")

    head = await db.fetch_one(
        """
        SELECT seq, entry_hash, state_hash, timestamp, new_did_key
        FROM {{tables.did_aw_log}}
        WHERE did_aw = $1
        ORDER BY seq DESC
        LIMIT 1
        """,
        did_aw,
    )
    if head is None:
        raise HTTPException(status_code=500, detail="log missing for did_aw")
    if head["new_did_key"] != row["current_did_key"]:
        raise HTTPException(status_code=500, detail="mapping/log inconsistency")

    return DidHeadResponse(
        did_aw=row["did_aw"],
        current_did_key=row["current_did_key"],
        seq=head["seq"],
        entry_hash=head["entry_hash"],
        state_hash=head["state_hash"],
        timestamp=head["timestamp"],
        updated_at=row["updated_at"],
    )


@router.get(
    "/{did_aw}/full",
    response_model=DidFullResponse,
    dependencies=[Depends(rate_limit_dep("did_full"))],
)
async def get_full(request: Request, did_aw: str, authorization: str | None = Header(default=None)):
    try:
        did_aw = validate_stable_id(did_aw)
        did_key, sig = parse_didkey_auth(authorization)
        timestamp = require_timestamp(request)
        enforce_timestamp_skew(timestamp)
        signing_payload = f"{timestamp}\n{request.method}\n{request.url.path}".encode("utf-8")
        verify_did_key_signature(did_key=did_key, payload=signing_payload, signature_b64=sig)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    db = _db(request)
    row = await db.fetch_one(
        """
        SELECT did_aw, current_did_key, server_url, address, handle, created_at, updated_at
        FROM {{tables.did_aw_mappings}}
        WHERE did_aw = $1
        """,
        did_aw,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="not found")
    if did_key != row["current_did_key"]:
        raise HTTPException(status_code=403, detail="forbidden")

    raw_server_url = (row["server_url"] or "").strip()
    if raw_server_url:
        try:
            server_url = require_canonical_server_origin(raw_server_url)
        except Exception:
            logger.error("Stored server_url failed validation for %s", did_aw, exc_info=True)
            raise HTTPException(status_code=500, detail="Internal server error")
    else:
        server_url = ""

    return DidFullResponse(
        did_aw=row["did_aw"],
        current_did_key=row["current_did_key"],
        server=server_url,
        address=row["address"],
        handle=row["handle"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


@router.get(
    "/{did_aw}/log",
    response_model=list[DidLogEntry],
    dependencies=[Depends(rate_limit_dep("did_log"))],
)
async def get_log(request: Request, did_aw: str) -> list[DidLogEntry]:
    try:
        did_aw = validate_stable_id(did_aw)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    db = _db(request)
    rows = await db.fetch_all(
        """
        SELECT did_aw, seq, operation, previous_did_key, new_did_key,
               prev_entry_hash, entry_hash, state_hash, authorized_by, signature,
               timestamp
        FROM {{tables.did_aw_log}}
        WHERE did_aw = $1
        ORDER BY seq ASC
        """,
        did_aw,
    )
    return [
        DidLogEntry(
            did_aw=row["did_aw"],
            seq=row["seq"],
            operation=row["operation"],
            previous_did_key=row["previous_did_key"],
            new_did_key=row["new_did_key"],
            prev_entry_hash=row["prev_entry_hash"],
            entry_hash=row["entry_hash"],
            state_hash=row["state_hash"],
            authorized_by=row["authorized_by"],
            signature=row["signature"],
            timestamp=row["timestamp"],
        )
        for row in rows
    ]


@router.put("/{did_aw}", dependencies=[Depends(rate_limit_dep("did_update"))])
async def update_mapping(request: Request, did_aw: str, req: DidUpdateRequest) -> dict:
    try:
        did_aw = validate_stable_id(did_aw)
        enforce_timestamp_skew(req.timestamp)
        public_key_from_did(req.new_did_key)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    db = _db(request)
    async with db.transaction() as tx:
        row = await tx.fetch_one(
            """
            SELECT did_aw, current_did_key, server_url, address, handle
            FROM {{tables.did_aw_mappings}}
            WHERE did_aw = $1
            """,
            did_aw,
        )
        if row is None:
            raise HTTPException(status_code=404, detail="not found")

        previous_did_key = row["current_did_key"]
        if req.new_did_key == previous_did_key:
            raise HTTPException(status_code=400, detail="rotate_key requires a different did:key")
        if req.authorized_by != previous_did_key:
            raise HTTPException(status_code=401, detail="authorized_by must be current did:key")

        last = await tx.fetch_one(
            """
            SELECT seq, entry_hash
            FROM {{tables.did_aw_log}}
            WHERE did_aw = $1
            ORDER BY seq DESC
            LIMIT 1
            """,
            did_aw,
        )
        if last is None:
            raise HTTPException(status_code=500, detail="missing audit log head")

        next_seq = last["seq"] + 1
        prev_entry_hash = last["entry_hash"]
        if req.seq != next_seq:
            raise HTTPException(status_code=409, detail="seq mismatch")
        if req.prev_entry_hash != prev_entry_hash:
            raise HTTPException(status_code=409, detail="prev_entry_hash mismatch")

        try:
            stored_server = row["server_url"]
            server_url = (
                require_canonical_server_origin(stored_server)
                if stored_server and stored_server.strip()
                else ""
            )
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

        address = row["address"]
        handle = row["handle"]
        state_hash = awid_state_hash(
            did_aw=did_aw,
            current_did_key=req.new_did_key,
            server=server_url,
            address=address,
            handle=handle,
        )
        if state_hash != req.state_hash:
            raise HTTPException(status_code=400, detail="state_hash mismatch")

        entry_payload = awid_log_entry_payload(
            did_aw=did_aw,
            seq=next_seq,
            operation=req.operation,
            previous_did_key=previous_did_key,
            new_did_key=req.new_did_key,
            prev_entry_hash=prev_entry_hash,
            state_hash=state_hash,
            authorized_by=req.authorized_by,
            timestamp=req.timestamp,
        )
        entry_hash = awid_sha256_hex(entry_payload)

        try:
            verify_did_key_signature(
                did_key=req.authorized_by,
                payload=entry_payload,
                signature_b64=req.signature,
            )
        except Exception as exc:
            raise HTTPException(status_code=401, detail="invalid signature") from exc

        await tx.execute(
            """
            UPDATE {{tables.did_aw_mappings}}
            SET current_did_key = $2,
                updated_at = NOW()
            WHERE did_aw = $1
            """,
            did_aw,
            req.new_did_key,
        )

        await tx.execute(
            """
            INSERT INTO {{tables.did_aw_log}}
                (did_aw, seq, operation, previous_did_key, new_did_key,
                 prev_entry_hash, entry_hash, state_hash, authorized_by, signature,
                 timestamp, created_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW())
            """,
            did_aw,
            next_seq,
            req.operation,
            previous_did_key,
            req.new_did_key,
            prev_entry_hash,
            entry_hash,
            state_hash,
            req.authorized_by,
            req.signature,
            req.timestamp,
        )

    return {"updated": True}
