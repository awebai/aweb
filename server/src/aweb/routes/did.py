from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field

from aweb.db import get_db_infra
from aweb.ratelimit import rate_limit_dep
from aweb.awid.did import (
    public_key_from_did,
    stable_id_from_public_key,
    validate_stable_id,
)
from aweb.awid.log import (
    log_entry_payload as awid_log_entry_payload,
    require_canonical_server_origin,
    sha256_hex as awid_sha256_hex,
    state_hash as awid_state_hash,
)
from aweb.awid.signing import canonical_json_bytes, verify_did_key_signature
from aweb.routes.dns_addresses import AddressListResponse, AddressResponse

router = APIRouter(prefix="/v1/did", tags=["did"])

_AUTH_TIMESTAMP_SKEW_SECONDS = 300


class DidRegisterRequest(BaseModel):
    did_aw: str = Field(..., max_length=256)
    did_key: str = Field(..., max_length=256)
    server: str = Field(..., max_length=512)
    address: str = Field(..., max_length=256)
    handle: str | None = Field(default=None, max_length=256)
    seq: int = Field(default=1, ge=1)
    prev_entry_hash: str | None = Field(default=None, max_length=128)
    state_hash: str = Field(..., max_length=128)
    authorized_by: str = Field(..., max_length=256)
    timestamp: str = Field(..., max_length=64)
    proof: str = Field(..., max_length=2048)


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
    operation: Literal["rotate_key", "update_server"] = "rotate_key"
    new_did_key: str = Field(..., max_length=256)
    server: str | None = Field(default=None, max_length=512)
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


def _parse_rfc3339(ts: str) -> datetime:
    ts = ts.strip()
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        raise ValueError("timestamp must include timezone offset (e.g. Z or +00:00)")
    if dt.microsecond != 0:
        raise ValueError("timestamp must be second precision (no fractional seconds)")
    return dt.astimezone(timezone.utc)


def _enforce_timestamp_skew(ts: str) -> None:
    dt = _parse_rfc3339(ts)
    delta = abs((_now() - dt).total_seconds())
    if delta > _AUTH_TIMESTAMP_SKEW_SECONDS:
        raise ValueError("timestamp outside allowed skew window")


def _parse_didkey_auth(authorization: str | None) -> tuple[str, str]:
    if not authorization:
        raise ValueError("missing Authorization")
    parts = authorization.split(" ")
    if len(parts) != 3 or parts[0] != "DIDKey":
        raise ValueError("Authorization must be: DIDKey <did:key> <signature>")
    return parts[1], parts[2]


def _request_timestamp_header(request: Request) -> str:
    value = request.headers.get("X-AWEB-Timestamp")
    if not value:
        raise ValueError("missing X-AWEB-Timestamp")
    return value


@router.post("", dependencies=[Depends(rate_limit_dep("did_register"))])
async def register_did(request: Request, req: DidRegisterRequest) -> dict:
    try:
        validate_stable_id(req.did_aw)
        _enforce_timestamp_skew(req.timestamp)
        if req.server.strip():
            canonical_server = require_canonical_server_origin(req.server)
        else:
            canonical_server = ""
        if req.seq != 1 or req.prev_entry_hash is not None:
            raise ValueError("seq must be 1 and prev_entry_hash must be null on create")
        if req.authorized_by != req.did_key:
            raise ValueError("authorized_by must equal did_key on create")
        public_key = public_key_from_did(req.did_key)
        derived = stable_id_from_public_key(public_key)
        if derived != req.did_aw:
            raise ValueError("did_aw does not match did_key derivation")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    db = _db(request)
    created_at = _now()
    updated_at = created_at

    async with db.transaction() as tx:
        existing = await tx.fetch_one(
            "SELECT did_aw FROM {{tables.did_aw_mappings}} WHERE did_aw = $1",
            req.did_aw,
        )
        if existing is not None:
            raise HTTPException(status_code=409, detail="did_aw already registered")

        state_hash = awid_state_hash(
            did_aw=req.did_aw,
            current_did_key=req.did_key,
            server=canonical_server,
            address=req.address,
            handle=req.handle,
        )
        if state_hash != req.state_hash:
            raise HTTPException(status_code=400, detail="state_hash mismatch")

        entry_payload = awid_log_entry_payload(
            did_aw=req.did_aw,
            seq=1,
            operation="create",
            previous_did_key=None,
            new_did_key=req.did_key,
            prev_entry_hash=None,
            state_hash=state_hash,
            authorized_by=req.did_key,
            timestamp=req.timestamp,
        )
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
            canonical_server,
            req.address,
            req.handle,
            created_at,
            updated_at,
        )

        entry_hash = awid_sha256_hex(entry_payload)

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
            "create",
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

    return {"registered": True}


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
async def list_did_addresses(request: Request, did_aw: str) -> AddressListResponse:
    try:
        did_aw = validate_stable_id(did_aw)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    db = _db(request)
    rows = await db.fetch_all(
        """
        SELECT pa.address_id, ns.domain, pa.name, pa.did_aw, pa.current_did_key,
               pa.reachability, pa.created_at
        FROM {{tables.public_addresses}} pa
        JOIN {{tables.dns_namespaces}} ns
          ON ns.namespace_id = pa.namespace_id
        WHERE pa.did_aw = $1
          AND pa.deleted_at IS NULL
          AND ns.deleted_at IS NULL
        ORDER BY ns.domain ASC, pa.name ASC
        """,
        did_aw,
    )
    return AddressListResponse(
        addresses=[
            AddressResponse(
                address_id=str(row["address_id"]),
                domain=row["domain"],
                name=row["name"],
                did_aw=row["did_aw"],
                current_did_key=row["current_did_key"],
                reachability=str(row.get("reachability") or "private"),
                created_at=row["created_at"].isoformat(),
            )
            for row in rows
        ]
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
        did_key, sig = _parse_didkey_auth(authorization)
        timestamp = _request_timestamp_header(request)
        _enforce_timestamp_skew(timestamp)
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

    try:
        server_url = require_canonical_server_origin(row["server_url"])
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

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
        _enforce_timestamp_skew(req.timestamp)
        public_key_from_did(req.new_did_key)
        if req.operation == "update_server":
            if req.server is None:
                raise ValueError("update_server requires a server URL")
            require_canonical_server_origin(req.server)
        elif req.server is not None:
            require_canonical_server_origin(req.server)
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
        if req.operation == "rotate_key" and req.new_did_key == previous_did_key:
            raise HTTPException(status_code=400, detail="rotate_key requires a different did:key")
        if req.operation == "update_server" and req.new_did_key != previous_did_key:
            raise HTTPException(status_code=400, detail="update_server must not change did:key")
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
            if req.operation == "update_server":
                assert req.server is not None
                server_url = require_canonical_server_origin(req.server)
            else:
                server_url = require_canonical_server_origin(row["server_url"])
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
                server_url = $3,
                address = $4,
                handle = $5,
                updated_at = NOW()
            WHERE did_aw = $1
            """,
            did_aw,
            req.new_did_key,
            server_url,
            address,
            handle,
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
