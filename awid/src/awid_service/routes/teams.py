"""Team management endpoints for the awid registry."""

from __future__ import annotations

import base64
import json
import re
from datetime import datetime, timezone

import asyncpg
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pgdbm.errors import QueryError
from pydantic import BaseModel, ConfigDict, Field, field_validator

_TEAM_NAME_PATTERN = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")

from awid_service.deps import get_db
from awid.pagination import encode_cursor, validate_pagination_params
from awid.ratelimit import rate_limit_dep
from awid.dns_auth import validate_did_key as _validate_did_key
from awid.dns_auth import (
    enforce_timestamp_skew,
    parse_didkey_auth,
    require_timestamp,
    verify_signed_json_request,
)
from awid.did import public_key_from_did
from awid.signing import VerifyResult, canonical_json_bytes, verify_signature_with_public_key
from awid.team_ids import build_team_id

router = APIRouter(prefix="/v1/namespaces/{domain}/teams", tags=["teams"])


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------


def _verify_signed_request(
    request: Request,
    *,
    domain: str,
    operation: str,
    extra_payload: dict[str, str] | None = None,
) -> str:
    """Verify DIDKey signature over a domain-scoped payload. Returns caller did:key."""
    payload = {"domain": domain, "operation": operation}
    if extra_payload:
        payload.update(extra_payload)
    return verify_signed_json_request(request, payload_dict=payload)


async def _require_namespace_controller(request: Request, db, *, domain: str, operation: str, **extra) -> str:
    """Verify auth and check that the signer is the namespace controller. Returns caller DID."""
    caller_did = _verify_signed_request(
        request, domain=domain, operation=operation, extra_payload=extra or None,
    )
    row = await db.fetch_one(
        """
        SELECT controller_did
        FROM {{tables.dns_namespaces}}
        WHERE domain = $1 AND deleted_at IS NULL
        """,
        domain,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Namespace not found")
    if caller_did != row["controller_did"]:
        raise HTTPException(status_code=403, detail="Only the namespace controller can manage teams")
    return caller_did


async def _require_team_controller(
    request: Request, db, *, domain: str, name: str, operation: str, **extra,
) -> tuple[str, dict]:
    """Verify auth against the team's own public key. Returns (caller_did, team_row)."""
    caller_did = _verify_signed_request(
        request, domain=domain, operation=operation,
        extra_payload={"team_name": name, **extra} if extra else {"team_name": name},
    )
    row = await db.fetch_one(
        """
        SELECT team_uuid, team_did_key
        FROM {{tables.teams}}
        WHERE domain = $1 AND name = $2 AND deleted_at IS NULL
        """,
        domain,
        name,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Team not found")
    if caller_did != row["team_did_key"]:
        raise HTTPException(status_code=403, detail="Only the team controller can perform this action")
    return caller_did, row


def _parse_member_address(member_address: str) -> tuple[str, str]:
    parts = member_address.strip().split("/", 1)
    if len(parts) != 2:
        raise HTTPException(status_code=422, detail="member_address must be domain/name")
    domain = parts[0].strip().lower().rstrip(".")
    name = parts[1].strip().lower()
    if not domain or not name:
        raise HTTPException(status_code=422, detail="member_address must be domain/name")
    return domain, name


async def _require_member_address_owned_by_did_aw(
    db,
    *,
    member_address: str | None,
    member_did_aw: str | None,
) -> None:
    member_address = (member_address or "").strip()
    if not member_address:
        return
    member_did_aw = (member_did_aw or "").strip()
    if not member_did_aw:
        raise HTTPException(
            status_code=422,
            detail="member_did_aw is required when member_address is set",
        )

    address_domain, address_name = _parse_member_address(member_address)
    row = await db.fetch_one(
        """
        SELECT pa.did_aw
        FROM {{tables.public_addresses}} pa
        JOIN {{tables.dns_namespaces}} ns ON ns.namespace_id = pa.namespace_id
        WHERE ns.domain = $1
          AND pa.name = $2
          AND pa.deleted_at IS NULL
          AND ns.deleted_at IS NULL
        LIMIT 1
        """,
        address_domain,
        address_name,
    )
    if row is None:
        raise HTTPException(status_code=422, detail="member_address is not registered")
    resolved_did_aw = str(row["did_aw"] or "").strip()
    if resolved_did_aw != member_did_aw:
        raise HTTPException(
            status_code=422,
            detail=f"member_address belongs to {resolved_did_aw}, not {member_did_aw}",
        )


def _parse_certificate_blob(value: str | None) -> dict | None:
    value = (value or "").strip()
    if not value:
        return None
    try:
        raw = base64.b64decode(value, validate=True)
        cert = json.loads(raw)
    except Exception as exc:
        raise HTTPException(status_code=422, detail="certificate must be base64-encoded JSON") from exc
    if not isinstance(cert, dict):
        raise HTTPException(status_code=422, detail="certificate must decode to a JSON object")
    return cert


def _verify_certificate_blob(
    certificate: str | None,
    *,
    team_id: str,
    team_did_key: str,
    body: "CertificateRegisterRequest",
) -> None:
    cert = _parse_certificate_blob(certificate)
    if cert is None:
        return

    expected = {
        "version": 1,
        "certificate_id": body.certificate_id,
        "team_id": team_id,
        "team_did_key": team_did_key,
        "member_did_key": body.member_did_key,
        "alias": body.alias,
        "lifetime": body.lifetime,
    }
    if body.member_did_aw:
        expected["member_did_aw"] = body.member_did_aw
    if body.member_address:
        expected["member_address"] = body.member_address

    for key, expected_value in expected.items():
        if cert.get(key) != expected_value:
            raise HTTPException(status_code=422, detail=f"certificate {key} does not match registration")

    for key in ("member_did_aw", "member_address"):
        if not expected.get(key) and cert.get(key):
            raise HTTPException(status_code=422, detail=f"certificate {key} does not match registration")

    signature = cert.get("signature")
    if not isinstance(signature, str) or not signature.strip():
        raise HTTPException(status_code=422, detail="certificate signature is required")
    issued_at = cert.get("issued_at")
    if not isinstance(issued_at, str) or not issued_at.strip():
        raise HTTPException(status_code=422, detail="certificate issued_at is required")

    payload = {k: v for k, v in cert.items() if k != "signature"}
    try:
        public_key = public_key_from_did(team_did_key)
    except Exception as exc:
        raise HTTPException(status_code=422, detail="team_did_key is invalid") from exc
    if verify_signature_with_public_key(public_key, canonical_json_bytes(payload), signature) != VerifyResult.VERIFIED:
        raise HTTPException(status_code=422, detail="certificate signature verification failed")


def _verify_path_signature(request: Request, authorization: str | None) -> str:
    try:
        did_key, sig = parse_didkey_auth(authorization)
        timestamp = require_timestamp(request)
        enforce_timestamp_skew(timestamp)
        payload = f"{timestamp}\n{request.method}\n{request.url.path}".encode("utf-8")
        if verify_signature_with_public_key(public_key_from_did(did_key), payload, sig) != VerifyResult.VERIFIED:
            raise ValueError("invalid signature")
        return did_key
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Request/response models
# ---------------------------------------------------------------------------


class TeamCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=128)
    display_name: str = Field(default="", max_length=256)
    team_did_key: str = Field(..., min_length=1, max_length=256)
    visibility: str = Field(default="private", max_length=32)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        if not _TEAM_NAME_PATTERN.fullmatch(value):
            raise ValueError("must be lowercase alphanumeric with hyphens (e.g. 'backend', 'my-team')")
        return value

    @field_validator("team_did_key")
    @classmethod
    def validate_team_did_key(cls, value: str) -> str:
        return _validate_did_key(value)

    @field_validator("visibility")
    @classmethod
    def validate_visibility(cls, value: str) -> str:
        if value not in ("public", "private"):
            raise ValueError("must be 'public' or 'private'")
        return value


class TeamRotateKeyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    new_team_did_key: str = Field(..., min_length=1, max_length=256)

    @field_validator("new_team_did_key")
    @classmethod
    def validate_new_team_did_key(cls, value: str) -> str:
        return _validate_did_key(value)


class TeamResponse(BaseModel):
    team_id: str
    domain: str
    name: str
    display_name: str
    team_did_key: str
    visibility: str
    created_at: str


class TeamListResponse(BaseModel):
    teams: list[TeamResponse]
    has_more: bool
    next_cursor: str | None = None


class TeamDeleteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str | None = Field(default=None, max_length=512)


class TeamVisibilityRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    visibility: str = Field(..., max_length=32)

    @field_validator("visibility")
    @classmethod
    def validate_visibility(cls, value: str) -> str:
        if value not in ("public", "private"):
            raise ValueError("must be 'public' or 'private'")
        return value


class CertificateRegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    certificate_id: str = Field(..., min_length=1, max_length=256)
    member_did_key: str = Field(..., min_length=1, max_length=256)
    member_did_aw: str | None = Field(default=None, max_length=256)
    member_address: str | None = Field(default=None, max_length=256)
    alias: str = Field(..., min_length=1, max_length=128)
    lifetime: str = Field(default="persistent", max_length=32)
    certificate: str | None = Field(default=None, max_length=16384)

    @field_validator("member_did_key")
    @classmethod
    def validate_member_did_key(cls, value: str) -> str:
        return _validate_did_key(value)

    @field_validator("lifetime")
    @classmethod
    def validate_lifetime(cls, value: str) -> str:
        if value not in ("persistent", "ephemeral"):
            raise ValueError("must be 'persistent' or 'ephemeral'")
        return value


class CertificateRegisterResponse(BaseModel):
    registered: bool
    certificate_id: str


class CertificateResponse(BaseModel):
    team_id: str
    certificate_id: str
    member_did_key: str
    member_did_aw: str | None = None
    member_address: str | None = None
    alias: str
    lifetime: str
    issued_at: str
    revoked_at: str | None = None


class CertificateFetchResponse(CertificateResponse):
    certificate: str


class CertificateListResponse(BaseModel):
    certificates: list[CertificateResponse]
    has_more: bool
    next_cursor: str | None = None


class TeamMemberReferenceResponse(BaseModel):
    team_id: str
    certificate_id: str
    member_did_key: str
    member_did_aw: str | None = None
    member_address: str | None = None
    alias: str
    lifetime: str
    issued_at: str


class CertificateRevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    certificate_id: str = Field(..., min_length=1, max_length=256)


class CertificateRevokeResponse(BaseModel):
    revoked: bool
    certificate_id: str


class RevocationEntry(BaseModel):
    certificate_id: str
    revoked_at: str


class RevocationListResponse(BaseModel):
    revocations: list[RevocationEntry]


class TeamRotateResponse(BaseModel):
    team_id: str
    domain: str
    name: str
    display_name: str
    team_did_key: str
    visibility: str
    created_at: str
    key_changed: bool


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post(
    "",
    response_model=TeamResponse,
    dependencies=[Depends(rate_limit_dep("team_create"))],
)
async def create_team(
    request: Request,
    domain: str,
    body: TeamCreateRequest,
    db_infra=Depends(get_db),
) -> TeamResponse:
    db = db_infra.get_manager("aweb")
    caller_did = await _require_namespace_controller(
        request, db, domain=domain, operation="create_team", name=body.name,
    )

    now = datetime.now(timezone.utc)
    try:
        row = await db.fetch_one(
            """
            INSERT INTO {{tables.teams}}
                (domain, name, display_name, team_did_key, visibility, created_by, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING team_uuid, domain, name, display_name, team_did_key, visibility, created_at
            """,
            domain,
            body.name,
            body.display_name,
            body.team_did_key,
            body.visibility,
            caller_did,
            now,
        )
    except QueryError as exc:
        if not isinstance(exc.__cause__, asyncpg.UniqueViolationError):
            raise
        raise HTTPException(status_code=409, detail="Team already exists")

    return _team_response(row)


@router.get(
    "",
    response_model=TeamListResponse,
    dependencies=[Depends(rate_limit_dep("team_list"))],
)
async def list_teams(
    domain: str,
    limit: int | None = Query(default=None, ge=1),
    cursor: str | None = Query(default=None),
    db_infra=Depends(get_db),
) -> TeamListResponse:
    db = db_infra.get_manager("aweb")
    try:
        validated_limit, decoded_cursor = validate_pagination_params(limit, cursor)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    where_clauses = ["domain = $1", "deleted_at IS NULL"]
    params: list[object] = [domain]

    if decoded_cursor is not None:
        cursor_created_at = decoded_cursor.get("created_at")
        cursor_team_uuid = decoded_cursor.get("team_uuid")
        if not isinstance(cursor_created_at, str) or not isinstance(cursor_team_uuid, str):
            raise HTTPException(status_code=400, detail="Invalid cursor")
        try:
            cursor_ts = datetime.fromisoformat(cursor_created_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid cursor") from exc
        params.extend([cursor_ts, cursor_team_uuid])
        where_clauses.append(
            f"(created_at, team_uuid) > (${len(params) - 1}::timestamptz, ${len(params)}::uuid)"
        )

    params.append(validated_limit + 1)
    query = (
        "SELECT team_uuid, domain, name, display_name, team_did_key, visibility, created_at"
        " FROM {{tables.teams}}"
        " WHERE " + " AND ".join(where_clauses)
        + f" ORDER BY created_at, team_uuid"
        f" LIMIT ${len(params)}"
    )
    rows = await db.fetch_all(query, *params)
    has_more = len(rows) > validated_limit
    page_rows = rows[:validated_limit]
    next_cursor = None
    if has_more and page_rows:
        last = page_rows[-1]
        next_cursor = encode_cursor({
            "created_at": last["created_at"].isoformat(),
            "team_uuid": str(last["team_uuid"]),
        })

    return TeamListResponse(
        teams=[_team_response(r) for r in page_rows],
        has_more=has_more,
        next_cursor=next_cursor,
    )


@router.get(
    "/{name}",
    response_model=TeamResponse,
    dependencies=[Depends(rate_limit_dep("team_get"))],
)
async def get_team(domain: str, name: str, db_infra=Depends(get_db)) -> TeamResponse:
    db = db_infra.get_manager("aweb")
    row = await db.fetch_one(
        """
        SELECT team_uuid, domain, name, display_name, team_did_key, visibility, created_at
        FROM {{tables.teams}}
        WHERE domain = $1 AND name = $2 AND deleted_at IS NULL
        """,
        domain,
        name,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Team not found")
    return _team_response(row)


@router.delete(
    "/{name}",
    dependencies=[Depends(rate_limit_dep("team_delete"))],
)
async def delete_team(
    request: Request,
    domain: str,
    name: str,
    body: TeamDeleteRequest | None = None,
    db_infra=Depends(get_db),
) -> dict:
    db = db_infra.get_manager("aweb")
    await _require_namespace_controller(
        request, db, domain=domain, operation="delete_team", team_name=name,
    )

    async with db.transaction() as tx:
        row = await tx.fetch_one(
            """
            SELECT team_uuid
            FROM {{tables.teams}}
            WHERE domain = $1 AND name = $2 AND deleted_at IS NULL
            FOR UPDATE
            """,
            domain,
            name,
        )
        if row is None:
            raise HTTPException(status_code=404, detail="Team not found")

        active_cert = await tx.fetch_one(
            """
            SELECT certificate_id
            FROM {{tables.team_certificates}}
            WHERE team_uuid = $1 AND revoked_at IS NULL
            LIMIT 1
            """,
            row["team_uuid"],
        )
        if active_cert is not None:
            raise HTTPException(status_code=409, detail="Team has active certificates")

        now = datetime.now(timezone.utc)
        await tx.execute(
            "DELETE FROM {{tables.team_certificates}} WHERE team_uuid = $1",
            row["team_uuid"],
        )
        await tx.execute(
            """
            UPDATE {{tables.teams}}
            SET deleted_at = $2
            WHERE team_uuid = $1 AND deleted_at IS NULL
            """,
            row["team_uuid"],
            now,
        )

    return {"deleted": True, "team_id": build_team_id(domain, name), "domain": domain, "name": name}


@router.post(
    "/{name}/rotate",
    response_model=TeamRotateResponse,
    dependencies=[Depends(rate_limit_dep("team_rotate"))],
)
async def rotate_team_key(
    request: Request,
    domain: str,
    name: str,
    body: TeamRotateKeyRequest,
    db_infra=Depends(get_db),
) -> TeamRotateResponse:
    db = db_infra.get_manager("aweb")
    await _require_namespace_controller(
        request, db, domain=domain, operation="rotate_team_key",
        name=name, new_team_did_key=body.new_team_did_key,
    )

    async with db.transaction() as tx:
        old_row = await tx.fetch_one(
            """
            SELECT team_did_key FROM {{tables.teams}}
            WHERE domain = $1 AND name = $2 AND deleted_at IS NULL
            FOR UPDATE
            """,
            domain,
            name,
        )
        if old_row is None:
            raise HTTPException(status_code=404, detail="Team not found")

        key_changed = old_row["team_did_key"] != body.new_team_did_key
        row = await tx.fetch_one(
            """
            UPDATE {{tables.teams}}
            SET team_did_key = $3
            WHERE domain = $1 AND name = $2 AND deleted_at IS NULL
            RETURNING team_uuid, domain, name, display_name, team_did_key, visibility, created_at
            """,
            domain,
            name,
            body.new_team_did_key,
        )

    resp = _team_response(row)
    return TeamRotateResponse(
        **resp.model_dump(),
        key_changed=key_changed,
    )


@router.post(
    "/{name}/certificates",
    response_model=CertificateRegisterResponse,
    dependencies=[Depends(rate_limit_dep("certificate_register"))],
)
async def register_certificate(
    request: Request,
    domain: str,
    name: str,
    body: CertificateRegisterRequest,
    db_infra=Depends(get_db),
) -> CertificateRegisterResponse:
    db = db_infra.get_manager("aweb")
    _, team_row = await _require_team_controller(
        request, db, domain=domain, name=name,
        operation="register_certificate", certificate_id=body.certificate_id,
    )
    await _require_member_address_owned_by_did_aw(
        db,
        member_address=body.member_address,
        member_did_aw=body.member_did_aw,
    )
    team_id = build_team_id(domain, name)
    _verify_certificate_blob(
        body.certificate,
        team_id=team_id,
        team_did_key=team_row["team_did_key"],
        body=body,
    )

    try:
        await db.execute(
            """
            INSERT INTO {{tables.team_certificates}}
                (team_uuid, certificate_id, member_did_key, member_did_aw,
                 member_address, alias, lifetime, certificate)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            """,
            team_row["team_uuid"],
            body.certificate_id,
            body.member_did_key,
            body.member_did_aw,
            body.member_address,
            body.alias,
            body.lifetime,
            body.certificate,
        )
    except QueryError as exc:
        cause = exc.__cause__
        if not isinstance(cause, asyncpg.UniqueViolationError):
            raise
        constraint_name = getattr(cause, "constraint_name", "")
        if constraint_name == "idx_team_certificates_alias_active":
            raise HTTPException(status_code=409, detail="Alias already active in team")
        raise HTTPException(status_code=409, detail="Certificate already registered")

    return CertificateRegisterResponse(registered=True, certificate_id=body.certificate_id)


@router.post(
    "/{name}/visibility",
    response_model=TeamResponse,
    dependencies=[Depends(rate_limit_dep("team_update"))],
)
async def set_team_visibility(
    request: Request,
    domain: str,
    name: str,
    body: TeamVisibilityRequest,
    db_infra=Depends(get_db),
) -> TeamResponse:
    db = db_infra.get_manager("aweb")
    await _require_team_controller(
        request, db, domain=domain, name=name,
        operation="set_team_visibility", visibility=body.visibility,
    )

    row = await db.fetch_one(
        """
        UPDATE {{tables.teams}}
        SET visibility = $3
        WHERE domain = $1 AND name = $2 AND deleted_at IS NULL
        RETURNING team_uuid, domain, name, display_name, team_did_key, visibility, created_at
        """,
        domain,
        name,
        body.visibility,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Team not found")
    return _team_response(row)


@router.get(
    "/{name}/certificates",
    response_model=CertificateListResponse,
    dependencies=[Depends(rate_limit_dep("certificate_list"))],
)
async def list_certificates(
    domain: str,
    name: str,
    active_only: bool = Query(default=False),
    since: str | None = Query(default=None),
    limit: int | None = Query(default=None, ge=1),
    cursor: str | None = Query(default=None),
    db_infra=Depends(get_db),
) -> CertificateListResponse:
    db = db_infra.get_manager("aweb")

    # Resolve internal team UUID.
    team_row = await db.fetch_one(
        "SELECT team_uuid FROM {{tables.teams}} WHERE domain = $1 AND name = $2 AND deleted_at IS NULL",
        domain, name,
    )
    if team_row is None:
        raise HTTPException(status_code=404, detail="Team not found")

    try:
        validated_limit, decoded_cursor = validate_pagination_params(limit, cursor)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    where_clauses = ["tc.team_uuid = $1"]
    params: list[object] = [team_row["team_uuid"]]

    if active_only:
        where_clauses.append("tc.revoked_at IS NULL")

    if since is not None:
        try:
            since_ts = datetime.fromisoformat(since.replace("Z", "+00:00"))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid since timestamp") from exc
        params.append(since_ts)
        where_clauses.append(f"tc.issued_at > ${len(params)}::timestamptz")

    if decoded_cursor is not None:
        cursor_issued_at = decoded_cursor.get("issued_at")
        cursor_id = decoded_cursor.get("id")
        if not isinstance(cursor_issued_at, str) or not isinstance(cursor_id, str):
            raise HTTPException(status_code=400, detail="Invalid cursor")
        try:
            cursor_ts = datetime.fromisoformat(cursor_issued_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid cursor") from exc
        params.extend([cursor_ts, cursor_id])
        where_clauses.append(
            f"(tc.issued_at, tc.id) > (${len(params) - 1}::timestamptz, ${len(params)}::uuid)"
        )

    params.append(validated_limit + 1)
    query = (
        "SELECT tc.id, tc.certificate_id, tc.member_did_key, tc.member_did_aw, tc.member_address,"
        " tc.alias, tc.lifetime, tc.issued_at, tc.revoked_at, t.domain, t.name"
        " FROM {{tables.team_certificates}} tc"
        " JOIN {{tables.teams}} t ON t.team_uuid = tc.team_uuid"
        " WHERE " + " AND ".join(where_clauses)
        + f" ORDER BY tc.issued_at, tc.id"
        f" LIMIT ${len(params)}"
    )
    rows = await db.fetch_all(query, *params)
    has_more = len(rows) > validated_limit
    page_rows = rows[:validated_limit]
    next_cursor = None
    if has_more and page_rows:
        last = page_rows[-1]
        next_cursor = encode_cursor({
            "issued_at": last["issued_at"].isoformat(),
            "id": str(last["id"]),
        })

    return CertificateListResponse(
        certificates=[_cert_response(r) for r in page_rows],
        has_more=has_more,
        next_cursor=next_cursor,
    )


@router.get(
    "/{name}/members/{alias}",
    response_model=TeamMemberReferenceResponse,
    dependencies=[Depends(rate_limit_dep("team_member_get"))],
)
async def get_team_member(
    domain: str,
    name: str,
    alias: str,
    db_infra=Depends(get_db),
) -> TeamMemberReferenceResponse:
    db = db_infra.get_manager("aweb")
    row = await db.fetch_one(
        """
        SELECT tc.certificate_id, tc.member_did_key, tc.member_did_aw,
               tc.member_address, tc.alias, tc.lifetime, tc.issued_at,
               t.domain, t.name
        FROM {{tables.team_certificates}} tc
        JOIN {{tables.teams}} t ON t.team_uuid = tc.team_uuid
        WHERE t.domain = $1
          AND t.name = $2
          AND t.deleted_at IS NULL
          AND tc.alias = $3
          AND tc.revoked_at IS NULL
        ORDER BY tc.issued_at DESC, tc.id DESC
        LIMIT 1
        """,
        domain,
        name,
        alias,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Team member not found")
    return TeamMemberReferenceResponse(
        team_id=build_team_id(row["domain"], row["name"]),
        certificate_id=row["certificate_id"],
        member_did_key=row["member_did_key"],
        member_did_aw=row["member_did_aw"],
        member_address=row["member_address"],
        alias=row["alias"],
        lifetime=row["lifetime"],
        issued_at=row["issued_at"].isoformat(),
    )


@router.get(
    "/{name}/certificates/{certificate_id}",
    response_model=CertificateFetchResponse,
    dependencies=[Depends(rate_limit_dep("certificate_fetch"))],
)
async def fetch_certificate(
    request: Request,
    domain: str,
    name: str,
    certificate_id: str,
    authorization: str | None = Header(default=None),
    db_infra=Depends(get_db),
) -> CertificateFetchResponse:
    caller_did = _verify_path_signature(request, authorization)
    db = db_infra.get_manager("aweb")

    row = await db.fetch_one(
        """
        SELECT tc.certificate_id, tc.member_did_key, tc.member_did_aw,
               tc.member_address, tc.alias, tc.lifetime, tc.issued_at,
               tc.revoked_at, tc.certificate, t.domain, t.name, t.team_did_key
        FROM {{tables.team_certificates}} tc
        JOIN {{tables.teams}} t ON t.team_uuid = tc.team_uuid
        WHERE t.domain = $1
          AND t.name = $2
          AND t.deleted_at IS NULL
          AND tc.certificate_id = $3
        LIMIT 1
        """,
        domain,
        name,
        certificate_id,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Certificate not found")

    if caller_did != row["member_did_key"]:
        raise HTTPException(status_code=403, detail="Certificate is not readable by this DID")
    if row["revoked_at"] is not None:
        raise HTTPException(status_code=409, detail="Certificate has been revoked")

    certificate = (row["certificate"] or "").strip()
    if not certificate:
        raise HTTPException(
            status_code=409,
            detail="Certificate blob is not available; reissue and register a blob-backed certificate",
        )

    return CertificateFetchResponse(
        **_cert_response(row).model_dump(),
        certificate=certificate,
    )


@router.post(
    "/{name}/certificates/revoke",
    response_model=CertificateRevokeResponse,
    dependencies=[Depends(rate_limit_dep("certificate_revoke"))],
)
async def revoke_certificate(
    request: Request,
    domain: str,
    name: str,
    body: CertificateRevokeRequest,
    db_infra=Depends(get_db),
) -> CertificateRevokeResponse:
    db = db_infra.get_manager("aweb")
    _, team_row = await _require_team_controller(
        request, db, domain=domain, name=name,
        operation="revoke_certificate", certificate_id=body.certificate_id,
    )

    row = await db.fetch_one(
        """
        UPDATE {{tables.team_certificates}}
        SET revoked_at = NOW()
        WHERE team_uuid = $1 AND certificate_id = $2 AND revoked_at IS NULL
        RETURNING certificate_id
        """,
        team_row["team_uuid"],
        body.certificate_id,
    )
    if row is None:
        # Distinguish between not found and already revoked
        exists = await db.fetch_one(
            "SELECT 1 FROM {{tables.team_certificates}} WHERE team_uuid = $1 AND certificate_id = $2",
            team_row["team_uuid"],
            body.certificate_id,
        )
        if exists is not None:
            raise HTTPException(status_code=409, detail="Certificate already revoked")
        raise HTTPException(status_code=404, detail="Certificate not found")

    return CertificateRevokeResponse(revoked=True, certificate_id=body.certificate_id)


@router.get(
    "/{name}/revocations",
    response_model=RevocationListResponse,
    dependencies=[Depends(rate_limit_dep("revocation_list"))],
)
async def list_revocations(
    domain: str,
    name: str,
    since: str | None = Query(default=None),
    db_infra=Depends(get_db),
) -> RevocationListResponse:
    db = db_infra.get_manager("aweb")

    team_row = await db.fetch_one(
        "SELECT team_uuid FROM {{tables.teams}} WHERE domain = $1 AND name = $2 AND deleted_at IS NULL",
        domain, name,
    )
    if team_row is None:
        raise HTTPException(status_code=404, detail="Team not found")

    where_clauses = ["team_uuid = $1", "revoked_at IS NOT NULL"]
    params: list[object] = [team_row["team_uuid"]]

    if since is not None:
        try:
            since_ts = datetime.fromisoformat(since.replace("Z", "+00:00"))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid since timestamp") from exc
        params.append(since_ts)
        where_clauses.append(f"revoked_at > ${len(params)}::timestamptz")

    _REVOCATION_HARD_LIMIT = 1000
    params.append(_REVOCATION_HARD_LIMIT)
    query = (
        "SELECT certificate_id, revoked_at"
        " FROM {{tables.team_certificates}}"
        " WHERE " + " AND ".join(where_clauses)
        + f" ORDER BY revoked_at"
        f" LIMIT ${len(params)}"
    )
    rows = await db.fetch_all(query, *params)

    return RevocationListResponse(
        revocations=[
            RevocationEntry(
                certificate_id=r["certificate_id"],
                revoked_at=r["revoked_at"].isoformat(),
            )
            for r in rows
        ],
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _team_response(row) -> TeamResponse:
    return TeamResponse(
        team_id=build_team_id(row["domain"], row["name"]),
        domain=row["domain"],
        name=row["name"],
        display_name=row["display_name"],
        team_did_key=row["team_did_key"],
        visibility=row["visibility"],
        created_at=row["created_at"].isoformat(),
    )


def _cert_response(row) -> CertificateResponse:
    return CertificateResponse(
        team_id=build_team_id(row["domain"], row["name"]),
        certificate_id=row["certificate_id"],
        member_did_key=row["member_did_key"],
        member_did_aw=row["member_did_aw"],
        member_address=row["member_address"],
        alias=row["alias"],
        lifetime=row["lifetime"],
        issued_at=row["issued_at"].isoformat(),
        revoked_at=row["revoked_at"].isoformat() if row["revoked_at"] else None,
    )
