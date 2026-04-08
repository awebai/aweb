"""Team management endpoints for the awid registry."""

from __future__ import annotations

import re
from datetime import datetime, timezone

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pgdbm.errors import QueryError
from pydantic import BaseModel, ConfigDict, Field, field_validator

_TEAM_NAME_PATTERN = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")

from awid_service.deps import get_db
from awid.pagination import encode_cursor, validate_pagination_params
from awid.ratelimit import rate_limit_dep
from awid.dns_auth import validate_did_key as _validate_did_key
from awid.dns_auth import verify_signed_json_request

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
        SELECT team_id, team_did_key
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
    certificate_id: str
    member_did_key: str
    member_did_aw: str | None = None
    member_address: str | None = None
    alias: str
    lifetime: str
    issued_at: str
    revoked_at: str | None = None


class CertificateListResponse(BaseModel):
    certificates: list[CertificateResponse]
    has_more: bool
    next_cursor: str | None = None


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
            RETURNING team_id, domain, name, display_name, team_did_key, visibility, created_at
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
        cursor_team_id = decoded_cursor.get("team_id")
        if not isinstance(cursor_created_at, str) or not isinstance(cursor_team_id, str):
            raise HTTPException(status_code=400, detail="Invalid cursor")
        try:
            cursor_ts = datetime.fromisoformat(cursor_created_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid cursor") from exc
        params.extend([cursor_ts, cursor_team_id])
        where_clauses.append(
            f"(created_at, team_id) > (${len(params) - 1}::timestamptz, ${len(params)}::uuid)"
        )

    params.append(validated_limit + 1)
    query = (
        "SELECT team_id, domain, name, display_name, team_did_key, visibility, created_at"
        " FROM {{tables.teams}}"
        " WHERE " + " AND ".join(where_clauses)
        + f" ORDER BY created_at, team_id"
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
            "team_id": str(last["team_id"]),
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
        SELECT team_id, domain, name, display_name, team_did_key, visibility, created_at
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
            SELECT team_id
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
            WHERE team_id = $1 AND revoked_at IS NULL
            LIMIT 1
            """,
            row["team_id"],
        )
        if active_cert is not None:
            raise HTTPException(status_code=409, detail="Team has active certificates")

        now = datetime.now(timezone.utc)
        await tx.execute(
            "DELETE FROM {{tables.team_certificates}} WHERE team_id = $1",
            row["team_id"],
        )
        await tx.execute(
            """
            UPDATE {{tables.teams}}
            SET deleted_at = $2
            WHERE team_id = $1 AND deleted_at IS NULL
            """,
            row["team_id"],
            now,
        )

    return {"deleted": True, "team_id": str(row["team_id"]), "domain": domain, "name": name}


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
            RETURNING team_id, domain, name, display_name, team_did_key, visibility, created_at
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

    try:
        await db.execute(
            """
            INSERT INTO {{tables.team_certificates}}
                (team_id, certificate_id, member_did_key, member_did_aw,
                 member_address, alias, lifetime)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            """,
            team_row["team_id"],
            body.certificate_id,
            body.member_did_key,
            body.member_did_aw,
            body.member_address,
            body.alias,
            body.lifetime,
        )
    except QueryError as exc:
        if not isinstance(exc.__cause__, asyncpg.UniqueViolationError):
            raise
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
        RETURNING team_id, domain, name, display_name, team_did_key, visibility, created_at
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

    # Resolve team_id
    team_row = await db.fetch_one(
        "SELECT team_id FROM {{tables.teams}} WHERE domain = $1 AND name = $2 AND deleted_at IS NULL",
        domain, name,
    )
    if team_row is None:
        raise HTTPException(status_code=404, detail="Team not found")

    try:
        validated_limit, decoded_cursor = validate_pagination_params(limit, cursor)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    where_clauses = ["team_id = $1"]
    params: list[object] = [team_row["team_id"]]

    if active_only:
        where_clauses.append("revoked_at IS NULL")

    if since is not None:
        try:
            since_ts = datetime.fromisoformat(since.replace("Z", "+00:00"))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid since timestamp") from exc
        params.append(since_ts)
        where_clauses.append(f"issued_at > ${len(params)}::timestamptz")

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
            f"(issued_at, id) > (${len(params) - 1}::timestamptz, ${len(params)}::uuid)"
        )

    params.append(validated_limit + 1)
    query = (
        "SELECT id, certificate_id, member_did_key, member_did_aw, member_address,"
        " alias, lifetime, issued_at, revoked_at"
        " FROM {{tables.team_certificates}}"
        " WHERE " + " AND ".join(where_clauses)
        + f" ORDER BY issued_at, id"
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
        WHERE team_id = $1 AND certificate_id = $2 AND revoked_at IS NULL
        RETURNING certificate_id
        """,
        team_row["team_id"],
        body.certificate_id,
    )
    if row is None:
        # Distinguish between not found and already revoked
        exists = await db.fetch_one(
            "SELECT 1 FROM {{tables.team_certificates}} WHERE team_id = $1 AND certificate_id = $2",
            team_row["team_id"],
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
        "SELECT team_id FROM {{tables.teams}} WHERE domain = $1 AND name = $2 AND deleted_at IS NULL",
        domain, name,
    )
    if team_row is None:
        raise HTTPException(status_code=404, detail="Team not found")

    where_clauses = ["team_id = $1", "revoked_at IS NOT NULL"]
    params: list[object] = [team_row["team_id"]]

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
        team_id=str(row["team_id"]),
        domain=row["domain"],
        name=row["name"],
        display_name=row["display_name"],
        team_did_key=row["team_did_key"],
        visibility=row["visibility"],
        created_at=row["created_at"].isoformat(),
    )


def _cert_response(row) -> CertificateResponse:
    return CertificateResponse(
        certificate_id=row["certificate_id"],
        member_did_key=row["member_did_key"],
        member_did_aw=row["member_did_aw"],
        member_address=row["member_address"],
        alias=row["alias"],
        lifetime=row["lifetime"],
        issued_at=row["issued_at"].isoformat(),
        revoked_at=row["revoked_at"].isoformat() if row["revoked_at"] else None,
    )
