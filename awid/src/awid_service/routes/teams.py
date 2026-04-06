"""Team management endpoints for the awid registry."""

from __future__ import annotations

import re
from datetime import datetime, timezone

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pgdbm.errors import QueryError
from pydantic import BaseModel, ConfigDict, Field, field_validator

_TEAM_NAME_PATTERN = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")

from aweb.deps import get_db
from aweb.pagination import encode_cursor, validate_pagination_params
from aweb.ratelimit import rate_limit_dep
from aweb.routes.dns_auth import validate_did_key as _validate_did_key
from aweb.routes.dns_auth import verify_signed_json_request

router = APIRouter(prefix="/v1/namespaces/{domain}/teams", tags=["teams"])


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------


def _verify_namespace_controller(
    request: Request,
    *,
    domain: str,
    operation: str,
    extra_payload: dict[str, str] | None = None,
) -> str:
    """Verify DIDKey signature from the namespace controller."""
    payload = {"domain": domain, "operation": operation}
    if extra_payload:
        payload.update(extra_payload)
    return verify_signed_json_request(request, payload_dict=payload)


async def _require_namespace_controller(request: Request, db, *, domain: str, operation: str, **extra) -> str:
    """Verify auth and check that the signer is the namespace controller. Returns caller DID."""
    caller_did = _verify_namespace_controller(
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


# ---------------------------------------------------------------------------
# Request/response models
# ---------------------------------------------------------------------------


class TeamCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=128)
    display_name: str = Field(default="", max_length=256)
    team_did_key: str = Field(..., min_length=1, max_length=256)

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
    created_at: str


class TeamListResponse(BaseModel):
    teams: list[TeamResponse]
    has_more: bool
    next_cursor: str | None = None


class TeamRotateResponse(BaseModel):
    team_id: str
    domain: str
    name: str
    display_name: str
    team_did_key: str
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
                (domain, name, display_name, team_did_key, created_by, created_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING team_id, domain, name, display_name, team_did_key, created_at
            """,
            domain,
            body.name,
            body.display_name,
            body.team_did_key,
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
        "SELECT team_id, domain, name, display_name, team_did_key, created_at"
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
        SELECT team_id, domain, name, display_name, team_did_key, created_at
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
    db_infra=Depends(get_db),
) -> dict:
    db = db_infra.get_manager("aweb")
    await _require_namespace_controller(
        request, db, domain=domain, operation="delete_team", name=name,
    )

    async with db.transaction() as tx:
        row = await tx.fetch_one(
            """
            UPDATE {{tables.teams}}
            SET deleted_at = NOW()
            WHERE domain = $1 AND name = $2 AND deleted_at IS NULL
            RETURNING team_id
            """,
            domain,
            name,
        )
        if row is None:
            raise HTTPException(status_code=404, detail="Team not found")

    return {"status": "deleted", "domain": domain, "name": name}


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
            RETURNING team_id, domain, name, display_name, team_did_key, created_at
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
        created_at=row["created_at"].isoformat(),
    )
