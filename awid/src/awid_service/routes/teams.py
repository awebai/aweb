"""Team management endpoints for the awid registry."""

from __future__ import annotations

import base64
import json
import re
import secrets
from datetime import datetime, timezone

import asyncpg
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pgdbm.errors import QueryError
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_TEAM_NAME_PATTERN = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")

from awid_service.deps import get_db
from awid.contract import normalize_identity_scope
from awid.pagination import encode_cursor, validate_pagination_params
from awid.ratelimit import AWID_SERVICE_TOKEN_HEADER, rate_limit_dep
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


def _validate_team_name_path(name: str) -> str:
    if not _TEAM_NAME_PATTERN.fullmatch(name):
        raise HTTPException(
            status_code=422,
            detail="team name must be lowercase alphanumeric with hyphens (e.g. 'backend', 'my-team')",
        )
    return name


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


def _certificate_scope_from_payload(cert: dict) -> str:
    """Return canonical identity_scope from current or legacy certificate JSON."""
    if cert.get("identity_scope") is None and cert.get("lifetime") is None:
        raise HTTPException(status_code=422, detail="certificate identity_scope is required")
    try:
        return normalize_identity_scope(cert.get("identity_scope") or cert.get("lifetime"))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


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
    }
    if body.member_did_aw:
        expected["member_did_aw"] = body.member_did_aw
    if body.member_address:
        expected["member_address"] = body.member_address

    for key, expected_value in expected.items():
        if cert.get(key) != expected_value:
            raise HTTPException(status_code=422, detail=f"certificate {key} does not match registration")

    if _certificate_scope_from_payload(cert) != body.identity_scope:
        raise HTTPException(status_code=422, detail="certificate identity_scope does not match registration")

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


# Machine-readable code for reads blocked by team visibility. The CLI branches
# on it to retry with a signed request; keep it stable.
TEAM_PRIVATE_ERROR_CODE = "team_private"


def _team_private_error() -> HTTPException:
    return HTTPException(
        status_code=403,
        detail={
            "code": TEAM_PRIVATE_ERROR_CODE,
            "message": (
                "Team is private; reads require a same-team signed request "
                "or the trusted service token"
            ),
        },
    )


def _presents_trusted_service_token(request: Request) -> bool:
    """True when the caller presents the configured AWID service token.

    Same header, state attribute, and constant-time comparison as the rate
    limiter's allow_trusted_service exemption (awid.ratelimit.rate_limit_dep);
    an unconfigured deployment accepts no token.
    """
    expected = getattr(request.app.state, "awid_service_token", None)
    presented = (request.headers.get(AWID_SERVICE_TOKEN_HEADER) or "").strip()
    return bool(
        expected
        and presented
        and secrets.compare_digest(expected.encode("utf-8"), presented.encode("utf-8"))
    )


async def _require_team_read_access(
    request: Request,
    db,
    *,
    team_uuid,
    team_did_key: str,
    visibility: str,
    authorization: str | None,
) -> None:
    """Enforce team visibility on a read route.

    Public teams are readable by anyone. For a private team the caller must
    present either the trusted service token (the aweb server's
    server-to-server revocation fetch) or a path-signature — the exact scheme
    the certificate blob fetch uses — from the team controller key or an
    unrevoked member key. Anything else is 403 team_private: existence is
    deliberately disclosed (the team-availability read contract depends on
    404 meaning "name free", and the CLI needs the signal to retry signed).
    """
    if visibility == "public":
        return
    if _presents_trusted_service_token(request):
        return
    if authorization:
        caller_did = _verify_path_signature(request, authorization)
        if caller_did == team_did_key:
            return
        member = await db.fetch_one(
            """
            SELECT 1
            FROM {{tables.team_certificates}}
            WHERE team_uuid = $1 AND member_did_key = $2 AND revoked_at IS NULL
            LIMIT 1
            """,
            team_uuid,
            caller_did,
        )
        if member is not None:
            return
    raise _team_private_error()


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
    identity_scope: str = Field(default="global", max_length=32)
    certificate: str | None = Field(default=None, max_length=16384)

    @model_validator(mode="before")
    @classmethod
    def normalize_legacy_lifetime(cls, data):
        if not isinstance(data, dict):
            return data
        values = dict(data)
        lifetime = values.pop("lifetime", None)
        if lifetime is not None:
            legacy_scope = normalize_identity_scope(str(lifetime))
            if (
                values.get("identity_scope") is not None
                and normalize_identity_scope(str(values["identity_scope"])) != legacy_scope
            ):
                raise ValueError("lifetime does not match identity_scope")
            values.setdefault("identity_scope", legacy_scope)
        return values

    @field_validator("member_did_key")
    @classmethod
    def validate_member_did_key(cls, value: str) -> str:
        return _validate_did_key(value)

    @field_validator("identity_scope")
    @classmethod
    def validate_identity_scope(cls, value: str) -> str:
        return normalize_identity_scope(value)


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
    identity_scope: str
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
    identity_scope: str
    issued_at: str


class CertificateRevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    certificate_id: str = Field(..., min_length=1, max_length=256)


class CertificateRevokeResponse(BaseModel):
    revoked: bool
    certificate_id: str


# The pre-pagination revocation route returned up to this many rows; legacy
# clients read that page as the complete set, so the no-limit page size must
# never shrink below it (aweb-abfo).
_LEGACY_REVOCATION_PAGE_ROWS = 1000


class RevocationEntry(BaseModel):
    certificate_id: str
    revoked_at: str


class RevocationListResponse(BaseModel):
    revocations: list[RevocationEntry]
    # Absent has_more/next_cursor (old servers) is not "complete": clients that
    # consume revocations as a completeness-bearing set must page until
    # has_more is false. aweb-abfo: the route previously returned the oldest
    # 1000 rows with no truncation signal, and verifiers read that as the
    # complete revocation set.
    has_more: bool = False
    next_cursor: str | None = None


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
    request: Request,
    domain: str,
    limit: int | None = Query(default=None, ge=1),
    cursor: str | None = Query(default=None),
    authorization: str | None = Header(default=None),
    db_infra=Depends(get_db),
) -> TeamListResponse:
    db = db_infra.get_manager("aweb")
    try:
        validated_limit, decoded_cursor = validate_pagination_params(limit, cursor)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    where_clauses = ["t.domain = $1", "t.deleted_at IS NULL"]
    params: list[object] = [domain]

    # Visibility: private teams are enumerable only by the trusted service, or
    # by a path-signed caller who controls the team or holds an unrevoked
    # member certificate in it. Anonymous callers see public teams only.
    if not _presents_trusted_service_token(request):
        if authorization:
            viewer_did = _verify_path_signature(request, authorization)
            params.append(viewer_did)
            idx = len(params)
            where_clauses.append(
                f"(t.visibility = 'public' OR t.team_did_key = ${idx}"
                " OR EXISTS ("
                "SELECT 1 FROM {{tables.team_certificates}} tc"
                f" WHERE tc.team_uuid = t.team_uuid AND tc.member_did_key = ${idx}"
                " AND tc.revoked_at IS NULL))"
            )
        else:
            where_clauses.append("t.visibility = 'public'")

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
        "SELECT t.team_uuid, t.domain, t.name, t.display_name, t.team_did_key, t.visibility, t.created_at"
        " FROM {{tables.teams}} t"
        " WHERE " + " AND ".join(where_clauses)
        + f" ORDER BY t.created_at, t.team_uuid"
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
async def get_team(
    request: Request,
    domain: str,
    name: str,
    authorization: str | None = Header(default=None),
    db_infra=Depends(get_db),
) -> TeamResponse:
    name = _validate_team_name_path(name)
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
    await _require_team_read_access(
        request,
        db,
        team_uuid=row["team_uuid"],
        team_did_key=row["team_did_key"],
        visibility=row["visibility"],
        authorization=authorization,
    )
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
                 member_address, alias, identity_scope, certificate)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            """,
            team_row["team_uuid"],
            body.certificate_id,
            body.member_did_key,
            body.member_did_aw,
            body.member_address,
            body.alias,
            body.identity_scope,
            body.certificate,
        )
    except QueryError as exc:
        cause = exc.__cause__
        if not isinstance(cause, asyncpg.UniqueViolationError):
            raise
        constraint_name = getattr(cause, "constraint_name", "")
        if constraint_name == "idx_team_certificates_alias_active":
            raise HTTPException(status_code=409, detail="Alias already active in team")
        raise HTTPException(
            status_code=409,
            detail={
                "code": "certificate_already_registered",
                "message": "Certificate already registered",
            },
        )

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
    request: Request,
    domain: str,
    name: str,
    active_only: bool = Query(default=False),
    since: str | None = Query(default=None),
    limit: int | None = Query(default=None, ge=1),
    cursor: str | None = Query(default=None),
    authorization: str | None = Header(default=None),
    db_infra=Depends(get_db),
) -> CertificateListResponse:
    db = db_infra.get_manager("aweb")

    # Resolve internal team UUID.
    team_row = await db.fetch_one(
        "SELECT team_uuid, team_did_key, visibility FROM {{tables.teams}}"
        " WHERE domain = $1 AND name = $2 AND deleted_at IS NULL",
        domain, name,
    )
    if team_row is None:
        raise HTTPException(status_code=404, detail="Team not found")
    await _require_team_read_access(
        request,
        db,
        team_uuid=team_row["team_uuid"],
        team_did_key=team_row["team_did_key"],
        visibility=team_row["visibility"],
        authorization=authorization,
    )

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
        " tc.alias, tc.identity_scope, tc.issued_at, tc.revoked_at, t.domain, t.name"
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
    request: Request,
    domain: str,
    name: str,
    alias: str,
    authorization: str | None = Header(default=None),
    db_infra=Depends(get_db),
) -> TeamMemberReferenceResponse:
    db = db_infra.get_manager("aweb")
    team_row = await db.fetch_one(
        "SELECT team_uuid, team_did_key, visibility FROM {{tables.teams}}"
        " WHERE domain = $1 AND name = $2 AND deleted_at IS NULL",
        domain, name,
    )
    if team_row is None:
        raise HTTPException(status_code=404, detail="Team member not found")
    await _require_team_read_access(
        request,
        db,
        team_uuid=team_row["team_uuid"],
        team_did_key=team_row["team_did_key"],
        visibility=team_row["visibility"],
        authorization=authorization,
    )

    row = await db.fetch_one(
        """
        SELECT tc.certificate_id, tc.member_did_key, tc.member_did_aw,
               tc.member_address, tc.alias, tc.identity_scope, tc.issued_at
        FROM {{tables.team_certificates}} tc
        WHERE tc.team_uuid = $1
          AND tc.alias = $2
          AND tc.revoked_at IS NULL
        ORDER BY tc.issued_at DESC, tc.id DESC
        LIMIT 1
        """,
        team_row["team_uuid"],
        alias,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Team member not found")
    return TeamMemberReferenceResponse(
        team_id=build_team_id(domain, name),
        certificate_id=row["certificate_id"],
        member_did_key=row["member_did_key"],
        member_did_aw=row["member_did_aw"],
        member_address=row["member_address"],
        alias=row["alias"],
        identity_scope=row["identity_scope"],
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
               tc.member_address, tc.alias, tc.identity_scope, tc.issued_at,
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
    # allow_trusted_service: since aweb-abfn/abfp, aweb backends poll this
    # route per team per revocation-cache TTL (60s) as the input to membership
    # enforcement, and a 429 here becomes a fail-closed 503 on every
    # authenticated request they serve for the team. A backend presenting the
    # configured service token bypasses the per-IP bucket, the same exemption
    # did_key/did_addresses already use; anonymous callers keep the limit.
    dependencies=[Depends(rate_limit_dep("revocation_list", allow_trusted_service=True))],
)
async def list_revocations(
    request: Request,
    domain: str,
    name: str,
    since: str | None = Query(default=None),
    limit: int | None = Query(default=None, ge=1),
    cursor: str | None = Query(default=None),
    authorization: str | None = Header(default=None),
    db_infra=Depends(get_db),
) -> RevocationListResponse:
    db = db_infra.get_manager("aweb")

    team_row = await db.fetch_one(
        "SELECT team_uuid, team_did_key, visibility FROM {{tables.teams}}"
        " WHERE domain = $1 AND name = $2 AND deleted_at IS NULL",
        domain, name,
    )
    if team_row is None:
        raise HTTPException(status_code=404, detail="Team not found")
    # The aweb server's revocation enforcement fetches this route
    # server-to-server with AWID_SERVICE_TOKEN; the token passes the gate for
    # private teams, so enforcement keeps working when a team goes private.
    await _require_team_read_access(
        request,
        db,
        team_uuid=team_row["team_uuid"],
        team_did_key=team_row["team_did_key"],
        visibility=team_row["visibility"],
        authorization=authorization,
    )

    try:
        validated_limit, decoded_cursor = validate_pagination_params(limit, cursor)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if limit is None:
        # Legacy clients (pre-pagination) send no limit and read the first
        # page as complete; their historical page was 1000 rows. Keep that as
        # this endpoint's no-limit page size so a mixed deployment never gets
        # a SHORTER complete-looking page than it did before pagination
        # existed. Explicit limits use the shared clamp.
        validated_limit = _LEGACY_REVOCATION_PAGE_ROWS

    where_clauses = ["team_uuid = $1", "revoked_at IS NOT NULL"]
    params: list[object] = [team_row["team_uuid"]]

    if since is not None:
        try:
            since_ts = datetime.fromisoformat(since.replace("Z", "+00:00"))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid since timestamp") from exc
        params.append(since_ts)
        where_clauses.append(f"revoked_at > ${len(params)}::timestamptz")

    # Pagination orders by (revoked_at, id): a mass revocation (team rotation)
    # stamps many rows with one revoked_at, so a timestamp-only cursor would
    # drop rows at page boundaries — the exact rows a verifier most needs.
    if decoded_cursor is not None:
        cursor_revoked_at = decoded_cursor.get("revoked_at")
        cursor_id = decoded_cursor.get("id")
        if not isinstance(cursor_revoked_at, str) or not isinstance(cursor_id, str):
            raise HTTPException(status_code=400, detail="Invalid cursor")
        try:
            cursor_ts = datetime.fromisoformat(cursor_revoked_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid cursor") from exc
        params.extend([cursor_ts, cursor_id])
        where_clauses.append(
            f"(revoked_at, id) > (${len(params) - 1}::timestamptz, ${len(params)}::uuid)"
        )

    params.append(validated_limit + 1)
    query = (
        "SELECT id, certificate_id, revoked_at"
        " FROM {{tables.team_certificates}}"
        " WHERE " + " AND ".join(where_clauses)
        + " ORDER BY revoked_at, id"
        f" LIMIT ${len(params)}"
    )
    rows = await db.fetch_all(query, *params)
    has_more = len(rows) > validated_limit
    page_rows = rows[:validated_limit]
    next_cursor = None
    if has_more and page_rows:
        last = page_rows[-1]
        next_cursor = encode_cursor({
            "revoked_at": last["revoked_at"].isoformat(),
            "id": str(last["id"]),
        })

    return RevocationListResponse(
        revocations=[
            RevocationEntry(
                certificate_id=r["certificate_id"],
                revoked_at=r["revoked_at"].isoformat(),
            )
            for r in page_rows
        ],
        has_more=has_more,
        next_cursor=next_cursor,
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
        identity_scope=row["identity_scope"],
        issued_at=row["issued_at"].isoformat(),
        revoked_at=row["revoked_at"].isoformat() if row["revoked_at"] else None,
    )
