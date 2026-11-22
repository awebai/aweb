from __future__ import annotations

from aweb.member_team_key import current_member_sql

from aweb.identity_binding import IdentityProjectionField, verified_identity_field_sql
from aweb.application_state import application_registry_client
from aweb.grant_liveness_policy import GrantLivenessFailurePolicy

import json
import logging
from datetime import datetime, timezone
from typing import Any, Literal, Optional
from uuid import UUID

import asyncpg
from awid.dns_auth import validate_did_key, verify_signed_json_request
from awid.e2ee_keys import validate_encryption_key_assertion
from awid.team_ids import parse_team_id
from fastapi import APIRouter, Body, Depends, HTTPException, Request
from pgdbm import AsyncDatabaseManager, TransactionManager
from pgdbm.errors import QueryError
from pydantic import (
    BaseModel,
    Field,
    field_validator,
    model_serializer,
    model_validator,
)

from aweb.agent_wake import (
    agent_wake_key,
    agent_wake_publisher,
    agent_wake_scope,
    record_agent_wake,
)
from aweb.alias_allocator import candidate_name_prefixes, used_name_prefixes
from aweb.auth_context import GRANT_SCOPE_ANY
from aweb.certificate_auth import VerifiedCertificateGeneration
from aweb.coordination.roles import ROLE_MAX_LENGTH
from aweb.coordination.routes.repos import canonicalize_git_url
from aweb.coordination.workspace_registry import ensure_repo
from aweb.deps import get_db, get_redis
from aweb.grant_liveness import (
    cleanup_expired_grant_liveness,
    grant_liveness_expiry,
    workspace_grant_liveness_join_sql,
)
from aweb.human_kind import agent_listing_predicate_sql, effective_agent_type
from aweb.identity_address import require_address_evidence
from aweb.inbound_modes import (
    INBOUND_MODES,
    effective_inbound_mode,
    normalize_inbound_mode,
    set_identity_inbound_mode,
)
from aweb.member_team_key import MemberProjection, current_member, read_member_projection
from aweb.role_name_compat import (
    normalize_optional_role_name,
    resolve_role_name_aliases,
)
from aweb.service_errors import ForbiddenError
from aweb.team_registry import resolve_team_key
from aweb.team_auth_deps import (
    TeamIdentity,
    get_team_identity,
    team_identity_with_grant_scope,
)

from ..presence import update_agent_presence
from aweb.config import get_presence_ttl_seconds
from aweb.workspace_activity import (
    PresenceStatus,
    workspace_activity_by_id,
    latest_workspace_activity,
)

router = APIRouter(prefix="/v1/agents", tags=["agents"])
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class AgentView(BaseModel):
    agent_id: str
    alias: str
    did_key: str
    did_aw: Optional[str] = None
    address: Optional[str] = None
    human_name: Optional[str] = None
    agent_type: Optional[str] = None
    workspace_type: Optional[str] = None
    role: Optional[str] = None
    role_name: Optional[str] = None
    hostname: Optional[str] = None
    workspace_path: Optional[str] = None
    repo: Optional[str] = None
    status: str = "offline"
    last_seen: Optional[str] = None
    online: bool = False
    identity_scope: str = "local"
    inbound_mode: Optional[str] = None
    encryption_key: Optional["EncryptionKeyAssertion"] = None


class ListAgentsResponse(BaseModel):
    team_id: str
    agents: list[AgentView]


class HeartbeatResponse(BaseModel):
    agent_id: str
    alias: str
    last_seen_at: str


class AgentInboundModeResponse(BaseModel):
    agent_id: str
    team_id: str
    alias: str
    identity_scope: str
    inbound_mode: str
    configurable: bool


class EncryptionKeyAssertion(BaseModel):
    model_config = {"extra": "forbid"}

    operation: Literal["publish_encryption_key"]
    version: Literal["aweb-e2ee-key-v1"]
    identity_did: str = Field(..., max_length=256)
    identity_stable_id: Optional[str] = Field(default=None, max_length=256)
    custody: Optional[Literal["self", "hosted_custodial"]] = None
    encryption_key_id: str = Field(..., max_length=128)
    encryption_public_key: str = Field(..., max_length=128)
    algorithm: Literal["x25519"]
    created_at: str = Field(..., max_length=64)
    not_before: str = Field(..., max_length=64)
    expires_at: str = Field(..., max_length=64)
    previous_encryption_key_id: Optional[str] = Field(default=None, max_length=128)
    signature: str = Field(..., max_length=2048)

    @model_serializer(mode="wrap")
    def serialize_without_null_optional_fields(self, handler):
        """Serialize the public assertion while omitting absent optional fields."""
        return {key: value for key, value in handler(self).items() if value is not None}


class PublishEncryptionKeyResponse(BaseModel):
    agent_id: str
    team_id: str
    alias: str
    encryption_key: EncryptionKeyAssertion


class UpdateAgentInboundModeRequest(BaseModel):
    model_config = {"extra": "forbid"}

    inbound_mode: str = Field(..., min_length=1, max_length=32)

    @field_validator("inbound_mode")
    @classmethod
    def validate_inbound_mode(cls, value: str) -> str:
        """Accept only the native inbound delivery modes supported by this request."""
        return normalize_inbound_mode(value, default="")


class SuggestAliasPrefixRequest(BaseModel):
    model_config = {"extra": "forbid"}

    scope: Literal["local", "global"] = "local"
    exclude: list[str] = Field(default_factory=list, max_length=100)
    count: int = Field(default=1, ge=1, le=100)

    @field_validator("exclude")
    @classmethod
    def validate_exclude(cls, values: list[str]) -> list[str]:
        """Normalize the requested exclusion list for alias suggestions."""
        out: list[str] = []
        for value in values or []:
            item = str(value or "").strip().lower()
            if item:
                out.append(item)
        return out


class SuggestAliasPrefixName(BaseModel):
    name: str


class SuggestAliasPrefixResponse(BaseModel):
    team_id: str
    name_prefix: str
    names: Optional[list[SuggestAliasPrefixName]] = None


class PatchWorkspaceRequest(BaseModel):
    model_config = {"extra": "forbid"}

    hostname: Optional[str] = Field(None, max_length=256)
    workspace_path: Optional[str] = Field(None, max_length=1024)
    role: Optional[str] = Field(None, max_length=ROLE_MAX_LENGTH)
    role_name: Optional[str] = Field(None, max_length=ROLE_MAX_LENGTH)
    human_name: Optional[str] = Field(None, max_length=64)
    repo_origin: Optional[str] = Field(None, max_length=2048)

    @field_validator("role", "role_name")
    @classmethod
    def validate_role_field(cls, value: Optional[str]) -> Optional[str]:
        """Validate a requested role against the native role-name contract."""
        return normalize_optional_role_name(value)

    @model_validator(mode="after")
    def sync_role_aliases(self):
        """Keep the supported role input spellings consistent before request handling."""
        resolved = resolve_role_name_aliases(role=self.role, role_name=self.role_name)
        self.role = resolved
        self.role_name = resolved
        return self


class PatchWorkspaceResponse(BaseModel):
    agent_id: str
    alias: str
    hostname: Optional[str] = None
    workspace_path: Optional[str] = None
    role: Optional[str] = None
    role_name: Optional[str] = None
    human_name: Optional[str] = None
    repo_id: Optional[str] = None
    canonical_origin: Optional[str] = None

    @model_validator(mode="after")
    def sync_role_aliases(self):
        """Keep the supported role input spellings consistent before request handling."""
        resolved = resolve_role_name_aliases(role=self.role, role_name=self.role_name)
        self.role = resolved
        self.role_name = resolved
        return self


class SendControlSignalRequest(BaseModel):
    model_config = {"extra": "forbid"}

    signal: Literal["pause", "resume", "interrupt"]


class ReplaceLocalIdentityKeyRequest(BaseModel):
    model_config = {"extra": "forbid"}

    team_id: str = Field(..., min_length=1, max_length=256)
    old_did_key: str = Field(..., min_length=1, max_length=256)
    new_did_key: str = Field(..., min_length=1, max_length=256)
    old_certificate_id: str = Field(..., min_length=1, max_length=256)
    new_certificate_id: str = Field(..., min_length=1, max_length=256)

    @field_validator("old_did_key", "new_did_key")
    @classmethod
    def validate_identity_did_key(cls, value: str) -> str:
        """Validate the asserted public identity key before publication."""
        return validate_did_key(value)

    @model_validator(mode="after")
    def require_changed_key(self):
        """Require a changed public key for this rotation request."""
        if self.old_did_key == self.new_did_key:
            raise ValueError("new_did_key must differ from old_did_key")
        return self


class ReplaceLocalIdentityKeyResponse(BaseModel):
    status: Literal["replaced"] = "replaced"
    audit_id: str
    agent_id: str
    team_id: str
    alias: str
    old_did_key: str
    new_did_key: str
    old_certificate_id: str
    new_certificate_id: str
    authorized_by: str
    authorized_at: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/suggest-alias-prefix",
    response_model=SuggestAliasPrefixResponse,
    response_model_exclude_none=True,
)
async def suggest_alias_prefix(
    request: Request,
    payload: SuggestAliasPrefixRequest | None = Body(default=None),
    db=Depends(get_db),
    identity: TeamIdentity = Depends(get_team_identity),
) -> SuggestAliasPrefixResponse:
    """Suggest next available agent names for the authenticated team/scope."""
    include_names = payload is not None
    request_payload = payload or SuggestAliasPrefixRequest()
    aweb_db = db.get_manager("aweb")
    if request_payload.scope == "global":
        existing = await _global_namespace_names(request, identity)
        user_prefix = _identity_global_name_prefix(identity)
        names = _suggest_scoped_names(
            existing,
            request_payload.exclude,
            count=request_payload.count,
            user_prefix=user_prefix,
        )
    else:
        existing = await _local_team_aliases(aweb_db, identity.team_id)
        names = _suggest_scoped_names(
            existing, request_payload.exclude, count=request_payload.count
        )
    if not names:
        raise HTTPException(status_code=409, detail="alias_exhausted")
    return SuggestAliasPrefixResponse(
        team_id=identity.team_id,
        name_prefix=names[0],
        names=[SuggestAliasPrefixName(name=name) for name in names]
        if include_names
        else None,
    )


async def _local_team_aliases(aweb_db, team_id: str) -> list[str]:
    rows = await aweb_db.fetch_all(
        """
        SELECT alias
        FROM (
            SELECT alias
            FROM {{tables.workspaces}}
            WHERE team_id = $1 AND deleted_at IS NULL
            UNION
            SELECT alias
            FROM {{tables.agents}}
            WHERE team_id = $1 AND deleted_at IS NULL
        ) aliases
        ORDER BY alias
        """,
        team_id,
    )
    return [str(r.get("alias") or "") for r in rows]


async def _global_namespace_names(
    request: Request, identity: TeamIdentity
) -> list[str]:
    namespace, _team_name = parse_team_id(identity.team_id)
    registry_client = application_registry_client(request.app.state)
    try:
        addresses = await registry_client.list_addresses(namespace)
    except Exception as exc:
        raise HTTPException(
            status_code=503, detail="awid_registry_unavailable"
        ) from exc
    names = []
    for address in addresses or []:
        if isinstance(address, dict):
            domain = str(address.get("domain") or "").strip().lower()
            name = str(address.get("name") or "").strip()
        else:
            domain = str(getattr(address, "domain", "") or "").strip().lower()
            name = str(getattr(address, "name", "") or "").strip()
        if domain == namespace and name:
            names.append(name)
    return names


def _suggest_scoped_names(
    existing_names: list[str],
    exclude: list[str],
    *,
    count: int,
    user_prefix: str | None = None,
) -> list[str]:
    if user_prefix:
        used = _used_global_names(existing_names, exclude, user_prefix=user_prefix)
    else:
        used = used_name_prefixes([*existing_names, *exclude])
    out: list[str] = []
    for candidate in candidate_name_prefixes():
        name = f"{user_prefix}-{candidate}" if user_prefix else candidate
        key = name.lower() if user_prefix else candidate
        if key in used:
            continue
        used.add(key)
        out.append(name)
        if len(out) >= count:
            return out
    return out


def _used_global_names(
    existing_names: list[str], exclude: list[str], *, user_prefix: str
) -> set[str]:
    used = {
        str(name or "").strip().lower()
        for name in existing_names
        if str(name or "").strip()
    }
    prefix = f"{user_prefix}-"
    for value in exclude:
        item = str(value or "").strip().lower()
        if not item:
            continue
        used.add(item)
        if not item.startswith(prefix):
            used.add(prefix + item)
    return used


def _identity_global_name_prefix(identity: TeamIdentity) -> str:

    require_address_evidence(identity)
    raw = ""
    if identity.address and "/" in identity.address:
        _namespace, raw = identity.address.split("/", 1)
    raw = (raw or identity.alias or "").strip().lower()
    if not raw:
        raise HTTPException(
            status_code=422, detail="global_scope_requires_identity_prefix"
        )
    for candidate in candidate_name_prefixes():
        suffix = f"-{candidate}"
        if raw.endswith(suffix) and raw[: -len(suffix)].strip("-"):
            return raw[: -len(suffix)].strip("-")
    return raw


@router.get("", response_model=ListAgentsResponse)
async def list_agents(
    request: Request,
    db=Depends(get_db),
    redis=Depends(get_redis),
    identity: TeamIdentity = Depends(team_identity_with_grant_scope(GRANT_SCOPE_ANY)),
) -> ListAgentsResponse:
    """List agents in the current team."""
    aweb_db = db.get_manager("aweb")

    rows = await aweb_db.fetch_all(
        f"""
        SELECT a.agent_id, a.alias, a.did_key, projected.did_aw, projected.address,
               a.human_name, a.agent_type, a.human_verified_key, a.role, a.identity_scope,
               a.inbound_mode, a.status,
               e.encryption_key_id,
               e.encryption_public_key,
               e.algorithm AS encryption_key_algorithm,
               e.identity_did AS encryption_key_identity_did,
               e.identity_stable_id AS encryption_key_identity_stable_id,
               e.assertion_custody AS encryption_key_custody,
               e.created_at_text AS encryption_key_created_at,
               e.not_before_text AS encryption_key_not_before,
               e.expires_at_text AS encryption_key_expires_at,
               e.previous_encryption_key_id,
               e.assertion_signature AS encryption_key_signature
        FROM {{{{tables.agents}}}} a
        CROSS JOIN LATERAL (
            SELECT {verified_identity_field_sql(IdentityProjectionField.STABLE_DID, agent="a")} AS did_aw,
                   {verified_identity_field_sql(IdentityProjectionField.ADDRESS, agent="a")} AS address
        ) projected
        LEFT JOIN LATERAL (
            SELECT encryption_key_id, encryption_public_key, algorithm,
                   identity_did, identity_stable_id, assertion_custody, created_at_text,
                   not_before_text, expires_at_text,
                   previous_encryption_key_id, assertion_signature
            FROM {{{{tables.agent_encryption_keys}}}}
            WHERE agent_id = a.agent_id
              AND team_id = a.team_id
              AND identity_did = a.did_key
              AND (
                  (NULLIF(BTRIM(COALESCE(projected.did_aw, '')), '') IS NULL
                   AND identity_stable_id IS NULL)
                  OR identity_stable_id = projected.did_aw
              )
              AND revoked_at IS NULL
              AND not_before_at <= NOW()
              AND expires_at > NOW()
            ORDER BY assertion_created_at DESC, not_before_at DESC, encryption_key_id DESC
            LIMIT 1
        ) e ON TRUE
        WHERE a.team_id = $1 AND {current_member_sql("a")}
          AND {agent_listing_predicate_sql("a")}
        ORDER BY a.alias
        """,
        identity.team_id,
    )

    workspace_rows = await aweb_db.fetch_all(
        f"""SELECT w.workspace_id, w.agent_id, w.workspace_type, w.hostname,
                  w.team_id, w.last_seen_at, w.workspace_path, w.role AS ws_role,
                  r.canonical_origin AS repo, grant_liveness.*
           FROM {{{{tables.workspaces}}}} w
           LEFT JOIN {{{{tables.repos}}}} r ON r.id=w.repo_id AND r.deleted_at IS NULL
           {workspace_grant_liveness_join_sql(workspace="w", ttl_seconds_parameter="$2")}
           WHERE w.team_id=$1 AND w.deleted_at IS NULL
           ORDER BY w.last_seen_at DESC NULLS LAST, w.created_at DESC, w.workspace_id,
                    grant_liveness.grant_liveness_last_seen_at DESC,
                    grant_liveness.grant_liveness_grant_id""",
        identity.team_id,
        get_presence_ttl_seconds(),
    )
    activity_by_id = await workspace_activity_by_id(
        aweb_db,
        redis,
        workspace_ids=[str(row["workspace_id"]) for row in workspace_rows],
        workspace_rows=workspace_rows,
        registry_client=application_registry_client(request.app.state),
        request=request,
        failure_policy=GrantLivenessFailurePolicy.OMIT_UNPROVEN,
    )
    context_by_agent = latest_workspace_activity(workspace_rows, activity_by_id)
    now = datetime.now(timezone.utc)

    agents: list[AgentView] = []
    for r in rows:
        agent_id = str(r["agent_id"])
        selected = context_by_agent.get(agent_id)
        ctx = selected.workspace if selected else None
        activity = selected.activity if selected else None
        presence = activity.presence if activity else None
        online = activity is not None and activity.is_online(now=now)
        status = (
            activity.display_status(now=now) if activity else PresenceStatus.OFFLINE
        )
        last_seen_at = activity.last_seen_at if activity else None
        last_seen = None
        role = (ctx.get("ws_role") if ctx else None) or (r.get("role") or None)
        if online and last_seen_at is not None:
            last_seen = last_seen_at.astimezone(timezone.utc).isoformat()
        if presence:
            role = presence.get("role") or role

        agents.append(
            AgentView(
                agent_id=agent_id,
                alias=r["alias"],
                did_key=r["did_key"],
                did_aw=r.get("did_aw"),
                address=r.get("address"),
                human_name=r.get("human_name") or None,
                agent_type=effective_agent_type(r),
                workspace_type=(ctx.get("workspace_type") if ctx else None),
                role=role,
                role_name=role,
                hostname=(ctx.get("hostname") if ctx else None),
                workspace_path=(ctx.get("workspace_path") if ctx else None),
                repo=(ctx.get("repo") if ctx else None),
                status=status,
                last_seen=last_seen,
                online=online,
                identity_scope=str(r.get("identity_scope") or "local"),
                inbound_mode=r.get("inbound_mode") or None,
                encryption_key=_encryption_assertion_from_row(r),
            )
        )

    return ListAgentsResponse(team_id=identity.team_id, agents=agents)


def _encryption_assertion_from_row(row) -> EncryptionKeyAssertion | None:
    if not row.get("encryption_key_id"):
        return None
    return EncryptionKeyAssertion(
        operation="publish_encryption_key",
        version="aweb-e2ee-key-v1",
        identity_did=row["encryption_key_identity_did"],
        identity_stable_id=row.get("encryption_key_identity_stable_id") or None,
        custody=row.get("encryption_key_custody") or None,
        encryption_key_id=row["encryption_key_id"],
        encryption_public_key=row["encryption_public_key"],
        algorithm=row["encryption_key_algorithm"],
        created_at=row["encryption_key_created_at"],
        not_before=row["encryption_key_not_before"],
        expires_at=row["encryption_key_expires_at"],
        previous_encryption_key_id=row.get("previous_encryption_key_id") or None,
        signature=row["encryption_key_signature"],
    )


@router.post("/heartbeat", response_model=HeartbeatResponse)
async def heartbeat(
    request: Request,
    db=Depends(get_db),
    redis=Depends(get_redis),
    identity: TeamIdentity = Depends(team_identity_with_grant_scope("presence.write")),
) -> HeartbeatResponse:
    """Update workspace last_seen_at and Redis presence."""
    aweb_db = db.get_manager("aweb")

    if identity.grant is not None:
        workspace = await aweb_db.fetch_one(
            """
            SELECT w.workspace_id
            FROM {{tables.workspaces}} w
            JOIN {{tables.agents}} a
              ON a.team_id = w.team_id
             AND a.agent_id = w.agent_id
             AND a.deleted_at IS NULL
            WHERE w.team_id = $1
              AND w.agent_id = $2::UUID
              AND w.alias = $3
              AND w.deleted_at IS NULL
            """,
            identity.team_id,
            identity.agent_id,
            identity.alias,
        )
        if workspace is None:
            raise HTTPException(status_code=409, detail="Agent has no active workspace")
        await cleanup_expired_grant_liveness(aweb_db)
        row = await aweb_db.fetch_one(
            """
            INSERT INTO {{tables.identity_grant_liveness}} (
                grant_id, team_id, subject_agent_id, workspace_id, alias,
                session_did_key, last_seen_at, expires_at
            )
            VALUES ($1::UUID, $2, $3::UUID, $4::UUID, $5, $6, NOW(), $7)
            ON CONFLICT (grant_id) DO UPDATE
            SET team_id = EXCLUDED.team_id,
                subject_agent_id = EXCLUDED.subject_agent_id,
                workspace_id = EXCLUDED.workspace_id,
                alias = EXCLUDED.alias,
                session_did_key = EXCLUDED.session_did_key,
                last_seen_at = EXCLUDED.last_seen_at,
                expires_at = EXCLUDED.expires_at
            RETURNING last_seen_at
            """,
            identity.grant.grant_id,
            identity.team_id,
            identity.agent_id,
            workspace["workspace_id"],
            identity.alias,
            identity.grant.session_did_key,
            grant_liveness_expiry(identity.grant),
        )
        return HeartbeatResponse(
            agent_id=identity.agent_id,
            alias=identity.alias,
            last_seen_at=row["last_seen_at"].astimezone(timezone.utc).isoformat(),
        )

    # Root/team-certificate heartbeat keeps today's workspace/Redis presence
    # semantics. Grant heartbeat intentionally does not write these shared
    # coordinates; it records grant-keyed ephemeral liveness above.
    workspace = await aweb_db.fetch_one(
        """
        UPDATE {{tables.workspaces}} w
        SET last_seen_at = NOW(), updated_at = NOW()
        FROM {{tables.agents}} a
        WHERE w.team_id = $1
          AND w.agent_id = $2::UUID
          AND w.alias = $3
          AND w.deleted_at IS NULL
          AND a.team_id = w.team_id
          AND a.agent_id = w.agent_id
          AND a.deleted_at IS NULL
        RETURNING w.workspace_id
        """,
        identity.team_id,
        identity.agent_id,
        identity.alias,
    )
    if workspace is None:
        raise HTTPException(status_code=409, detail="Agent has no active workspace")

    ttl_seconds = get_presence_ttl_seconds()
    last_seen = await update_agent_presence(
        redis,
        workspace_id=str(workspace["workspace_id"]),
        alias=identity.alias,
        team_id=identity.team_id,
        ttl_seconds=ttl_seconds,
    )

    return HeartbeatResponse(
        agent_id=identity.agent_id,
        alias=identity.alias,
        last_seen_at=last_seen,
    )


async def _load_current_agent_inbound_mode(
    db,
    identity: TeamIdentity,
) -> AgentInboundModeResponse:
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT agent_id, team_id, alias, identity_scope, inbound_mode, did_aw
        FROM {{tables.agents}}
        WHERE team_id = $1
          AND agent_id = $2::UUID
          AND deleted_at IS NULL
        """,
        identity.team_id,
        identity.agent_id,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    identity_scope = str(row.get("identity_scope") or "local")
    inbound_mode = str(row.get("inbound_mode") or "").strip().lower()
    if str(row.get("did_aw") or "").startswith("did:aw:"):
        try:
            inbound_mode = await effective_inbound_mode(aweb_db, row["did_aw"])
        except ForbiddenError as exc:
            raise HTTPException(
                status_code=409, detail="Agent inbound policy is unavailable"
            ) from exc
    if inbound_mode not in INBOUND_MODES:
        raise HTTPException(status_code=409, detail="Agent inbound policy is unavailable")
    return AgentInboundModeResponse(
        agent_id=str(row["agent_id"]),
        team_id=str(row["team_id"]),
        alias=str(row["alias"]),
        identity_scope=identity_scope,
        inbound_mode=inbound_mode,
        configurable=identity_scope == "global",
    )


@router.get("/me/inbound-mode", response_model=AgentInboundModeResponse)
async def get_my_inbound_mode(
    request: Request,
    db=Depends(get_db),
    identity: TeamIdentity = Depends(get_team_identity),
) -> AgentInboundModeResponse:
    """Return the calling agent's inbound delivery mode."""
    return await _load_current_agent_inbound_mode(db, identity)


@router.patch("/me/inbound-mode", response_model=AgentInboundModeResponse)
async def update_my_inbound_mode(
    request: Request,
    payload: UpdateAgentInboundModeRequest,
    db=Depends(get_db),
    identity: TeamIdentity = Depends(get_team_identity),
) -> AgentInboundModeResponse:
    """Update the calling global agent's inbound delivery mode."""
    state = await _load_current_agent_inbound_mode(db, identity)
    if state.identity_scope != "global":
        raise HTTPException(
            status_code=409,
            detail="inbound_mode is only configurable for global identities",
        )
    # Only authentication's verified global identity may select an identity-wide
    # write. A membership row's raw claim is not identity authority.
    did_aw = str(identity.did_aw or "").strip()
    if not did_aw.startswith("did:aw:"):
        raise HTTPException(status_code=409, detail="Agent identity migration required")
    aweb_db = db.get_manager("aweb")
    async with aweb_db.transaction() as tx:
        await set_identity_inbound_mode(tx, did_aw, payload.inbound_mode)
    return await _load_current_agent_inbound_mode(db, identity)


@router.put(
    "/me/encryption-key",
    response_model=PublishEncryptionKeyResponse,
    response_model_exclude_none=True,
)
async def publish_my_encryption_key(
    request: Request,
    payload: EncryptionKeyAssertion,
    db=Depends(get_db),
    identity: TeamIdentity = Depends(get_team_identity),
) -> PublishEncryptionKeyResponse:
    """Publish the calling agent's identity-signed E2E encryption key."""
    return await publish_encryption_key(
        db=db.get_manager("aweb"), identity=identity, payload=payload
    )


async def publish_encryption_key(
    *,
    db: AsyncDatabaseManager | TransactionManager,
    payload: EncryptionKeyAssertion,
    identity: TeamIdentity | None = None,
    generation: VerifiedCertificateGeneration | None = None,
    agent_id: UUID | None = None,
) -> PublishEncryptionKeyResponse:
    """Validate and store a request-authenticated or just-admitted member's key.

    Request callers supply TeamIdentity. System admission callers supply the
    actual generation and exact agent UUID inside the same open transaction
    as connect_agent, retaining its team-then-member locks. This operation
    never creates request proof or admits pending material. Current eligibility
    and exact certificate/key equality come from the canonical member owner;
    stable identity attribution comes only from its verified projection.
    Both paths share signature/validity validation and storage. Private key
    material stays with its custody owner; same-key renewal is supported.
    """
    if (identity is None) == (generation is None) or (
        identity is not None and agent_id is not None
    ):
        raise HTTPException(
            status_code=422,
            detail={
                "code": "encryption_publication_input_invalid",
                "message": "Supply either a verified request identity or the admitted generation and agent_id, then retry.",
            },
        )
    aweb_db = db
    row: MemberProjection | dict[str, Any] | None = None
    if generation is not None:
        if (
            not isinstance(generation, VerifiedCertificateGeneration)
            or not isinstance(agent_id, UUID)
            or not isinstance(db, TransactionManager)
        ):
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "encryption_admission_transaction_required",
                    "message": "Publish the verified generation and exact agent_id inside the same open admission transaction, then retry.",
                },
            )
        claims = generation.certificate.claims
        projection = await read_member_projection(
            db, team_id=claims["team_id"], agent_id=agent_id
        )
        if (
            projection is None
            or not current_member(projection)
            or any(
                (
                    projection["did_key"] != claims["member_did_key"],
                    projection["certificate_id"] != claims["certificate_id"],
                    projection["accepted_team_did_key"]
                    != generation.verified_team_did_key,
                )
            )
        ):
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "encryption_admission_conflict",
                    "message": "The generation does not match the current admitted member. Complete admission with the current certificate and retry in that transaction.",
                },
            )
        row = projection.verified_identity()
        principal = row
        member_key = principal["did_key"]
        member_id = principal["agent_id"]
        team_id = principal["team_id"]
        expected_stable_id = principal["did_aw"] or None
    else:
        assert identity is not None  # The exclusive-input check above establishes this.
        member_key = identity.did_key
        member_id = identity.agent_id
        team_id = identity.team_id
        expected_stable_id = identity.did_aw.strip() or None
    try:
        canonical_payload, created_at, not_before, expires_at = (
            validate_encryption_key_assertion(
                payload.model_dump(exclude_none=True),
                current_did_key=member_key,
                stable_id=expected_stable_id,
                now=datetime.now(timezone.utc),
            )
        )
    except ValueError as exc:
        logger.warning(
            "Encryption-key assertion refused for member %s", member_id, exc_info=True
        )
        raise HTTPException(
            status_code=422,
            detail={
                "code": "invalid_encryption_key_assertion",
                "message": str(exc)
                + ". Publish an identity-signed encryption-key assertion "
                "with current validity and matching identity fields, then retry.",
            },
        )

    if row is None:
        row = await aweb_db.fetch_one(
            """
            SELECT agent_id, team_id, alias
            FROM {{tables.agents}}
            WHERE team_id = $1
              AND agent_id = $2::UUID
              AND did_key = $3
              AND deleted_at IS NULL
            """,
            team_id,
            member_id,
            member_key,
        )
    if row is None:
        raise HTTPException(
            status_code=404,
            detail="Agent not found. Reconnect this identity to the team before publishing its encryption key.",
        )

    await aweb_db.execute(
        """
        INSERT INTO {{tables.agent_encryption_keys}} (
            agent_id,
            team_id,
            encryption_key_id,
            encryption_public_key,
            algorithm,
            identity_did,
            identity_stable_id,
            assertion_custody,
            assertion_signature,
            assertion_canonical,
            created_at_text,
            not_before_text,
            expires_at_text,
            assertion_created_at,
            not_before_at,
            expires_at,
            previous_encryption_key_id,
            revoked_at
        )
        VALUES (
            $1::UUID, $2, $3, $4, $5, $6, $7, $8, $9,
            $10, $11, $12, $13, $14, $15, $16, $17, NULL
        )
        ON CONFLICT (agent_id, encryption_key_id) DO UPDATE SET
            team_id = EXCLUDED.team_id,
            encryption_public_key = EXCLUDED.encryption_public_key,
            algorithm = EXCLUDED.algorithm,
            identity_did = EXCLUDED.identity_did,
            identity_stable_id = EXCLUDED.identity_stable_id,
            assertion_custody = EXCLUDED.assertion_custody,
            assertion_signature = EXCLUDED.assertion_signature,
            assertion_canonical = EXCLUDED.assertion_canonical,
            created_at_text = EXCLUDED.created_at_text,
            not_before_text = EXCLUDED.not_before_text,
            expires_at_text = EXCLUDED.expires_at_text,
            assertion_created_at = EXCLUDED.assertion_created_at,
            not_before_at = EXCLUDED.not_before_at,
            expires_at = EXCLUDED.expires_at,
            previous_encryption_key_id = EXCLUDED.previous_encryption_key_id,
            published_at = NOW(),
            revoked_at = NULL
        """,
        member_id,
        team_id,
        payload.encryption_key_id,
        payload.encryption_public_key,
        payload.algorithm,
        payload.identity_did,
        payload.identity_stable_id,
        payload.custody,
        payload.signature,
        canonical_payload.decode("utf-8"),
        payload.created_at,
        payload.not_before,
        payload.expires_at,
        created_at,
        not_before,
        expires_at,
        payload.previous_encryption_key_id,
    )
    return PublishEncryptionKeyResponse(
        agent_id=str(row["agent_id"]),
        team_id=str(row["team_id"]),
        alias=str(row["alias"]),
        encryption_key=payload,
    )


@router.patch("/me", response_model=PatchWorkspaceResponse)
async def patch_agent_workspace(
    request: Request,
    payload: PatchWorkspaceRequest,
    db=Depends(get_db),
    identity: TeamIdentity = Depends(get_team_identity),
) -> PatchWorkspaceResponse:
    """Update the calling agent's workspace info."""
    aweb_db = db.get_manager("aweb")

    row = await aweb_db.fetch_one(
        """
        SELECT w.workspace_id, w.hostname, w.workspace_path, w.role,
               w.human_name, w.repo_id, r.canonical_origin
        FROM {{tables.workspaces}} w
        JOIN {{tables.agents}} a ON a.agent_id = w.agent_id
        LEFT JOIN {{tables.repos}} r ON r.id = w.repo_id AND r.deleted_at IS NULL
        WHERE w.team_id = $1
          AND a.agent_id = $2::UUID
          AND a.deleted_at IS NULL
          AND w.deleted_at IS NULL
        """,
        identity.team_id,
        identity.agent_id,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Workspace not found")

    new_hostname = payload.hostname if payload.hostname is not None else row["hostname"]
    new_path = (
        payload.workspace_path
        if payload.workspace_path is not None
        else row["workspace_path"]
    )
    new_role = payload.role if payload.role is not None else row["role"]
    new_human_name = (
        payload.human_name if payload.human_name is not None else row["human_name"]
    )
    new_repo_id = row["repo_id"]
    canonical_origin = row["canonical_origin"]
    if payload.repo_origin is not None:
        try:
            canonical_origin = canonicalize_git_url(payload.repo_origin)
            new_repo_id = await ensure_repo(
                aweb_db, identity.team_id, payload.repo_origin
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=422, detail=f"invalid repo_origin: {exc}"
            ) from exc

    await aweb_db.execute(
        """
        UPDATE {{tables.workspaces}}
        SET hostname = $1, workspace_path = $2, role = $3,
            human_name = $4,
            repo_id = CASE WHEN $6::BOOLEAN THEN $5::UUID ELSE repo_id END,
            workspace_type = CASE WHEN $6::BOOLEAN THEN 'agent' ELSE workspace_type END,
            updated_at = NOW()
        WHERE workspace_id = $7
        """,
        new_hostname,
        new_path,
        new_role,
        new_human_name,
        new_repo_id,
        payload.repo_origin is not None,
        row["workspace_id"],
    )

    return PatchWorkspaceResponse(
        agent_id=identity.agent_id,
        alias=identity.alias,
        hostname=new_hostname,
        workspace_path=new_path,
        role=new_role,
        role_name=new_role,
        human_name=new_human_name,
        repo_id=str(new_repo_id) if new_repo_id else None,
        canonical_origin=canonical_origin,
    )


@router.post("/{alias}/replace-key", response_model=ReplaceLocalIdentityKeyResponse)
async def replace_local_identity_key(
    request: Request,
    alias: str,
    payload: ReplaceLocalIdentityKeyRequest,
    db=Depends(get_db),
) -> ReplaceLocalIdentityKeyResponse:
    """Replace a local member did:key under team-controller authority."""
    alias = alias.strip()
    if not alias:
        raise HTTPException(status_code=422, detail="Agent alias is required")
    team_id = payload.team_id.strip()
    try:
        parse_team_id(team_id)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    aweb_db = db.get_manager("aweb")
    team = await aweb_db.fetch_one(
        "SELECT team_id FROM {{tables.teams}} WHERE team_id = $1",
        team_id,
    )
    if team is None:
        raise HTTPException(status_code=404, detail="Team not found")

    authorizer_did = verify_signed_json_request(
        request,
        payload_dict={
            "operation": "replace_local_identity_key",
            "team_id": team_id,
            "agent_alias": alias,
            "old_did_key": payload.old_did_key,
            "new_did_key": payload.new_did_key,
            "old_certificate_id": payload.old_certificate_id,
            "new_certificate_id": payload.new_certificate_id,
        },
    )
    if authorizer_did != await resolve_team_key(request, team_id):
        raise HTTPException(
            status_code=403,
            detail="Team controller authorization is required for local identity key replacement",
        )

    try:
        async with aweb_db.transaction() as tx:
            agent = await tx.fetch_one(
                """
                SELECT agent_id, did_key, identity_scope
                FROM {{tables.agents}}
                WHERE team_id = $1
                  AND alias = $2
                  AND deleted_at IS NULL
                FOR UPDATE
                """,
                team_id,
                alias,
            )
            if agent is None:
                raise HTTPException(status_code=404, detail="Agent not found")
            if str(agent["identity_scope"]) != "local":
                raise HTTPException(
                    status_code=409,
                    detail="replace-key is only valid for local team-scoped identities",
                )
            current_did_key = str(agent["did_key"])
            audit = None
            if current_did_key == payload.new_did_key:
                # A controller may safely replay the exact transition when the
                # committed response was lost. No other new-key request is a replay.
                audit = await tx.fetch_one(
                    """
                    SELECT id, created_at
                    FROM {{tables.audit_log}}
                    WHERE team_id = $1
                      AND alias = $2
                      AND event_type = 'local_identity_key_replaced'
                      AND resource = $3
                      AND details->>'agent_id' = $4
                      AND details->>'agent_alias' = $5
                      AND details->>'authorized_by' = $2
                      AND details->>'old_did_key' = $6
                      AND details->>'new_did_key' = $7
                      AND details->>'old_certificate_id' = $8
                      AND details->>'new_certificate_id' = $9
                    ORDER BY created_at DESC
                    LIMIT 1
                    """,
                    team_id,
                    authorizer_did,
                    f"agent:{agent['agent_id']}",
                    str(agent["agent_id"]),
                    alias,
                    payload.old_did_key,
                    payload.new_did_key,
                    payload.old_certificate_id,
                    payload.new_certificate_id,
                )
            if current_did_key != payload.old_did_key and audit is None:
                raise HTTPException(
                    status_code=409,
                    detail={
                        "code": "identity_key_changed",
                        "message": (
                            "Agent did:key no longer matches old_did_key; "
                            "re-read the roster before replacing it"
                        ),
                        "current_did_key": current_did_key,
                    },
                )
            if audit is None:
                collision = await tx.fetch_one(
                    """
                    SELECT agent_id
                    FROM {{tables.agents}}
                    WHERE team_id = $1
                      AND did_key = $2
                      AND deleted_at IS NULL
                      AND agent_id <> $3
                    """,
                    team_id,
                    payload.new_did_key,
                    agent["agent_id"],
                )
                if collision is not None:
                    raise HTTPException(
                        status_code=409,
                        detail="new_did_key is already assigned to another active team agent",
                    )

                await tx.execute(
                    "UPDATE {{tables.agents}} SET did_key = $2 WHERE agent_id = $1",
                    agent["agent_id"],
                    payload.new_did_key,
                )
                audit = await tx.fetch_one(
                    """
                    INSERT INTO {{tables.audit_log}}
                        (team_id, alias, event_type, resource, details)
                    VALUES ($1, $2, 'local_identity_key_replaced', $3, $4)
                    RETURNING id, created_at
                    """,
                    team_id,
                    authorizer_did,
                    f"agent:{agent['agent_id']}",
                    json.dumps(
                        {
                            "agent_id": str(agent["agent_id"]),
                            "agent_alias": alias,
                            "authorized_by": authorizer_did,
                            "old_did_key": payload.old_did_key,
                            "new_did_key": payload.new_did_key,
                            "old_certificate_id": payload.old_certificate_id,
                            "new_certificate_id": payload.new_certificate_id,
                        }
                    ),
                )
    except (QueryError, asyncpg.exceptions.UniqueViolationError) as exc:
        if isinstance(exc, QueryError) and not isinstance(
            exc.__cause__, asyncpg.exceptions.UniqueViolationError
        ):
            raise
        raise HTTPException(
            status_code=409,
            detail="new_did_key is already assigned to another active team agent",
        ) from exc

    return ReplaceLocalIdentityKeyResponse(
        audit_id=str(audit["id"]),
        agent_id=str(agent["agent_id"]),
        team_id=team_id,
        alias=alias,
        old_did_key=payload.old_did_key,
        new_did_key=payload.new_did_key,
        old_certificate_id=payload.old_certificate_id,
        new_certificate_id=payload.new_certificate_id,
        authorized_by=authorizer_did,
        authorized_at=audit["created_at"].isoformat(),
    )


@router.post("/{alias}/control")
async def send_control_signal(
    request: Request,
    alias: str,
    payload: SendControlSignalRequest,
    db=Depends(get_db),
    identity: TeamIdentity = Depends(get_team_identity),
):
    """Send a control signal (pause/resume/interrupt) to another agent."""
    aweb_db = db.get_manager("aweb")

    target = await aweb_db.fetch_one(
        """
        SELECT a.agent_id FROM {{tables.agents}} a
        WHERE a.team_id = $1 AND a.alias = $2 AND """
        + current_member_sql("a")
        + """
        """,
        identity.team_id,
        alias,
    )
    if not target:
        raise HTTPException(status_code=404, detail="Agent not found")

    with agent_wake_scope(agent_wake_publisher(request.app.state)):
        result = await aweb_db.fetch_one(
            """
            INSERT INTO {{tables.control_signals}} (team_id, target_agent_id, from_agent_id, signal_type)
            VALUES ($1, $2, $3, $4)
            RETURNING signal_id
            """,
            identity.team_id,
            target["agent_id"],
            UUID(identity.agent_id),
            payload.signal,
        )
        record_agent_wake(agent_wake_key(str(target["agent_id"])), "control")
    return {"signal_id": str(result["signal_id"]), "signal": payload.signal}
