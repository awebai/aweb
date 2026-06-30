from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal, Optional
from uuid import UUID

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator, model_serializer, model_validator

from awid.e2ee_keys import validate_encryption_key_assertion
from awid.team_ids import parse_team_id
from aweb.alias_allocator import candidate_name_prefixes, used_name_prefixes
from aweb.coordination.roles import ROLE_MAX_LENGTH
from aweb.deps import get_db, get_redis
from aweb.role_name_compat import normalize_optional_role_name, resolve_role_name_aliases
from aweb.team_auth_deps import TeamIdentity, get_team_identity

from ..presence import list_agent_presences_by_workspace_ids, update_agent_presence

router = APIRouter(prefix="/v1/agents", tags=["agents"])


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
        value = (value or "").strip().lower()
        if value == "contacts_only":
            return "team_and_contacts"
        if value not in {"open", "team_and_contacts"}:
            raise ValueError("inbound_mode must be one of open, team_and_contacts")
        return value


class SuggestAliasPrefixRequest(BaseModel):
    model_config = {"extra": "forbid"}

    scope: Literal["local", "global"] = "local"
    exclude: list[str] = Field(default_factory=list, max_length=100)
    count: int = Field(default=1, ge=1, le=100)

    @field_validator("exclude")
    @classmethod
    def validate_exclude(cls, values: list[str]) -> list[str]:
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

    @field_validator("role", "role_name")
    @classmethod
    def validate_role_field(cls, value: Optional[str]) -> Optional[str]:
        return normalize_optional_role_name(value)

    @model_validator(mode="after")
    def sync_role_aliases(self):
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

    @model_validator(mode="after")
    def sync_role_aliases(self):
        resolved = resolve_role_name_aliases(role=self.role, role_name=self.role_name)
        self.role = resolved
        self.role_name = resolved
        return self


class SendControlSignalRequest(BaseModel):
    model_config = {"extra": "forbid"}

    signal: Literal["pause", "resume", "interrupt"]


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
        existing = await _global_namespace_names(request, aweb_db, identity)
        user_prefix = _identity_global_name_prefix(identity)
        names = _suggest_scoped_names(
            existing,
            request_payload.exclude,
            count=request_payload.count,
            user_prefix=user_prefix,
        )
    else:
        existing = await _local_team_aliases(aweb_db, identity.team_id)
        names = _suggest_scoped_names(existing, request_payload.exclude, count=request_payload.count)
    if not names:
        raise HTTPException(status_code=409, detail="alias_exhausted")
    return SuggestAliasPrefixResponse(
        team_id=identity.team_id,
        name_prefix=names[0],
        names=[SuggestAliasPrefixName(name=name) for name in names] if include_names else None,
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


async def _global_namespace_names(request: Request, aweb_db, identity: TeamIdentity) -> list[str]:
    namespace, _team_name = parse_team_id(identity.team_id)
    registry_client = getattr(request.app.state, "awid_registry_client", None)
    if registry_client is None or not hasattr(registry_client, "list_addresses"):
        raise HTTPException(status_code=503, detail="awid_registry_unavailable")
    try:
        addresses = await registry_client.list_addresses(namespace)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="awid_registry_unavailable") from exc
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


def _used_global_names(existing_names: list[str], exclude: list[str], *, user_prefix: str) -> set[str]:
    used = {str(name or "").strip().lower() for name in existing_names if str(name or "").strip()}
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
    raw = ""
    if identity.address and "/" in identity.address:
        _namespace, raw = identity.address.split("/", 1)
    raw = (raw or identity.alias or "").strip().lower()
    if not raw:
        raise HTTPException(status_code=422, detail="global_scope_requires_identity_prefix")
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
    identity: TeamIdentity = Depends(get_team_identity),
) -> ListAgentsResponse:
    """List agents in the current team."""
    aweb_db = db.get_manager("aweb")

    rows = await aweb_db.fetch_all(
        """
        SELECT a.agent_id, a.alias, a.did_key, a.did_aw, a.address,
               a.human_name, a.agent_type, a.role, a.identity_scope,
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
        FROM {{tables.agents}} a
        LEFT JOIN LATERAL (
            SELECT encryption_key_id, encryption_public_key, algorithm,
                   identity_did, identity_stable_id, assertion_custody, created_at_text,
                   not_before_text, expires_at_text,
                   previous_encryption_key_id, assertion_signature
            FROM {{tables.agent_encryption_keys}}
            WHERE agent_id = a.agent_id
              AND team_id = a.team_id
              AND identity_did = a.did_key
              AND (
                  (NULLIF(BTRIM(COALESCE(a.did_aw, '')), '') IS NULL
                   AND identity_stable_id IS NULL)
                  OR identity_stable_id = a.did_aw
              )
              AND revoked_at IS NULL
              AND not_before_at <= NOW()
              AND expires_at > NOW()
            ORDER BY assertion_created_at DESC, not_before_at DESC, encryption_key_id DESC
            LIMIT 1
        ) e ON TRUE
        WHERE a.team_id = $1 AND a.deleted_at IS NULL
          AND COALESCE(a.agent_type, 'agent') != 'human'
        ORDER BY a.alias
        """,
        identity.team_id,
    )

    # Workspace context for each agent
    context_rows = await aweb_db.fetch_all(
        """
        SELECT w.agent_id,
               w.workspace_type,
               w.hostname,
               w.workspace_path,
               w.role AS ws_role,
               r.canonical_origin AS repo
        FROM {{tables.workspaces}} w
        LEFT JOIN {{tables.repos}} r ON w.repo_id = r.id AND r.deleted_at IS NULL
        WHERE w.team_id = $1 AND w.deleted_at IS NULL
        """,
        identity.team_id,
    )
    context_by_agent = {str(r["agent_id"]): r for r in context_rows}

    # Presence from Redis
    agent_ids = [str(r["agent_id"]) for r in rows]
    presences = await list_agent_presences_by_workspace_ids(redis, agent_ids) if redis and agent_ids else []
    presence_by_id = {str(p.get("workspace_id")): p for p in presences if p.get("workspace_id")}

    agents: list[AgentView] = []
    for r in rows:
        agent_id = str(r["agent_id"])
        ctx = context_by_agent.get(agent_id)
        presence = presence_by_id.get(agent_id)

        status = "offline"
        last_seen = None
        online = False
        role = (ctx.get("ws_role") if ctx else None) or (r.get("role") or None)

        if presence:
            online = True
            status = presence.get("status") or "active"
            last_seen = presence.get("last_seen") or None
            role = presence.get("role") or role

        agents.append(
            AgentView(
                agent_id=agent_id,
                alias=r["alias"],
                did_key=r["did_key"],
                did_aw=r.get("did_aw"),
                address=r.get("address"),
                human_name=r.get("human_name") or None,
                agent_type=r.get("agent_type") or None,
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
    identity: TeamIdentity = Depends(get_team_identity),
) -> HeartbeatResponse:
    """Update workspace last_seen_at and Redis presence."""
    aweb_db = db.get_manager("aweb")

    # Update last_seen_at on the workspace scoped by team_id
    await aweb_db.execute(
        """
        UPDATE {{tables.workspaces}}
        SET last_seen_at = NOW(), updated_at = NOW()
        WHERE team_id = $1 AND agent_id = (
            SELECT agent_id FROM {{tables.agents}}
            WHERE agent_id = $2::UUID AND team_id = $1 AND deleted_at IS NULL
        ) AND deleted_at IS NULL
        """,
        identity.team_id,
        identity.agent_id,
    )

    ttl_seconds = 1800
    last_seen = await update_agent_presence(
        redis,
        agent_id=identity.agent_id,
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
        SELECT agent_id, team_id, alias, identity_scope, inbound_mode
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
    if inbound_mode == "contacts_only":
        inbound_mode = "team_and_contacts"
    if inbound_mode not in {"open", "team_and_contacts"}:
        raise HTTPException(status_code=409, detail="Agent inbound_mode migration required")
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
        raise HTTPException(status_code=409, detail="inbound_mode is only configurable for global identities")
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        UPDATE {{tables.agents}}
        SET inbound_mode = $3
        WHERE team_id = $1
          AND agent_id = $2::UUID
          AND deleted_at IS NULL
        RETURNING agent_id, team_id, alias, identity_scope, inbound_mode
        """,
        identity.team_id,
        identity.agent_id,
        payload.inbound_mode,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Agent not found")
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
    aweb_db = db.get_manager("aweb")
    expected_stable_id = identity.did_aw.strip() or None
    try:
        canonical_payload, created_at, not_before, expires_at = validate_encryption_key_assertion(
            payload.model_dump(exclude_none=True),
            current_did_key=identity.did_key,
            stable_id=expected_stable_id,
            now=datetime.now(timezone.utc),
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "invalid_encryption_key_assertion",
                "message": str(exc),
            },
        )

    row = await aweb_db.fetch_one(
        """
        SELECT agent_id, team_id, alias
        FROM {{tables.agents}}
        WHERE team_id = $1
          AND agent_id = $2::UUID
          AND did_key = $3
          AND deleted_at IS NULL
        """,
        identity.team_id,
        identity.agent_id,
        identity.did_key,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Agent not found")

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
        identity.agent_id,
        identity.team_id,
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
               w.human_name
        FROM {{tables.workspaces}} w
        JOIN {{tables.agents}} a ON a.agent_id = w.agent_id
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
    new_path = payload.workspace_path if payload.workspace_path is not None else row["workspace_path"]
    new_role = payload.role if payload.role is not None else row["role"]
    new_human_name = payload.human_name if payload.human_name is not None else row["human_name"]

    await aweb_db.execute(
        """
        UPDATE {{tables.workspaces}}
        SET hostname = $1, workspace_path = $2, role = $3,
            human_name = $4, updated_at = NOW()
        WHERE workspace_id = $5
        """,
        new_hostname,
        new_path,
        new_role,
        new_human_name,
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
        SELECT agent_id FROM {{tables.agents}}
        WHERE team_id = $1 AND alias = $2 AND deleted_at IS NULL
        """,
        identity.team_id,
        alias,
    )
    if not target:
        raise HTTPException(status_code=404, detail="Agent not found")

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
    return {"signal_id": str(result["signal_id"]), "signal": payload.signal}
