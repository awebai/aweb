from __future__ import annotations

import json
import os
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from aweb.alias_allocator import suggest_next_name_prefix
from aweb.auth import get_actor_agent_id_from_auth, get_project_from_auth, validate_project_slug
from aweb.deps import get_db, get_redis
from aweb.did import decode_public_key, did_from_public_key, encode_public_key, generate_keypair
from aweb.hooks import fire_mutation_hook
from aweb.presence import (
    DEFAULT_PRESENCE_TTL_SECONDS,
    list_agent_presences_by_ids,
    update_agent_presence,
)
from aweb.stable_id import stable_id_from_did_key

router = APIRouter(prefix="/v1/agents", tags=["aweb-agents"])


def _parse_context(val):
    """Parse context from DB — may be a JSON string or already a dict."""
    if val is None:
        return None
    if isinstance(val, dict):
        return val
    if isinstance(val, str):
        try:
            return json.loads(val)
        except (json.JSONDecodeError, TypeError):
            return val
    return val


class SuggestAliasPrefixRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_slug: str = Field(..., min_length=1, max_length=256)

    @field_validator("project_slug")
    @classmethod
    def _validate_project_slug(cls, v: str) -> str:
        return validate_project_slug(v.strip())


class SuggestAliasPrefixResponse(BaseModel):
    project_slug: str
    project_id: str | None
    name_prefix: str


@router.post("/suggest-alias-prefix", response_model=SuggestAliasPrefixResponse)
async def suggest_alias_prefix(
    payload: SuggestAliasPrefixRequest, db=Depends(get_db)
) -> SuggestAliasPrefixResponse:
    """Suggest the next available classic alias prefix for a project.

    - Does not allocate (no project/agent/key creation).
    - Works without an API key for OSS clean-start UX.
    """
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT project_id, slug
        FROM {{tables.projects}}
        WHERE slug = $1 AND deleted_at IS NULL
        """,
        payload.project_slug,
    )

    if row is None:
        # Project doesn't exist yet: first prefix is always available.
        return SuggestAliasPrefixResponse(
            project_slug=payload.project_slug,
            project_id=None,
            name_prefix="alice",
        )

    project_id = str(row["project_id"])
    aliases = await aweb_db.fetch_all(
        """
        SELECT alias
        FROM {{tables.agents}}
        WHERE project_id = $1 AND deleted_at IS NULL
        ORDER BY alias
        """,
        UUID(project_id),
    )
    name_prefix = suggest_next_name_prefix([r.get("alias") or "" for r in aliases])
    if name_prefix is None:
        raise HTTPException(status_code=409, detail="alias_exhausted")

    return SuggestAliasPrefixResponse(
        project_slug=payload.project_slug,
        project_id=project_id,
        name_prefix=name_prefix,
    )


class AgentView(BaseModel):
    agent_id: str
    alias: str
    human_name: str | None = None
    agent_type: str | None = None
    access_mode: str = "open"
    status: str | None = None
    last_seen: str | None = None
    online: bool = False
    did: str | None = None
    custody: str | None = None
    lifetime: str = "persistent"
    identity_status: str = "active"
    role: str | None = None
    program: str | None = None
    context: dict | None = None


class ListAgentsResponse(BaseModel):
    project_id: str
    namespace_slug: str
    agents: list[AgentView]


@router.get("", response_model=ListAgentsResponse)
async def list_agents(
    request: Request,
    include_internal: bool = Query(False),
    db=Depends(get_db),
    redis=Depends(get_redis),
):
    """List all agents in the authenticated project with online status."""
    project_id = await get_project_from_auth(request, db)
    aweb_db = db.get_manager("aweb")

    proj_row = await aweb_db.fetch_one(
        """
        SELECT p.project_id, n.slug AS namespace_slug
        FROM {{tables.projects}} p
        LEFT JOIN {{tables.namespaces}} n ON p.namespace_id = n.namespace_id
            AND n.deleted_at IS NULL
        WHERE p.project_id = $1 AND p.deleted_at IS NULL
        """,
        UUID(project_id),
    )
    if not proj_row:
        raise HTTPException(status_code=404, detail="Project not found")
    namespace_slug = proj_row["namespace_slug"] or ""

    type_filter = "" if include_internal else "AND agent_type != 'human'"
    rows = await aweb_db.fetch_all(
        f"""
        SELECT agent_id, alias, human_name, agent_type, access_mode,
               did, custody, lifetime, status, role, program, context
        FROM {{{{tables.agents}}}}
        WHERE project_id = $1 AND deleted_at IS NULL
          {type_filter}
        ORDER BY alias
        """,
        UUID(project_id),
    )

    agent_ids = [str(r["agent_id"]) for r in rows]
    presences = await list_agent_presences_by_ids(redis, agent_ids)
    presence_map = {p["agent_id"]: p for p in presences}

    agents = []
    for r in rows:
        aid = str(r["agent_id"])
        p = presence_map.get(aid)
        agents.append(
            AgentView(
                agent_id=aid,
                alias=r["alias"],
                human_name=r.get("human_name"),
                agent_type=r.get("agent_type"),
                access_mode=r.get("access_mode", "open"),
                status=p["status"] if p else None,
                last_seen=p["last_seen"] if p else None,
                online=p is not None,
                did=r.get("did"),
                custody=r.get("custody"),
                lifetime=r.get("lifetime", "persistent"),
                identity_status=r.get("status", "active"),
                role=r.get("role"),
                program=r.get("program"),
                context=_parse_context(r.get("context")),
            )
        )

    return ListAgentsResponse(project_id=project_id, namespace_slug=namespace_slug, agents=agents)


class HeartbeatResponse(BaseModel):
    agent_id: str
    last_seen: str
    ttl_seconds: int


@router.post("/heartbeat", response_model=HeartbeatResponse)
async def heartbeat(request: Request, db=Depends(get_db), redis=Depends(get_redis)):
    """Report agent liveness. Refreshes presence TTL in Redis (best-effort)."""
    project_id = await get_project_from_auth(request, db)
    agent_id = await get_actor_agent_id_from_auth(request, db)

    # Look up the agent's alias for presence
    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT alias
        FROM {{tables.agents}}
        WHERE agent_id = $1 AND project_id = $2 AND deleted_at IS NULL
        """,
        UUID(agent_id),
        UUID(project_id),
    )
    if not row:
        raise HTTPException(status_code=404, detail="Agent not found")

    ttl = DEFAULT_PRESENCE_TTL_SECONDS
    last_seen = await update_agent_presence(
        redis,
        agent_id=agent_id,
        alias=row["alias"],
        project_id=project_id,
        ttl_seconds=ttl,
    )

    return HeartbeatResponse(agent_id=agent_id, last_seen=last_seen, ttl_seconds=ttl)


VALID_ACCESS_MODES = {"open", "contacts_only"}


class PatchAgentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    access_mode: str | None = None
    role: str | None = None
    program: str | None = None
    context: dict | None = None

    @field_validator("access_mode")
    @classmethod
    def _validate_access_mode(cls, v: str | None) -> str | None:
        if v is not None and v not in VALID_ACCESS_MODES:
            raise ValueError(f"access_mode must be one of {sorted(VALID_ACCESS_MODES)}")
        return v


class PatchAgentResponse(BaseModel):
    agent_id: str
    access_mode: str
    role: str | None = None
    program: str | None = None
    context: dict | None = None


@router.patch("/me", response_model=PatchAgentResponse)
async def patch_agent(
    request: Request, payload: PatchAgentRequest, db=Depends(get_db)
) -> PatchAgentResponse:
    project_id = await get_project_from_auth(request, db)
    agent_id = await get_actor_agent_id_from_auth(request, db)
    aweb_db = db.get_manager("aweb")
    agent_uuid = UUID(agent_id)

    row = await aweb_db.fetch_one(
        """
        SELECT agent_id, access_mode, role, program, context
        FROM {{tables.agents}}
        WHERE agent_id = $1 AND project_id = $2 AND deleted_at IS NULL
        """,
        agent_uuid,
        UUID(project_id),
    )
    if not row:
        raise HTTPException(status_code=404, detail="Agent not found")

    new_access_mode = payload.access_mode if payload.access_mode is not None else row["access_mode"]
    new_role = payload.role if payload.role is not None else row["role"]
    new_program = payload.program if payload.program is not None else row["program"]
    new_context = payload.context if payload.context is not None else row["context"]

    await aweb_db.execute(
        """
        UPDATE {{tables.agents}}
        SET access_mode = $1, role = $2, program = $3, context = $4
        WHERE agent_id = $5 AND project_id = $6
        """,
        new_access_mode,
        new_role,
        new_program,
        json.dumps(new_context) if isinstance(new_context, dict) else new_context,
        agent_uuid,
        UUID(project_id),
    )

    return PatchAgentResponse(
        agent_id=str(agent_uuid),
        access_mode=new_access_mode,
        role=new_role,
        program=new_program,
        context=_parse_context(new_context),
    )


class ResolveAgentResponse(BaseModel):
    did: str | None
    stable_id: str | None
    address: str
    agent_id: str
    human_name: str | None
    public_key: str | None
    server: str
    custody: str | None
    lifetime: str
    status: str


@router.get("/resolve/{namespace}/{alias}", response_model=ResolveAgentResponse)
async def resolve_agent(
    request: Request,
    namespace: str,
    alias: str,
    db=Depends(get_db),
) -> ResolveAgentResponse:
    """Resolve an agent by namespace slug and alias.

    Authenticated but NOT project-scoped — any valid API key can resolve any agent.
    Per clawdid/sot.md §4.6.
    """
    # Auth check: caller must have a valid API key
    await get_project_from_auth(request, db)

    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT a.agent_id, a.alias, a.human_name, a.did, a.stable_id, a.public_key,
               a.custody, a.lifetime, a.status
        FROM {{tables.agents}} a
        JOIN {{tables.projects}} p ON a.project_id = p.project_id
        JOIN {{tables.namespaces}} n ON a.namespace_id = n.namespace_id
        WHERE n.slug = $1
          AND a.alias = $2
          AND a.deleted_at IS NULL
          AND p.deleted_at IS NULL
          AND n.deleted_at IS NULL
        """,
        namespace,
        alias,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    server_url = os.environ.get("AWEB_SERVER_URL", "")

    return ResolveAgentResponse(
        did=row["did"],
        stable_id=row.get("stable_id"),
        address=f"{namespace}/{alias}",
        agent_id=str(row["agent_id"]),
        human_name=row.get("human_name"),
        public_key=row["public_key"],
        server=server_url,
        custody=row["custody"],
        lifetime=row["lifetime"],
        status=row["status"],
    )


class AgentLogEntry(BaseModel):
    log_id: str
    operation: str
    old_did: str | None
    new_did: str | None
    signed_by: str | None
    entry_signature: str | None
    metadata: dict | None
    created_at: str


class AgentLogResponse(BaseModel):
    agent_id: str
    address: str
    log: list[AgentLogEntry]


def _parse_log_metadata(raw) -> dict | None:
    if not raw:
        return None
    if isinstance(raw, dict):
        return raw
    import json as _json

    return _json.loads(raw)


@router.get("/me/log", response_model=AgentLogResponse)
async def agent_log(
    request: Request,
    db=Depends(get_db),
) -> AgentLogResponse:
    """Return the lifecycle audit log for the authenticated agent.

    Append-only log of create, rotate, retire, deregister, custody_change events.
    Ordered by created_at ASC.
    """
    project_id = await get_project_from_auth(request, db)
    agent_id = await get_actor_agent_id_from_auth(request, db)
    aweb_db = db.get_manager("aweb")
    agent_uuid = UUID(agent_id)

    agent = await aweb_db.fetch_one(
        """
        SELECT a.agent_id, a.alias, n.slug AS namespace_slug
        FROM {{tables.agents}} a
        JOIN {{tables.projects}} p ON a.project_id = p.project_id
        LEFT JOIN {{tables.namespaces}} n ON a.namespace_id = n.namespace_id
            AND n.deleted_at IS NULL
        WHERE a.agent_id = $1 AND a.project_id = $2
          AND p.deleted_at IS NULL
        """,
        agent_uuid,
        UUID(project_id),
    )
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    rows = await aweb_db.fetch_all(
        """
        SELECT log_id, operation, old_did, new_did, signed_by, entry_signature, metadata, created_at
        FROM {{tables.agent_log}}
        WHERE agent_id = $1 AND project_id = $2
        ORDER BY created_at ASC
        """,
        agent_uuid,
        UUID(project_id),
    )

    namespace_slug = agent["namespace_slug"] or ""
    return AgentLogResponse(
        agent_id=str(agent_uuid),
        address=f"{namespace_slug}/{agent['alias']}" if namespace_slug else agent["alias"],
        log=[
            AgentLogEntry(
                log_id=str(r["log_id"]),
                operation=r["operation"],
                old_did=r["old_did"],
                new_did=r["new_did"],
                signed_by=r["signed_by"],
                entry_signature=r["entry_signature"],
                metadata=_parse_log_metadata(r["metadata"]),
                created_at=r["created_at"].isoformat(),
            )
            for r in rows
        ],
    )


class ClaimIdentityRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    did: str = Field(..., max_length=256)
    public_key: str = Field(..., max_length=64)
    custody: Literal["self"]
    lifetime: Literal["persistent"]


class ClaimIdentityResponse(BaseModel):
    agent_id: str
    alias: str
    did: str
    public_key: str
    stable_id: str | None = None
    custody: str
    lifetime: str


@router.put("/me/identity", response_model=ClaimIdentityResponse)
async def claim_identity(
    request: Request,
    payload: ClaimIdentityRequest,
    db=Depends(get_db),
) -> ClaimIdentityResponse:
    """Bind a did:key + public_key to an unclaimed agent (one-time identity claim).

    For dashboard-first onboarding: the agent record exists but has no keypair.
    The client generates a keypair locally and calls this endpoint to bind it.
    """
    project_id = await get_project_from_auth(request, db)
    agent_id = await get_actor_agent_id_from_auth(request, db)
    aweb_db = db.get_manager("aweb")
    agent_uuid = UUID(agent_id)

    # Validate DID format and DID/public_key consistency
    try:
        pub_bytes = decode_public_key(payload.public_key)
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="public_key must be a base64-encoded 32-byte Ed25519 key",
        )
    expected_did = did_from_public_key(pub_bytes)
    if expected_did != payload.did:
        raise HTTPException(
            status_code=400,
            detail="DID does not match public_key",
        )

    row = await aweb_db.fetch_one(
        """
        SELECT agent_id, alias, did, public_key, stable_id, custody, lifetime
        FROM {{tables.agents}}
        WHERE agent_id = $1 AND project_id = $2 AND deleted_at IS NULL
        """,
        agent_uuid,
        UUID(project_id),
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    existing_did = row["did"]
    if existing_did is not None:
        # Idempotent: same DID → 200, different DID → 409
        if existing_did == payload.did:
            existing_stable_id = row["stable_id"]
            if not existing_stable_id:
                existing_stable_id = stable_id_from_did_key(existing_did)
            return ClaimIdentityResponse(
                agent_id=str(agent_uuid),
                alias=row["alias"],
                did=row["did"],
                public_key=row["public_key"],
                stable_id=existing_stable_id,
                custody=row["custody"] or "self",
                lifetime=row["lifetime"] or "persistent",
            )
        raise HTTPException(
            status_code=409,
            detail="Identity already claimed with a different DID",
        )

    # Compute stable_id from the initial DID
    new_stable_id = stable_id_from_did_key(payload.did)
    canonical_public_key = encode_public_key(pub_bytes)

    # Atomic: only update if did IS NULL (guards against concurrent claims)
    updated = await aweb_db.fetch_one(
        """
        UPDATE {{tables.agents}}
        SET did = $1, public_key = $2, stable_id = $3,
            custody = $4, lifetime = $5
        WHERE agent_id = $6 AND project_id = $7 AND did IS NULL
        RETURNING agent_id
        """,
        payload.did,
        canonical_public_key,
        new_stable_id,
        payload.custody,
        payload.lifetime,
        agent_uuid,
        UUID(project_id),
    )

    if updated is None:
        # Lost the race: another request claimed identity first. Re-check.
        current = await aweb_db.fetch_one(
            """
            SELECT did FROM {{tables.agents}}
            WHERE agent_id = $1 AND project_id = $2 AND deleted_at IS NULL
            """,
            agent_uuid,
            UUID(project_id),
        )
        if current and current["did"] == payload.did:
            # Same DID won the race — idempotent success
            return ClaimIdentityResponse(
                agent_id=str(agent_uuid),
                alias=row["alias"],
                did=payload.did,
                public_key=canonical_public_key,
                stable_id=new_stable_id,
                custody=payload.custody,
                lifetime=payload.lifetime,
            )
        raise HTTPException(
            status_code=409,
            detail="Identity already claimed with a different DID",
        )

    # Append agent_log entry anchoring the initial DID for stable_id derivation
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agent_log}}
            (agent_id, project_id, operation, new_did)
        VALUES ($1, $2, $3, $4)
        """,
        agent_uuid,
        UUID(project_id),
        "claim_identity",
        payload.did,
    )

    return ClaimIdentityResponse(
        agent_id=str(agent_uuid),
        alias=row["alias"],
        did=payload.did,
        public_key=canonical_public_key,
        stable_id=new_stable_id,
        custody=payload.custody,
        lifetime=payload.lifetime,
    )


class ResetIdentityRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    confirm: bool


class ResetIdentityResponse(BaseModel):
    agent_id: str
    alias: str
    did: str | None = None
    public_key: str | None = None
    stable_id: str | None = None
    custody: str | None = None
    lifetime: str | None = None


@router.post("/me/identity/reset", response_model=ResetIdentityResponse)
async def reset_identity(
    request: Request,
    payload: ResetIdentityRequest,
    db=Depends(get_db),
) -> ResetIdentityResponse:
    """Reset an agent's identity (clear did/public_key/stable_id).

    Self-service escape hatch for when a self-custodial signing key is lost.
    After reset, PUT /me/identity can be used to reclaim with a new keypair.
    """
    if not payload.confirm:
        raise HTTPException(
            status_code=400,
            detail="confirm must be true to reset identity",
        )

    project_id = await get_project_from_auth(request, db)
    agent_id = await get_actor_agent_id_from_auth(request, db)
    aweb_db = db.get_manager("aweb")
    agent_uuid = UUID(agent_id)

    row = await aweb_db.fetch_one(
        """
        SELECT agent_id, alias, did, public_key, stable_id, custody, lifetime
        FROM {{tables.agents}}
        WHERE agent_id = $1 AND project_id = $2 AND deleted_at IS NULL
        """,
        agent_uuid,
        UUID(project_id),
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    old_did = row["did"]
    if old_did is None:
        # Already unclaimed — no-op
        return ResetIdentityResponse(
            agent_id=str(agent_uuid),
            alias=row["alias"],
        )

    import json as _json

    metadata = _json.dumps(
        {
            "old_public_key": row["public_key"],
            "old_stable_id": row["stable_id"],
        }
    )

    await aweb_db.execute(
        """
        UPDATE {{tables.agents}}
        SET did = NULL, public_key = NULL, stable_id = NULL,
            custody = NULL, signing_key_enc = NULL
        WHERE agent_id = $1 AND project_id = $2
        """,
        agent_uuid,
        UUID(project_id),
    )

    await aweb_db.execute(
        """
        INSERT INTO {{tables.agent_log}}
            (agent_id, project_id, operation, old_did, metadata)
        VALUES ($1, $2, $3, $4, $5::jsonb)
        """,
        agent_uuid,
        UUID(project_id),
        "reset_identity",
        old_did,
        metadata,
    )

    return ResetIdentityResponse(
        agent_id=str(agent_uuid),
        alias=row["alias"],
    )


class RotateKeyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    new_did: str | None = None
    new_public_key: str | None = None
    custody: Literal["self", "custodial"]
    rotation_signature: str | None = None
    timestamp: str

    @model_validator(mode="after")
    def _validate_key_fields(self) -> "RotateKeyRequest":
        if self.custody == "self":
            if not self.new_did or not self.new_public_key:
                raise ValueError("new_did and new_public_key are required when custody='self'")
        else:
            if self.new_did is not None or self.new_public_key is not None:
                raise ValueError("new_did/new_public_key must be omitted when custody='custodial'")
        return self


class RotateKeyResponse(BaseModel):
    status: str
    old_did: str | None
    new_did: str
    new_public_key: str
    custody: str


@router.put("/me/rotate", response_model=RotateKeyResponse)
async def rotate_key(
    request: Request,
    payload: RotateKeyRequest,
    db=Depends(get_db),
) -> RotateKeyResponse:
    """Rotate the authenticated agent's signing key.

    Persistent agents only. Verifies the rotation proof (signed by old key).
    If graduating custodial->self, destroys the encrypted private key.
    """
    import base64 as _base64
    import json as _json

    from nacl.exceptions import BadSignatureError
    from nacl.signing import VerifyKey

    from aweb.custody import decrypt_signing_key, encrypt_signing_key, get_custody_key
    from aweb.signing import sign_message

    project_id = await get_project_from_auth(request, db)
    agent_id = await get_actor_agent_id_from_auth(request, db)
    aweb_db = db.get_manager("aweb")
    agent_uuid = UUID(agent_id)

    row = await aweb_db.fetch_one(
        """
        SELECT agent_id, did, public_key, custody, lifetime, signing_key_enc
        FROM {{tables.agents}}
        WHERE agent_id = $1 AND project_id = $2 AND deleted_at IS NULL
        """,
        agent_uuid,
        UUID(project_id),
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    if row["lifetime"] == "ephemeral":
        raise HTTPException(
            status_code=400,
            detail="Cannot rotate key for an ephemeral agent. Deregister and create a new agent instead.",
        )

    current_custody = row["custody"]
    if current_custody not in ("self", "custodial"):
        raise HTTPException(status_code=403, detail="Agent custody is not configured for rotation")

    if current_custody == "self" and payload.custody != "self":
        raise HTTPException(
            status_code=400,
            detail="Cannot change a self-custodial agent back to custodial via rotate",
        )
    if current_custody != "custodial" and payload.custody == "custodial":
        raise HTTPException(
            status_code=400,
            detail="Only custodial agents can request custody='custodial' rotations",
        )

    # Verify rotation proof: signed by old key
    old_did = row["did"]
    old_public_key_encoded = row["public_key"]

    if not old_did:
        raise HTTPException(status_code=403, detail="Agent has no DID to rotate")

    if not old_public_key_encoded:
        raise HTTPException(
            status_code=403, detail="Agent has no public key to verify proof against"
        )

    try:
        old_public_key = decode_public_key(old_public_key_encoded)
    except Exception:
        raise HTTPException(status_code=500, detail="Corrupt public key in database")

    new_did: str
    new_public_key_encoded: str
    new_signing_key_enc: bytes | None = None

    if payload.custody == "custodial":
        master_key = get_custody_key()
        if master_key is None:
            raise HTTPException(status_code=500, detail="Custody key not configured")
        seed, pub = generate_keypair()
        new_did = did_from_public_key(pub)
        new_public_key_encoded = encode_public_key(pub)
        try:
            new_signing_key_enc = encrypt_signing_key(seed, master_key)
        except Exception:
            raise HTTPException(status_code=500, detail="Failed to encrypt new signing key")
    else:
        # custody='self' — caller provides new DID/public key (accept std base64 or base64url)
        new_did = payload.new_did or ""
        new_public_key = payload.new_public_key or ""
        try:
            new_pub_bytes = decode_public_key(new_public_key)
        except Exception:
            raise HTTPException(
                status_code=400,
                detail="new_public_key must be a base64-encoded 32-byte Ed25519 key (url-safe or standard)",
            )
        expected_did = did_from_public_key(new_pub_bytes)
        if expected_did != new_did:
            raise HTTPException(status_code=400, detail="DID does not match new_public_key")
        new_public_key_encoded = encode_public_key(new_pub_bytes)

    canonical = _json.dumps(
        {
            "new_did": new_did,
            "old_did": old_did,
            "timestamp": payload.timestamp,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    rotation_signature = payload.rotation_signature
    if rotation_signature is None and current_custody == "custodial":
        master_key = get_custody_key()
        if master_key is None:
            raise HTTPException(status_code=500, detail="Custody key not configured")
        if row["signing_key_enc"] is None:
            raise HTTPException(status_code=500, detail="Agent has no signing key")
        try:
            old_private_key = decrypt_signing_key(bytes(row["signing_key_enc"]), master_key)
        except Exception:
            raise HTTPException(status_code=500, detail="Failed to decrypt signing key")
        rotation_signature = sign_message(old_private_key, canonical)

    if rotation_signature is None:
        raise HTTPException(status_code=422, detail="rotation_signature is required")

    try:
        padded = rotation_signature + "=" * (-len(rotation_signature) % 4)
        sig_bytes = _base64.b64decode(padded, validate=True)
    except Exception:
        raise HTTPException(status_code=403, detail="Malformed rotation proof encoding")

    try:
        verify_key = VerifyKey(old_public_key)
        verify_key.verify(canonical, sig_bytes)
    except BadSignatureError:
        raise HTTPException(status_code=403, detail="Invalid rotation proof")
    except Exception:
        raise HTTPException(status_code=403, detail="Rotation proof verification error")

    # Update agent record
    if payload.custody == "custodial":
        await aweb_db.execute(
            """
            UPDATE {{tables.agents}}
            SET did = $1,
                public_key = $2,
                custody = 'custodial',
                signing_key_enc = $3
            WHERE agent_id = $4 AND project_id = $5
            """,
            new_did,
            new_public_key_encoded,
            new_signing_key_enc,
            agent_uuid,
            UUID(project_id),
        )
    else:
        await aweb_db.execute(
            """
            UPDATE {{tables.agents}}
            SET did = $1,
                public_key = $2,
                custody = 'self',
                signing_key_enc = NULL
            WHERE agent_id = $3 AND project_id = $4
            """,
            new_did,
            new_public_key_encoded,
            agent_uuid,
            UUID(project_id),
        )

    # Append rotation log entry
    metadata = _json.dumps({"timestamp": payload.timestamp, "new_custody": payload.custody})
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agent_log}}
            (agent_id, project_id, operation, old_did, new_did, signed_by, entry_signature, metadata)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
        """,
        agent_uuid,
        UUID(project_id),
        "rotate",
        old_did,
        new_did,
        old_did,
        rotation_signature,
        metadata,
    )

    # Store rotation announcement for per-peer injection (§5.4)
    await aweb_db.execute(
        """
        INSERT INTO {{tables.rotation_announcements}}
            (agent_id, project_id, old_did, new_did, rotation_timestamp, old_key_signature)
        VALUES ($1, $2, $3, $4, $5, $6)
        """,
        agent_uuid,
        UUID(project_id),
        old_did,
        new_did,
        payload.timestamp,
        rotation_signature,
    )

    await fire_mutation_hook(
        request,
        "agent.key_rotated",
        {
            "agent_id": str(agent_uuid),
            "project_id": project_id,
            "old_did": old_did,
            "new_did": new_did,
            "custody": payload.custody,
        },
    )

    return RotateKeyResponse(
        status="rotated",
        old_did=old_did,
        new_did=new_did,
        new_public_key=new_public_key_encoded,
        custody=payload.custody,
    )


class RetireAgentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    successor_agent_id: str
    retirement_proof: str | None = None
    timestamp: str | None = None

    @field_validator("successor_agent_id")
    @classmethod
    def _validate_successor_id(cls, v: str) -> str:
        try:
            return str(UUID(v.strip()))
        except Exception:
            raise ValueError("Invalid successor_agent_id format")


class RetireAgentResponse(BaseModel):
    status: str
    agent_id: str
    successor_agent_id: str


@router.put("/me/retire", response_model=RetireAgentResponse)
async def retire_agent(
    request: Request,
    payload: RetireAgentRequest,
    db=Depends(get_db),
) -> RetireAgentResponse:
    """Retire the authenticated agent with a designated successor.

    For self-custodial agents: requires a retirement_proof (Ed25519 sig by the
    agent's current key over the canonical retirement payload).
    For custodial agents: server signs the proof on behalf.
    Ephemeral agents → 400 (use deregister instead).
    """
    import base64 as _base64
    import json as _json

    from nacl.exceptions import BadSignatureError
    from nacl.signing import VerifyKey

    from aweb.custody import decrypt_signing_key, get_custody_key
    from aweb.signing import sign_message

    project_id = await get_project_from_auth(request, db)
    agent_id = await get_actor_agent_id_from_auth(request, db)
    aweb_db = db.get_manager("aweb")
    agent_uuid = UUID(agent_id)

    row = await aweb_db.fetch_one(
        """
        SELECT agent_id, did, public_key, custody, lifetime, status, signing_key_enc
        FROM {{tables.agents}}
        WHERE agent_id = $1 AND project_id = $2 AND deleted_at IS NULL
        """,
        agent_uuid,
        UUID(project_id),
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    if row["lifetime"] == "ephemeral":
        raise HTTPException(
            status_code=400,
            detail="Cannot retire an ephemeral agent. Use the deregister endpoint instead.",
        )

    if row["status"] == "retired":
        raise HTTPException(status_code=400, detail="Agent is already retired")

    if row["status"] == "deregistered":
        raise HTTPException(status_code=400, detail="Agent is already deregistered")

    # Validate successor exists in the same project and is not self
    successor_uuid = UUID(payload.successor_agent_id)
    if successor_uuid == agent_uuid:
        raise HTTPException(
            status_code=400, detail="An agent cannot name itself as its own successor"
        )
    successor = await aweb_db.fetch_one(
        """
        SELECT agent_id, did, alias FROM {{tables.agents}}
        WHERE agent_id = $1 AND project_id = $2 AND deleted_at IS NULL
        """,
        successor_uuid,
        UUID(project_id),
    )
    if successor is None:
        raise HTTPException(status_code=404, detail="Successor agent not found in this project")

    # Resolve protocol-level identifiers for the canonical proof
    ns_row = await aweb_db.fetch_one(
        """
        SELECT n.slug FROM {{tables.namespaces}} n
        JOIN {{tables.projects}} p ON p.namespace_id = n.namespace_id
        WHERE p.project_id = $1 AND p.deleted_at IS NULL AND n.deleted_at IS NULL
        """,
        UUID(project_id),
    )
    if ns_row is None:
        raise HTTPException(status_code=404, detail="Project not found")
    if not successor["did"]:
        raise HTTPException(
            status_code=422,
            detail="Successor agent has no DID — cannot build verifiable retirement proof",
        )
    successor_did = successor["did"]
    successor_address = f"{ns_row['slug']}/{successor['alias']}"

    # Build canonical retirement proof with protocol-level fields.
    # The API accepts successor_agent_id, but the proof uses
    # successor_did + successor_address for cross-server verifiability.
    timestamp = payload.timestamp or ""
    canonical = _json.dumps(
        {
            "operation": "retire",
            "successor_address": successor_address,
            "successor_did": successor_did,
            "timestamp": timestamp,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    entry_signature: str | None = None

    if row["custody"] == "custodial" and payload.retirement_proof is None:
        # Server signs on behalf of custodial agent
        master_key = get_custody_key()
        if master_key is None:
            raise HTTPException(status_code=500, detail="Custody key not configured")
        if row["signing_key_enc"] is None:
            raise HTTPException(status_code=500, detail="Agent has no signing key")
        try:
            private_key = decrypt_signing_key(bytes(row["signing_key_enc"]), master_key)
        except Exception:
            raise HTTPException(status_code=500, detail="Failed to decrypt signing key")
        entry_signature = sign_message(private_key, canonical)
    else:
        # Self-custodial: verify proof provided by caller
        if not payload.retirement_proof:
            raise HTTPException(
                status_code=422, detail="retirement_proof is required for self-custodial agents"
            )

        old_public_key_encoded = row["public_key"]
        if not old_public_key_encoded:
            raise HTTPException(
                status_code=403, detail="Agent has no public key to verify proof against"
            )

        try:
            old_public_key = decode_public_key(old_public_key_encoded)
        except Exception:
            raise HTTPException(status_code=500, detail="Corrupt public key in database")

        try:
            padded = payload.retirement_proof + "=" * (-len(payload.retirement_proof) % 4)
            sig_bytes = _base64.b64decode(padded, validate=True)
        except Exception:
            raise HTTPException(status_code=403, detail="Malformed retirement proof encoding")

        try:
            verify_key = VerifyKey(old_public_key)
            verify_key.verify(canonical, sig_bytes)
        except BadSignatureError:
            raise HTTPException(status_code=403, detail="Invalid retirement proof")
        except Exception:
            raise HTTPException(status_code=403, detail="Retirement proof verification error")

        entry_signature = payload.retirement_proof

    # Update agent status
    await aweb_db.execute(
        """
        UPDATE {{tables.agents}}
        SET status = 'retired', successor_agent_id = $1
        WHERE agent_id = $2 AND project_id = $3
        """,
        successor_uuid,
        agent_uuid,
        UUID(project_id),
    )

    # Append retire entry to agent_log
    metadata = _json.dumps(
        {
            "successor_agent_id": payload.successor_agent_id,
            "successor_did": successor_did,
            "successor_address": successor_address,
        }
    )
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agent_log}}
            (agent_id, project_id, operation, old_did, signed_by, entry_signature, metadata)
        VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
        """,
        agent_uuid,
        UUID(project_id),
        "retire",
        row["did"],
        row["did"],
        entry_signature,
        metadata,
    )

    await fire_mutation_hook(
        request,
        "agent.retired",
        {
            "agent_id": str(agent_uuid),
            "project_id": project_id,
            "did": row["did"],
            "successor_agent_id": payload.successor_agent_id,
        },
    )

    return RetireAgentResponse(
        status="retired",
        agent_id=str(agent_uuid),
        successor_agent_id=payload.successor_agent_id,
    )


class DeregisterAgentResponse(BaseModel):
    agent_id: str
    status: str


async def _deregister_agent(
    request: Request, aweb_db, *, agent_uuid: UUID, project_id: str
) -> DeregisterAgentResponse:
    """Shared deregistration logic for self and peer endpoints.

    Precondition: caller has verified that the authenticated principal is
    authorized to act on agents in ``project_id``.  This function performs
    no authorization check.
    """
    row = await aweb_db.fetch_one(
        """
        SELECT agent_id, did, lifetime, signing_key_enc
        FROM {{tables.agents}}
        WHERE agent_id = $1 AND project_id = $2 AND deleted_at IS NULL
        """,
        agent_uuid,
        UUID(project_id),
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    if row["lifetime"] == "persistent":
        raise HTTPException(
            status_code=400,
            detail="Cannot deregister a persistent agent. Use the retire endpoint instead.",
        )

    # Destroy signing key, set status, soft-delete
    await aweb_db.execute(
        """
        UPDATE {{tables.agents}}
        SET signing_key_enc = NULL,
            status = 'deregistered',
            deleted_at = NOW()
        WHERE agent_id = $1 AND project_id = $2
        """,
        agent_uuid,
        UUID(project_id),
    )

    # Append deregister entry to agent_log
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agent_log}} (agent_id, project_id, operation, old_did)
        VALUES ($1, $2, $3, $4)
        """,
        agent_uuid,
        UUID(project_id),
        "deregister",
        row["did"],
    )

    await fire_mutation_hook(
        request,
        "agent.deregistered",
        {
            "agent_id": str(agent_uuid),
            "project_id": project_id,
            "did": row["did"],
        },
    )

    return DeregisterAgentResponse(agent_id=str(agent_uuid), status="deregistered")


@router.delete("/me", response_model=DeregisterAgentResponse)
async def deregister_agent(
    request: Request,
    db=Depends(get_db),
) -> DeregisterAgentResponse:
    """Self-deregister the authenticated ephemeral agent.

    Destroys the signing key, sets status to 'deregistered', soft-deletes
    (sets deleted_at so the alias can be reused). Rejects persistent agents
    with 400 — use the retire endpoint instead.

    For peer deregistration, use DELETE /v1/agents/{namespace}/{alias}.
    """
    project_id = await get_project_from_auth(request, db)
    agent_id = await get_actor_agent_id_from_auth(request, db)
    aweb_db = db.get_manager("aweb")
    return await _deregister_agent(
        request, aweb_db, agent_uuid=UUID(agent_id), project_id=project_id
    )


# Catch-all: must be registered LAST — static DELETE routes (/me) above
# take precedence only because of registration order.
@router.delete("/{address:path}", response_model=DeregisterAgentResponse)
async def peer_deregister_agent(
    request: Request,
    address: str,
    db=Depends(get_db),
) -> DeregisterAgentResponse:
    """Deregister an ephemeral agent by address (namespace/alias).

    Caller must be authenticated and belong to the same project as the target.
    Ephemeral-only: persistent agents return 400.
    """
    # Split address into namespace slug and alias on the last '/'
    sep = address.rfind("/")
    if sep <= 0:
        raise HTTPException(status_code=404, detail="Invalid address format")
    namespace = address[:sep]
    alias = address[sep + 1 :]
    if not alias:
        raise HTTPException(status_code=404, detail="Invalid address format")

    caller_project_id = await get_project_from_auth(request, db)
    aweb_db = db.get_manager("aweb")

    # Resolve namespace/alias → agent (join via agents.namespace_id for consistency
    # with resolve_agent)
    agent_row = await aweb_db.fetch_one(
        """
        SELECT a.agent_id, a.project_id
        FROM {{tables.agents}} a
        JOIN {{tables.namespaces}} n ON a.namespace_id = n.namespace_id
        JOIN {{tables.projects}} p ON a.project_id = p.project_id
        WHERE n.slug = $1 AND a.alias = $2
          AND a.deleted_at IS NULL AND p.deleted_at IS NULL AND n.deleted_at IS NULL
        """,
        namespace,
        alias,
    )
    if agent_row is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    target_project_id = str(agent_row["project_id"])

    # Authorization: caller must be in the same project
    if target_project_id != caller_project_id:
        raise HTTPException(
            status_code=403, detail="Not authorized to deregister agents in another project"
        )

    return await _deregister_agent(
        request, aweb_db, agent_uuid=agent_row["agent_id"], project_id=target_project_id
    )
