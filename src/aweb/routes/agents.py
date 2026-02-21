from __future__ import annotations

import os
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator

from aweb.alias_allocator import suggest_next_name_prefix
from aweb.auth import get_actor_agent_id_from_auth, get_project_from_auth, validate_project_slug
from aweb.deps import get_db, get_redis
from aweb.hooks import fire_mutation_hook
from aweb.presence import (
    DEFAULT_PRESENCE_TTL_SECONDS,
    list_agent_presences_by_ids,
    update_agent_presence,
)

router = APIRouter(prefix="/v1/agents", tags=["aweb-agents"])


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


class ListAgentsResponse(BaseModel):
    project_id: str
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

    type_filter = "" if include_internal else "AND agent_type != 'human'"
    rows = await aweb_db.fetch_all(
        f"""
        SELECT agent_id, alias, human_name, agent_type, access_mode,
               did, custody, lifetime, status
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
            )
        )

    return ListAgentsResponse(project_id=project_id, agents=agents)


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

    @field_validator("access_mode")
    @classmethod
    def _validate_access_mode(cls, v: str | None) -> str | None:
        if v is not None and v not in VALID_ACCESS_MODES:
            raise ValueError(f"access_mode must be one of {sorted(VALID_ACCESS_MODES)}")
        return v


class PatchAgentResponse(BaseModel):
    agent_id: str
    access_mode: str


@router.patch("/{agent_id}", response_model=PatchAgentResponse)
async def patch_agent(
    request: Request, agent_id: str, payload: PatchAgentRequest, db=Depends(get_db)
) -> PatchAgentResponse:
    project_id = await get_project_from_auth(request, db)
    aweb_db = db.get_manager("aweb")

    try:
        agent_uuid = UUID(agent_id.strip())
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid agent_id format")

    row = await aweb_db.fetch_one(
        """
        SELECT agent_id, access_mode
        FROM {{tables.agents}}
        WHERE agent_id = $1 AND project_id = $2 AND deleted_at IS NULL
        """,
        agent_uuid,
        UUID(project_id),
    )
    if not row:
        raise HTTPException(status_code=404, detail="Agent not found")

    new_access_mode = payload.access_mode if payload.access_mode is not None else row["access_mode"]

    await aweb_db.execute(
        """
        UPDATE {{tables.agents}}
        SET access_mode = $1
        WHERE agent_id = $2 AND project_id = $3
        """,
        new_access_mode,
        agent_uuid,
        UUID(project_id),
    )

    return PatchAgentResponse(agent_id=str(agent_uuid), access_mode=new_access_mode)


class ResolveAgentResponse(BaseModel):
    did: str | None
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
    """Resolve an agent by namespace (project slug) and alias.

    Authenticated but NOT project-scoped — any valid API key can resolve any agent.
    Per clawdid/sot.md §4.6.
    """
    # Auth check: caller must have a valid API key
    await get_project_from_auth(request, db)

    aweb_db = db.get_manager("aweb")
    row = await aweb_db.fetch_one(
        """
        SELECT a.agent_id, a.alias, a.human_name, a.did, a.public_key,
               a.custody, a.lifetime, a.status, p.slug
        FROM {{tables.agents}} a
        JOIN {{tables.projects}} p ON a.project_id = p.project_id
        WHERE p.slug = $1
          AND a.alias = $2
          AND a.deleted_at IS NULL
          AND p.deleted_at IS NULL
        """,
        namespace,
        alias,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Agent not found")

    server_url = os.environ.get("AWEB_SERVER_URL", "")

    return ResolveAgentResponse(
        did=row["did"],
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


@router.get("/{agent_id}/log", response_model=AgentLogResponse)
async def agent_log(
    request: Request,
    agent_id: str,
    db=Depends(get_db),
) -> AgentLogResponse:
    """Return the lifecycle audit log for an agent.

    Append-only log of create, rotate, retire, deregister, custody_change events.
    Ordered by created_at ASC. Authenticated, project-scoped.
    """
    project_id = await get_project_from_auth(request, db)
    aweb_db = db.get_manager("aweb")

    try:
        agent_uuid = UUID(agent_id.strip())
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid agent_id format")

    agent = await aweb_db.fetch_one(
        """
        SELECT a.agent_id, a.alias, p.slug
        FROM {{tables.agents}} a
        JOIN {{tables.projects}} p ON a.project_id = p.project_id
        WHERE a.agent_id = $1 AND a.project_id = $2
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

    return AgentLogResponse(
        agent_id=str(agent_uuid),
        address=f"{agent['slug']}/{agent['alias']}",
        log=[
            AgentLogEntry(
                log_id=str(r["log_id"]),
                operation=r["operation"],
                old_did=r["old_did"],
                new_did=r["new_did"],
                signed_by=r["signed_by"],
                entry_signature=r["entry_signature"],
                metadata=dict(r["metadata"]) if r["metadata"] else None,
                created_at=r["created_at"].isoformat(),
            )
            for r in rows
        ],
    )


class RotateKeyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    new_did: str
    new_public_key: str
    custody: str
    rotation_proof: str
    timestamp: str

    @field_validator("custody")
    @classmethod
    def _validate_custody(cls, v: str) -> str:
        if v not in ("self", "custodial"):
            raise ValueError("custody must be 'self' or 'custodial'")
        return v


class RotateKeyResponse(BaseModel):
    status: str
    old_did: str | None
    new_did: str
    custody: str


@router.put("/{agent_id}/rotate", response_model=RotateKeyResponse)
async def rotate_key(
    request: Request,
    agent_id: str,
    payload: RotateKeyRequest,
    db=Depends(get_db),
) -> RotateKeyResponse:
    """Rotate an agent's signing key.

    Persistent agents only. Verifies the rotation proof (signed by old key).
    If graduating custodial->self, destroys the encrypted private key.
    """
    import base64 as _base64
    import json as _json

    from nacl.exceptions import BadSignatureError
    from nacl.signing import VerifyKey

    project_id = await get_project_from_auth(request, db)
    aweb_db = db.get_manager("aweb")

    try:
        agent_uuid = UUID(agent_id.strip())
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid agent_id format")

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

    # Verify rotation proof: signed by old key
    old_did = row["did"]
    old_public_key_hex = row["public_key"]

    if not old_public_key_hex:
        raise HTTPException(status_code=403, detail="Agent has no public key to verify proof against")

    try:
        old_public_key = bytes.fromhex(old_public_key_hex)
    except ValueError:
        raise HTTPException(status_code=500, detail="Corrupt public key in database")

    canonical = _json.dumps(
        {
            "new_did": payload.new_did,
            "old_did": old_did,
            "timestamp": payload.timestamp,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    try:
        padded = payload.rotation_proof + "=" * (-len(payload.rotation_proof) % 4)
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
    graduating = row["custody"] == "custodial" and payload.custody == "self"

    await aweb_db.execute(
        """
        UPDATE {{tables.agents}}
        SET did = $1,
            public_key = $2,
            custody = $3,
            signing_key_enc = CASE WHEN $4::bool THEN NULL ELSE signing_key_enc END
        WHERE agent_id = $5 AND project_id = $6
        """,
        payload.new_did,
        payload.new_public_key,
        payload.custody,
        graduating,
        agent_uuid,
        UUID(project_id),
    )

    # Append rotation log entry
    await aweb_db.execute(
        """
        INSERT INTO {{tables.agent_log}} (agent_id, project_id, operation, old_did, new_did, signed_by)
        VALUES ($1, $2, $3, $4, $5, $6)
        """,
        agent_uuid,
        UUID(project_id),
        "rotate",
        old_did,
        payload.new_did,
        old_did,
    )

    await fire_mutation_hook(
        request,
        "agent.key_rotated",
        {
            "agent_id": str(agent_uuid),
            "project_id": project_id,
            "old_did": old_did,
            "new_did": payload.new_did,
            "custody": payload.custody,
        },
    )

    return RotateKeyResponse(
        status="rotated",
        old_did=old_did,
        new_did=payload.new_did,
        custody=payload.custody,
    )


class DeregisterAgentResponse(BaseModel):
    agent_id: str
    status: str


@router.delete("/{agent_id}", response_model=DeregisterAgentResponse)
async def deregister_agent(
    request: Request,
    agent_id: str,
    db=Depends(get_db),
) -> DeregisterAgentResponse:
    """Deregister an ephemeral agent.

    Destroys the signing key, sets status to 'deregistered', soft-deletes
    (sets deleted_at so the alias can be reused). Rejects persistent agents
    with 400 — use the retire endpoint instead.

    Auth: any authenticated agent in the same project can call this
    (peer-callable for stale workspace cleanup).
    """
    project_id = await get_project_from_auth(request, db)
    aweb_db = db.get_manager("aweb")

    try:
        agent_uuid = UUID(agent_id.strip())
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid agent_id format")

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
