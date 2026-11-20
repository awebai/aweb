"""POST /v1/connect — agent auto-provisioning via team certificate.

Called by `aw init`. Auto-provisions team and agent rows from the
verified certificate, creates or updates a workspace.
"""

from __future__ import annotations

from aweb.member_team_key import current_member_sql

import uuid
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import asyncpg
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pgdbm import AsyncDatabaseManager, TransactionManager
from pgdbm.errors import QueryError
from pydantic import BaseModel, Field

from aweb.certificate_auth import VerifiedCertificateGeneration
from aweb.coordination.workspace_registry import ensure_repo
from aweb.deps import get_db
from aweb.human_kind import IdentityKindObservation
from aweb.identity_binding import IdentityBinding, refresh_projection_binding
from aweb.identity_scope import normalize_identity_scope
from aweb.inbound_modes import effective_inbound_mode
from aweb.service_errors import ServiceError, ValidationError
from aweb.team_admission import admit_team
from aweb.team_auth_deps import get_team_identity, verify_request_certificate

router = APIRouter(prefix="/v1", tags=["connect"])


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------


class ConnectRequest(BaseModel):
    hostname: str = Field(default="", max_length=256)
    workspace_path: str = Field(default="", max_length=1024)
    repo_origin: str = Field(default="", max_length=1024)
    role: str = Field(default="", max_length=50)
    human_name: str = Field(default="", max_length=64)
    agent_type: str = Field(default="agent", max_length=32)


class ConnectResponse(BaseModel):
    agent_type: str = "agent"
    team_id: str
    alias: str
    agent_id: str
    workspace_id: str
    role: str


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


class WorkspaceProfile(StrEnum):
    """Host-requested kinds for an admitted workspace without a repository."""

    MANUAL = "manual"
    HOSTED_MCP = "hosted_mcp"


@dataclass(frozen=True)
class _ConnectedWorkspace:
    workspace_id: str
    workspace_type: str


@dataclass(frozen=True, kw_only=True)
class PlannedIdentityIds:
    """Exact retained creation resources; these IDs grant no identity authority."""

    agent_id: uuid.UUID
    workspace_id: uuid.UUID

    def __post_init__(self) -> None:
        if not isinstance(self.agent_id, uuid.UUID) or not isinstance(
            self.workspace_id, uuid.UUID
        ):
            raise TypeError("Pass UUID values for the planned agent and workspace IDs.")


class PlannedIdentityConflict(ServiceError):
    """The retained IDs differ from the identity the constructor would reuse."""

    status_code = 409
    code = "planned_identity_conflict"

    def __init__(self) -> None:
        self.message = "Reload the retained creation request and use its exact agent and workspace IDs."
        super().__init__({"code": self.code, "message": self.message})


def _require_planned_id(actual: uuid.UUID | str, planned: uuid.UUID | None) -> None:
    if planned is not None and str(actual) != str(planned):
        raise PlannedIdentityConflict()


class ConnectIdentityRefusalReason(StrEnum):
    """Stable refusal codes returned by the native identity constructor."""

    BINDING_MISMATCH = "identity_binding_mismatch"
    KIND_MISMATCH = "identity_kind_mismatch"
    GENERATION_MISMATCH = "certificate_generation_mismatch"
    GENERATION_STALE = "certificate_generation_stale"


class ConnectIdentityRefusal(ValueError):
    """A verified observation does not describe the identity being connected."""

    def __init__(self, reason: ConnectIdentityRefusalReason) -> None:
        super().__init__(reason.value)
        self.reason = reason
        messages = {
            ConnectIdentityRefusalReason.BINDING_MISMATCH: "Verify the certificate's exact identity and address before connecting this agent.",
            ConnectIdentityRefusalReason.KIND_MISMATCH: "Verify the certificate's exact identity kind before connecting this agent.",
            ConnectIdentityRefusalReason.GENERATION_MISMATCH: "Use the verified generation's exact certificate claims and current team key, then retry connecting.",
        }
        messages[ConnectIdentityRefusalReason.GENERATION_STALE] = (
            "Verify the retained certificate under the team's current controller key, then retry connecting."
        )
        self.message = messages[reason]


class AliasConflictError(ValueError):
    """Raised when a connect would give an alias or a did_key two owners.

    code is the stable wire code: alias_active when another active agent holds
    the alias, alias_mismatch when the did_key is already bound to another
    alias in the team.
    """

    def __init__(self, message: str, *, code: str) -> None:
        super().__init__(message)
        self.code = code


async def _ensure_agent(
    db: AsyncDatabaseManager | TransactionManager,
    team_id: str,
    did_key: str,
    did_aw: str,
    address: str,
    alias: str,
    identity_scope: str,
    human_name: str,
    agent_type: str,
    role: str,
    certificate_id: str,
    human_verified_key: str | None,
    accepted_team_did_key: str,
    planned_agent_id: uuid.UUID | None = None,
) -> str:
    """Find or create the agent row. Returns agent_id as string.

    did_aw and address come from independently verified identity bindings. Empty strings are stored as NULL (local
    certificates do not carry these fields).
    """
    existing_agent = await db.fetch_one(
        """
        SELECT agent_id, alias FROM {{tables.agents}}
        WHERE team_id = $1 AND did_key = $2 AND deleted_at IS NULL
        """,
        team_id,
        did_key,
    )
    if existing_agent:
        _require_planned_id(existing_agent["agent_id"], planned_agent_id)
        existing_alias = existing_agent["alias"]
        if existing_alias != alias:
            raise AliasConflictError(
                f"cert claims alias {alias!r} but did_key is already bound to alias {existing_alias!r} in team {team_id}",
                code="alias_mismatch",
            )
        await db.execute(
            """
            UPDATE {{tables.agents}}
            SET did_aw = $1, address = $2, identity_scope = $3, human_name = $4,
                agent_type = $5, role = $6, status = 'active', certificate_id = $8, did_aw_verified_key = $9, human_verified_key = $10,
                accepted_team_did_key = $11
            WHERE agent_id = $7
            """,
            did_aw or None,
            address or None,
            identity_scope,
            human_name,
            agent_type,
            role,
            existing_agent["agent_id"],
            (certificate_id or "").strip() or None,
            did_key if did_aw else None,
            human_verified_key,
            accepted_team_did_key,
        )
        return str(existing_agent["agent_id"])

    existing_alias = await db.fetch_one(
        """
        SELECT agent_id, did_key FROM {{tables.agents}}
        WHERE team_id = $1 AND alias = $2 AND deleted_at IS NULL
        """,
        team_id,
        alias,
    )
    if existing_alias and existing_alias["did_key"] != did_key:
        raise AliasConflictError(
            f"alias {alias!r} is already in use by another active agent in team {team_id}",
            code="alias_active",
        )

    inbound_mode = "open"
    if str(did_aw or "").startswith("did:aw:"):
        inbound_mode = await effective_inbound_mode(
            db, did_aw, for_share=True, default="open"
        )
    agent_id = planned_agent_id or uuid.uuid4()
    try:
        async with db.transaction() as insert_tx:
            await insert_tx.execute(
                """
                INSERT INTO {{tables.agents}}
                    (agent_id, team_id, did_key, did_aw, address,
                     alias, identity_scope, human_name, agent_type, role, inbound_mode,
                     certificate_id, did_aw_verified_key, human_verified_key, accepted_team_did_key)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $13, $11, $12, $14, $15)
                ON CONFLICT (team_id, did_key) WHERE deleted_at IS NULL DO NOTHING
                """,
                agent_id,
                team_id,
                did_key,
                did_aw or None,
                address or None,
                alias,
                identity_scope,
                human_name,
                agent_type,
                role,
                (certificate_id or "").strip() or None,
                did_key if did_aw else None,
                inbound_mode,
                human_verified_key,
                accepted_team_did_key,
            )
    except (QueryError, asyncpg.exceptions.UniqueViolationError) as exc:
        if isinstance(exc, QueryError) and not isinstance(
            exc.__cause__, asyncpg.exceptions.UniqueViolationError
        ):
            raise
        existing_agent = await db.fetch_one(
            """
            SELECT agent_id, alias FROM {{tables.agents}}
            WHERE team_id = $1 AND did_key = $2 AND deleted_at IS NULL
            """,
            team_id,
            did_key,
        )
        if existing_agent:
            _require_planned_id(existing_agent["agent_id"], planned_agent_id)
            existing_alias = existing_agent["alias"]
            if existing_alias != alias:
                raise AliasConflictError(
                    f"cert claims alias {alias!r} but did_key is already bound to alias {existing_alias!r} in team {team_id}",
                    code="alias_mismatch",
                ) from exc
            await db.execute(
                """
                UPDATE {{tables.agents}}
                SET did_aw = $1, address = $2, identity_scope = $3, human_name = $4,
                    agent_type = $5, role = $6, status = 'active', certificate_id = $8, did_aw_verified_key = $9, human_verified_key = $10,
                    accepted_team_did_key = $11
                WHERE agent_id = $7
                """,
                did_aw or None,
                address or None,
                identity_scope,
                human_name,
                agent_type,
                role,
                existing_agent["agent_id"],
                (certificate_id or "").strip() or None,
                did_key if did_aw else None,
                human_verified_key,
                accepted_team_did_key,
            )
            return str(existing_agent["agent_id"])
        existing_alias = await db.fetch_one(
            """
            SELECT agent_id, did_key FROM {{tables.agents}}
            WHERE team_id = $1 AND alias = $2 AND deleted_at IS NULL
            """,
            team_id,
            alias,
        )
        if existing_alias and existing_alias["did_key"] != did_key:
            raise AliasConflictError(
                f"alias {alias!r} is already in use by another active agent in team {team_id}",
                code="alias_active",
            ) from exc
        if planned_agent_id is not None:
            raise PlannedIdentityConflict() from exc
        raise

    row = await db.fetch_one(
        """
        SELECT agent_id, alias FROM {{tables.agents}}
        WHERE team_id = $1 AND did_key = $2 AND deleted_at IS NULL
        """,
        team_id,
        did_key,
    )
    assert row is not None  # The insert or its locked existing winner supplies this row.
    if row["alias"] != alias:
        raise AliasConflictError(
            f"cert claims alias {alias!r} but did_key is already bound to alias {row['alias']!r} in team {team_id}",
            code="alias_mismatch",
        )
    _require_planned_id(row["agent_id"], planned_agent_id)
    return str(row["agent_id"])


async def _lock_reconnecting_workspace(db, *, team_id: str, alias: str) -> None:
    """Take the selected workspace before member writes, matching lifecycle order.

    docs/aweb-sot.md:1242-1244 locks cleanup workspaces before member/claim
    mutations. A reconnect must not hold its agent while waiting for a cleanup
    that already holds this workspace and needs that agent. These storage locks
    grant no identity or membership authority.
    """
    await db.fetch_all(
        "SELECT workspace_id FROM {{tables.workspaces}} "
        "WHERE team_id=$1 AND alias=$2 AND deleted_at IS NULL "
        "ORDER BY workspace_id FOR UPDATE",
        team_id,
        alias,
    )


async def _ensure_workspace(
    db: AsyncDatabaseManager | TransactionManager,
    team_id: str,
    agent_id: str,
    alias: str,
    hostname: str,
    workspace_path: str,
    repo_origin: str,
    role: str,
    human_name: str,
    planned_workspace_id: uuid.UUID | None = None,
    workspace_profile: WorkspaceProfile | None = None,
) -> _ConnectedWorkspace:
    """Find or create a workspace row. Returns workspace_id as string.

    On reconnect (same team_id + alias), updates the existing workspace
    with fresh hostname/path/role/agent_id info.
    """
    repo_id = None
    if repo_origin:
        repo_id = await _ensure_repo(db, team_id, repo_origin)

    async def _get_existing_workspace():
        return await db.fetch_one(
            """
            SELECT workspace_id, agent_id, repo_id, workspace_type FROM {{tables.workspaces}}
            WHERE team_id = $1 AND alias = $2 AND deleted_at IS NULL
            """,
            team_id,
            alias,
        )

    async def _update_existing_workspace(existing) -> _ConnectedWorkspace:
        workspace_id = existing["workspace_id"]
        _require_planned_id(workspace_id, planned_workspace_id)
        if repo_id is not None or existing["repo_id"] is not None:
            workspace_type = "agent"
        elif workspace_profile is not None:
            workspace_type = workspace_profile.value
        else:
            workspace_type = existing["workspace_type"]
        await db.execute(
            """
            UPDATE {{tables.workspaces}}
            SET hostname = $1, workspace_path = $2, role = $3,
                human_name = $4, repo_id = COALESCE($5, repo_id),
                agent_id = $6, last_seen_at = NOW(), updated_at = NOW(), workspace_type = $8
            WHERE workspace_id = $7
            """,
            hostname,
            workspace_path,
            role,
            human_name,
            repo_id,
            uuid.UUID(agent_id),
            workspace_id,
            workspace_type,
        )
        return _ConnectedWorkspace(str(workspace_id), workspace_type)

    existing = await _get_existing_workspace()
    if existing:
        if str(existing["agent_id"]) != agent_id:
            raise AliasConflictError(
                f"alias {alias!r} is already in use by another active agent in team {team_id}",
                code="alias_active",
            )
        return await _update_existing_workspace(existing)

    workspace_id = planned_workspace_id or uuid.uuid4()
    if repo_id is not None:
        workspace_type = "agent"
    elif workspace_profile is not None:
        workspace_type = workspace_profile.value
    else:
        workspace_type = "manual"
    try:
        async with db.transaction() as insert_tx:
            row = await insert_tx.fetch_one(
                """
                INSERT INTO {{tables.workspaces}}
                    (workspace_id, team_id, agent_id, repo_id, alias, human_name,
                     role, hostname, workspace_path, workspace_type, last_seen_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
                RETURNING workspace_id
                """,
                workspace_id,
                team_id,
                uuid.UUID(agent_id),
                repo_id,
                alias,
                human_name,
                role,
                hostname,
                workspace_path,
                workspace_type,
            )
        assert row is not None  # This INSERT always returns the workspace it created.
        return _ConnectedWorkspace(str(row["workspace_id"]), workspace_type)
    except (QueryError, asyncpg.exceptions.UniqueViolationError) as exc:
        if isinstance(exc, QueryError) and not isinstance(
            exc.__cause__, asyncpg.exceptions.UniqueViolationError
        ):
            raise
        existing = await _get_existing_workspace()
        if existing and str(existing["agent_id"]) == agent_id:
            return await _update_existing_workspace(existing)
        if planned_workspace_id is not None and existing is None:
            raise PlannedIdentityConflict() from exc
        raise AliasConflictError(
            f"alias {alias!r} is already in use by another active agent in team {team_id}",
            code="alias_active",
        ) from exc


async def _ensure_repo(
    db: AsyncDatabaseManager | TransactionManager,
    team_id: str,
    repo_origin: str,
) -> str:
    """Find or create a repo row. Returns repo id."""
    try:
        return await ensure_repo(db, team_id, repo_origin)
    except ValueError as exc:
        raise HTTPException(
            status_code=422, detail=f"invalid repo_origin: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def connect_agent(
    *,
    db: AsyncDatabaseManager,
    cert_info: dict[str, str] | None = None,
    team_did_key: str | None = None,
    hostname: str,
    workspace_path: str,
    repo_origin: str,
    role: str,
    human_name: str,
    agent_type: str,
    identity_binding: IdentityBinding | None = None,
    identity_kind: IdentityKindObservation | None = None,
    planned_ids: PlannedIdentityIds | None = None,
    generation: VerifiedCertificateGeneration | None = None,
    workspace_profile: WorkspaceProfile | None = None,
) -> dict[str, Any]:
    """Auto-provision team + agent + workspace from certificate info.

    Args:
        db: The aweb database manager.
        cert_info: Verified team membership fields; member identity fields are claims.
        identity_binding: Exact fresh observation from observe_identity_binding,
            obtained before the caller opens its transaction. Required for global
            identity/address claims. This function performs no registry I/O.
        team_did_key: The team's public key from awid registry.
        hostname: Agent's hostname.
        workspace_path: Agent's workspace path.
        repo_origin: Git remote URL (empty if none).
        role: Agent role.
        human_name: Agent display name.
        agent_type: Non-authoritative runtime label; a human claim alone is ignored.
        identity_kind: Exact-subject observation from the public ID-chain verifier.
        planned_ids: Retained creation IDs; existing projections must match both exactly.
        workspace_profile: Explicit non-repository kind; an existing repository
            always keeps agent kind. Omission preserves an existing workspace kind.
        generation: Actual current-controller proof from verify_certificate_generation.
            Its immutable claims and verified key replace issuer-supplied mint fields.
            Registration status remains separate. Acquire this proof before locks;
            this constructor performs no registry read or certificate reparse.

    Returns:
        Dict with team_id, alias, agent_id, workspace_id, role.
    """
    if workspace_profile is not None and not isinstance(
        workspace_profile, WorkspaceProfile
    ):
        raise ValidationError(
            {
                "code": "workspace_profile_invalid",
                "message": "Choose WorkspaceProfile.MANUAL or WorkspaceProfile.HOSTED_MCP, then retry.",
            }
        )
    if generation is not None:
        if not isinstance(generation, VerifiedCertificateGeneration):
            raise TypeError(
                "Pass the result of verify_certificate_generation for generation admission."
            )
        claims = generation.certificate.claims
        verified = dict(claims)
        verified["did_key"] = claims["member_did_key"]
        verified["team_did_key"] = generation.verified_team_did_key
        if (
            team_did_key is not None
            and team_did_key != generation.verified_team_did_key
        ):
            raise ConnectIdentityRefusal(
                ConnectIdentityRefusalReason.GENERATION_MISMATCH
            )
        if cert_info is not None:
            for field in (
                "team_id",
                "team_did_key",
                "alias",
                "did_key",
                "member_did_key",
                "certificate_id",
                "member_did_aw",
                "member_address",
            ):
                if field not in cert_info:
                    continue
                supplied, checked = cert_info[field], verified.get(field, "")
                if field in ("member_did_aw", "member_address"):
                    supplied, checked = supplied or "", checked or ""
                if supplied != checked:
                    raise ConnectIdentityRefusal(
                        ConnectIdentityRefusalReason.GENERATION_MISMATCH
                    )
            if "identity_scope" in cert_info or "lifetime" in cert_info:
                supplied_scope = normalize_identity_scope(
                    cert_info.get("identity_scope") or cert_info.get("lifetime")
                )
                checked_scope = normalize_identity_scope(
                    verified.get("identity_scope") or verified.get("lifetime")
                )
                if supplied_scope != checked_scope:
                    raise ConnectIdentityRefusal(
                        ConnectIdentityRefusalReason.GENERATION_MISMATCH
                    )
        cert_info = verified
        team_did_key = generation.verified_team_did_key
    if cert_info is None or team_did_key is None:
        raise TypeError(
            "Pass verified request certificate fields and team key, or a verified generation."
        )
    if planned_ids is not None and not isinstance(planned_ids, PlannedIdentityIds):
        raise TypeError("Pass PlannedIdentityIds for retained creation resources.")
    team_id = cert_info["team_id"]
    alias = cert_info["alias"]
    did_key = cert_info["did_key"]
    identity_scope = normalize_identity_scope(
        cert_info.get("identity_scope") or cert_info.get("lifetime")
    )
    claimed_did_aw = cert_info.get("member_did_aw") or ""
    claimed_address = cert_info.get("member_address") or ""
    has_claims = bool(claimed_did_aw or claimed_address)
    if has_claims and identity_binding is None:
        raise ConnectIdentityRefusal(ConnectIdentityRefusalReason.BINDING_MISMATCH)
    if identity_binding is not None and (
        not isinstance(identity_binding, IdentityBinding)
        or identity_binding.did_key != did_key
        or identity_binding.did_aw != claimed_did_aw
        or identity_binding.address != claimed_address
        or (has_claims and not identity_binding.fresh_observation)
    ):
        raise ConnectIdentityRefusal(ConnectIdentityRefusalReason.BINDING_MISMATCH)
    did_aw = identity_binding.did_aw if identity_binding is not None else ""
    address = identity_binding.address if identity_binding is not None else ""

    if identity_kind is not None and (
        not isinstance(identity_kind, IdentityKindObservation)
        or identity_kind.did_key != did_key
        or identity_kind.did_aw != did_aw
    ):
        raise ConnectIdentityRefusal(ConnectIdentityRefusalReason.KIND_MISMATCH)
    human_verified_key = (
        did_key if identity_kind is not None and identity_kind.is_human else None
    )
    if human_verified_key:
        agent_type = "human"
    elif agent_type == "human":
        agent_type = "agent"

    async with db.transaction() as tx:
        await admit_team(db=tx, team_id=team_id, team_did_key=team_did_key)
        if generation is not None:
            # Lock the admitted pin before any member/workspace write. A proof
            # obtained before a concurrent controller move cannot restore the
            # old accepted key; the factory must verify it again outside locks.
            current_key = await tx.fetch_value(
                "SELECT team_did_key FROM {{tables.teams}} WHERE team_id=$1 FOR SHARE",
                team_id,
            )
            if current_key != generation.verified_team_did_key:
                raise ConnectIdentityRefusal(
                    ConnectIdentityRefusalReason.GENERATION_STALE
                )

        await _lock_reconnecting_workspace(tx, team_id=team_id, alias=alias)

        agent_id = await _ensure_agent(
            tx,
            team_id=team_id,
            did_key=did_key,
            did_aw=did_aw,
            address=address,
            alias=alias,
            identity_scope=identity_scope,
            human_name=human_name,
            agent_type=agent_type,
            role=role,
            certificate_id=cert_info.get("certificate_id", ""),
            human_verified_key=human_verified_key,
            accepted_team_did_key=team_did_key,
            planned_agent_id=planned_ids.agent_id if planned_ids is not None else None,
        )

        if identity_binding is not None:
            await refresh_projection_binding(
                tx,
                agent_id=agent_id,
                did_key=did_key,
                binding=identity_binding,
            )

        workspace = await _ensure_workspace(
            tx,
            team_id=team_id,
            agent_id=agent_id,
            alias=alias,
            hostname=hostname,
            workspace_path=workspace_path,
            repo_origin=repo_origin,
            role=role,
            human_name=human_name,
            planned_workspace_id=planned_ids.workspace_id
            if planned_ids is not None
            else None,
            workspace_profile=workspace_profile,
        )

    return {
        "team_id": team_id,
        "agent_type": agent_type,
        "alias": alias,
        "agent_id": agent_id,
        "workspace_id": workspace.workspace_id,
        "workspace_type": workspace.workspace_type,
        "role": role,
    }


# ---------------------------------------------------------------------------
# HTTP endpoint
# ---------------------------------------------------------------------------


@router.post("/connect", response_model=ConnectResponse)
async def connect_endpoint(
    request: Request, payload: ConnectRequest, db=Depends(get_db)
) -> ConnectResponse | JSONResponse:
    """Agent connects with certificate. Auto-provisions team + agent + workspace.

    Uses certificate-only auth (no agent lookup) since the agent may not
    exist yet — this endpoint creates the agent row.
    """
    cert_info = await verify_request_certificate(request, db, fresh=True)

    aweb_db = db.get_manager("aweb")

    # Use the registry-resolved team key (verified by verify_request_certificate)
    team_did_key = cert_info.get("verified_team_did_key", "")

    try:
        result = await connect_agent(
            db=aweb_db,
            cert_info=cert_info,
            identity_binding=cert_info.get("identity_binding"),
            identity_kind=cert_info.get("identity_kind"),
            team_did_key=team_did_key,
            hostname=payload.hostname,
            workspace_path=payload.workspace_path,
            repo_origin=payload.repo_origin,
            role=payload.role,
            human_name=payload.human_name,
            agent_type=payload.agent_type,
        )
    except AliasConflictError as exc:
        raise HTTPException(
            status_code=409, detail={"code": exc.code, "message": str(exc)}
        ) from exc
    except ConnectIdentityRefusal as exc:
        return JSONResponse(
            status_code=403,
            content={"detail": exc.reason.value, "message": exc.message},
        )
    except ServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc

    return ConnectResponse(**result)


class TeamInfoResponse(BaseModel):
    team_id: str
    namespace: str
    team_name: str
    team_did_key: str
    member_count: int


@router.get("/team", response_model=TeamInfoResponse)
async def get_team_info(request: Request, db=Depends(get_db)) -> TeamInfoResponse:
    """Get team info from the authenticated certificate."""

    identity = await get_team_identity(request, db)
    aweb_db = db.get_manager("aweb")

    team = await aweb_db.fetch_one(
        "SELECT * FROM {{tables.teams}} WHERE team_id = $1",
        identity.team_id,
    )
    if not team:
        raise HTTPException(status_code=404, detail="Team not found")

    count = await aweb_db.fetch_one(
        "SELECT COUNT(*)::int AS cnt FROM {{tables.agents}} a WHERE a.team_id = $1 AND "
        + current_member_sql("a"),
        identity.team_id,
    )

    return TeamInfoResponse(
        team_id=team["team_id"],
        namespace=team["namespace"],
        team_name=team["team_name"],
        team_did_key=team["team_did_key"],
        member_count=count["cnt"] if count else 0,
    )
