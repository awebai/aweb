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
from aweb.controller_import import VerifiedControllerImportMember
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

class _ProfileUpdate(StrEnum):
    RECONNECT = "reconnect"
    IMPORT = "import"


class WorkspaceContact(StrEnum):
    """The observed contact a constructor caller can attest to."""

    NONE = "none"
    SIGNED_CONNECT = "signed_connect"
    PERSON_SESSION = "person_session"
    OBSERVED_REFRESH = "observed_refresh"


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
    IMPORT_MISMATCH = "controller_import_mismatch"
    IMPORT_STALE = "controller_import_stale"


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
        messages[ConnectIdentityRefusalReason.IMPORT_MISMATCH] = (
            "Use the checked import's exact live member and controller fields, then retry importing."
        )
        messages[ConnectIdentityRefusalReason.IMPORT_STALE] = (
            "Read and verify the import again under the team's current controller, then retry importing."
        )
        self.message = messages[reason]


def _require_matching_admission_fields(
    *,
    supplied: dict[str, str] | None,
    supplied_team_key: str | None,
    checked: dict[str, str],
    reason: ConnectIdentityRefusalReason,
) -> None:
    """Accompanying fields constrain a checked proof; they cannot replace it."""
    if supplied_team_key is not None and supplied_team_key != checked["team_did_key"]:
        raise ConnectIdentityRefusal(reason)
    if supplied is None:
        return
    for field in (
        "team_id", "team_did_key", "alias", "did_key", "member_did_key",
        "certificate_id", "member_did_aw", "member_address",
    ):
        if field not in supplied:
            continue
        value, expected = supplied[field], checked.get(field, "")
        if field in ("member_did_aw", "member_address"):
            value, expected = value or "", expected or ""
        if value != expected:
            raise ConnectIdentityRefusal(reason)
    if "identity_scope" in supplied or "lifetime" in supplied:
        scope = normalize_identity_scope(supplied.get("identity_scope") or supplied.get("lifetime"))
        expected = normalize_identity_scope(checked.get("identity_scope") or checked.get("lifetime"))
        if scope != expected:
            raise ConnectIdentityRefusal(reason)


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
    profile_update: _ProfileUpdate = _ProfileUpdate.RECONNECT,
    identity_kind: IdentityKindObservation | None = None,
) -> str:
    """Find or create the agent row. Returns agent_id as string.

    did_aw and address come from independently verified identity bindings. Empty strings are stored as NULL (local
    certificates do not carry these fields).
    """

    stored_certificate_id = (
        certificate_id
        if profile_update is _ProfileUpdate.IMPORT
        else (certificate_id or "").strip() or None
    )

    async def _update_existing_agent(existing_agent) -> str:
        _require_planned_id(existing_agent["agent_id"], planned_agent_id)
        existing_alias = existing_agent["alias"]
        if existing_alias != alias:
            raise AliasConflictError(
                f"cert claims alias {alias!r} but did_key is already bound to alias {existing_alias!r} in team {team_id}",
                code="alias_mismatch",
            )
        if profile_update is _ProfileUpdate.IMPORT:
            effective_name, effective_role = existing_agent["human_name"], existing_agent["role"]
            if identity_kind is None:
                effective_type = existing_agent["agent_type"]
                effective_human_key = existing_agent["human_verified_key"]
            else:
                effective_type, effective_human_key = agent_type, human_verified_key
        else:
            effective_name, effective_role = human_name, role
            effective_type, effective_human_key = agent_type, human_verified_key
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
            effective_name,
            effective_type,
            effective_role,
            existing_agent["agent_id"],
            stored_certificate_id,
            did_key if did_aw else None,
            effective_human_key,
            accepted_team_did_key,
        )
        return str(existing_agent["agent_id"])

    existing_agent = await db.fetch_one(
        """
        SELECT agent_id, alias, human_name, role, agent_type, human_verified_key FROM {{tables.agents}}
        WHERE team_id = $1 AND did_key = $2 AND deleted_at IS NULL FOR UPDATE
        """,
        team_id,
        did_key,
    )
    if existing_agent:
        return await _update_existing_agent(existing_agent)

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
                stored_certificate_id,
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
            SELECT agent_id, alias, human_name, role, agent_type, human_verified_key FROM {{tables.agents}}
            WHERE team_id = $1 AND did_key = $2 AND deleted_at IS NULL FOR UPDATE
            """,
            team_id,
            did_key,
        )
        if existing_agent:
            try:
                return await _update_existing_agent(existing_agent)
            except AliasConflictError as conflict:
                raise conflict from exc
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
        SELECT agent_id, alias, human_name, role, agent_type, human_verified_key FROM {{tables.agents}}
        WHERE team_id = $1 AND did_key = $2 AND deleted_at IS NULL FOR UPDATE
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
    profile_update: _ProfileUpdate = _ProfileUpdate.RECONNECT,
    contact: WorkspaceContact = WorkspaceContact.NONE,
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
        if profile_update is _ProfileUpdate.IMPORT:
            return _ConnectedWorkspace(str(workspace_id), existing["workspace_type"])
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
                agent_id = $6, last_seen_at = CASE
                    WHEN $9 IN ('signed_connect', 'person_session')
                        OR ($9 = 'observed_refresh' AND last_seen_at IS NOT NULL)
                    THEN NOW()
                    ELSE last_seen_at
                END,
                updated_at = NOW(), workspace_type = $8
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
            contact.value,
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
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, CASE WHEN $11 = 'signed_connect' THEN NOW() END)
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
                contact.value,
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
    controller_import: VerifiedControllerImportMember | None = None,
    workspace_profile: WorkspaceProfile | None = None,
    contact: WorkspaceContact = WorkspaceContact.NONE,
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
        contact: Signed connect records contact on insert and update. A current
            person session refreshes an existing row. An observed refresh updates
            an existing row only once contact has already been recorded.
        controller_import: Actual live APPLY member from verify_controller_import.
            It is separate from generation/request proof, needs independent global
            binding/kind observations and preserves existing profiles on reuse.
        generation: Actual current-controller proof from verify_certificate_generation.
            Its immutable claims and verified key replace issuer-supplied mint fields.
            Registration status remains separate. Acquire this proof before locks;
            this constructor performs no registry read or certificate reparse.

    Returns:
        Dict with team_id, alias, agent_id, workspace_id, role.
    """
    if workspace_profile is not None and not isinstance(workspace_profile, WorkspaceProfile):
        raise ValidationError({
            "code": "workspace_profile_invalid",
            "message": "Choose WorkspaceProfile.MANUAL or WorkspaceProfile.HOSTED_MCP, then retry.",
        })
    if generation is not None and controller_import is not None:
        raise TypeError("Choose exactly one generation or checked controller-import input.")
    if controller_import is not None:
        if not isinstance(controller_import, VerifiedControllerImportMember):
            raise TypeError("Pass a checked controller-import member from verify_controller_import.")
        controller_import.require_freshness()
        certificate = controller_import.certificate
        if certificate.revoked_at is not None or controller_import.request.dry_run:
            raise ConnectIdentityRefusal(ConnectIdentityRefusalReason.IMPORT_MISMATCH)
        imported = {
            "team_id": controller_import.team_id,
            "team_did_key": controller_import.verified_team_did_key,
            "did_key": certificate.member_did_key,
            "member_did_key": certificate.member_did_key,
            "certificate_id": certificate.certificate_id,
            "alias": certificate.alias,
            "identity_scope": certificate.identity_scope,
            "member_did_aw": certificate.member_did_aw or "",
            "member_address": certificate.member_address or "",
        }
        _require_matching_admission_fields(
            supplied=cert_info, supplied_team_key=team_did_key, checked=imported,
            reason=ConnectIdentityRefusalReason.IMPORT_MISMATCH,
        )
        cert_info = imported
        team_did_key = controller_import.verified_team_did_key
        # Ordinary self-custodial import supplies no runtime/worktree profile.
        # Existing workspaces retain their complete profile; new ones are manual.
        hostname, workspace_path, repo_origin = "", "", ""
        workspace_profile = WorkspaceProfile.MANUAL
    if generation is not None:
        if not isinstance(generation, VerifiedCertificateGeneration):
            raise TypeError(
                "Pass the result of verify_certificate_generation for generation admission."
            )
        claims = generation.certificate.claims
        verified = dict(claims)
        verified["did_key"] = claims["member_did_key"]
        verified["team_did_key"] = generation.verified_team_did_key
        _require_matching_admission_fields(
            supplied=cert_info, supplied_team_key=team_did_key, checked=verified,
            reason=ConnectIdentityRefusalReason.GENERATION_MISMATCH,
        )
        cert_info = verified
        team_did_key = generation.verified_team_did_key
    if cert_info is None or team_did_key is None:
        raise TypeError("Pass verified request fields and team key, a verified generation, or a checked controller-import member.")
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
        if generation is not None or controller_import is not None:
            # Lock the admitted pin before any member/workspace write. A proof
            # obtained before a concurrent controller move cannot restore the
            # old accepted key; the factory must verify it again outside locks.
            current_key = await tx.fetch_value(
                "SELECT team_did_key FROM {{tables.teams}} WHERE team_id=$1 FOR SHARE",
                team_id,
            )
            if current_key != team_did_key:
                reason = (
                    ConnectIdentityRefusalReason.IMPORT_STALE
                    if controller_import is not None
                    else ConnectIdentityRefusalReason.GENERATION_STALE
                )
                raise ConnectIdentityRefusal(reason)

        await _lock_reconnecting_workspace(tx, team_id=team_id, alias=alias)
        if controller_import is not None:
            controller_import.require_freshness()
        profile_update = (
            _ProfileUpdate.IMPORT if controller_import is not None else _ProfileUpdate.RECONNECT
        )

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
            profile_update=profile_update,
            identity_kind=identity_kind,
        )

        if controller_import is not None:
            controller_import.require_freshness()
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
            profile_update=profile_update,
            contact=contact,
        )
        if controller_import is not None:
            controller_import.require_freshness()
            effective_profile = await tx.fetch_one(
                "SELECT role, agent_type FROM {{tables.agents}} WHERE agent_id=$1",
                uuid.UUID(agent_id),
            )
            assert effective_profile is not None  # The member write is held in this transaction.
            role, agent_type = effective_profile["role"], effective_profile["agent_type"]

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
            contact=WorkspaceContact.SIGNED_CONNECT,
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
