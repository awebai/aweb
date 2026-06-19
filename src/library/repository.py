from __future__ import annotations

import json
from typing import Any
from uuid import UUID, uuid4

from fastapi import HTTPException
from pgdbm import AsyncDatabaseManager

from library.auth import Principal
from library.models import MaterializeRequest, ProfileBindingRequest, ProposalCreateRequest
from library.profile_pack import (
    ParsedProfile,
    import_return,
    materialize_home_files,
    parse_import_payload,
)


def _json_value(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return None
    return value


def _dumps(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"))


async def import_profile_pack(
    db: AsyncDatabaseManager, *, principal: Principal, payload: dict[str, Any]
) -> dict[str, Any]:
    try:
        pack = parse_import_payload(payload)
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=422, detail=f"Invalid profile pack: {exc}") from exc

    async with db.transaction() as tx:
        # visibility/tags are intentionally absent here: a new pack defaults to
        # private/empty, and a re-import of the same version preserves whatever
        # access settings the owner set (the UPDATE never touches them).
        await tx.execute(
            """
            INSERT INTO {{tables.profile_packs}}
              (owner_team, pack_ref, version, digest, name, summary, description,
               recommendations, runtime_hints, expected_apps, first_mission_examples, payload)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10, $11, $12::jsonb)
            ON CONFLICT (owner_team, pack_ref, version) DO UPDATE SET
                digest = EXCLUDED.digest, name = EXCLUDED.name, summary = EXCLUDED.summary,
                description = EXCLUDED.description, recommendations = EXCLUDED.recommendations,
                runtime_hints = EXCLUDED.runtime_hints, expected_apps = EXCLUDED.expected_apps,
                first_mission_examples = EXCLUDED.first_mission_examples, payload = EXCLUDED.payload
            """,
            principal.team_id,
            pack.pack_ref,
            pack.version,
            pack.digest,
            pack.name,
            pack.summary,
            pack.description,
            _dumps(pack.recommendations),
            pack.runtime_hints,
            pack.expected_apps,
            pack.first_mission_examples,
            _dumps(pack.files),
        )
        for profile in pack.profiles:
            await tx.execute(
                """
                INSERT INTO {{tables.profiles}}
                  (owner_team, profile_ref, version, digest, pack_ref, pack_version, name, mission,
                   accepted_work, runtime_assumptions, memory_policy, expected_apps,
                   event_subscriptions, approval_required, files)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12, $13::jsonb, $14, $15::jsonb)
                ON CONFLICT (owner_team, profile_ref, version) DO UPDATE SET
                    digest = EXCLUDED.digest, pack_ref = EXCLUDED.pack_ref,
                    pack_version = EXCLUDED.pack_version, name = EXCLUDED.name, mission = EXCLUDED.mission,
                    accepted_work = EXCLUDED.accepted_work, runtime_assumptions = EXCLUDED.runtime_assumptions,
                    memory_policy = EXCLUDED.memory_policy, expected_apps = EXCLUDED.expected_apps,
                    event_subscriptions = EXCLUDED.event_subscriptions,
                    approval_required = EXCLUDED.approval_required, files = EXCLUDED.files
                """,
                principal.team_id,
                profile.profile_ref,
                profile.version,
                profile.digest,
                pack.pack_ref,
                pack.version,
                profile.name,
                profile.mission,
                profile.accepted_work,
                profile.runtime_assumptions,
                _dumps(profile.memory_policy) if profile.memory_policy is not None else None,
                profile.expected_apps,
                _dumps(profile.event_subscriptions),
                profile.approval_required,
                _dumps(profile.files),
            )
    return import_return(pack)


async def register_team(
    db: AsyncDatabaseManager, *, principal: Principal, owner: str | None, display_name: str | None
) -> dict[str, Any]:
    await db.execute(
        """
        INSERT INTO {{tables.team_registrations}} (team_id, owner, display_name)
        VALUES ($1, $2, $3)
        ON CONFLICT (team_id) DO NOTHING
        """,
        principal.team_id,
        owner,
        display_name,
    )
    row = await db.fetch_one(
        "SELECT team_id, owner, display_name, registered_at FROM {{tables.team_registrations}} WHERE team_id = $1",
        principal.team_id,
    )
    data = dict(row) if row is not None else {"team_id": principal.team_id}
    return {
        "team_id": data["team_id"],
        "owner": data.get("owner"),
        "display_name": data.get("display_name"),
        "registered_at": data.get("registered_at"),
    }


async def set_profile_binding(
    db: AsyncDatabaseManager, *, principal: Principal, agent_id: str, binding: ProfileBindingRequest
) -> dict[str, Any]:
    async with db.transaction() as tx:
        # First-bind auto-registers the team (idempotent), so binding can never
        # race ahead of registration.
        await tx.execute(
            "INSERT INTO {{tables.team_registrations}} (team_id) VALUES ($1) ON CONFLICT (team_id) DO NOTHING",
            principal.team_id,
        )
        await tx.execute(
            """
            INSERT INTO {{tables.profile_bindings}}
              (team_id, agent_id, profile_ref, profile_version, profile_digest, source_profile_pack_ref)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (team_id, agent_id) DO UPDATE SET
                profile_ref = EXCLUDED.profile_ref, profile_version = EXCLUDED.profile_version,
                profile_digest = EXCLUDED.profile_digest,
                source_profile_pack_ref = EXCLUDED.source_profile_pack_ref, bound_at = NOW()
            """,
            principal.team_id,
            agent_id,
            binding.profile_ref,
            binding.profile_version,
            binding.profile_digest,
            binding.source_profile_pack_ref,
        )
    return await get_profile_binding(db, principal=principal, agent_id=agent_id)


async def get_profile_binding(
    db: AsyncDatabaseManager, *, principal: Principal, agent_id: str
) -> dict[str, Any]:
    row = await db.fetch_one(
        """
        SELECT agent_id, profile_ref, profile_version, profile_digest, source_profile_pack_ref
        FROM {{tables.profile_bindings}}
        WHERE team_id = $1 AND agent_id = $2
        """,
        principal.team_id,
        agent_id,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="No profile binding for agent")
    return dict(row)


def _pack_summary(row: Any) -> dict[str, Any]:
    data = dict(row)
    return {
        "pack_ref": data["pack_ref"],
        "version": data["version"],
        "digest": data["digest"],
        "visibility": data["visibility"],
        "tags": list(data["tags"] or []),
        "name": data["name"],
        "summary": data.get("summary"),
        "description": data.get("description"),
        "recommendations": _json_value(data.get("recommendations")) or [],
        "runtime_hints": list(data.get("runtime_hints") or []),
        "expected_apps": list(data.get("expected_apps") or []),
        "first_mission_examples": list(data.get("first_mission_examples") or []),
    }


def _profile_summary(row: Any) -> dict[str, Any]:
    data = dict(row)
    return {
        "profile_ref": data["profile_ref"],
        "version": data["version"],
        "digest": data["digest"],
        "visibility": data["visibility"],
        "tags": list(data["tags"] or []),
        "name": data["name"],
        "mission": data.get("mission"),
        "accepted_work": list(data.get("accepted_work") or []),
        "runtime_assumptions": list(data.get("runtime_assumptions") or []),
        "memory_policy": _json_value(data.get("memory_policy")),
        "expected_apps": list(data.get("expected_apps") or []),
    }


_PACK_COLUMNS = (
    "pack_ref, version, digest, visibility, tags, name, summary, description, "
    "recommendations, runtime_hints, expected_apps, first_mission_examples"
)
_PROFILE_COLUMNS = (
    "profile_ref, version, digest, visibility, tags, name, mission, accepted_work, "
    "runtime_assumptions, memory_policy, expected_apps"
)


async def list_profile_packs(
    db: AsyncDatabaseManager, *, team_id: str | None, tags: list[str] | None
) -> list[dict[str, Any]]:
    # Public packs are visible to everyone; the caller's own private packs are
    # added only when a team certificate is present (team_id is not None).
    rows = await db.fetch_all(
        "SELECT DISTINCT ON (owner_team, pack_ref) "
        + _PACK_COLUMNS
        + " FROM {{tables.profile_packs}}"
        + " WHERE (visibility = 'public' OR owner_team = $1) AND ($2::text[] IS NULL OR tags && $2)"
        + " ORDER BY owner_team, pack_ref, created_at DESC",
        team_id,
        tags,
    )
    return [_pack_summary(row) for row in rows]


async def get_profile_pack(db: AsyncDatabaseManager, *, team_id: str | None, pack_ref: str) -> dict[str, Any]:
    row = await db.fetch_one(
        "SELECT "
        + _PACK_COLUMNS
        + " FROM {{tables.profile_packs}}"
        + " WHERE pack_ref = $1 AND (visibility = 'public' OR owner_team = $2)"
        + " ORDER BY created_at DESC LIMIT 1",
        pack_ref,
        team_id,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Profile pack not found")
    return _pack_summary(row)


async def list_profiles(
    db: AsyncDatabaseManager, *, team_id: str | None, tags: list[str] | None
) -> list[dict[str, Any]]:
    rows = await db.fetch_all(
        "SELECT DISTINCT ON (owner_team, profile_ref) "
        + _PROFILE_COLUMNS
        + " FROM {{tables.profiles}}"
        + " WHERE (visibility = 'public' OR owner_team = $1) AND ($2::text[] IS NULL OR tags && $2)"
        + " ORDER BY owner_team, profile_ref, created_at DESC",
        team_id,
        tags,
    )
    return [_profile_summary(row) for row in rows]


async def get_profile(db: AsyncDatabaseManager, *, team_id: str | None, profile_ref: str) -> dict[str, Any]:
    row = await db.fetch_one(
        "SELECT "
        + _PROFILE_COLUMNS
        + " FROM {{tables.profiles}}"
        + " WHERE profile_ref = $1 AND (visibility = 'public' OR owner_team = $2)"
        + " ORDER BY created_at DESC LIMIT 1",
        profile_ref,
        team_id,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Profile not found")
    return _profile_summary(row)


def _proposal_row(row: Any) -> dict[str, Any]:
    data = dict(row)
    return {
        "proposal_id": str(data["proposal_id"]),
        "target": data["target"],
        "profile_ref": data.get("profile_ref"),
        "profile_version": data.get("profile_version"),
        "status": data["status"],
        "content": _json_value(data.get("content")) or {},
        "created_by_alias": data.get("created_by_alias"),
        "created_at": data.get("created_at"),
    }


async def _get_proposal(db: AsyncDatabaseManager, team_id: str, proposal_id: UUID) -> dict[str, Any]:
    row = await db.fetch_one(
        "SELECT proposal_id, target, profile_ref, profile_version, status, content, created_by_alias, created_at"
        " FROM {{tables.proposals}} WHERE team_id = $1 AND proposal_id = $2",
        team_id,
        proposal_id,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Proposal not found")
    return _proposal_row(row)


async def create_proposal(
    db: AsyncDatabaseManager, *, principal: Principal, request: ProposalCreateRequest
) -> dict[str, Any]:
    proposal_id = uuid4()
    await db.execute(
        "INSERT INTO {{tables.proposals}}"
        " (proposal_id, team_id, target, profile_ref, profile_version, content, created_by_alias)"
        " VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)",
        proposal_id,
        principal.team_id,
        request.target,
        request.profile_ref,
        request.profile_version,
        _dumps(request.content),
        principal.alias,
    )
    return await _get_proposal(db, principal.team_id, proposal_id)


async def list_proposals(db: AsyncDatabaseManager, *, principal: Principal) -> list[dict[str, Any]]:
    rows = await db.fetch_all(
        "SELECT proposal_id, target, profile_ref, profile_version, status, content, created_by_alias, created_at"
        " FROM {{tables.proposals}} WHERE team_id = $1 ORDER BY created_at DESC",
        principal.team_id,
    )
    return [_proposal_row(row) for row in rows]


def _parse_proposal_id(proposal_id: str) -> UUID:
    try:
        return UUID(proposal_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail="Proposal not found") from exc


async def _set_proposal_status(
    db: AsyncDatabaseManager, *, principal: Principal, proposal_id: str, status: str
) -> dict[str, Any]:
    pid = _parse_proposal_id(proposal_id)
    rows = await db.fetch_all(
        "UPDATE {{tables.proposals}} SET status = $3, updated_at = NOW()"
        " WHERE team_id = $1 AND proposal_id = $2 RETURNING proposal_id",
        principal.team_id,
        pid,
        status,
    )
    if not rows:
        raise HTTPException(status_code=404, detail="Proposal not found")
    return await _get_proposal(db, principal.team_id, pid)


async def approve_proposal(db: AsyncDatabaseManager, *, principal: Principal, proposal_id: str) -> dict[str, Any]:
    return await _set_proposal_status(db, principal=principal, proposal_id=proposal_id, status="approved")


async def reject_proposal(db: AsyncDatabaseManager, *, principal: Principal, proposal_id: str) -> dict[str, Any]:
    return await _set_proposal_status(db, principal=principal, proposal_id=proposal_id, status="rejected")


def normalize_tags(tags: list[Any]) -> list[str]:
    """Owner-set free-form tags, normalized to deduped lowercase-trimmed strings."""
    return sorted({str(tag).strip().lower() for tag in tags if str(tag).strip()})


async def _set_record_field(
    db: AsyncDatabaseManager, *, table: str, ref_column: str, ref: str, team_id: str, field: str, value: Any
) -> None:
    rows = await db.fetch_all(
        f"UPDATE {table} SET {field} = $3 WHERE owner_team = $1 AND {ref_column} = $2 RETURNING version",
        team_id,
        ref,
        value,
    )
    if not rows:
        raise HTTPException(status_code=404, detail="Not found")


async def set_profile_visibility(
    db: AsyncDatabaseManager, *, principal: Principal, profile_ref: str, visibility: str
) -> dict[str, Any]:
    if visibility not in ("public", "private"):
        raise HTTPException(status_code=422, detail="visibility must be 'public' or 'private'")
    await _set_record_field(
        db, table="{{tables.profiles}}", ref_column="profile_ref", ref=profile_ref,
        team_id=principal.team_id, field="visibility", value=visibility,
    )
    return {"profile_ref": profile_ref, "visibility": visibility}


async def set_profile_tags(
    db: AsyncDatabaseManager, *, principal: Principal, profile_ref: str, tags: list[Any]
) -> dict[str, Any]:
    normalized = normalize_tags(tags)
    await _set_record_field(
        db, table="{{tables.profiles}}", ref_column="profile_ref", ref=profile_ref,
        team_id=principal.team_id, field="tags", value=normalized,
    )
    return {"profile_ref": profile_ref, "tags": normalized}


async def set_pack_visibility(
    db: AsyncDatabaseManager, *, principal: Principal, pack_ref: str, visibility: str
) -> dict[str, Any]:
    if visibility not in ("public", "private"):
        raise HTTPException(status_code=422, detail="visibility must be 'public' or 'private'")
    await _set_record_field(
        db, table="{{tables.profile_packs}}", ref_column="pack_ref", ref=pack_ref,
        team_id=principal.team_id, field="visibility", value=visibility,
    )
    return {"pack_ref": pack_ref, "visibility": visibility}


async def set_pack_tags(
    db: AsyncDatabaseManager, *, principal: Principal, pack_ref: str, tags: list[Any]
) -> dict[str, Any]:
    normalized = normalize_tags(tags)
    await _set_record_field(
        db, table="{{tables.profile_packs}}", ref_column="pack_ref", ref=pack_ref,
        team_id=principal.team_id, field="tags", value=normalized,
    )
    return {"pack_ref": pack_ref, "tags": normalized}


async def materialize(
    db: AsyncDatabaseManager, *, principal: Principal, request: MaterializeRequest
) -> dict[str, Any]:
    profile_ref = request.profile_ref
    version = request.profile_version
    if request.agent_id:
        binding = await db.fetch_one(
            "SELECT profile_ref, profile_version FROM {{tables.profile_bindings}} WHERE team_id = $1 AND agent_id = $2",
            principal.team_id,
            request.agent_id,
        )
        if binding is None:
            raise HTTPException(status_code=404, detail="No profile binding for agent")
        profile_ref, version = binding["profile_ref"], binding["profile_version"]
    if not profile_ref:
        raise HTTPException(status_code=422, detail="materialize requires agent_id or profile_ref")
    if version is None:
        latest = await db.fetch_one(
            "SELECT version FROM {{tables.profiles}} WHERE owner_team = $1 AND profile_ref = $2 ORDER BY created_at DESC LIMIT 1",
            principal.team_id,
            profile_ref,
        )
        if latest is None:
            raise HTTPException(status_code=404, detail="Profile not found")
        version = latest["version"]

    row = await db.fetch_one(
        """
        SELECT profile_ref, version, digest, pack_ref, pack_version, runtime_assumptions, memory_policy, files
        FROM {{tables.profiles}}
        WHERE owner_team = $1 AND profile_ref = $2 AND version = $3
        """,
        principal.team_id,
        profile_ref,
        version,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Profile not found")

    pack_digest = None
    if row["pack_ref"]:
        pack = await db.fetch_one(
            "SELECT digest FROM {{tables.profile_packs}} WHERE owner_team = $1 AND pack_ref = $2 AND version = $3",
            principal.team_id,
            row["pack_ref"],
            row["pack_version"],
        )
        pack_digest = pack["digest"] if pack is not None else None

    runtime_assumptions = list(row["runtime_assumptions"] or [])
    memory_policy = _json_value(row["memory_policy"])
    profile = ParsedProfile(
        profile_ref=row["profile_ref"],
        version=row["version"],
        digest=row["digest"],
        name="",
        mission=None,
        accepted_work=[],
        runtime_assumptions=runtime_assumptions,
        memory_policy=memory_policy,
        expected_apps=[],
        event_subscriptions=[],
        approval_required=[],
        files=_json_value(row["files"]) or [],
    )
    home_files = materialize_home_files(
        profile,
        source_profile_pack_ref=row["pack_ref"] or "",
        source_profile_pack_version=row["pack_version"] or "",
        source_profile_pack_digest=pack_digest or "",
    )
    return {
        "profile_ref": profile.profile_ref,
        "profile_version": profile.version,
        "profile_digest": profile.digest,
        "source_profile_pack_ref": row["pack_ref"],
        "source_profile_pack_version": row["pack_version"],
        "source_profile_pack_digest": pack_digest,
        "runtime_assumptions": runtime_assumptions,
        "memory_policy": memory_policy,
        "home_files": home_files,
    }
