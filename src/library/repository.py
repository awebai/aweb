from __future__ import annotations

import json
from typing import Any

from fastapi import HTTPException
from pgdbm import AsyncDatabaseManager

from library.auth import Principal
from library.models import MaterializeRequest, ProfileBindingRequest
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
