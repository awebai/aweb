from __future__ import annotations

import hashlib
import json
from typing import Any
from uuid import UUID, uuid4

import yaml
from fastapi import HTTPException
from pgdbm import AsyncDatabaseManager

from library.auth import Principal
from library.blueprint import (
    PROFILE_FIELD_ASSETS,
    ParsedBlueprint,
    ParsedProfile,
    build_blueprint_payload,
    import_return,
    materialize_home,
    parse_import_payload,
    parse_profile_payload,
    part_baselines,
    profile_asset_digests,
    three_way_merge,
)
from library.models import (
    MaterializeRequest,
    ProfileBindingRequest,
    ProfilePublishRequest,
    ProposalCreateRequest,
    UpdateFromSourceRequest,
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


def normalize_tags(tags: list[Any]) -> list[str]:
    """Owner-set free-form tags, normalized to deduped lowercase-trimmed strings."""
    return sorted({str(tag).strip().lower() for tag in tags if str(tag).strip()})


# --- Public blueprints (the catalog) -----------------------------------------------

_AWEB_BLUEPRINT_PREFIX = "aweb."


async def _ensure_blueprint_ref_publishable(
    tx: Any, *, owner_team: str, blueprint_ref: str
) -> None:
    """Reserve/check the public blueprint ref before minting catalog rows.

    Public reads resolve by bare blueprint_ref, so refs are globally exclusive:
    the first publisher owns the ref permanently. The first publisher of any
    aweb.* ref also reserves that prefix for first-party blueprints, including
    refs that do not currently exist or were deleted from the catalog.
    """
    if blueprint_ref.startswith(_AWEB_BLUEPRINT_PREFIX):
        prefix_inserted = await tx.fetch_one(
            """
            INSERT INTO {{tables.blueprint_ref_prefix_owners}} (ref_prefix, owner_team)
            VALUES ($1, $2)
            ON CONFLICT (ref_prefix) DO NOTHING
            RETURNING owner_team
            """,
            _AWEB_BLUEPRINT_PREFIX,
            owner_team,
        )
        prefix_owner = prefix_inserted or await tx.fetch_one(
            "SELECT owner_team FROM {{tables.blueprint_ref_prefix_owners}} WHERE ref_prefix = $1",
            _AWEB_BLUEPRINT_PREFIX,
        )
        if prefix_owner is not None and prefix_owner["owner_team"] != owner_team:
            raise HTTPException(
                status_code=409,
                detail="aweb.* blueprint refs are reserved to their first-party owner",
            )

    inserted = await tx.fetch_one(
        """
        INSERT INTO {{tables.blueprint_ref_owners}} (blueprint_ref, owner_team)
        VALUES ($1, $2)
        ON CONFLICT (blueprint_ref) DO NOTHING
        RETURNING owner_team
        """,
        blueprint_ref,
        owner_team,
    )
    if inserted is not None:
        return

    row = await tx.fetch_one(
        "SELECT owner_team FROM {{tables.blueprint_ref_owners}} WHERE blueprint_ref = $1",
        blueprint_ref,
    )
    if row is not None and row["owner_team"] != owner_team:
        if blueprint_ref.startswith(_AWEB_BLUEPRINT_PREFIX):
            detail = "aweb.* blueprint refs are reserved to their first-party owner"
        else:
            detail = f"Blueprint ref '{blueprint_ref}' is already owned by another team"
        raise HTTPException(status_code=409, detail=detail)


async def publish_blueprint(
    db: AsyncDatabaseManager, *, principal: Principal, payload: dict[str, Any]
) -> dict[str, Any]:
    """Publish (or update) a public blueprint in the global catalog. Wire-compatible
    with the frozen import-payload -> import-return contract; the blueprint and its
    profile snapshots are always public."""
    try:
        blueprint = parse_import_payload(payload)
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=422, detail=f"Invalid blueprint: {exc}") from exc

    await _persist_blueprint(db, principal=principal, blueprint=blueprint)
    return import_return(blueprint)


async def _persist_blueprint(
    db: AsyncDatabaseManager, *, principal: Principal, blueprint: ParsedBlueprint
) -> None:
    async with db.transaction() as tx:
        await _ensure_blueprint_ref_publishable(
            tx, owner_team=principal.team_id, blueprint_ref=blueprint.blueprint_ref
        )
        await tx.execute(
            """
            INSERT INTO {{tables.blueprints}}
              (owner_team, blueprint_ref, version, digest, name, summary, description,
               recommendations, runtime_hints, expected_apps, first_mission_examples, payload)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10, $11, $12::jsonb)
            ON CONFLICT (owner_team, blueprint_ref, version) DO UPDATE SET
                digest = EXCLUDED.digest, name = EXCLUDED.name, summary = EXCLUDED.summary,
                description = EXCLUDED.description, recommendations = EXCLUDED.recommendations,
                runtime_hints = EXCLUDED.runtime_hints, expected_apps = EXCLUDED.expected_apps,
                first_mission_examples = EXCLUDED.first_mission_examples, payload = EXCLUDED.payload
            """,
            principal.team_id,
            blueprint.blueprint_ref,
            blueprint.version,
            blueprint.digest,
            blueprint.name,
            blueprint.summary,
            blueprint.description,
            _dumps(blueprint.recommendations),
            blueprint.runtime_hints,
            blueprint.expected_apps,
            blueprint.first_mission_examples,
            _dumps(blueprint.files),
        )
        for profile in blueprint.profiles:
            await tx.execute(
                """
                INSERT INTO {{tables.blueprint_profiles}}
                  (owner_team, blueprint_ref, blueprint_version, profile_ref, profile_version, digest, name,
                   mission, accepted_work, runtime_assumptions, memory_policy, expected_apps,
                   event_subscriptions, approval_required, files)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12, $13::jsonb, $14, $15::jsonb)
                ON CONFLICT (owner_team, blueprint_ref, blueprint_version, profile_ref) DO UPDATE SET
                    profile_version = EXCLUDED.profile_version, digest = EXCLUDED.digest,
                    name = EXCLUDED.name, mission = EXCLUDED.mission,
                    accepted_work = EXCLUDED.accepted_work,
                    runtime_assumptions = EXCLUDED.runtime_assumptions,
                    memory_policy = EXCLUDED.memory_policy, expected_apps = EXCLUDED.expected_apps,
                    event_subscriptions = EXCLUDED.event_subscriptions,
                    approval_required = EXCLUDED.approval_required, files = EXCLUDED.files
                """,
                principal.team_id,
                blueprint.blueprint_ref,
                blueprint.version,
                profile.profile_ref,
                profile.version,
                profile.digest,
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


def _profile_runtime_hints(recommendations: Any, profile_ref: str) -> list[str]:
    """Structured harness hints are profile-specific blueprint recommendation metadata.

    v0.2.0 stores these in blueprint.yaml's ``profiles`` entries, persisted as the
    blueprints.recommendations JSON. Public get-profile surfaces the matching
    recommendation as a top-level field so callers do not need to parse blueprint.yaml.
    """
    for recommendation in _json_value(recommendations) or []:
        if not isinstance(recommendation, dict):
            continue
        recommendation_ref = str(
            recommendation.get("id") or recommendation.get("profile_ref") or ""
        )
        if recommendation_ref == profile_ref:
            value = recommendation.get("runtime_hints")
            return [str(item) for item in value] if isinstance(value, list) else []
    return []


def _blueprint_summary(row: Any) -> dict[str, Any]:
    data = dict(row)
    return {
        "blueprint_ref": data["blueprint_ref"],
        "version": data["version"],
        "digest": data["digest"],
        "tags": list(data["tags"] or []),
        "name": data["name"],
        "summary": data.get("summary"),
        "description": data.get("description"),
        "recommendations": _json_value(data.get("recommendations")) or [],
        "runtime_hints": list(data.get("runtime_hints") or []),
        "expected_apps": list(data.get("expected_apps") or []),
        "first_mission_examples": list(data.get("first_mission_examples") or []),
    }


_BLUEPRINT_COLUMNS = (
    "blueprint_ref, version, digest, tags, name, summary, description, "
    "recommendations, runtime_hints, expected_apps, first_mission_examples"
)


async def list_blueprints(
    db: AsyncDatabaseManager, *, tags: list[str] | None
) -> list[dict[str, Any]]:
    """The public catalog: latest version of every blueprint, optional ?tags overlap."""
    rows = await db.fetch_all(
        "SELECT DISTINCT ON (owner_team, blueprint_ref) "
        + _BLUEPRINT_COLUMNS
        + " FROM {{tables.blueprints}}"
        + " WHERE ($1::text[] IS NULL OR tags && $1)"
        + " ORDER BY owner_team, blueprint_ref, created_at DESC",
        tags,
    )
    return [_blueprint_summary(row) for row in rows]


async def get_blueprint(db: AsyncDatabaseManager, *, blueprint_ref: str) -> dict[str, Any]:
    row = await db.fetch_one(
        "SELECT " + _BLUEPRINT_COLUMNS + " FROM {{tables.blueprints}}"
        " WHERE blueprint_ref = $1 ORDER BY created_at DESC LIMIT 1",
        blueprint_ref,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Blueprint not found")
    summary = _blueprint_summary(row)
    profiles = await db.fetch_all(
        "SELECT profile_ref, profile_version AS version, digest, name, mission"
        " FROM {{tables.blueprint_profiles}}"
        " WHERE blueprint_ref = $1 AND blueprint_version = $2 ORDER BY profile_ref",
        blueprint_ref,
        summary["version"],
    )
    summary["profiles"] = [dict(profile) for profile in profiles]
    return summary


async def get_blueprint_profile(
    db: AsyncDatabaseManager, *, blueprint_ref: str, profile_ref: str
) -> dict[str, Any]:
    """A public profile snapshot from the latest version of a catalog blueprint — the
    full profile content, for previewing before import. No auth (public catalog)."""
    blueprint = await db.fetch_one(
        "SELECT owner_team, version, recommendations FROM {{tables.blueprints}}"
        " WHERE blueprint_ref = $1 ORDER BY created_at DESC LIMIT 1",
        blueprint_ref,
    )
    if blueprint is None:
        raise HTTPException(status_code=404, detail="Blueprint not found")
    row = await db.fetch_one(
        "SELECT profile_ref, profile_version, digest, name, mission, accepted_work,"
        " runtime_assumptions, memory_policy, expected_apps, event_subscriptions, approval_required, files"
        " FROM {{tables.blueprint_profiles}}"
        " WHERE owner_team = $1 AND blueprint_ref = $2 AND blueprint_version = $3 AND profile_ref = $4",
        blueprint["owner_team"],
        blueprint_ref,
        blueprint["version"],
        profile_ref,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Profile not found in blueprint")
    data = dict(row)
    return {
        "blueprint_ref": blueprint_ref,
        "blueprint_version": blueprint["version"],
        "profile_ref": data["profile_ref"],
        "version": data["profile_version"],
        "digest": data["digest"],
        "name": data["name"],
        "mission": data.get("mission"),
        "accepted_work": list(data.get("accepted_work") or []),
        "runtime_assumptions": list(data.get("runtime_assumptions") or []),
        "runtime_hints": _profile_runtime_hints(blueprint["recommendations"], data["profile_ref"]),
        "memory_policy": _json_value(data.get("memory_policy")),
        "expected_apps": list(data.get("expected_apps") or []),
        "event_subscriptions": _json_value(data.get("event_subscriptions")) or [],
        "approval_required": list(data.get("approval_required") or []),
        "files": _json_value(data.get("files")) or [],
    }


async def set_blueprint_tags(
    db: AsyncDatabaseManager, *, principal: Principal, blueprint_ref: str, tags: list[Any]
) -> dict[str, Any]:
    normalized = normalize_tags(tags)
    rows = await db.fetch_all(
        "UPDATE {{tables.blueprints}} SET tags = $3"
        " WHERE owner_team = $1 AND blueprint_ref = $2 RETURNING version",
        principal.team_id,
        blueprint_ref,
        normalized,
    )
    if not rows:
        raise HTTPException(status_code=404, detail="Blueprint not found")
    return {"blueprint_ref": blueprint_ref, "tags": normalized}


async def delete_blueprint(
    db: AsyncDatabaseManager, *, principal: Principal, blueprint_ref: str
) -> dict[str, Any]:
    """Hard-delete a public blueprint the team owns (all versions), cascading to its
    catalog profiles via the FK. Shelf profiles that source-track it are DETACHED -
    their source_* pins NULLed - so they survive as rootless profiles rather than
    orphaning (only update-from-source goes N/A, the source being gone). Irreversible."""
    async with db.transaction() as tx:
        deleted = await tx.fetch_all(
            "DELETE FROM {{tables.blueprints}}"
            " WHERE owner_team = $1 AND blueprint_ref = $2 RETURNING version",
            principal.team_id,
            blueprint_ref,
        )
        if not deleted:
            raise HTTPException(status_code=404, detail="Blueprint not found")
        # Detach EVERY dependent shelf profile, across ALL teams - this UPDATE is
        # intentionally NOT scoped by team_id. A public blueprint can be imported
        # onto any team's shelf, so deleting it must NULL every adopter's source pin,
        # not just the owner's, or other teams orphan. Do not add a team_id predicate.
        # The match is by source_blueprint_ref alone. Public blueprint refs are
        # globally exclusive (first publisher owns the ref), so this safely detaches
        # all dependents of exactly that public source ref.
        await tx.execute(
            "UPDATE {{tables.shelf_profiles}} SET"
            " source_blueprint_ref = NULL, source_blueprint_version = NULL, source_blueprint_digest = NULL,"
            " source_profile_ref = NULL, source_profile_version = NULL, source_profile_digest = NULL"
            " WHERE source_blueprint_ref = $1",
            blueprint_ref,
        )
    return {
        "blueprint_ref": blueprint_ref,
        "deleted_versions": sorted(row["version"] for row in deleted),
    }


async def delete_shelf_profile(
    db: AsyncDatabaseManager, *, principal: Principal, profile_ref: str
) -> dict[str, Any]:
    """Hard-delete a team's shelf profile (all versions) and clean its dependents -
    profile bindings and proposals for that profile_ref (neither has an FK to the
    shelf row). Team-scoped, irreversible."""
    async with db.transaction() as tx:
        deleted = await tx.fetch_all(
            "DELETE FROM {{tables.shelf_profiles}}"
            " WHERE team_id = $1 AND profile_ref = $2 RETURNING version",
            principal.team_id,
            profile_ref,
        )
        if not deleted:
            raise HTTPException(status_code=404, detail="Shelf profile not found")
        await tx.execute(
            "DELETE FROM {{tables.profile_bindings}} WHERE team_id = $1 AND profile_ref = $2",
            principal.team_id,
            profile_ref,
        )
        await tx.execute(
            "DELETE FROM {{tables.proposals}} WHERE team_id = $1 AND profile_ref = $2",
            principal.team_id,
            profile_ref,
        )
    return {
        "profile_ref": profile_ref,
        "deleted_versions": sorted(row["version"] for row in deleted),
    }


async def publish_profile(
    db: AsyncDatabaseManager,
    *,
    principal: Principal,
    profile_ref: str,
    request: ProfilePublishRequest,
) -> dict[str, Any]:
    """Publish a private shelf profile into a public blueprint. The blueprint is created
    (``new_blueprint``) or a new version of an owned blueprint (``existing_blueprint_ref``), with
    a library-generated blueprint.yaml and an accumulating profile set. The blueprint digest
    is the import-payload.v1 digest of the generated files; the published profile
    keeps the digest it had on the shelf."""
    existing_blueprint_ref = request.target_blueprint_ref
    new_blueprint = request.new_blueprint
    if bool(existing_blueprint_ref) == bool(new_blueprint):
        raise HTTPException(
            status_code=422,
            detail="exactly one of target_blueprint_ref or new_blueprint is required",
        )

    version = request.profile_version
    if version is None:
        latest = await db.fetch_one(
            "SELECT version FROM {{tables.shelf_profiles}}"
            " WHERE team_id = $1 AND profile_ref = $2 ORDER BY created_at DESC LIMIT 1",
            principal.team_id,
            profile_ref,
        )
        if latest is None:
            raise HTTPException(status_code=404, detail="Shelf profile not found")
        version = latest["version"]
    row = await db.fetch_one(
        "SELECT files FROM {{tables.shelf_profiles}}"
        " WHERE team_id = $1 AND profile_ref = $2 AND version = $3",
        principal.team_id,
        profile_ref,
        version,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Shelf profile not found")
    profile_files = _json_value(row["files"]) or []

    tags: list[str] | None = None
    if existing_blueprint_ref is not None:
        blueprint_row = await db.fetch_one(
            "SELECT name, summary, description, first_mission_examples, payload"
            " FROM {{tables.blueprints}}"
            " WHERE owner_team = $1 AND blueprint_ref = $2 ORDER BY created_at DESC LIMIT 1",
            principal.team_id,
            existing_blueprint_ref,
        )
        if blueprint_row is None:
            raise HTTPException(status_code=404, detail="Blueprint not found")
        blueprint_ref = existing_blueprint_ref
        name = blueprint_row["name"]
        summary = blueprint_row["summary"]
        description = blueprint_row["description"]
        first_mission_examples = list(blueprint_row["first_mission_examples"] or [])
        prior_files = _json_value(blueprint_row["payload"]) or []
        readme = None
    else:
        assert new_blueprint is not None
        blueprint_ref = new_blueprint.blueprint_ref
        name = new_blueprint.name
        summary = new_blueprint.summary
        description = new_blueprint.description
        first_mission_examples = list(new_blueprint.missions)
        prior_files = None
        readme = new_blueprint.readme
        tags = normalize_tags(new_blueprint.tags) or None

    payload = build_blueprint_payload(
        blueprint_ref=blueprint_ref,
        blueprint_version=request.blueprint_version,
        name=name,
        summary=summary,
        description=description,
        first_mission_examples=first_mission_examples,
        readme=readme,
        prior_files=prior_files,
        profile_ref=profile_ref,
        profile_files=profile_files,
    )
    try:
        blueprint = parse_import_payload(payload)
    except (ValueError, KeyError) as exc:  # pragma: no cover - generated payload is well-formed
        raise HTTPException(status_code=422, detail=f"Invalid generated blueprint: {exc}") from exc
    published = next(p for p in blueprint.profiles if p.profile_ref == profile_ref)

    await _persist_blueprint(db, principal=principal, blueprint=blueprint)
    if tags:
        await set_blueprint_tags(db, principal=principal, blueprint_ref=blueprint_ref, tags=tags)

    return {
        "blueprint_ref": blueprint.blueprint_ref,
        "blueprint_version": blueprint.version,
        "blueprint_digest": blueprint.digest,
        "profile_ref": published.profile_ref,
        "profile_version": published.version,
        "profile_digest": published.digest,
    }


# --- Private shelf ------------------------------------------------------------


def _shelf_summary(row: Any) -> dict[str, Any]:
    data = dict(row)
    return {
        "profile_ref": data["profile_ref"],
        "version": data["version"],
        "digest": data["digest"],
        "tags": list(data["tags"] or []),
        "name": data["name"],
        "mission": data.get("mission"),
        "accepted_work": list(data.get("accepted_work") or []),
        "runtime_assumptions": list(data.get("runtime_assumptions") or []),
        "memory_policy": _json_value(data.get("memory_policy")),
        "expected_apps": list(data.get("expected_apps") or []),
        "source_blueprint_ref": data.get("source_blueprint_ref"),
        "source_blueprint_version": data.get("source_blueprint_version"),
        "source_blueprint_digest": data.get("source_blueprint_digest"),
        "source_profile_ref": data.get("source_profile_ref"),
        "source_profile_version": data.get("source_profile_version"),
        "source_profile_digest": data.get("source_profile_digest"),
    }


_SHELF_SUMMARY_COLUMNS = (
    "profile_ref, version, digest, tags, name, mission, accepted_work, runtime_assumptions, "
    "memory_policy, expected_apps, source_blueprint_ref, source_blueprint_version, "
    "source_blueprint_digest, source_profile_ref, source_profile_version, source_profile_digest"
)


async def list_shelf(db: AsyncDatabaseManager, *, principal: Principal) -> dict[str, Any]:
    """The team's shelf working set: the latest version of each shelf profile, each
    carrying its source provenance and an ``update_available`` signal. The signal is
    computed here — true when the entry came from a blueprint and that blueprint's latest
    catalog version differs from the copy's pinned source version (the source
    blueprint has moved on). The update-from-source ACT is chunk B; this is the SIGNAL."""
    rows = await db.fetch_all(
        "SELECT DISTINCT ON (profile_ref) profile_ref, version, digest, name, mission, tags,"
        " source_blueprint_ref, source_blueprint_version, source_blueprint_digest,"
        " source_profile_ref, source_profile_version"
        " FROM {{tables.shelf_profiles}} WHERE team_id = $1"
        " ORDER BY profile_ref, created_at DESC",
        principal.team_id,
    )
    blueprint_refs = sorted({r["source_blueprint_ref"] for r in rows if r["source_blueprint_ref"]})
    latest: dict[str, str] = {}
    if blueprint_refs:
        latest_rows = await db.fetch_all(
            "SELECT DISTINCT ON (blueprint_ref) blueprint_ref, version FROM {{tables.blueprints}}"
            " WHERE blueprint_ref = ANY($1::text[]) ORDER BY blueprint_ref, created_at DESC",
            blueprint_refs,
        )
        latest = {r["blueprint_ref"]: r["version"] for r in latest_rows}

    profiles: list[dict[str, Any]] = []
    for row in rows:
        data = dict(row)
        source_blueprint_ref = data["source_blueprint_ref"]
        latest_version = latest.get(source_blueprint_ref) if source_blueprint_ref else None
        update_available = bool(
            source_blueprint_ref
            and latest_version is not None
            and latest_version != data["source_blueprint_version"]
        )
        profiles.append(
            {
                "profile_ref": data["profile_ref"],
                "version": data["version"],
                "digest": data["digest"],
                "name": data["name"],
                "summary": data["mission"],
                "tags": list(data["tags"] or []),
                "source_blueprint_ref": source_blueprint_ref,
                "source_blueprint_version": data["source_blueprint_version"],
                "source_blueprint_digest": data["source_blueprint_digest"],
                "source_profile_ref": data["source_profile_ref"],
                "source_profile_version": data["source_profile_version"],
                "source_blueprint_latest_version": latest_version,
                "update_available": update_available,
            }
        )
    return {"profiles": profiles}


async def get_shelf_profile(
    db: AsyncDatabaseManager, *, principal: Principal, profile_ref: str, include_files: bool = False
) -> dict[str, Any]:
    # The latest shelf version is the one approve() minted, so a refresh that reads
    # this picks up the team's own learning. include_files adds the profile content
    # for a local materialize; the digest stays the stored canonical profile digest.
    columns = _SHELF_SUMMARY_COLUMNS + (", files" if include_files else "")
    row = await db.fetch_one(
        "SELECT " + columns + " FROM {{tables.shelf_profiles}}"
        " WHERE team_id = $1 AND profile_ref = $2 ORDER BY created_at DESC LIMIT 1",
        principal.team_id,
        profile_ref,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Shelf profile not found")
    summary = _shelf_summary(row)
    if include_files:
        summary["files"] = _json_value(dict(row).get("files")) or []
    return summary


async def set_profile_tags(
    db: AsyncDatabaseManager, *, principal: Principal, profile_ref: str, tags: list[Any]
) -> dict[str, Any]:
    normalized = normalize_tags(tags)
    rows = await db.fetch_all(
        "UPDATE {{tables.shelf_profiles}} SET tags = $3"
        " WHERE team_id = $1 AND profile_ref = $2 RETURNING version",
        principal.team_id,
        profile_ref,
        normalized,
    )
    if not rows:
        raise HTTPException(status_code=404, detail="Shelf profile not found")
    return {"profile_ref": profile_ref, "tags": normalized}


async def _upsert_shelf_profile(
    db: AsyncDatabaseManager,
    *,
    team_id: str,
    profile: ParsedProfile,
    tags: list[str],
    source_blueprint_ref: str | None,
    source_blueprint_version: str | None,
    source_blueprint_digest: str | None,
    source_profile_ref: str | None,
    source_profile_version: str | None,
    source_profile_digest: str | None,
    part_baselines: dict[str, str],
) -> None:
    """Insert a shelf-profile version. Versions are unique per (team, profile_ref):
    supplying a version that already exists is a 409 conflict, never a silent
    overwrite (the anti-divergence guard — a version's content is immutable)."""
    row = await db.fetch_one(
        """
        INSERT INTO {{tables.shelf_profiles}}
          (team_id, profile_ref, version, digest, tags, name, mission, accepted_work,
           runtime_assumptions, memory_policy, expected_apps, event_subscriptions, approval_required,
           files, source_blueprint_ref, source_blueprint_version, source_blueprint_digest,
           source_profile_ref, source_profile_version, source_profile_digest, part_baselines)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11, $12::jsonb, $13, $14::jsonb,
                $15, $16, $17, $18, $19, $20, $21::jsonb)
        ON CONFLICT (team_id, profile_ref, version) DO NOTHING
        RETURNING version
        """,
        team_id,
        profile.profile_ref,
        profile.version,
        profile.digest,
        tags,
        profile.name,
        profile.mission,
        profile.accepted_work,
        profile.runtime_assumptions,
        _dumps(profile.memory_policy) if profile.memory_policy is not None else None,
        profile.expected_apps,
        _dumps(profile.event_subscriptions),
        profile.approval_required,
        _dumps(profile.files),
        source_blueprint_ref,
        source_blueprint_version,
        source_blueprint_digest,
        source_profile_ref,
        source_profile_version,
        source_profile_digest,
        _dumps(part_baselines),
    )
    if row is None:
        raise HTTPException(
            status_code=409,
            detail=f"Shelf profile '{profile.profile_ref}' version '{profile.version}' already exists",
        )


async def create_shelf_profile(
    db: AsyncDatabaseManager, *, principal: Principal, files: list[dict[str, str]], tags: list[Any]
) -> dict[str, Any]:
    """Create a directly-authored private shelf profile (no source blueprint)."""
    try:
        profile = parse_profile_payload(files)
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=422, detail=f"Invalid profile: {exc}") from exc
    await _upsert_shelf_profile(
        db,
        team_id=principal.team_id,
        profile=profile,
        tags=normalize_tags(tags or []),
        source_blueprint_ref=None,
        source_blueprint_version=None,
        source_blueprint_digest=None,
        source_profile_ref=None,
        source_profile_version=None,
        source_profile_digest=None,
        part_baselines={},
    )
    return await get_shelf_profile(db, principal=principal, profile_ref=profile.profile_ref)


async def create_shelf_version(
    db: AsyncDatabaseManager, *, principal: Principal, profile_ref: str, files: list[dict[str, str]]
) -> dict[str, Any]:
    """Add a new content version of an owned shelf profile (the evolve path).
    Source provenance, tags, and per-part baselines carry from the prior version."""
    try:
        profile = parse_profile_payload(files)
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=422, detail=f"Invalid profile: {exc}") from exc
    if profile.profile_ref != profile_ref:
        raise HTTPException(
            status_code=422, detail="profile.yaml id must match the path profile_ref"
        )
    prior = await db.fetch_one(
        "SELECT tags, source_blueprint_ref, source_blueprint_version, source_blueprint_digest,"
        " source_profile_ref, source_profile_version, source_profile_digest, part_baselines"
        " FROM {{tables.shelf_profiles}} WHERE team_id = $1 AND profile_ref = $2"
        " ORDER BY created_at DESC LIMIT 1",
        principal.team_id,
        profile_ref,
    )
    if prior is None:
        raise HTTPException(status_code=404, detail="Shelf profile not found")
    await _upsert_shelf_profile(
        db,
        team_id=principal.team_id,
        profile=profile,
        tags=list(prior["tags"] or []),
        source_blueprint_ref=prior["source_blueprint_ref"],
        source_blueprint_version=prior["source_blueprint_version"],
        source_blueprint_digest=prior["source_blueprint_digest"],
        source_profile_ref=prior["source_profile_ref"],
        source_profile_version=prior["source_profile_version"],
        source_profile_digest=prior["source_profile_digest"],
        part_baselines=_json_value(prior["part_baselines"]) or {},
    )
    return await get_shelf_profile(db, principal=principal, profile_ref=profile_ref)


def _shelf_provenance(data: dict[str, Any], *, created: bool) -> dict[str, Any]:
    return {
        "profile_ref": data["profile_ref"],
        "version": data["version"],
        "digest": data["digest"],
        "source_profile_ref": data["source_profile_ref"],
        "source_profile_version": data["source_profile_version"],
        "source_profile_digest": data["source_profile_digest"],
        "source_blueprint_ref": data["source_blueprint_ref"],
        "source_blueprint_version": data["source_blueprint_version"],
        "source_blueprint_digest": data["source_blueprint_digest"],
        "created": created,
    }


async def import_to_shelf(
    db: AsyncDatabaseManager,
    *,
    principal: Principal,
    source_blueprint_ref: str,
    source_blueprint_version: str | None,
    profile_ref: str,
    tags: list[Any] | None,
) -> dict[str, Any]:
    """Copy a public-blueprint profile onto the team's private shelf under its source
    profile_ref. Idempotent keyed by (team, source blueprint, profile_ref): a re-import
    from the same blueprint is a pure no-op returning the existing copy — it NEVER pulls
    a newer version (that is update-from-source). A profile_ref already held from a
    DIFFERENT source is a 409 conflict. First import records baselines + provenance."""
    existing = await db.fetch_one(
        "SELECT profile_ref, version, digest, source_profile_ref, source_profile_version,"
        " source_profile_digest, source_blueprint_ref, source_blueprint_version,"
        " source_blueprint_digest FROM {{tables.shelf_profiles}}"
        " WHERE team_id = $1 AND profile_ref = $2 ORDER BY created_at DESC LIMIT 1",
        principal.team_id,
        profile_ref,
    )
    if existing is not None:
        data = dict(existing)
        if data["source_blueprint_ref"] != source_blueprint_ref:
            raise HTTPException(
                status_code=409,
                detail=f"Shelf profile '{profile_ref}' already exists from a different source",
            )
        return _shelf_provenance(data, created=False)

    blueprint = await db.fetch_one(
        "SELECT owner_team, version, digest FROM {{tables.blueprints}}"
        " WHERE blueprint_ref = $1 AND ($2::text IS NULL OR version = $2)"
        " ORDER BY created_at DESC LIMIT 1",
        source_blueprint_ref,
        source_blueprint_version,
    )
    if blueprint is None:
        raise HTTPException(status_code=404, detail="Source blueprint not found")
    blueprint_version = blueprint["version"]
    blueprint_digest = blueprint["digest"]

    source = await db.fetch_one(
        "SELECT profile_ref, profile_version, digest, name, mission, accepted_work,"
        " runtime_assumptions, memory_policy, expected_apps, event_subscriptions, approval_required, files"
        " FROM {{tables.blueprint_profiles}}"
        " WHERE owner_team = $1 AND blueprint_ref = $2 AND blueprint_version = $3 AND profile_ref = $4",
        blueprint["owner_team"],
        source_blueprint_ref,
        blueprint_version,
        profile_ref,
    )
    if source is None:
        raise HTTPException(status_code=404, detail="Source profile not found in blueprint")

    source_profile = ParsedProfile(
        profile_ref=source["profile_ref"],
        version=source["profile_version"],
        digest=source["digest"],
        name=source["name"],
        mission=source["mission"],
        accepted_work=list(source["accepted_work"] or []),
        runtime_assumptions=list(source["runtime_assumptions"] or []),
        memory_policy=_json_value(source["memory_policy"]),
        expected_apps=list(source["expected_apps"] or []),
        event_subscriptions=_json_value(source["event_subscriptions"]) or [],
        approval_required=list(source["approval_required"] or []),
        files=_json_value(source["files"]) or [],
    )
    # The shelf copy is byte-identical to the source profile at copy time, so the
    # shelf digest == source digest and the source content is the per-part baseline.
    await _upsert_shelf_profile(
        db,
        team_id=principal.team_id,
        profile=source_profile,
        tags=normalize_tags(tags or []),
        source_blueprint_ref=source_blueprint_ref,
        source_blueprint_version=blueprint_version,
        source_blueprint_digest=blueprint_digest,
        source_profile_ref=source_profile.profile_ref,
        source_profile_version=source_profile.version,
        source_profile_digest=source_profile.digest,
        part_baselines=part_baselines(source_profile),
    )
    return _shelf_provenance(
        {
            "profile_ref": source_profile.profile_ref,
            "version": source_profile.version,
            "digest": source_profile.digest,
            "source_profile_ref": source_profile.profile_ref,
            "source_profile_version": source_profile.version,
            "source_profile_digest": source_profile.digest,
            "source_blueprint_ref": source_blueprint_ref,
            "source_blueprint_version": blueprint_version,
            "source_blueprint_digest": blueprint_digest,
        },
        created=True,
    )


def _blueprint_profile_files(row: Any) -> list[dict[str, str]]:
    return _json_value(row["files"]) or []


async def update_from_source(
    db: AsyncDatabaseManager,
    *,
    principal: Principal,
    profile_ref: str,
    request: UpdateFromSourceRequest,
) -> dict[str, Any]:
    """Per-part 3-way merge of a shelf profile against a newer version of its source
    blueprint: pull upstream improvements only into parts the team has not evolved, never
    clobbering local edits. A real merge (some part pulled) mints a new version
    (``target_version``) and advances the source pin + baselines to the synced
    version; if nothing is pullable it is a pure no-op (no new version, pin
    unchanged)."""
    ours = await db.fetch_one(
        "SELECT version, digest, tags, files, part_baselines, source_blueprint_ref,"
        " source_blueprint_version, source_blueprint_digest, source_profile_ref"
        " FROM {{tables.shelf_profiles}}"
        " WHERE team_id = $1 AND profile_ref = $2 ORDER BY created_at DESC LIMIT 1",
        principal.team_id,
        profile_ref,
    )
    if ours is None:
        raise HTTPException(status_code=404, detail="Shelf profile not found")
    source_blueprint_ref = ours["source_blueprint_ref"]
    if not source_blueprint_ref:
        raise HTTPException(
            status_code=422, detail="Shelf profile has no source blueprint to update from"
        )

    blueprint = await db.fetch_one(
        "SELECT owner_team, version, digest FROM {{tables.blueprints}}"
        " WHERE blueprint_ref = $1 AND ($2::text IS NULL OR version = $2)"
        " ORDER BY created_at DESC LIMIT 1",
        source_blueprint_ref,
        request.source_blueprint_version,
    )
    if blueprint is None:
        raise HTTPException(status_code=404, detail="Source blueprint not found")
    theirs_row = await db.fetch_one(
        "SELECT files FROM {{tables.blueprint_profiles}}"
        " WHERE owner_team = $1 AND blueprint_ref = $2 AND blueprint_version = $3 AND profile_ref = $4",
        blueprint["owner_team"],
        source_blueprint_ref,
        blueprint["version"],
        ours["source_profile_ref"] or profile_ref,
    )
    if theirs_row is None:
        raise HTTPException(status_code=404, detail="Source profile not found in blueprint")

    baselines = _json_value(ours["part_baselines"]) or {}
    merge = three_way_merge(
        ours_files=_json_value(ours["files"]) or [],
        theirs_files=_blueprint_profile_files(theirs_row),
        baselines=baselines,
        target_version=request.target_version,
    )

    if not merge.updated_parts:
        # Nothing pullable (no newer parts, or all newer parts are locally evolved):
        # a pure no-op — no new version, the source pin is left untouched.
        return {
            "profile_ref": profile_ref,
            "version": ours["version"],
            "digest": ours["digest"],
            "updated_parts": [],
            "preserved_parts": merge.preserved_parts,
            "source_blueprint_version": ours["source_blueprint_version"],
            "source_blueprint_digest": ours["source_blueprint_digest"],
        }

    merged = parse_profile_payload(merge.files)
    theirs = parse_profile_payload(_blueprint_profile_files(theirs_row))
    await _upsert_shelf_profile(
        db,
        team_id=principal.team_id,
        profile=merged,
        tags=list(ours["tags"] or []),
        source_blueprint_ref=source_blueprint_ref,
        source_blueprint_version=blueprint["version"],
        source_blueprint_digest=blueprint["digest"],
        source_profile_ref=ours["source_profile_ref"] or profile_ref,
        source_profile_version=theirs.version,
        source_profile_digest=theirs.digest,
        part_baselines=part_baselines(theirs),
    )
    return {
        "profile_ref": profile_ref,
        "version": merged.version,
        "digest": merged.digest,
        "updated_parts": merge.updated_parts,
        "preserved_parts": merge.preserved_parts,
        "source_blueprint_version": blueprint["version"],
        "source_blueprint_digest": blueprint["digest"],
    }


# --- Registration, bindings, materialize --------------------------------------


async def register_team(
    db: AsyncDatabaseManager, *, principal: Principal, owner: str | None, display_name: str | None
) -> dict[str, Any]:
    await db.execute(
        "INSERT INTO {{tables.team_registrations}} (team_id, owner, display_name)"
        " VALUES ($1, $2, $3) ON CONFLICT (team_id) DO NOTHING",
        principal.team_id,
        owner,
        display_name,
    )
    row = await db.fetch_one(
        "SELECT team_id, owner, display_name, registered_at FROM {{tables.team_registrations}}"
        " WHERE team_id = $1",
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
        await tx.execute(
            "INSERT INTO {{tables.team_registrations}} (team_id) VALUES ($1) ON CONFLICT (team_id) DO NOTHING",
            principal.team_id,
        )
        await tx.execute(
            """
            INSERT INTO {{tables.profile_bindings}}
              (team_id, agent_id, profile_ref, profile_version, profile_digest)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (team_id, agent_id) DO UPDATE SET
                profile_ref = EXCLUDED.profile_ref, profile_version = EXCLUDED.profile_version,
                profile_digest = EXCLUDED.profile_digest, bound_at = NOW()
            """,
            principal.team_id,
            agent_id,
            binding.profile_ref,
            binding.profile_version,
            binding.profile_digest,
        )
    return await get_profile_binding(db, principal=principal, agent_id=agent_id)


async def get_profile_binding(
    db: AsyncDatabaseManager, *, principal: Principal, agent_id: str
) -> dict[str, Any]:
    row = await db.fetch_one(
        "SELECT agent_id, profile_ref, profile_version, profile_digest"
        " FROM {{tables.profile_bindings}} WHERE team_id = $1 AND agent_id = $2",
        principal.team_id,
        agent_id,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="No profile binding for agent")
    return dict(row)


async def materialize(
    db: AsyncDatabaseManager, *, principal: Principal, request: MaterializeRequest
) -> dict[str, Any]:
    profile_ref = request.profile_ref
    version = request.profile_version
    if request.agent_id:
        binding = await db.fetch_one(
            "SELECT profile_ref, profile_version FROM {{tables.profile_bindings}}"
            " WHERE team_id = $1 AND agent_id = $2",
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
            "SELECT version FROM {{tables.shelf_profiles}}"
            " WHERE team_id = $1 AND profile_ref = $2 ORDER BY created_at DESC LIMIT 1",
            principal.team_id,
            profile_ref,
        )
        if latest is None:
            raise HTTPException(status_code=404, detail="Shelf profile not found")
        version = latest["version"]

    row = await db.fetch_one(
        "SELECT profile_ref, version, digest, runtime_assumptions, memory_policy, files,"
        " source_blueprint_ref, source_blueprint_version, source_blueprint_digest"
        " FROM {{tables.shelf_profiles}} WHERE team_id = $1 AND profile_ref = $2 AND version = $3",
        principal.team_id,
        profile_ref,
        version,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Shelf profile not found")

    runtime_assumptions = list(row["runtime_assumptions"] or [])
    memory_policy = _json_value(row["memory_policy"])
    home_files = materialize_home(
        _json_value(row["files"]) or [],
        profile_ref=row["profile_ref"],
        profile_version=row["version"],
        profile_digest=row["digest"],
        source_blueprint_ref=row["source_blueprint_ref"],
        source_blueprint_version=row["source_blueprint_version"],
        source_blueprint_digest=row["source_blueprint_digest"],
        runtime_kind=request.runtime_kind,
    )
    return {
        "profile_ref": row["profile_ref"],
        "profile_version": row["version"],
        "profile_digest": row["digest"],
        "source_blueprint_ref": row["source_blueprint_ref"],
        "source_blueprint_version": row["source_blueprint_version"],
        "source_blueprint_digest": row["source_blueprint_digest"],
        "runtime_assumptions": runtime_assumptions,
        "memory_policy": memory_policy,
        "home_files": home_files,
    }


# --- Proposals ---------------------------------------------------------------


PROFILE_ASSET_CHANGESET_SCHEMA = "aweb.library.profile-asset-changeset.v1"
_FIELD_ASSET_PREFIX = "profile.yaml#"

_PROPOSAL_COLUMNS = "proposal_id, target, profile_ref, status, content, summary, rationale, created_by_alias, created_at"


def _proposal_row(row: Any) -> dict[str, Any]:
    data = dict(row)
    return {
        "proposal_id": str(data["proposal_id"]),
        "target": data["target"],
        "profile_ref": data.get("profile_ref"),
        "status": data["status"],
        "content": _json_value(data.get("content")) or {},
        "summary": data.get("summary"),
        "rationale": data.get("rationale"),
        "created_by_alias": data.get("created_by_alias"),
        "created_at": data.get("created_at"),
    }


async def _get_proposal(
    db: AsyncDatabaseManager, team_id: str, proposal_id: UUID
) -> dict[str, Any]:
    row = await db.fetch_one(
        "SELECT " + _PROPOSAL_COLUMNS + " FROM {{tables.proposals}}"
        " WHERE team_id = $1 AND proposal_id = $2",
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
        " (proposal_id, team_id, target, profile_ref, content, summary, rationale, created_by_alias)"
        " VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8)",
        proposal_id,
        principal.team_id,
        request.target,
        request.profile_ref,
        _dumps(request.content),
        request.summary,
        request.rationale,
        principal.alias,
    )
    return await _get_proposal(db, principal.team_id, proposal_id)


async def list_proposals(db: AsyncDatabaseManager, *, principal: Principal) -> list[dict[str, Any]]:
    rows = await db.fetch_all(
        "SELECT " + _PROPOSAL_COLUMNS + " FROM {{tables.proposals}}"
        " WHERE team_id = $1 ORDER BY created_at DESC",
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


def _payload_file(path: str, content_utf8: str) -> dict[str, str]:
    return {
        "content_utf8": content_utf8,
        "path": path,
        "sha256": "sha256:" + hashlib.sha256(content_utf8.encode("utf-8")).hexdigest(),
    }


def _asset_key(path: str) -> str:
    if path.startswith(_FIELD_ASSET_PREFIX):
        field = path[len(_FIELD_ASSET_PREFIX) :]
        if field not in PROFILE_FIELD_ASSETS:
            raise HTTPException(
                status_code=422, detail=f"Unsupported profile.yaml asset field '{field}'"
            )
        return f"field:{field}"
    if path == "profile.yaml":
        raise HTTPException(
            status_code=422, detail="profile.yaml must be changed by profile.yaml#<field> assets"
        )
    if path.startswith("/") or ".." in path.split("/"):
        raise HTTPException(status_code=422, detail=f"Invalid asset path '{path}'")
    return f"file:{path}"


def _current_asset_digest(files: list[dict[str, str]], path: str) -> str | None:
    key = _asset_key(path)
    if path.startswith(_FIELD_ASSET_PREFIX):
        field = path[len(_FIELD_ASSET_PREFIX) :]
        by_path = {entry["path"]: entry for entry in files}
        profile_doc = yaml.safe_load(by_path["profile.yaml"]["content_utf8"]) or {}
        if field not in profile_doc:
            return None
    return profile_asset_digests(files).get(key)


def _validate_asset_base(
    *, files: list[dict[str, str]], asset: dict[str, Any], path: str, deleting: bool
) -> None:
    current = _current_asset_digest(files, path)
    base = asset.get("base_asset_digest")
    if current is None:
        if deleting:
            raise HTTPException(
                status_code=409, detail=f"Asset '{path}' is stale; it does not exist"
            )
        if base is not None:
            raise HTTPException(
                status_code=409, detail=f"Asset '{path}' is stale; it does not exist"
            )
        return
    if base is None:
        raise HTTPException(status_code=409, detail=f"Asset '{path}' already exists")
    if base != current:
        raise HTTPException(status_code=409, detail=f"Asset '{path}' is stale")


def _next_patch_version(version: str) -> str:
    parts = version.split(".")
    if parts and parts[-1].isdigit():
        parts[-1] = str(int(parts[-1]) + 1)
        return ".".join(parts)
    return f"{version}.1"


def _apply_asset_changeset(
    *, prior_files: list[dict[str, str]], changeset: dict[str, Any], target_version: str
) -> list[dict[str, str]]:
    if changeset.get("schema") != PROFILE_ASSET_CHANGESET_SCHEMA:
        raise HTTPException(
            status_code=422,
            detail=f"proposal content schema must be {PROFILE_ASSET_CHANGESET_SCHEMA}",
        )
    assets = changeset.get("assets")
    if not isinstance(assets, list) or not assets:
        raise HTTPException(
            status_code=422, detail="proposal content assets must be a non-empty list"
        )

    files_by_path = {entry["path"]: dict(entry) for entry in prior_files}
    profile_doc = yaml.safe_load(files_by_path["profile.yaml"]["content_utf8"]) or {}

    for raw_asset in assets:
        if not isinstance(raw_asset, dict):
            raise HTTPException(status_code=422, detail="proposal asset must be an object")
        path = raw_asset.get("path")
        if not isinstance(path, str) or not path:
            raise HTTPException(status_code=422, detail="proposal asset path is required")
        delete_value = raw_asset.get("delete", False)
        if not isinstance(delete_value, bool):
            raise HTTPException(status_code=422, detail=f"Asset '{path}' delete must be boolean")
        deleting = delete_value
        if deleting and ("content" in raw_asset or "content_utf8" in raw_asset):
            raise HTTPException(
                status_code=422, detail=f"Asset '{path}' cannot include content and delete"
            )
        _validate_asset_base(
            files=list(files_by_path.values()), asset=raw_asset, path=path, deleting=deleting
        )

        if path.startswith(_FIELD_ASSET_PREFIX):
            field = path[len(_FIELD_ASSET_PREFIX) :]
            if deleting:
                profile_doc.pop(field, None)
            elif "content" in raw_asset:
                profile_doc[field] = raw_asset["content"]
            else:
                raise HTTPException(
                    status_code=422, detail=f"Field asset '{path}' requires content"
                )
            profile_doc["version"] = target_version
            files_by_path["profile.yaml"] = _payload_file(
                "profile.yaml", yaml.safe_dump(profile_doc, sort_keys=False, allow_unicode=True)
            )
            continue

        if deleting:
            files_by_path.pop(path, None)
        elif isinstance(raw_asset.get("content_utf8"), str):
            files_by_path[path] = _payload_file(path, raw_asset["content_utf8"])
        else:
            raise HTTPException(
                status_code=422, detail=f"File asset '{path}' requires content_utf8"
            )

    profile_doc = yaml.safe_load(files_by_path["profile.yaml"]["content_utf8"]) or {}
    profile_doc["version"] = target_version
    files_by_path["profile.yaml"] = _payload_file(
        "profile.yaml", yaml.safe_dump(profile_doc, sort_keys=False, allow_unicode=True)
    )
    files = sorted(files_by_path.values(), key=lambda entry: entry["path"])
    try:
        parse_profile_payload(files)
    except (ValueError, KeyError) as exc:
        raise HTTPException(
            status_code=422, detail=f"Invalid minted profile after changeset: {exc}"
        ) from exc
    return files


async def _mint_from_proposal(
    db: AsyncDatabaseManager, *, principal: Principal, proposal: dict[str, Any]
) -> dict[str, Any]:
    """Mint a new shelf-profile version from an approved asset changeset.

    The stale guard is per asset: each proposed asset's base digest must match the
    current shelf profile asset digest. Non-overlapping proposals therefore compose.
    """
    profile_ref = proposal["profile_ref"]
    if not profile_ref:
        raise HTTPException(status_code=422, detail="profile proposal requires profile_ref")
    prior = await db.fetch_one(
        "SELECT version, digest, tags, files, part_baselines, source_blueprint_ref, source_blueprint_version,"
        " source_blueprint_digest, source_profile_ref, source_profile_version, source_profile_digest"
        " FROM {{tables.shelf_profiles}}"
        " WHERE team_id = $1 AND profile_ref = $2 ORDER BY created_at DESC LIMIT 1",
        principal.team_id,
        profile_ref,
    )
    if prior is None:
        raise HTTPException(status_code=404, detail="Shelf profile not found")
    target_version = _next_patch_version(str(prior["version"]))

    minted_files = _apply_asset_changeset(
        prior_files=_json_value(prior["files"]) or [],
        changeset=proposal["content"],
        target_version=target_version,
    )
    try:
        profile = parse_profile_payload(minted_files)
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=422, detail=f"Invalid minted profile: {exc}") from exc
    if profile.profile_ref != profile_ref:
        raise HTTPException(status_code=422, detail="minted profile.yaml id must match profile_ref")
    if profile.version != target_version:
        raise HTTPException(
            status_code=422,
            detail="minted profile.yaml version must match auto-incremented version",
        )

    await _upsert_shelf_profile(
        db,
        team_id=principal.team_id,
        profile=profile,
        tags=list(prior["tags"] or []),
        source_blueprint_ref=prior["source_blueprint_ref"],
        source_blueprint_version=prior["source_blueprint_version"],
        source_blueprint_digest=prior["source_blueprint_digest"],
        source_profile_ref=prior["source_profile_ref"],
        source_profile_version=prior["source_profile_version"],
        source_profile_digest=prior["source_profile_digest"],
        part_baselines=_json_value(prior["part_baselines"]) or {},
    )
    return {
        "profile_ref": profile.profile_ref,
        "version": profile.version,
        "digest": profile.digest,
        "supersedes_profile_version": prior["version"],
        "supersedes_profile_digest": prior["digest"],
    }


async def approve_proposal(
    db: AsyncDatabaseManager, *, principal: Principal, proposal_id: str
) -> dict[str, Any]:
    pid = _parse_proposal_id(proposal_id)
    proposal = await _get_proposal(db, principal.team_id, pid)
    if proposal["status"] != "open":
        raise HTTPException(status_code=409, detail=f"Proposal is already {proposal['status']}")
    minted = None
    if proposal["target"] == "profile":
        minted = await _mint_from_proposal(db, principal=principal, proposal=proposal)
    result = await _set_proposal_status(
        db, principal=principal, proposal_id=proposal_id, status="approved"
    )
    if minted is not None:
        result["minted"] = minted
    return result


async def reject_proposal(
    db: AsyncDatabaseManager, *, principal: Principal, proposal_id: str
) -> dict[str, Any]:
    return await _set_proposal_status(
        db, principal=principal, proposal_id=proposal_id, status="rejected"
    )
