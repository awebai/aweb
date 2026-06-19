from __future__ import annotations

import json
from typing import Any
from uuid import UUID, uuid4

from fastapi import HTTPException
from pgdbm import AsyncDatabaseManager

from library.auth import Principal
from library.models import (
    MaterializeRequest,
    ProfileBindingRequest,
    ProfilePublishRequest,
    ProposalCreateRequest,
)
from library.profile_pack import (
    ParsedPack,
    ParsedProfile,
    build_pack_payload,
    import_return,
    materialize_home,
    parse_import_payload,
    parse_profile_payload,
    part_baselines,
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


# --- Public packs (the catalog) -----------------------------------------------


async def publish_pack(
    db: AsyncDatabaseManager, *, principal: Principal, payload: dict[str, Any]
) -> dict[str, Any]:
    """Publish (or update) a public pack in the global catalog. Wire-compatible
    with the frozen import-payload -> import-return contract; the pack and its
    profile snapshots are always public."""
    try:
        pack = parse_import_payload(payload)
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=422, detail=f"Invalid profile pack: {exc}") from exc

    await _persist_pack(db, principal=principal, pack=pack)
    return import_return(pack)


async def _persist_pack(db: AsyncDatabaseManager, *, principal: Principal, pack: ParsedPack) -> None:
    async with db.transaction() as tx:
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
            principal.team_id, pack.pack_ref, pack.version, pack.digest, pack.name, pack.summary,
            pack.description, _dumps(pack.recommendations), pack.runtime_hints, pack.expected_apps,
            pack.first_mission_examples, _dumps(pack.files),
        )
        for profile in pack.profiles:
            await tx.execute(
                """
                INSERT INTO {{tables.pack_profiles}}
                  (owner_team, pack_ref, pack_version, profile_ref, profile_version, digest, name,
                   mission, accepted_work, runtime_assumptions, memory_policy, expected_apps,
                   event_subscriptions, approval_required, files)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12, $13::jsonb, $14, $15::jsonb)
                ON CONFLICT (owner_team, pack_ref, pack_version, profile_ref) DO UPDATE SET
                    profile_version = EXCLUDED.profile_version, digest = EXCLUDED.digest,
                    name = EXCLUDED.name, mission = EXCLUDED.mission,
                    accepted_work = EXCLUDED.accepted_work,
                    runtime_assumptions = EXCLUDED.runtime_assumptions,
                    memory_policy = EXCLUDED.memory_policy, expected_apps = EXCLUDED.expected_apps,
                    event_subscriptions = EXCLUDED.event_subscriptions,
                    approval_required = EXCLUDED.approval_required, files = EXCLUDED.files
                """,
                principal.team_id, pack.pack_ref, pack.version, profile.profile_ref, profile.version,
                profile.digest, profile.name, profile.mission, profile.accepted_work,
                profile.runtime_assumptions,
                _dumps(profile.memory_policy) if profile.memory_policy is not None else None,
                profile.expected_apps, _dumps(profile.event_subscriptions), profile.approval_required,
                _dumps(profile.files),
            )


def _pack_summary(row: Any) -> dict[str, Any]:
    data = dict(row)
    return {
        "pack_ref": data["pack_ref"],
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


_PACK_COLUMNS = (
    "pack_ref, version, digest, tags, name, summary, description, "
    "recommendations, runtime_hints, expected_apps, first_mission_examples"
)


async def list_profile_packs(db: AsyncDatabaseManager, *, tags: list[str] | None) -> list[dict[str, Any]]:
    """The public catalog: latest version of every pack, optional ?tags overlap."""
    rows = await db.fetch_all(
        "SELECT DISTINCT ON (owner_team, pack_ref) "
        + _PACK_COLUMNS
        + " FROM {{tables.profile_packs}}"
        + " WHERE ($1::text[] IS NULL OR tags && $1)"
        + " ORDER BY owner_team, pack_ref, created_at DESC",
        tags,
    )
    return [_pack_summary(row) for row in rows]


async def get_profile_pack(db: AsyncDatabaseManager, *, pack_ref: str) -> dict[str, Any]:
    row = await db.fetch_one(
        "SELECT " + _PACK_COLUMNS + " FROM {{tables.profile_packs}}"
        " WHERE pack_ref = $1 ORDER BY created_at DESC LIMIT 1",
        pack_ref,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Profile pack not found")
    summary = _pack_summary(row)
    profiles = await db.fetch_all(
        "SELECT profile_ref, profile_version AS version, digest, name, mission"
        " FROM {{tables.pack_profiles}}"
        " WHERE pack_ref = $1 AND pack_version = $2 ORDER BY profile_ref",
        pack_ref,
        summary["version"],
    )
    summary["profiles"] = [dict(profile) for profile in profiles]
    return summary


async def get_pack_profile(db: AsyncDatabaseManager, *, pack_ref: str, profile_ref: str) -> dict[str, Any]:
    """A public profile snapshot from the latest version of a catalog pack — the
    full profile content, for previewing before import. No auth (public catalog)."""
    pack = await db.fetch_one(
        "SELECT owner_team, version FROM {{tables.profile_packs}}"
        " WHERE pack_ref = $1 ORDER BY created_at DESC LIMIT 1",
        pack_ref,
    )
    if pack is None:
        raise HTTPException(status_code=404, detail="Profile pack not found")
    row = await db.fetch_one(
        "SELECT profile_ref, profile_version, digest, name, mission, accepted_work,"
        " runtime_assumptions, memory_policy, expected_apps, event_subscriptions, approval_required, files"
        " FROM {{tables.pack_profiles}}"
        " WHERE owner_team = $1 AND pack_ref = $2 AND pack_version = $3 AND profile_ref = $4",
        pack["owner_team"],
        pack_ref,
        pack["version"],
        profile_ref,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Profile not found in pack")
    data = dict(row)
    return {
        "pack_ref": pack_ref,
        "pack_version": pack["version"],
        "profile_ref": data["profile_ref"],
        "version": data["profile_version"],
        "digest": data["digest"],
        "name": data["name"],
        "mission": data.get("mission"),
        "accepted_work": list(data.get("accepted_work") or []),
        "runtime_assumptions": list(data.get("runtime_assumptions") or []),
        "memory_policy": _json_value(data.get("memory_policy")),
        "expected_apps": list(data.get("expected_apps") or []),
        "event_subscriptions": _json_value(data.get("event_subscriptions")) or [],
        "approval_required": list(data.get("approval_required") or []),
        "files": _json_value(data.get("files")) or [],
    }


async def set_pack_tags(
    db: AsyncDatabaseManager, *, principal: Principal, pack_ref: str, tags: list[Any]
) -> dict[str, Any]:
    normalized = normalize_tags(tags)
    rows = await db.fetch_all(
        "UPDATE {{tables.profile_packs}} SET tags = $3"
        " WHERE owner_team = $1 AND pack_ref = $2 RETURNING version",
        principal.team_id,
        pack_ref,
        normalized,
    )
    if not rows:
        raise HTTPException(status_code=404, detail="Profile pack not found")
    return {"pack_ref": pack_ref, "tags": normalized}


async def publish_profile(
    db: AsyncDatabaseManager, *, principal: Principal, profile_ref: str, request: ProfilePublishRequest
) -> dict[str, Any]:
    """Publish a private shelf profile into a public pack. The pack is created
    (``new_pack``) or a new version of an owned pack (``existing_pack_ref``), with
    a library-generated pack.yaml and an accumulating profile set. The pack digest
    is the import-payload.v1 digest of the generated files; the published profile
    keeps the digest it had on the shelf."""
    existing_pack_ref = request.target_pack_ref
    new_pack = request.new_pack
    if bool(existing_pack_ref) == bool(new_pack):
        raise HTTPException(
            status_code=422, detail="exactly one of target_pack_ref or new_pack is required"
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
    if existing_pack_ref is not None:
        pack_row = await db.fetch_one(
            "SELECT name, summary, description, first_mission_examples, payload"
            " FROM {{tables.profile_packs}}"
            " WHERE owner_team = $1 AND pack_ref = $2 ORDER BY created_at DESC LIMIT 1",
            principal.team_id,
            existing_pack_ref,
        )
        if pack_row is None:
            raise HTTPException(status_code=404, detail="Profile pack not found")
        pack_ref = existing_pack_ref
        name = pack_row["name"]
        summary = pack_row["summary"]
        description = pack_row["description"]
        first_mission_examples = list(pack_row["first_mission_examples"] or [])
        prior_files = _json_value(pack_row["payload"]) or []
        readme = None
    else:
        assert new_pack is not None
        pack_ref = new_pack.pack_ref
        name = new_pack.name
        summary = new_pack.summary
        description = new_pack.description
        first_mission_examples = list(new_pack.missions)
        prior_files = None
        readme = new_pack.readme
        tags = normalize_tags(new_pack.tags) or None

    payload = build_pack_payload(
        pack_ref=pack_ref,
        pack_version=request.pack_version,
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
        pack = parse_import_payload(payload)
    except (ValueError, KeyError) as exc:  # pragma: no cover - generated payload is well-formed
        raise HTTPException(status_code=422, detail=f"Invalid generated pack: {exc}") from exc
    published = next(p for p in pack.profiles if p.profile_ref == profile_ref)

    await _persist_pack(db, principal=principal, pack=pack)
    if tags:
        await set_pack_tags(db, principal=principal, pack_ref=pack_ref, tags=tags)

    return {
        "pack_ref": pack.pack_ref,
        "pack_version": pack.version,
        "pack_digest": pack.digest,
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
        "source_profile_pack_ref": data.get("source_profile_pack_ref"),
        "source_profile_pack_version": data.get("source_profile_pack_version"),
        "source_profile_pack_digest": data.get("source_profile_pack_digest"),
        "source_profile_ref": data.get("source_profile_ref"),
        "source_profile_version": data.get("source_profile_version"),
        "source_profile_digest": data.get("source_profile_digest"),
    }


_SHELF_SUMMARY_COLUMNS = (
    "profile_ref, version, digest, tags, name, mission, accepted_work, runtime_assumptions, "
    "memory_policy, expected_apps, source_profile_pack_ref, source_profile_pack_version, "
    "source_profile_pack_digest, source_profile_ref, source_profile_version, source_profile_digest"
)


async def list_shelf(db: AsyncDatabaseManager, *, principal: Principal) -> dict[str, Any]:
    """The team's shelf working set: the latest version of each shelf profile, each
    carrying its source provenance and an ``update_available`` signal. The signal is
    computed here — true when the entry came from a pack and that pack's latest
    catalog version differs from the copy's pinned source version (the source
    pack has moved on). The update-from-source ACT is chunk B; this is the SIGNAL."""
    rows = await db.fetch_all(
        "SELECT DISTINCT ON (profile_ref) profile_ref, version, digest, name, mission, tags,"
        " source_profile_pack_ref, source_profile_pack_version, source_profile_pack_digest,"
        " source_profile_ref, source_profile_version"
        " FROM {{tables.shelf_profiles}} WHERE team_id = $1"
        " ORDER BY profile_ref, created_at DESC",
        principal.team_id,
    )
    pack_refs = sorted({r["source_profile_pack_ref"] for r in rows if r["source_profile_pack_ref"]})
    latest: dict[str, str] = {}
    if pack_refs:
        latest_rows = await db.fetch_all(
            "SELECT DISTINCT ON (pack_ref) pack_ref, version FROM {{tables.profile_packs}}"
            " WHERE pack_ref = ANY($1::text[]) ORDER BY pack_ref, created_at DESC",
            pack_refs,
        )
        latest = {r["pack_ref"]: r["version"] for r in latest_rows}

    profiles: list[dict[str, Any]] = []
    for row in rows:
        data = dict(row)
        source_pack_ref = data["source_profile_pack_ref"]
        latest_version = latest.get(source_pack_ref) if source_pack_ref else None
        update_available = bool(
            source_pack_ref
            and latest_version is not None
            and latest_version != data["source_profile_pack_version"]
        )
        profiles.append(
            {
                "profile_ref": data["profile_ref"],
                "version": data["version"],
                "digest": data["digest"],
                "name": data["name"],
                "summary": data["mission"],
                "tags": list(data["tags"] or []),
                "source_profile_pack_ref": source_pack_ref,
                "source_profile_pack_version": data["source_profile_pack_version"],
                "source_profile_pack_digest": data["source_profile_pack_digest"],
                "source_profile_ref": data["source_profile_ref"],
                "source_profile_version": data["source_profile_version"],
                "source_pack_latest_version": latest_version,
                "update_available": update_available,
            }
        )
    return {"profiles": profiles}


async def get_shelf_profile(db: AsyncDatabaseManager, *, principal: Principal, profile_ref: str) -> dict[str, Any]:
    row = await db.fetch_one(
        "SELECT " + _SHELF_SUMMARY_COLUMNS + " FROM {{tables.shelf_profiles}}"
        " WHERE team_id = $1 AND profile_ref = $2 ORDER BY created_at DESC LIMIT 1",
        principal.team_id,
        profile_ref,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Shelf profile not found")
    return _shelf_summary(row)


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
    source_profile_pack_ref: str | None,
    source_profile_pack_version: str | None,
    source_profile_pack_digest: str | None,
    source_profile_ref: str | None,
    source_profile_version: str | None,
    source_profile_digest: str | None,
    part_baselines: dict[str, str],
) -> None:
    await db.execute(
        """
        INSERT INTO {{tables.shelf_profiles}}
          (team_id, profile_ref, version, digest, tags, name, mission, accepted_work,
           runtime_assumptions, memory_policy, expected_apps, event_subscriptions, approval_required,
           files, source_profile_pack_ref, source_profile_pack_version, source_profile_pack_digest,
           source_profile_ref, source_profile_version, source_profile_digest, part_baselines)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11, $12::jsonb, $13, $14::jsonb,
                $15, $16, $17, $18, $19, $20, $21::jsonb)
        ON CONFLICT (team_id, profile_ref, version) DO UPDATE SET
            digest = EXCLUDED.digest, tags = EXCLUDED.tags, name = EXCLUDED.name,
            mission = EXCLUDED.mission, accepted_work = EXCLUDED.accepted_work,
            runtime_assumptions = EXCLUDED.runtime_assumptions, memory_policy = EXCLUDED.memory_policy,
            expected_apps = EXCLUDED.expected_apps, event_subscriptions = EXCLUDED.event_subscriptions,
            approval_required = EXCLUDED.approval_required, files = EXCLUDED.files,
            source_profile_pack_ref = EXCLUDED.source_profile_pack_ref,
            source_profile_pack_version = EXCLUDED.source_profile_pack_version,
            source_profile_pack_digest = EXCLUDED.source_profile_pack_digest,
            source_profile_ref = EXCLUDED.source_profile_ref,
            source_profile_version = EXCLUDED.source_profile_version,
            source_profile_digest = EXCLUDED.source_profile_digest,
            part_baselines = EXCLUDED.part_baselines
        """,
        team_id, profile.profile_ref, profile.version, profile.digest, tags, profile.name,
        profile.mission, profile.accepted_work, profile.runtime_assumptions,
        _dumps(profile.memory_policy) if profile.memory_policy is not None else None,
        profile.expected_apps, _dumps(profile.event_subscriptions), profile.approval_required,
        _dumps(profile.files), source_profile_pack_ref, source_profile_pack_version,
        source_profile_pack_digest, source_profile_ref, source_profile_version, source_profile_digest,
        _dumps(part_baselines),
    )


async def create_shelf_profile(
    db: AsyncDatabaseManager, *, principal: Principal, files: list[dict[str, str]], tags: list[Any]
) -> dict[str, Any]:
    """Create a directly-authored private shelf profile (no source pack)."""
    try:
        profile = parse_profile_payload(files)
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=422, detail=f"Invalid profile: {exc}") from exc
    await _upsert_shelf_profile(
        db,
        team_id=principal.team_id,
        profile=profile,
        tags=normalize_tags(tags or []),
        source_profile_pack_ref=None,
        source_profile_pack_version=None,
        source_profile_pack_digest=None,
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
        raise HTTPException(status_code=422, detail="profile.yaml id must match the path profile_ref")
    prior = await db.fetch_one(
        "SELECT tags, source_profile_pack_ref, source_profile_pack_version, source_profile_pack_digest,"
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
        source_profile_pack_ref=prior["source_profile_pack_ref"],
        source_profile_pack_version=prior["source_profile_pack_version"],
        source_profile_pack_digest=prior["source_profile_pack_digest"],
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
        "source_profile_pack_ref": data["source_profile_pack_ref"],
        "source_profile_pack_version": data["source_profile_pack_version"],
        "source_profile_pack_digest": data["source_profile_pack_digest"],
        "created": created,
    }


async def import_to_shelf(
    db: AsyncDatabaseManager,
    *,
    principal: Principal,
    source_profile_pack_ref: str,
    source_profile_pack_version: str | None,
    profile_ref: str,
    tags: list[Any] | None,
) -> dict[str, Any]:
    """Copy a public-pack profile onto the team's private shelf under its source
    profile_ref. Idempotent keyed by (team, source pack, profile_ref): a re-import
    from the same pack is a pure no-op returning the existing copy — it NEVER pulls
    a newer version (that is update-from-source). A profile_ref already held from a
    DIFFERENT source is a 409 conflict. First import records baselines + provenance."""
    existing = await db.fetch_one(
        "SELECT profile_ref, version, digest, source_profile_ref, source_profile_version,"
        " source_profile_digest, source_profile_pack_ref, source_profile_pack_version,"
        " source_profile_pack_digest FROM {{tables.shelf_profiles}}"
        " WHERE team_id = $1 AND profile_ref = $2 ORDER BY created_at DESC LIMIT 1",
        principal.team_id,
        profile_ref,
    )
    if existing is not None:
        data = dict(existing)
        if data["source_profile_pack_ref"] != source_profile_pack_ref:
            raise HTTPException(
                status_code=409,
                detail=f"Shelf profile '{profile_ref}' already exists from a different source",
            )
        return _shelf_provenance(data, created=False)

    pack = await db.fetch_one(
        "SELECT owner_team, version, digest FROM {{tables.profile_packs}}"
        " WHERE pack_ref = $1 AND ($2::text IS NULL OR version = $2)"
        " ORDER BY created_at DESC LIMIT 1",
        source_profile_pack_ref,
        source_profile_pack_version,
    )
    if pack is None:
        raise HTTPException(status_code=404, detail="Source profile pack not found")
    pack_version = pack["version"]
    pack_digest = pack["digest"]

    source = await db.fetch_one(
        "SELECT profile_ref, profile_version, digest, name, mission, accepted_work,"
        " runtime_assumptions, memory_policy, expected_apps, event_subscriptions, approval_required, files"
        " FROM {{tables.pack_profiles}}"
        " WHERE owner_team = $1 AND pack_ref = $2 AND pack_version = $3 AND profile_ref = $4",
        pack["owner_team"],
        source_profile_pack_ref,
        pack_version,
        profile_ref,
    )
    if source is None:
        raise HTTPException(status_code=404, detail="Source profile not found in pack")

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
        source_profile_pack_ref=source_profile_pack_ref,
        source_profile_pack_version=pack_version,
        source_profile_pack_digest=pack_digest,
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
            "source_profile_pack_ref": source_profile_pack_ref,
            "source_profile_pack_version": pack_version,
            "source_profile_pack_digest": pack_digest,
        },
        created=True,
    )


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
        " source_profile_pack_ref, source_profile_pack_version, source_profile_pack_digest"
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
        source_profile_pack_ref=row["source_profile_pack_ref"],
        source_profile_pack_version=row["source_profile_pack_version"],
        source_profile_pack_digest=row["source_profile_pack_digest"],
    )
    return {
        "profile_ref": row["profile_ref"],
        "profile_version": row["version"],
        "profile_digest": row["digest"],
        "source_profile_pack_ref": row["source_profile_pack_ref"],
        "source_profile_pack_version": row["source_profile_pack_version"],
        "source_profile_pack_digest": row["source_profile_pack_digest"],
        "runtime_assumptions": runtime_assumptions,
        "memory_policy": memory_policy,
        "home_files": home_files,
    }


# --- Proposals (lifecycle only; minting deferred) -----------------------------


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
