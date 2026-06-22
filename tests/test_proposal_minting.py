"""Real-Postgres flow for asset-scoped proposal minting.

A profile proposal carries a changeset of assets (files and profile.yaml fields).
Approve applies the changeset to the current shelf profile, rejects only assets whose
base digest is stale, and mints a new shelf version.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from fastapi import HTTPException

from library.blueprint import parse_profile_payload, profile_asset_digests
from library.digest import BLUEPRINT_PAYLOAD_SCHEMA, collect_files
from library.models import ProposalCreateRequest
from library.repository import (
    PROFILE_ASSET_CHANGESET_SCHEMA,
    approve_proposal,
    create_proposal,
    create_shelf_profile,
    import_to_shelf,
    list_shelf,
    publish_blueprint,
)

_SOURCE = Path(__file__).parent / "vectors" / "blueprints" / "engineering" / "source"
_TEAM = "default:atext.aweb.ai"


def _payload_file(path: str, content: str) -> dict[str, str]:
    return {
        "path": path,
        "content_utf8": content,
        "sha256": "sha256:" + hashlib.sha256(content.encode("utf-8")).hexdigest(),
    }


async def _publish_and_import(db) -> None:
    await db.execute(
        "INSERT INTO {{tables.teams}} (team_id, team_did_key) VALUES ($1, $2)"
        " ON CONFLICT (team_id) DO NOTHING",
        _TEAM,
        "did:key:zMintTest",
    )
    principal = SimpleNamespace(team_id=_TEAM, alias="dev")
    await publish_blueprint(
        db, principal=principal, payload={"files": collect_files(_SOURCE), "schema": BLUEPRINT_PAYLOAD_SCHEMA}
    )
    await import_to_shelf(
        db,
        principal=principal,
        source_blueprint_ref="aweb.engineering",
        source_blueprint_version=None,
        profile_ref="coordinator",
        tags=None,
    )


async def _latest_row(db, profile_ref: str = "coordinator") -> dict[str, Any]:
    row = await db.fetch_one(
        "SELECT version, digest, files, part_baselines, source_blueprint_ref"
        " FROM {{tables.shelf_profiles}} WHERE team_id = $1 AND profile_ref = $2"
        " ORDER BY created_at DESC LIMIT 1",
        _TEAM,
        profile_ref,
    )
    assert row is not None
    return dict(row)


def _json(value: Any) -> Any:
    import json

    return json.loads(value) if isinstance(value, str) else value


def _files(row: dict[str, Any]) -> list[dict[str, str]]:
    return _json(row["files"])


def _files_with_changes(base_files: list[dict[str, str]], *, version: str, replacements: dict[str, str]) -> list[dict[str, str]]:
    by_path = {entry["path"]: dict(entry) for entry in base_files}
    for path, content in replacements.items():
        by_path[path] = _payload_file(path, content)
    doc = yaml.safe_load(by_path["profile.yaml"]["content_utf8"]) or {}
    doc["version"] = version
    by_path["profile.yaml"] = _payload_file(
        "profile.yaml", yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)
    )
    return sorted(by_path.values(), key=lambda entry: entry["path"])


def _changeset(*assets: dict[str, Any]) -> dict[str, Any]:
    return {"schema": PROFILE_ASSET_CHANGESET_SCHEMA, "assets": list(assets)}


async def test_approve_applies_file_asset_to_current_profile_and_mints(migrated_db) -> None:
    db = migrated_db
    await _publish_and_import(db)
    principal = SimpleNamespace(team_id=_TEAM, alias="dev")
    base = await _latest_row(db)
    base_files = _files(base)
    base_digests = profile_asset_digests(base_files)
    base_part_baselines = _json(base["part_baselines"])

    new_instructions = next(f["content_utf8"] for f in base_files if f["path"] == "instructions.md") + (
        "\nRemember to report blockers early.\n"
    )
    expected_files = _files_with_changes(base_files, version="0.1.1", replacements={"instructions.md": new_instructions})
    expected_profile = parse_profile_payload(expected_files)

    proposal = await create_proposal(
        db,
        principal=principal,
        request=ProposalCreateRequest(
            target="profile",
            profile_ref="coordinator",
            content=_changeset(
                {
                    "path": "instructions.md",
                    "content_utf8": new_instructions,
                    "base_asset_digest": base_digests["file:instructions.md"],
                }
            ),
            summary="Sharpen coordinator instructions",
        ),
    )
    assert proposal["status"] == "open"
    approved = await approve_proposal(db, principal=principal, proposal_id=proposal["proposal_id"])
    assert approved["status"] == "approved"
    assert approved["minted"] == {
        "profile_ref": "coordinator",
        "version": "0.1.1",
        "digest": expected_profile.digest,
        "supersedes_profile_version": base["version"],
        "supersedes_profile_digest": base["digest"],
    }

    latest = await _latest_row(db)
    assert latest["version"] == "0.1.1"
    assert latest["digest"] == expected_profile.digest
    assert latest["source_blueprint_ref"] == "aweb.engineering"
    latest_files = _files(latest)
    assert next(f for f in latest_files if f["path"] == "instructions.md")["content_utf8"] == new_instructions
    # Team mints do not re-anchor blueprint baselines. The current asset digest is
    # recomputed for future proposal stale checks, but part_baselines must remain
    # the adopted blueprint baseline so update-from-source preserves this team edit.
    assert _json(latest["part_baselines"]) == base_part_baselines
    assert profile_asset_digests(latest_files)["file:instructions.md"] != base_part_baselines["file:instructions.md"]

    shelf = await list_shelf(db, principal=principal)
    coordinator = next(p for p in shelf["profiles"] if p["profile_ref"] == "coordinator")
    assert coordinator["version"] == "0.1.1"
    assert coordinator["digest"] == expected_profile.digest


async def test_non_overlapping_asset_proposals_do_not_conflict(migrated_db) -> None:
    db = migrated_db
    await _publish_and_import(db)
    principal = SimpleNamespace(team_id=_TEAM, alias="dev")
    base = await _latest_row(db)
    base_files = _files(base)
    base_digests = profile_asset_digests(base_files)
    instructions = next(f["content_utf8"] for f in base_files if f["path"] == "instructions.md") + "\nOne more rule.\n"
    mission = "Coordinate focused delivery and keep everyone unblocked."

    first = await create_proposal(
        db,
        principal=principal,
        request=ProposalCreateRequest(
            target="profile",
            profile_ref="coordinator",
            content=_changeset(
                {
                    "path": "instructions.md",
                    "content_utf8": instructions,
                    "base_asset_digest": base_digests["file:instructions.md"],
                }
            ),
        ),
    )
    second = await create_proposal(
        db,
        principal=principal,
        request=ProposalCreateRequest(
            target="profile",
            profile_ref="coordinator",
            content=_changeset(
                {"path": "profile.yaml#mission", "content": mission, "base_asset_digest": base_digests["field:mission"]}
            ),
        ),
    )

    await approve_proposal(db, principal=principal, proposal_id=first["proposal_id"])
    approved_second = await approve_proposal(db, principal=principal, proposal_id=second["proposal_id"])
    assert approved_second["minted"]["version"] == "0.1.2"
    latest = await _latest_row(db)
    latest_files = _files(latest)
    assert next(f for f in latest_files if f["path"] == "instructions.md")["content_utf8"] == instructions
    assert parse_profile_payload(latest_files).mission == mission


async def test_approve_rejects_only_stale_changed_asset(migrated_db) -> None:
    db = migrated_db
    await _publish_and_import(db)
    principal = SimpleNamespace(team_id=_TEAM, alias="dev")
    base = await _latest_row(db)
    base_files = _files(base)
    base_digests = profile_asset_digests(base_files)
    original_instructions = next(f["content_utf8"] for f in base_files if f["path"] == "instructions.md")

    first = await create_proposal(
        db,
        principal=principal,
        request=ProposalCreateRequest(
            target="profile",
            profile_ref="coordinator",
            content=_changeset(
                {
                    "path": "instructions.md",
                    "content_utf8": original_instructions + "\nFirst change.\n",
                    "base_asset_digest": base_digests["file:instructions.md"],
                }
            ),
        ),
    )
    stale = await create_proposal(
        db,
        principal=principal,
        request=ProposalCreateRequest(
            target="profile",
            profile_ref="coordinator",
            content=_changeset(
                {
                    "path": "instructions.md",
                    "content_utf8": original_instructions + "\nStale change.\n",
                    "base_asset_digest": base_digests["file:instructions.md"],
                }
            ),
        ),
    )
    await approve_proposal(db, principal=principal, proposal_id=first["proposal_id"])
    with pytest.raises(HTTPException) as excinfo:
        await approve_proposal(db, principal=principal, proposal_id=stale["proposal_id"])
    assert excinfo.value.status_code == 409


async def test_create_new_skill_changeset_is_atomic(migrated_db) -> None:
    db = migrated_db
    await _publish_and_import(db)
    principal = SimpleNamespace(team_id=_TEAM, alias="dev")
    base = await _latest_row(db)
    base_files = _files(base)
    base_digests = profile_asset_digests(base_files)
    profile_doc = yaml.safe_load(next(f["content_utf8"] for f in base_files if f["path"] == "profile.yaml")) or {}
    skills = list(profile_doc["skills"])
    skills.append({"path": "skills/debug/SKILL.md", "kind": "skill"})
    skill_content = "---\nname: debug\ndescription: Debug a failure.\n---\n\n# Debug\n"

    proposal = await create_proposal(
        db,
        principal=principal,
        request=ProposalCreateRequest(
            target="profile",
            profile_ref="coordinator",
            content=_changeset(
                {"path": "skills/debug/SKILL.md", "content_utf8": skill_content},
                {"path": "profile.yaml#skills", "content": skills, "base_asset_digest": base_digests["field:skills"]},
            ),
        ),
    )
    approved = await approve_proposal(db, principal=principal, proposal_id=proposal["proposal_id"])
    assert approved["minted"]["version"] == "0.1.1"
    latest_files = _files(await _latest_row(db))
    assert next(f for f in latest_files if f["path"] == "skills/debug/SKILL.md")["content_utf8"] == skill_content
    minted_doc = yaml.safe_load(next(f["content_utf8"] for f in latest_files if f["path"] == "profile.yaml")) or {}
    assert {entry["path"] for entry in minted_doc["skills"]} >= {"skills/debug/SKILL.md"}


async def test_create_first_skill_when_profile_yaml_skills_field_absent(migrated_db) -> None:
    db = migrated_db
    await _publish_and_import(db)
    principal = SimpleNamespace(team_id=_TEAM, alias="dev")
    minimal_files: list[dict[str, str]] = []
    for entry in collect_files(_SOURCE / "profiles" / "coordinator"):
        if entry["path"].startswith("skills/"):
            continue
        if entry["path"] == "profile.yaml":
            doc = yaml.safe_load(entry["content_utf8"]) or {}
            doc["id"] = "minimal"
            doc["name"] = "Minimal"
            doc.pop("skills", None)
            content = yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)
            minimal_files.append(_payload_file("profile.yaml", content))
        else:
            minimal_files.append(entry)
    await create_shelf_profile(db, principal=principal, files=sorted(minimal_files, key=lambda item: item["path"]), tags=[])

    base = await _latest_row(db, profile_ref="minimal")
    base_files = _files(base)
    base_doc = yaml.safe_load(next(f["content_utf8"] for f in base_files if f["path"] == "profile.yaml")) or {}
    assert "skills" not in base_doc
    # profile_asset_digests still emits the null field digest for update-from-source,
    # but proposal create semantics must treat the absent field as non-existent.
    assert "field:skills" in profile_asset_digests(base_files)
    skill_content = "---\nname: debug\ndescription: Debug a failure.\n---\n\n# Debug\n"

    proposal = await create_proposal(
        db,
        principal=principal,
        request=ProposalCreateRequest(
            target="profile",
            profile_ref="minimal",
            content=_changeset(
                {"path": "skills/debug/SKILL.md", "content_utf8": skill_content},
                {"path": "profile.yaml#skills", "content": [{"path": "skills/debug/SKILL.md", "kind": "skill"}]},
            ),
        ),
    )
    approved = await approve_proposal(db, principal=principal, proposal_id=proposal["proposal_id"])
    assert approved["minted"]["version"] == "0.1.1"
    latest_files = _files(await _latest_row(db, profile_ref="minimal"))
    minted_doc = yaml.safe_load(next(f["content_utf8"] for f in latest_files if f["path"] == "profile.yaml")) or {}
    assert minted_doc["skills"] == [{"path": "skills/debug/SKILL.md", "kind": "skill"}]
    assert next(f for f in latest_files if f["path"] == "skills/debug/SKILL.md")["content_utf8"] == skill_content


async def test_delete_asset_marker_removes_file_and_field_entry(migrated_db) -> None:
    db = migrated_db
    await _publish_and_import(db)
    principal = SimpleNamespace(team_id=_TEAM, alias="dev")
    base = await _latest_row(db)
    base_files = _files(base)
    base_digests = profile_asset_digests(base_files)
    profile_doc = yaml.safe_load(next(f["content_utf8"] for f in base_files if f["path"] == "profile.yaml")) or {}
    artifacts = [entry for entry in profile_doc["artifacts"] if entry["path"] != "artifacts/status-template.md"]

    proposal = await create_proposal(
        db,
        principal=principal,
        request=ProposalCreateRequest(
            target="profile",
            profile_ref="coordinator",
            content=_changeset(
                {
                    "path": "artifacts/status-template.md",
                    "delete": True,
                    "base_asset_digest": base_digests["file:artifacts/status-template.md"],
                },
                {
                    "path": "profile.yaml#artifacts",
                    "content": artifacts,
                    "base_asset_digest": base_digests["field:artifacts"],
                },
            ),
        ),
    )
    approved = await approve_proposal(db, principal=principal, proposal_id=proposal["proposal_id"])
    assert approved["minted"]["version"] == "0.1.1"
    latest_files = _files(await _latest_row(db))
    assert "artifacts/status-template.md" not in {entry["path"] for entry in latest_files}
    minted_doc = yaml.safe_load(next(f["content_utf8"] for f in latest_files if f["path"] == "profile.yaml")) or {}
    assert minted_doc["artifacts"] == []
