"""Real-Postgres flow for update-from-source (chunk B).

Pull upstream improvements into un-evolved parts, keep local edits, mint a new
version only on a real merge, and never silently overwrite a version. Skips when no
Postgres is configured.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from library.digest import PACK_PAYLOAD_SCHEMA, collect_files
from library.models import UpdateFromSourceRequest
from library.repository import (
    create_shelf_version,
    import_to_shelf,
    list_shelf,
    publish_pack,
    update_from_source,
)

_SOURCE = Path(__file__).parent / "vectors" / "profile-packs" / "engineering" / "source"
_TEAM = "default:atext.aweb.ai"
_ORIGINAL_MISSION = "Coordinate the team, keep work unblocked, and maintain evidence."


def _repack(entry: dict[str, str], content: str) -> dict[str, str]:
    return {
        "content_utf8": content,
        "path": entry["path"],
        "sha256": "sha256:" + hashlib.sha256(content.encode("utf-8")).hexdigest(),
    }


def _v2_payload(new_mission: str) -> dict:
    """The fixture pack at version 0.2.0 with the coordinator's mission changed."""
    out: list[dict[str, str]] = []
    for entry in collect_files(_SOURCE):
        if entry["path"] == "pack.yaml":
            out.append(_repack(entry, entry["content_utf8"].replace("version: 0.1.0", "version: 0.2.0")))
        elif entry["path"] == "profiles/coordinator/profile.yaml":
            out.append(_repack(entry, entry["content_utf8"].replace(_ORIGINAL_MISSION, new_mission)))
        else:
            out.append(entry)
    return {"files": out, "schema": PACK_PAYLOAD_SCHEMA}


async def _setup(db) -> SimpleNamespace:
    await db.execute(
        "INSERT INTO {{tables.teams}} (team_id, team_did_key) VALUES ($1, $2)"
        " ON CONFLICT (team_id) DO NOTHING",
        _TEAM,
        "did:key:zUpdateTest",
    )
    principal = SimpleNamespace(team_id=_TEAM, alias="dev")
    await publish_pack(
        db, principal=principal, payload={"files": collect_files(_SOURCE), "schema": PACK_PAYLOAD_SCHEMA}
    )
    await import_to_shelf(
        db,
        principal=principal,
        source_profile_pack_ref="aweb.engineering-pack",
        source_profile_pack_version=None,
        profile_ref="coordinator",
        tags=None,
    )
    return principal


async def test_update_from_source_mints_merged_version(migrated_db) -> None:
    db = migrated_db
    principal = await _setup(db)
    await publish_pack(db, principal=principal, payload=_v2_payload("Coordinate sharply and keep evidence."))

    result = await update_from_source(
        db,
        principal=principal,
        profile_ref="coordinator",
        request=UpdateFromSourceRequest(target_version="0.2.0"),
    )
    assert "field:mission" in result["updated_parts"]
    assert result["version"] == "0.2.0"
    assert result["source_profile_pack_version"] == "0.2.0"

    shelf = await list_shelf(db, principal=principal)
    coordinator = next(p for p in shelf["profiles"] if p["profile_ref"] == "coordinator")
    assert coordinator["version"] == "0.2.0"
    assert coordinator["summary"] == "Coordinate sharply and keep evidence."  # mission pulled upstream
    assert coordinator["source_profile_pack_version"] == "0.2.0"  # pin advanced
    assert coordinator["update_available"] is False  # now current


async def test_update_from_source_noop_when_nothing_newer(migrated_db) -> None:
    db = migrated_db
    principal = await _setup(db)
    # No newer pack version published -> theirs == baseline -> pure no-op.
    result = await update_from_source(
        db,
        principal=principal,
        profile_ref="coordinator",
        request=UpdateFromSourceRequest(target_version="0.2.0"),
    )
    assert result["updated_parts"] == []
    assert result["version"] == "0.1.0"  # unchanged, no new version
    assert result["source_profile_pack_version"] == "0.1.0"  # pin unchanged


async def test_writing_an_existing_version_is_409(migrated_db) -> None:
    db = migrated_db
    principal = await _setup(db)
    # The imported coordinator is version 0.1.0; a shelf-version reusing 0.1.0 collides.
    with pytest.raises(HTTPException) as excinfo:
        await create_shelf_version(
            db,
            principal=principal,
            profile_ref="coordinator",
            files=collect_files(_SOURCE / "profiles" / "coordinator"),
        )
    assert excinfo.value.status_code == 409
