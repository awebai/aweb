"""Real-Postgres domain smoke for the normal publish path.

The unit suite exercises pure logic against fake DBs; it cannot catch a malformed
INSERT. This smoke runs the actual ``publish_pack`` -> ``import_to_shelf`` SQL
against a real Postgres with the frozen fixture, permanently covering the path a
public pack and a shelf adoption take from normal API state. Skips when no Postgres
is configured.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from library.digest import PACK_PAYLOAD_SCHEMA, collect_files
from library.repository import import_to_shelf, list_shelf, publish_pack

_SOURCE = Path(__file__).parent / "vectors" / "profile-packs" / "engineering" / "source"
_TEAM = "default:atext.aweb.ai"
_COORDINATOR_DIGEST = "sha256:34d0305a43753bed042d7bfbdbdae77c19bdb89d4353ea103a9e1b0faa8be619"


async def test_publish_pack_then_import_to_shelf(migrated_db) -> None:
    db = migrated_db
    await db.execute(
        "INSERT INTO {{tables.teams}} (team_id, team_did_key) VALUES ($1, $2)"
        " ON CONFLICT (team_id) DO NOTHING",
        _TEAM,
        "did:key:zSmokeTest",
    )
    principal = SimpleNamespace(team_id=_TEAM)

    payload = {"files": collect_files(_SOURCE), "schema": PACK_PAYLOAD_SCHEMA}
    published = await publish_pack(db, principal=principal, payload=payload)
    assert published["pack_ref"] == "aweb.engineering-pack"
    assert {p["profile_ref"] for p in published["profiles"]} == {"coordinator", "developer", "reviewer"}

    imported = await import_to_shelf(
        db,
        principal=principal,
        source_profile_pack_ref="aweb.engineering-pack",
        source_profile_pack_version=None,
        profile_ref="coordinator",
        tags=["coder"],
    )
    assert imported["created"] is True
    assert imported["digest"] == _COORDINATOR_DIGEST
    assert imported["source_profile_pack_ref"] == "aweb.engineering-pack"

    # A re-import from the same pack is a pure no-op.
    again = await import_to_shelf(
        db,
        principal=principal,
        source_profile_pack_ref="aweb.engineering-pack",
        source_profile_pack_version=None,
        profile_ref="coordinator",
        tags=["coder"],
    )
    assert again["created"] is False

    shelf = await list_shelf(db, principal=principal)
    coordinator = next(p for p in shelf["profiles"] if p["profile_ref"] == "coordinator")
    assert coordinator["digest"] == _COORDINATOR_DIGEST
    assert coordinator["source_profile_pack_ref"] == "aweb.engineering-pack"
    assert coordinator["update_available"] is False
