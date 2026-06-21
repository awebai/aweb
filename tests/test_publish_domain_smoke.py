"""Real-Postgres domain smoke for the normal publish path.

The unit suite exercises pure logic against fake DBs; it cannot catch a malformed
INSERT. This smoke runs the actual ``publish_blueprint`` -> ``import_to_shelf`` SQL
against a real Postgres with the frozen fixture, permanently covering the path a
public blueprint and a shelf adoption take from normal API state. Skips when no Postgres
is configured.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from library.digest import BLUEPRINT_PAYLOAD_SCHEMA, collect_files
from library.repository import import_to_shelf, list_shelf, publish_blueprint

_SOURCE = Path(__file__).parent / "vectors" / "blueprints" / "engineering" / "source"
_TEAM = "default:atext.aweb.ai"
_COORDINATOR_DIGEST = "sha256:b84396c46b66559e0a881f9cd1e85acb8e531296e45dcc6398c695841ecfcbe0"


async def test_publish_blueprint_then_import_to_shelf(migrated_db) -> None:
    db = migrated_db
    await db.execute(
        "INSERT INTO {{tables.teams}} (team_id, team_did_key) VALUES ($1, $2)"
        " ON CONFLICT (team_id) DO NOTHING",
        _TEAM,
        "did:key:zSmokeTest",
    )
    principal = SimpleNamespace(team_id=_TEAM)

    payload = {"files": collect_files(_SOURCE), "schema": BLUEPRINT_PAYLOAD_SCHEMA}
    published = await publish_blueprint(db, principal=principal, payload=payload)
    assert published["blueprint_ref"] == "aweb.engineering"
    assert {p["profile_ref"] for p in published["profiles"]} == {"coordinator", "developer", "reviewer"}

    imported = await import_to_shelf(
        db,
        principal=principal,
        source_blueprint_ref="aweb.engineering",
        source_blueprint_version=None,
        profile_ref="coordinator",
        tags=["coder"],
    )
    assert imported["created"] is True
    assert imported["digest"] == _COORDINATOR_DIGEST
    assert imported["source_blueprint_ref"] == "aweb.engineering"

    # A re-import from the same blueprint is a pure no-op.
    again = await import_to_shelf(
        db,
        principal=principal,
        source_blueprint_ref="aweb.engineering",
        source_blueprint_version=None,
        profile_ref="coordinator",
        tags=["coder"],
    )
    assert again["created"] is False

    shelf = await list_shelf(db, principal=principal)
    coordinator = next(p for p in shelf["profiles"] if p["profile_ref"] == "coordinator")
    assert coordinator["digest"] == _COORDINATOR_DIGEST
    assert coordinator["source_blueprint_ref"] == "aweb.engineering"
    assert coordinator["update_available"] is False
