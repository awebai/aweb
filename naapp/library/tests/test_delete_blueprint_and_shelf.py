"""Real-Postgres domain coverage for hard-delete of blueprints and shelf profiles.

delete_blueprint detaches dependent shelf pins (the shelf profiles survive,
rootless) then hard-deletes the blueprint (cascading to its catalog profiles);
delete_shelf_profile hard-deletes a team's shelf profile and cleans its bindings +
proposals. Both are owner/team-scoped and irreversible. Skips when no Postgres.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from library.digest import BLUEPRINT_PAYLOAD_SCHEMA, collect_files
from library.models import ProfileBindingRequest
from library.repository import (
    delete_blueprint,
    delete_shelf_profile,
    get_blueprint,
    get_blueprint_profile,
    get_profile_binding,
    get_shelf_profile,
    import_to_shelf,
    publish_blueprint,
    set_profile_binding,
)

_SOURCE = Path(__file__).parent / "vectors" / "blueprints" / "engineering" / "source"
_TEAM = "default:atext.aweb.ai"
_OTHER_TEAM = "default:other.example"


async def _seed_team(db, team_id: str) -> None:
    await db.execute(
        "INSERT INTO {{tables.teams}} (team_id, team_did_key) VALUES ($1, $2)"
        " ON CONFLICT (team_id) DO NOTHING",
        team_id,
        "did:key:z" + team_id.replace(":", ""),
    )


async def _publish_engineering(db, principal) -> None:
    payload = {"files": collect_files(_SOURCE), "schema": BLUEPRINT_PAYLOAD_SCHEMA}
    await publish_blueprint(db, principal=principal, payload=payload)


async def test_delete_blueprint_detaches_shelf_pins_and_cascades_profiles(migrated_db) -> None:
    db = migrated_db
    await _seed_team(db, _TEAM)
    principal = SimpleNamespace(team_id=_TEAM)
    await _publish_engineering(db, principal)
    await import_to_shelf(
        db,
        principal=principal,
        source_blueprint_ref="aweb.engineering",
        source_blueprint_version=None,
        profile_ref="coordinator",
        tags=[],
    )
    before = await get_shelf_profile(db, principal=principal, profile_ref="coordinator")
    assert before["source_blueprint_ref"] == "aweb.engineering"

    result = await delete_blueprint(db, principal=principal, blueprint_ref="aweb.engineering")
    assert result["blueprint_ref"] == "aweb.engineering"

    # the blueprint and its catalog profiles are gone.
    with pytest.raises(HTTPException) as exc:
        await get_blueprint(db, blueprint_ref="aweb.engineering")
    assert exc.value.status_code == 404
    with pytest.raises(HTTPException):
        await get_blueprint_profile(db, blueprint_ref="aweb.engineering", profile_ref="coordinator")

    # the dependent shelf profile SURVIVES, detached (rootless): ALL six source pins
    # NULL (assert each so a partial-null regression can't pass), content untouched.
    after = await get_shelf_profile(db, principal=principal, profile_ref="coordinator")
    for field in (
        "source_blueprint_ref",
        "source_blueprint_version",
        "source_blueprint_digest",
        "source_profile_ref",
        "source_profile_version",
        "source_profile_digest",
    ):
        assert after[field] is None, field
    assert after["digest"] == before["digest"]


async def test_delete_blueprint_is_owner_scoped(migrated_db) -> None:
    db = migrated_db
    await _seed_team(db, _TEAM)
    await _seed_team(db, _OTHER_TEAM)
    await _publish_engineering(db, SimpleNamespace(team_id=_TEAM))

    with pytest.raises(HTTPException) as exc:
        await delete_blueprint(
            db, principal=SimpleNamespace(team_id=_OTHER_TEAM), blueprint_ref="aweb.engineering"
        )
    assert exc.value.status_code == 404
    # it survives for the owner.
    assert (await get_blueprint(db, blueprint_ref="aweb.engineering"))[
        "blueprint_ref"
    ] == "aweb.engineering"


async def test_delete_shelf_profile_cleans_bindings_and_proposals(migrated_db) -> None:
    db = migrated_db
    await _seed_team(db, _TEAM)
    principal = SimpleNamespace(team_id=_TEAM)
    await _publish_engineering(db, principal)
    imported = await import_to_shelf(
        db,
        principal=principal,
        source_blueprint_ref="aweb.engineering",
        source_blueprint_version=None,
        profile_ref="coordinator",
        tags=[],
    )
    await set_profile_binding(
        db,
        principal=principal,
        agent_id="lead",
        binding=ProfileBindingRequest(
            profile_ref="coordinator",
            profile_version=imported["version"],
            profile_digest=imported["digest"],
        ),
    )
    await db.execute(
        "INSERT INTO {{tables.proposals}} (proposal_id, team_id, target, profile_ref, status, content)"
        " VALUES ('00000000-0000-0000-0000-000000000001'::uuid, $1, 'profile', 'coordinator', 'open', '{}'::jsonb)",
        _TEAM,
    )

    result = await delete_shelf_profile(db, principal=principal, profile_ref="coordinator")
    assert result["profile_ref"] == "coordinator"

    with pytest.raises(HTTPException) as exc:
        await get_shelf_profile(db, principal=principal, profile_ref="coordinator")
    assert exc.value.status_code == 404
    with pytest.raises(HTTPException):
        await get_profile_binding(db, principal=principal, agent_id="lead")
    remaining = await db.fetch_one(
        "SELECT count(*) AS n FROM {{tables.proposals}} WHERE team_id = $1 AND profile_ref = $2",
        _TEAM,
        "coordinator",
    )
    assert remaining["n"] == 0


async def test_delete_blueprint_detaches_other_adopting_teams_shelf(migrated_db) -> None:
    """The detach is cross-team: deleting a public blueprint NULLs the source pins on
    EVERY team's shelf that adopted it, not just the owner's. Locks the intentional
    no-team_id detach so a future author cannot silently re-scope it to owner-only."""
    db = migrated_db
    await _seed_team(db, _TEAM)
    await _seed_team(db, _OTHER_TEAM)
    owner = SimpleNamespace(team_id=_TEAM)
    other = SimpleNamespace(team_id=_OTHER_TEAM)
    await _publish_engineering(db, owner)
    # a DIFFERENT team adopts the owner's public blueprint onto its shelf.
    await import_to_shelf(
        db,
        principal=other,
        source_blueprint_ref="aweb.engineering",
        source_blueprint_version=None,
        profile_ref="coordinator",
        tags=[],
    )
    before = await get_shelf_profile(db, principal=other, profile_ref="coordinator")
    assert before["source_blueprint_ref"] == "aweb.engineering"

    # the OWNER deletes the blueprint.
    await delete_blueprint(db, principal=owner, blueprint_ref="aweb.engineering")

    # the OTHER team's shelf is also detached (not orphaned), and survives - all six
    # source pins NULL, like the owner's own detach.
    after = await get_shelf_profile(db, principal=other, profile_ref="coordinator")
    for field in (
        "source_blueprint_ref",
        "source_blueprint_version",
        "source_blueprint_digest",
        "source_profile_ref",
        "source_profile_version",
        "source_profile_digest",
    ):
        assert after[field] is None, field
    assert after["digest"] == before["digest"]


async def test_delete_shelf_profile_is_team_scoped(migrated_db) -> None:
    db = migrated_db
    await _seed_team(db, _TEAM)
    await _seed_team(db, _OTHER_TEAM)
    owner = SimpleNamespace(team_id=_TEAM)
    await _publish_engineering(db, owner)
    await import_to_shelf(
        db,
        principal=owner,
        source_blueprint_ref="aweb.engineering",
        source_blueprint_version=None,
        profile_ref="coordinator",
        tags=[],
    )
    # another team cannot delete this team's shelf profile.
    with pytest.raises(HTTPException) as exc:
        await delete_shelf_profile(
            db, principal=SimpleNamespace(team_id=_OTHER_TEAM), profile_ref="coordinator"
        )
    assert exc.value.status_code == 404
    # it survives for the owner.
    assert (await get_shelf_profile(db, principal=owner, profile_ref="coordinator"))[
        "profile_ref"
    ] == "coordinator"
