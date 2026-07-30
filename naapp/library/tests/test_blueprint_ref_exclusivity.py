from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from fastapi import HTTPException

from library.digest import BLUEPRINT_PAYLOAD_SCHEMA, collect_files
from library.models import NewBlueprintTarget, ProfilePublishRequest
from library.repository import (
    create_shelf_profile,
    delete_blueprint,
    get_blueprint,
    publish_blueprint,
    publish_profile,
)

_SOURCE = Path(__file__).parent / "vectors" / "blueprints" / "engineering" / "source"
_PROFILE_SOURCE = _SOURCE / "profiles" / "coordinator"
_OWNER_TEAM = "default:atext.aweb.ai"
_OTHER_TEAM = "default:other.example"


async def _seed_team(db, team_id: str) -> None:
    await db.execute(
        "INSERT INTO {{tables.teams}} (team_id, team_did_key) VALUES ($1, $2)"
        " ON CONFLICT (team_id) DO NOTHING",
        team_id,
        "did:key:z" + team_id.replace(":", ""),
    )


def _blueprint_payload(blueprint_ref: str, *, version: str = "0.1.0") -> dict[str, Any]:
    files = []
    for entry in collect_files(_SOURCE):
        if entry["path"] == "blueprint.yaml":
            doc = yaml.safe_load(entry["content_utf8"])
            doc["id"] = blueprint_ref
            doc["version"] = version
            entry = {
                **entry,
                "content_utf8": yaml.safe_dump(doc, sort_keys=False),
            }
        elif entry["path"].endswith("/profile.yaml"):
            doc = yaml.safe_load(entry["content_utf8"])
            doc["version"] = version
            entry = {
                **entry,
                "content_utf8": yaml.safe_dump(doc, sort_keys=False),
            }
        files.append(entry)
    return {"files": files, "schema": BLUEPRINT_PAYLOAD_SCHEMA}


def _profile_files() -> list[dict[str, str]]:
    return collect_files(_PROFILE_SOURCE)


async def _publish(db, team_id: str, blueprint_ref: str, *, version: str = "0.1.0") -> dict[str, Any]:
    return await publish_blueprint(
        db,
        principal=SimpleNamespace(team_id=team_id),
        payload=_blueprint_payload(blueprint_ref, version=version),
    )


async def _assert_conflict(coro, message_fragment: str) -> None:
    with pytest.raises(HTTPException) as exc:
        await coro
    assert exc.value.status_code == 409
    assert message_fragment in str(exc.value.detail)


async def test_cross_team_blueprint_ref_collision_is_rejected(migrated_db) -> None:
    db = migrated_db
    await _seed_team(db, _OWNER_TEAM)
    await _seed_team(db, _OTHER_TEAM)
    await _publish(db, _OWNER_TEAM, "example.tools")

    await _assert_conflict(
        _publish(db, _OTHER_TEAM, "example.tools", version="0.2.0"),
        "already owned by another team",
    )

    assert (await get_blueprint(db, blueprint_ref="example.tools"))["version"] == "0.1.0"


async def test_same_team_blueprint_ref_update_is_allowed(migrated_db) -> None:
    db = migrated_db
    await _seed_team(db, _OWNER_TEAM)
    await _publish(db, _OWNER_TEAM, "example.tools")

    updated = await _publish(db, _OWNER_TEAM, "example.tools", version="0.2.0")

    assert updated["version"] == "0.2.0"
    assert (await get_blueprint(db, blueprint_ref="example.tools"))["version"] == "0.2.0"


async def test_aweb_prefix_claim_by_non_first_party_team_is_rejected_for_existing_ref(
    migrated_db,
) -> None:
    db = migrated_db
    await _seed_team(db, _OWNER_TEAM)
    await _seed_team(db, _OTHER_TEAM)
    await _publish(db, _OWNER_TEAM, "aweb.team")

    await _assert_conflict(
        _publish(db, _OTHER_TEAM, "aweb.team", version="0.2.0"),
        "aweb.* blueprint refs are reserved",
    )


async def test_aweb_prefix_claim_by_non_first_party_team_is_rejected_for_new_ref(
    migrated_db,
) -> None:
    db = migrated_db
    await _seed_team(db, _OWNER_TEAM)
    await _seed_team(db, _OTHER_TEAM)
    await _publish(db, _OWNER_TEAM, "aweb.team")

    await _assert_conflict(
        _publish(db, _OTHER_TEAM, "aweb.future"),
        "aweb.* blueprint refs are reserved",
    )


async def test_aweb_prefix_reservation_survives_blueprint_delete(migrated_db) -> None:
    db = migrated_db
    await _seed_team(db, _OWNER_TEAM)
    await _seed_team(db, _OTHER_TEAM)
    owner = SimpleNamespace(team_id=_OWNER_TEAM)
    await _publish(db, _OWNER_TEAM, "aweb.development")
    await delete_blueprint(db, principal=owner, blueprint_ref="aweb.development")

    await _assert_conflict(
        _publish(db, _OTHER_TEAM, "aweb.development"),
        "aweb.* blueprint refs are reserved",
    )


async def test_normal_new_ref_by_any_team_is_allowed(migrated_db) -> None:
    db = migrated_db
    await _seed_team(db, _OWNER_TEAM)
    await _seed_team(db, _OTHER_TEAM)
    await _publish(db, _OWNER_TEAM, "aweb.team")

    result = await _publish(db, _OTHER_TEAM, "other.tools")

    assert result["blueprint_ref"] == "other.tools"


async def test_publish_profile_new_blueprint_obeys_ref_exclusivity(migrated_db) -> None:
    db = migrated_db
    await _seed_team(db, _OWNER_TEAM)
    await _seed_team(db, _OTHER_TEAM)
    await _publish(db, _OWNER_TEAM, "example.tools")
    other = SimpleNamespace(team_id=_OTHER_TEAM)
    await create_shelf_profile(db, principal=other, files=_profile_files(), tags=[])

    await _assert_conflict(
        publish_profile(
            db,
            principal=other,
            profile_ref="coordinator",
            request=ProfilePublishRequest(
                blueprint_version="0.1.0",
                new_blueprint=NewBlueprintTarget(
                    blueprint_ref="example.tools",
                    name="Other Tools",
                ),
            ),
        ),
        "already owned by another team",
    )


async def test_publish_profile_existing_owned_blueprint_update_is_allowed(migrated_db) -> None:
    db = migrated_db
    await _seed_team(db, _OWNER_TEAM)
    principal = SimpleNamespace(team_id=_OWNER_TEAM)
    await create_shelf_profile(db, principal=principal, files=_profile_files(), tags=[])
    await publish_profile(
        db,
        principal=principal,
        profile_ref="coordinator",
        request=ProfilePublishRequest(
            blueprint_version="0.1.0",
            new_blueprint=NewBlueprintTarget(
                blueprint_ref="example.tools",
                name="Example Tools",
            ),
        ),
    )

    updated = await publish_profile(
        db,
        principal=principal,
        profile_ref="coordinator",
        request=ProfilePublishRequest(
            blueprint_version="0.2.0",
            target_blueprint_ref="example.tools",
        ),
    )

    assert updated["blueprint_ref"] == "example.tools"
    assert updated["blueprint_version"] == "0.2.0"
