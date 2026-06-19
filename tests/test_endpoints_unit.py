from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from library.digest import collect_files
from library.models import MaterializeRequest, NewPackTarget, ProfilePublishRequest, PublishTarget
from library.profile_pack import parse_profile_payload, part_baselines
from library.repository import import_to_shelf, materialize, normalize_tags, publish_profile

_FIXTURE = Path(__file__).parent / "vectors" / "profile-packs" / "engineering"


async def test_materialize_requires_agent_or_profile_ref() -> None:
    # With neither agent_id nor profile_ref, materialize fails before any DB use —
    # "materialize requires a bound profile" at the request boundary.
    with pytest.raises(HTTPException) as excinfo:
        await materialize(
            object(),  # never touched on this path
            principal=SimpleNamespace(team_id="default:atext.aweb.ai"),
            request=MaterializeRequest(runtime_kind="claude-code", target="local"),
        )
    assert excinfo.value.status_code == 422


def test_normalize_tags_lowercases_trims_dedups_and_sorts() -> None:
    assert normalize_tags([" GitHub ", "github", "Coder", "", "  ", "TWITTER"]) == [
        "coder",
        "github",
        "twitter",
    ]


class _ShelfImportDB:
    """A stateful fake honoring the three reads and one write import_to_shelf makes.
    Routes fetch_one by SQL fragment; stores the written shelf row so a re-import's
    existence check sees it."""

    def __init__(self, source) -> None:
        self._source = source
        self.shelf_row: dict | None = None
        self.writes: list[tuple] = []

    async def fetch_one(self, sql: str, *params):
        if "FROM {{tables.shelf_profiles}}" in sql:
            return self.shelf_row
        if "FROM {{tables.profile_packs}}" in sql:
            return {"owner_team": "default:atext.aweb.ai", "version": "0.1.0", "digest": "sha256:packdigest"}
        if "FROM {{tables.pack_profiles}}" in sql:
            s = self._source
            return {
                "profile_ref": s.profile_ref,
                "profile_version": s.version,
                "digest": s.digest,
                "name": s.name,
                "mission": s.mission,
                "accepted_work": s.accepted_work,
                "runtime_assumptions": s.runtime_assumptions,
                "memory_policy": json.dumps(s.memory_policy) if s.memory_policy is not None else None,
                "expected_apps": s.expected_apps,
                "event_subscriptions": json.dumps(s.event_subscriptions),
                "approval_required": s.approval_required,
                "files": json.dumps(s.files),
            }
        raise AssertionError(f"unexpected query: {sql}")

    async def execute(self, sql: str, *params) -> None:
        self.writes.append(params)
        # Mirror what was written so a subsequent existence check returns it.
        self.shelf_row = {
            "profile_ref": params[1],
            "version": params[2],
            "digest": params[3],
            "source_profile_ref": params[17],
            "source_profile_version": params[18],
            "source_profile_digest": params[19],
            "source_profile_pack_ref": params[14],
            "source_profile_pack_version": params[15],
            "source_profile_pack_digest": params[16],
        }


async def test_import_to_shelf_copies_then_is_idempotent() -> None:
    source = parse_profile_payload(collect_files(_FIXTURE / "source" / "profiles" / "coordinator"))
    db = _ShelfImportDB(source)
    principal = SimpleNamespace(team_id="default:atext.aweb.ai")

    first = await import_to_shelf(
        db,
        principal=principal,
        source_profile_pack_ref="aweb.engineering-pack",
        source_profile_pack_version=None,
        profile_ref="coordinator",
        tags=["Coder"],
    )
    assert first["created"] is True
    assert first["profile_ref"] == "coordinator"
    assert first["digest"] == source.digest
    assert first["source_profile_ref"] == "coordinator"
    assert first["source_profile_digest"] == source.digest
    assert first["source_profile_pack_ref"] == "aweb.engineering-pack"
    assert first["source_profile_pack_version"] == "0.1.0"
    assert first["source_profile_pack_digest"] == "sha256:packdigest"
    # Per-part baselines recorded as the canonical copy-time content digests.
    written_baselines = json.loads(db.writes[0][20])
    assert written_baselines == part_baselines(source)

    # A re-import keyed by (team, source pack, source profile) is a pure no-op:
    # created=False, no new write, returns the existing copy.
    second = await import_to_shelf(
        db,
        principal=principal,
        source_profile_pack_ref="aweb.engineering-pack",
        source_profile_pack_version=None,
        profile_ref="coordinator",
        tags=["Coder"],
    )
    assert second["created"] is False
    assert second["digest"] == source.digest
    assert len(db.writes) == 1


async def test_import_to_shelf_conflicts_on_different_source() -> None:
    # A profile_ref already held from a different source pack is a 409 — v1 never
    # renames or shadows; the team must resolve the name clash explicitly.
    source = parse_profile_payload(collect_files(_FIXTURE / "source" / "profiles" / "coordinator"))
    db = _ShelfImportDB(source)
    db.shelf_row = {
        "profile_ref": "coordinator",
        "version": "0.1.0",
        "digest": source.digest,
        "source_profile_ref": "coordinator",
        "source_profile_version": "0.1.0",
        "source_profile_digest": source.digest,
        "source_profile_pack_ref": "some-other-pack",
        "source_profile_pack_version": "0.1.0",
        "source_profile_pack_digest": "sha256:other",
    }
    with pytest.raises(HTTPException) as excinfo:
        await import_to_shelf(
            db,
            principal=SimpleNamespace(team_id="default:atext.aweb.ai"),
            source_profile_pack_ref="aweb.engineering-pack",
            source_profile_pack_version=None,
            profile_ref="coordinator",
            tags=None,
        )
    assert excinfo.value.status_code == 409
    assert db.writes == []


async def test_publish_profile_rejects_ambiguous_target() -> None:
    # target must set exactly one of existing_pack_ref / new_pack — checked before
    # any DB use, so the db is never touched.
    both = ProfilePublishRequest(
        pack_version="1.0.0",
        target=PublishTarget(
            existing_pack_ref="my-team.starter",
            new_pack=NewPackTarget(pack_ref="my-team.starter", name="Starter"),
        ),
    )
    with pytest.raises(HTTPException) as excinfo:
        await publish_profile(object(), principal=SimpleNamespace(team_id="t"), profile_ref="coordinator", request=both)
    assert excinfo.value.status_code == 422

    neither = ProfilePublishRequest(pack_version="1.0.0", target=PublishTarget())
    with pytest.raises(HTTPException) as excinfo:
        await publish_profile(object(), principal=SimpleNamespace(team_id="t"), profile_ref="coordinator", request=neither)
    assert excinfo.value.status_code == 422


def test_empty_profile_invariant_is_what_library_honors() -> None:
    invariant = json.loads((_FIXTURE / "expected" / "empty-profile-invariant.json").read_text(encoding="utf-8"))
    assert invariant["schema"] == "aweb.profile-pack.empty-profile-invariant.v1"
    # Library is optional: a team and its agents exist without any Library state.
    assert invariant["team_create"]["must_succeed_without_library"] is True
    assert invariant["team_create"]["profile_pack_required"] is False
    assert invariant["agent_add"]["profile_binding_required"] is False
    # Materialize needs a bound profile, but an all-empty team is not an error.
    assert invariant["materialize"]["requires_bound_profile"] is True
    assert invariant["materialize"]["empty_profile_is_not_error"] is True
