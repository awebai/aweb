from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from library.blueprint import materialize_home, parse_profile_payload, part_baselines
from library.digest import collect_files
from library.models import MaterializeRequest, NewBlueprintTarget, ProfilePublishRequest
from library.repository import (
    get_blueprint_profile,
    import_to_shelf,
    list_shelf,
    materialize,
    normalize_tags,
    publish_profile,
)

_FIXTURE = Path(__file__).parent / "vectors" / "blueprints" / "engineering"

_CLAUDE_CODE_PRODUCTION_ORDER = [
    "AGENTS.md",
    "CLAUDE.md",
    ".aw/profile/profile.yaml",
    ".aw/profile/instructions.md",
    "skills/implement/SKILL.md",
    ".aw/profile/skills/implement/SKILL.md",
    ".claude/skills/implement",
    "skills/debug/SKILL.md",
    ".aw/profile/skills/debug/SKILL.md",
    ".claude/skills/debug",
    "artifacts/handoff-template.md",
    ".aw/profile/artifacts/handoff-template.md",
    ".aw/profile/ref.json",
]
_PI_PRODUCTION_ORDER = [
    "AGENTS.md",
    "CLAUDE.md",
    ".aw/profile/profile.yaml",
    ".aw/profile/instructions.md",
    "skills/implement/SKILL.md",
    ".aw/profile/skills/implement/SKILL.md",
    "skills/debug/SKILL.md",
    ".aw/profile/skills/debug/SKILL.md",
    "artifacts/handoff-template.md",
    ".aw/profile/artifacts/handoff-template.md",
    ".aw/profile/ref.json",
]


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


class _MaterializeDB:
    def __init__(self, profile) -> None:
        self.profile = profile

    async def fetch_one(self, sql: str, *params):
        if "FROM {{tables.shelf_profiles}}" in sql:
            return {
                "profile_ref": self.profile.profile_ref,
                "version": self.profile.version,
                "digest": self.profile.digest,
                "runtime_assumptions": self.profile.runtime_assumptions,
                "memory_policy": json.dumps(self.profile.memory_policy)
                if self.profile.memory_policy is not None
                else None,
                "files": json.dumps(self.profile.files),
                "source_blueprint_ref": None,
                "source_blueprint_version": None,
                "source_blueprint_digest": None,
            }
        raise AssertionError(f"unexpected query: {sql}")


async def test_server_materialize_path_emits_same_ref_json_as_materializer() -> None:
    files = collect_files(_FIXTURE / "source" / "profiles" / "developer")
    profile = parse_profile_payload(files)
    result = await materialize(
        _MaterializeDB(profile),
        principal=SimpleNamespace(team_id="default:atext.aweb.ai"),
        request=MaterializeRequest(
            profile_ref="developer",
            profile_version=profile.version,
            runtime_kind="claude-code",
            target="local",
        ),
    )
    direct_ref = next(
        entry
        for entry in materialize_home(
            files,
            profile_ref="developer",
            profile_version=profile.version,
            profile_digest=profile.digest,
            source_blueprint_ref=None,
            source_blueprint_version=None,
            source_blueprint_digest=None,
            runtime_kind="claude-code",
        )
        if entry["path"] == ".aw/profile/ref.json"
    )
    route_ref = next(
        entry for entry in result["home_files"] if entry["path"] == ".aw/profile/ref.json"
    )
    assert route_ref == direct_ref
    ref = json.loads(route_ref["content_utf8"])
    assert ref["runtime_kind"] == "claude-code"
    assert "skills/implement/assets/checklist.md" in ref["managed_set"]
    assert ".claude/skills/implement" in ref["managed_set"]


def _production_profile():
    profile_yaml = """id: developer
name: Developer
version: 0.1.8
instructions: instructions.md
skills:
  - path: skills/implement/SKILL.md
    kind: skill
  - path: skills/debug/SKILL.md
    kind: skill
artifacts:
  - path: artifacts/handoff-template.md
    kind: template
"""
    content_by_path = {
        "profile.yaml": profile_yaml,
        "instructions.md": "Implement one scoped task at a time.\n",
        "skills/implement/SKILL.md": "# Implement\n",
        "skills/debug/SKILL.md": "# Debug\n",
        "artifacts/handoff-template.md": "# Handoff\n",
    }
    files = [
        {
            "path": path,
            "content_utf8": content,
            "sha256": "sha256:" + hashlib.sha256(content.encode("utf-8")).hexdigest(),
        }
        for path, content in content_by_path.items()
    ]
    return parse_profile_payload(files)


@pytest.mark.parametrize(
    ("runtime_kind", "expected_paths"),
    [
        ("claude-code", _CLAUDE_CODE_PRODUCTION_ORDER),
        ("pi", _PI_PRODUCTION_ORDER),
    ],
)
async def test_server_materialize_paths_match_managed_set_in_production_order(
    runtime_kind: str, expected_paths: list[str]
) -> None:
    profile = _production_profile()
    result = await materialize(
        _MaterializeDB(profile),
        principal=SimpleNamespace(team_id="default:atext.aweb.ai"),
        request=MaterializeRequest(
            profile_ref="developer",
            profile_version=profile.version,
            runtime_kind=runtime_kind,
            target="local",
        ),
    )

    home_paths = [entry["path"] for entry in result["home_files"]]
    ref_entry = next(
        entry for entry in result["home_files"] if entry["path"] == ".aw/profile/ref.json"
    )
    managed_set = json.loads(ref_entry["content_utf8"])["managed_set"]

    assert managed_set == expected_paths
    assert home_paths == managed_set


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
        if "INSERT INTO {{tables.shelf_profiles}}" in sql:
            self.writes.append(params)
            self.shelf_row = {
                "profile_ref": params[1],
                "version": params[2],
                "digest": params[3],
                "source_profile_ref": params[17],
                "source_profile_version": params[18],
                "source_profile_digest": params[19],
                "source_blueprint_ref": params[14],
                "source_blueprint_version": params[15],
                "source_blueprint_digest": params[16],
            }
            return {"version": params[2]}  # RETURNING version (no prior conflict)
        if "FROM {{tables.shelf_profiles}}" in sql:
            return self.shelf_row
        if "FROM {{tables.blueprints}}" in sql:
            return {"owner_team": "default:atext.aweb.ai", "version": "0.1.0", "digest": "sha256:blueprintdigest"}
        if "FROM {{tables.blueprint_profiles}}" in sql:
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


async def test_import_to_shelf_copies_then_is_idempotent() -> None:
    source = parse_profile_payload(collect_files(_FIXTURE / "source" / "profiles" / "coordinator"))
    db = _ShelfImportDB(source)
    principal = SimpleNamespace(team_id="default:atext.aweb.ai")

    first = await import_to_shelf(
        db,
        principal=principal,
        source_blueprint_ref="aweb.engineering",
        source_blueprint_version=None,
        profile_ref="coordinator",
        tags=["Coder"],
    )
    assert first["created"] is True
    assert first["profile_ref"] == "coordinator"
    assert first["digest"] == source.digest
    assert first["source_profile_ref"] == "coordinator"
    assert first["source_profile_digest"] == source.digest
    assert first["source_blueprint_ref"] == "aweb.engineering"
    assert first["source_blueprint_version"] == "0.1.0"
    assert first["source_blueprint_digest"] == "sha256:blueprintdigest"
    # Per-part baselines recorded as the canonical copy-time content digests.
    written_baselines = json.loads(db.writes[0][20])
    assert written_baselines == part_baselines(source)

    # A re-import keyed by (team, source blueprint, source profile) is a pure no-op:
    # created=False, no new write, returns the existing copy.
    second = await import_to_shelf(
        db,
        principal=principal,
        source_blueprint_ref="aweb.engineering",
        source_blueprint_version=None,
        profile_ref="coordinator",
        tags=["Coder"],
    )
    assert second["created"] is False
    assert second["digest"] == source.digest
    assert len(db.writes) == 1


class _BlueprintProfileDB:
    def __init__(self, source, recommendations: list[dict]) -> None:
        self._source = source
        self._recommendations = recommendations

    async def fetch_one(self, sql: str, *params):
        if "FROM {{tables.blueprints}}" in sql:
            return {
                "owner_team": "default:atext.aweb.ai",
                "version": "0.2.0",
                "recommendations": json.dumps(self._recommendations),
            }
        if "FROM {{tables.blueprint_profiles}}" in sql:
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


@pytest.mark.parametrize(
    ("profile_ref", "runtime_hints"),
    [("coordinator", ["claude-code"]), ("reviewer", ["pi", "claude-code"])],
)
async def test_get_blueprint_profile_surfaces_profile_runtime_hints_from_blueprint_recommendation(
    profile_ref: str, runtime_hints: list[str]
) -> None:
    source = parse_profile_payload(collect_files(_FIXTURE / "source" / "profiles" / profile_ref))
    db = _BlueprintProfileDB(
        source,
        [
            {"id": "coordinator", "runtime_hints": ["claude-code"]},
            {"id": "reviewer", "runtime_hints": ["pi", "claude-code"]},
        ],
    )

    result = await get_blueprint_profile(db, blueprint_ref="aweb.engineering", profile_ref=profile_ref)

    assert result["profile_ref"] == profile_ref
    assert result["runtime_hints"] == runtime_hints


async def test_import_to_shelf_conflicts_on_different_source() -> None:
    # A profile_ref already held from a different source blueprint is a 409 — v1 never
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
        "source_blueprint_ref": "some-other-blueprint",
        "source_blueprint_version": "0.1.0",
        "source_blueprint_digest": "sha256:other",
    }
    with pytest.raises(HTTPException) as excinfo:
        await import_to_shelf(
            db,
            principal=SimpleNamespace(team_id="default:atext.aweb.ai"),
            source_blueprint_ref="aweb.engineering",
            source_blueprint_version=None,
            profile_ref="coordinator",
            tags=None,
        )
    assert excinfo.value.status_code == 409
    assert db.writes == []


async def test_publish_profile_rejects_ambiguous_target() -> None:
    # target must set exactly one of existing_blueprint_ref / new_blueprint — checked before
    # any DB use, so the db is never touched.
    both = ProfilePublishRequest(
        blueprint_version="1.0.0",
        target_blueprint_ref="my-team.starter",
        new_blueprint=NewBlueprintTarget(blueprint_ref="my-team.starter", name="Starter"),
    )
    with pytest.raises(HTTPException) as excinfo:
        await publish_profile(object(), principal=SimpleNamespace(team_id="t"), profile_ref="coordinator", request=both)
    assert excinfo.value.status_code == 422

    neither = ProfilePublishRequest(blueprint_version="1.0.0")
    with pytest.raises(HTTPException) as excinfo:
        await publish_profile(object(), principal=SimpleNamespace(team_id="t"), profile_ref="coordinator", request=neither)
    assert excinfo.value.status_code == 422


class _ShelfListDB:
    """Returns the shelf rows then the per-blueprint latest catalog versions, routed by
    SQL fragment, so list_shelf can compute update_available."""

    def __init__(self, shelf_rows: list[dict], latest_rows: list[dict]) -> None:
        self._shelf_rows = shelf_rows
        self._latest_rows = latest_rows

    async def fetch_all(self, sql: str, *params):
        if "FROM {{tables.shelf_profiles}}" in sql:
            return self._shelf_rows
        if "FROM {{tables.blueprints}}" in sql:
            return self._latest_rows
        raise AssertionError(f"unexpected query: {sql}")


def _shelf_row(profile_ref: str, *, source_blueprint=None, source_blueprint_version=None) -> dict:
    return {
        "profile_ref": profile_ref,
        "version": "1",
        "digest": "sha256:d",
        "name": profile_ref.title(),
        "mission": f"{profile_ref} mission",
        "tags": ["coder"],
        "source_blueprint_ref": source_blueprint,
        "source_blueprint_version": source_blueprint_version,
        "source_blueprint_digest": "sha256:p" if source_blueprint else None,
        "source_profile_ref": profile_ref if source_blueprint else None,
        "source_profile_version": "0.1.0" if source_blueprint else None,
    }


async def test_list_shelf_flags_update_available_only_when_blueprint_moved_on() -> None:
    shelf_rows = [
        _shelf_row("coordinator", source_blueprint="aweb.eng", source_blueprint_version="0.1.0"),
        _shelf_row("developer", source_blueprint="aweb.eng", source_blueprint_version="0.2.0"),
        _shelf_row("home-grown"),  # created fresh, no source blueprint
    ]
    # The catalog's latest version of aweb.eng is 0.2.0.
    db = _ShelfListDB(shelf_rows, [{"blueprint_ref": "aweb.eng", "version": "0.2.0"}])

    result = await list_shelf(db, principal=SimpleNamespace(team_id="default:atext.aweb.ai"))
    by_ref = {p["profile_ref"]: p for p in result["profiles"]}

    # Pinned to 0.1.0 while latest is 0.2.0 -> update available, latest surfaced.
    assert by_ref["coordinator"]["update_available"] is True
    assert by_ref["coordinator"]["source_blueprint_latest_version"] == "0.2.0"
    assert by_ref["coordinator"]["summary"] == "coordinator mission"
    # Already on the latest -> no update.
    assert by_ref["developer"]["update_available"] is False
    assert by_ref["developer"]["source_blueprint_latest_version"] == "0.2.0"
    # Created fresh -> source provenance null, never an update.
    assert by_ref["home-grown"]["update_available"] is False
    assert by_ref["home-grown"]["source_blueprint_ref"] is None
    assert by_ref["home-grown"]["source_blueprint_latest_version"] is None


def test_empty_profile_invariant_is_what_library_honors() -> None:
    invariant = json.loads((_FIXTURE / "expected" / "empty-profile-invariant.json").read_text(encoding="utf-8"))
    assert invariant["schema"] == "aweb.blueprint.empty-profile-invariant.v1"
    # Library is optional: a team and its agents exist without any Library state.
    assert invariant["team_create"]["must_succeed_without_library"] is True
    assert invariant["team_create"]["blueprint_required"] is False
    assert invariant["agent_add"]["profile_binding_required"] is False
    # Materialize needs a bound profile, but an all-empty team is not an error.
    assert invariant["materialize"]["requires_bound_profile"] is True
    assert invariant["materialize"]["empty_profile_is_not_error"] is True
