from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from library.blueprint import (
    _entries_in_managed_order,
    build_blueprint_payload,
    import_return,
    materialize_home,
    parse_import_payload,
    parse_profile_payload,
)
from library.digest import BLUEPRINT_PAYLOAD_SCHEMA, collect_files, payload_digest

_FIXTURE = Path(__file__).parent / "vectors" / "blueprints" / "engineering"
_SOURCE = _FIXTURE / "source"
_MATERIALIZED = _FIXTURE / "expected" / "materialized-home"
_MATERIALIZED_CREATED = _FIXTURE / "expected" / "materialized-home-created"


def _import_payload() -> dict:
    # The payload aw uploads on import.
    return {"files": collect_files(_SOURCE), "schema": BLUEPRINT_PAYLOAD_SCHEMA}


def test_parse_import_payload_yields_blueprint_metadata() -> None:
    blueprint = parse_import_payload(_import_payload())
    assert blueprint.blueprint_ref == "aweb.engineering"
    assert blueprint.version == "0.1.0"
    assert [p.profile_ref for p in blueprint.profiles] == ["coordinator", "developer", "reviewer"]
    coordinator = blueprint.profiles[0]
    assert coordinator.name == "Coordinator"
    assert coordinator.mission.startswith("Coordinate the team")
    assert "planning" in coordinator.accepted_work


def test_import_return_matches_fixture_exactly() -> None:
    expected = json.loads((_FIXTURE / "expected" / "import-return.json").read_text(encoding="utf-8"))
    assert import_return(parse_import_payload(_import_payload())) == expected


def _assert_home_matches(entries: list[dict], home_dir: Path) -> None:
    """The composed home reproduces the fixture tree byte-exact: regular files by
    content, symlinks by target, and the path set matches exactly."""
    expected: dict[str, tuple[str, str]] = {}
    for path in home_dir.rglob("*"):
        rel = path.relative_to(home_dir).as_posix()
        if path.is_symlink():
            expected[rel] = ("symlink", os.readlink(path))
        elif path.is_file():
            expected[rel] = ("file", path.read_text(encoding="utf-8"))

    produced = {entry["path"]: entry for entry in entries}
    assert set(produced) == set(expected)
    for rel, (kind, payload) in expected.items():
        entry = produced[rel]
        assert entry["kind"] == kind, rel
        if kind == "file":
            assert entry["content_utf8"] == payload, rel
        else:
            assert entry["target"] == payload, rel


def test_materialize_home_blueprint_provenance_matches_fixture_byte_exact() -> None:
    blueprint = parse_import_payload(_import_payload())
    for profile in blueprint.profiles:
        entries = materialize_home(
            collect_files(_SOURCE / "profiles" / profile.profile_ref),
            profile_ref=profile.profile_ref,
            profile_version=profile.version,
            profile_digest=profile.digest,
            source_blueprint_ref=blueprint.blueprint_ref,
            source_blueprint_version=blueprint.version,
            source_blueprint_digest=blueprint.digest,
        )
        _assert_home_matches(entries, _MATERIALIZED / profile.profile_ref)


def test_materialize_home_created_provenance_matches_fixture_byte_exact() -> None:
    files = collect_files(_SOURCE / "profiles" / "developer")
    profile = parse_profile_payload(files)
    entries = materialize_home(
        files,
        profile_ref="developer",
        profile_version=profile.version,
        profile_digest=profile.digest,
        source_blueprint_ref=None,
        source_blueprint_version=None,
        source_blueprint_digest=None,
    )
    _assert_home_matches(entries, _MATERIALIZED_CREATED / "developer")
    # The created form drops all source-blueprint provenance, but still records
    # runtime and the complete managed path set.
    ref = json.loads(next(e for e in entries if e["path"] == ".aw/profile/ref.json")["content_utf8"])
    assert not any(key.startswith("source_blueprint_") for key in ref)
    assert ref["runtime_kind"] == "claude-code"
    assert ref["managed_set"][-1] == ".aw/profile/ref.json"


def test_parse_profile_payload_reproduces_a_profile() -> None:
    profile = parse_profile_payload(collect_files(_SOURCE / "profiles" / "coordinator"))
    assert profile.profile_ref == "coordinator"
    assert profile.version == "0.1.0"
    assert profile.digest == "sha256:b84396c46b66559e0a881f9cd1e85acb8e531296e45dcc6398c695841ecfcbe0"
    assert profile.mission.startswith("Coordinate")
    assert "planning" in profile.accepted_work


def test_publish_profile_round_trips_to_import_digest() -> None:
    # The coordinator's round-trip invariant: a profile published into a blueprint, then
    # imported back, keeps its shelf digest; the blueprint digest is the import-payload.v1
    # digest of the generated files (publish == import-the-same-files).
    profile_files = collect_files(_SOURCE / "profiles" / "coordinator")
    shelf = parse_profile_payload(profile_files)

    payload = build_blueprint_payload(
        blueprint_ref="my-team.starter",
        blueprint_version="1.0.0",
        name="Starter",
        summary=None,
        description=None,
        first_mission_examples=[],
        readme=None,
        prior_files=None,
        profile_ref="coordinator",
        profile_files=profile_files,
    )
    blueprint = parse_import_payload(payload)
    assert blueprint.blueprint_ref == "my-team.starter"
    assert blueprint.digest == payload_digest(payload["files"], BLUEPRINT_PAYLOAD_SCHEMA)

    published = next(p for p in blueprint.profiles if p.profile_ref == "coordinator")
    assert published.digest == shelf.digest

    # Building the same publish again is byte-stable (deterministic blueprint.yaml).
    again = build_blueprint_payload(
        blueprint_ref="my-team.starter",
        blueprint_version="1.0.0",
        name="Starter",
        summary=None,
        description=None,
        first_mission_examples=[],
        readme=None,
        prior_files=None,
        profile_ref="coordinator",
        profile_files=profile_files,
    )
    assert again == payload


def test_publish_profile_accumulates_onto_existing_blueprint() -> None:
    # Publishing a second profile onto a blueprint's prior files keeps both profiles and
    # leaves the first profile's digest untouched.
    coordinator_files = collect_files(_SOURCE / "profiles" / "coordinator")
    developer_files = collect_files(_SOURCE / "profiles" / "developer")

    first = build_blueprint_payload(
        blueprint_ref="my-team.starter",
        blueprint_version="1.0.0",
        name="Starter",
        summary=None,
        description=None,
        first_mission_examples=[],
        readme=None,
        prior_files=None,
        profile_ref="coordinator",
        profile_files=coordinator_files,
    )
    second = build_blueprint_payload(
        blueprint_ref="my-team.starter",
        blueprint_version="1.1.0",
        name="Starter",
        summary=None,
        description=None,
        first_mission_examples=[],
        readme=None,
        prior_files=first["files"],
        profile_ref="developer",
        profile_files=developer_files,
    )
    blueprint = parse_import_payload(second)
    assert [p.profile_ref for p in blueprint.profiles] == ["coordinator", "developer"]
    coordinator = next(p for p in blueprint.profiles if p.profile_ref == "coordinator")
    assert coordinator.digest == parse_profile_payload(coordinator_files).digest


def test_materialize_home_omits_empty_sections() -> None:
    # A minimal profile renders only the sections it has — empty components omit
    # their whole title, uniformly.
    profile_yaml = "id: minimal\nname: Minimal\nversion: 0.1.0\nmission: Do one thing.\n"
    files = [
        {"content_utf8": profile_yaml, "path": "profile.yaml", "sha256": "sha256:x"},
    ]
    entries = materialize_home(
        files,
        profile_ref="minimal",
        profile_version="0.1.0",
        profile_digest="sha256:d",
        source_blueprint_ref=None,
        source_blueprint_version=None,
        source_blueprint_digest=None,
    )
    agents = next(e for e in entries if e["path"] == "AGENTS.md")["content_utf8"]
    assert "## Mission" in agents
    for absent in ("## Work you take on", "## Instructions", "## Apps you use",
                   "## Actions requiring human approval", "## Memory and learning", "## Skills"):
        assert absent not in agents, absent
    # No skills/artifacts means no canonical resources and no .claude symlinks.
    assert not any(e["path"].startswith(".claude/") for e in entries)


def _profile_file(path: str, content_utf8: str) -> dict[str, str]:
    return {
        "content_utf8": content_utf8,
        "path": path,
        "sha256": "sha256:" + hashlib.sha256(content_utf8.encode("utf-8")).hexdigest(),
    }


def test_materialize_home_projects_entire_skill_directory_and_directory_harness_link() -> None:
    profile_yaml = """id: video-maker
name: Video Maker
version: 0.1.0
skills:
  - path: skills/agent-demo-video/SKILL.md
    kind: skill
"""
    files = [
        _profile_file("profile.yaml", profile_yaml),
        _profile_file("skills/agent-demo-video/SKILL.md", "# Agent demo video\n"),
        _profile_file("skills/agent-demo-video/assets/capture.ts", "console.log('capture')\n"),
        _profile_file("skills/agent-demo-video/assets/edit.py", "print('edit')\n"),
        _profile_file("skills/agent-demo-video/assets/render.sh", "#!/bin/sh\n"),
        _profile_file("skills/agent-demo-video/assets/README.md", "# Assets\n"),
    ]

    entries = materialize_home(
        files,
        profile_ref="video-maker",
        profile_version="0.1.0",
        profile_digest="sha256:d",
        source_blueprint_ref=None,
        source_blueprint_version=None,
        source_blueprint_digest=None,
    )
    produced = {entry["path"]: entry for entry in entries}

    for rel in (
        "skills/agent-demo-video/SKILL.md",
        "skills/agent-demo-video/assets/capture.ts",
        "skills/agent-demo-video/assets/edit.py",
        "skills/agent-demo-video/assets/render.sh",
        "skills/agent-demo-video/assets/README.md",
    ):
        assert produced[rel]["kind"] == "file"
        assert produced[f".aw/profile/{rel}"]["kind"] == "file"
    assert produced[".claude/skills/agent-demo-video"] == {
        "path": ".claude/skills/agent-demo-video",
        "kind": "symlink",
        "target": "../../skills/agent-demo-video",
    }
    assert ".claude/skills/agent-demo-video/SKILL.md" not in produced


def test_materialize_home_managed_set_uses_declaration_order_and_byte_sorted_skill_paths() -> None:
    profile_yaml = """id: developer
name: Developer
version: 0.1.0
instructions: instructions.md
skills:
  - path: skills/zeta/SKILL.md
    kind: skill
  - path: skills/alpha/SKILL.md
    kind: skill
artifacts:
  - path: artifacts/z-last.md
    kind: note
  - path: artifacts/a-first.md
    kind: note
"""
    files = [
        _profile_file("skills/alpha/assets/b.md", "alpha b\n"),
        _profile_file("artifacts/a-first.md", "artifact a\n"),
        _profile_file("skills/zeta/assets/b.md", "zeta b\n"),
        _profile_file("profile.yaml", profile_yaml),
        _profile_file("skills/alpha/SKILL.md", "# Alpha\n"),
        _profile_file("skills/zeta/assets/a.md", "zeta a\n"),
        _profile_file("instructions.md", "Work in declared order.\n"),
        _profile_file("skills/zeta/SKILL.md", "# Zeta\n"),
        _profile_file("artifacts/z-last.md", "artifact z\n"),
    ]

    entries = materialize_home(
        files,
        profile_ref="developer",
        profile_version="0.1.0",
        profile_digest="sha256:d",
        source_blueprint_ref=None,
        source_blueprint_version=None,
        source_blueprint_digest=None,
        runtime_kind="claude-code",
    )
    ref = json.loads(next(e for e in entries if e["path"] == ".aw/profile/ref.json")["content_utf8"])

    assert ref["managed_set"] == [
        "AGENTS.md",
        "CLAUDE.md",
        ".aw/profile/profile.yaml",
        ".aw/profile/instructions.md",
        "skills/zeta/SKILL.md",
        ".aw/profile/skills/zeta/SKILL.md",
        "skills/zeta/assets/a.md",
        ".aw/profile/skills/zeta/assets/a.md",
        "skills/zeta/assets/b.md",
        ".aw/profile/skills/zeta/assets/b.md",
        ".claude/skills/zeta",
        "skills/alpha/SKILL.md",
        ".aw/profile/skills/alpha/SKILL.md",
        "skills/alpha/assets/b.md",
        ".aw/profile/skills/alpha/assets/b.md",
        ".claude/skills/alpha",
        "artifacts/z-last.md",
        ".aw/profile/artifacts/z-last.md",
        "artifacts/a-first.md",
        ".aw/profile/artifacts/a-first.md",
        ".aw/profile/ref.json",
    ]


def test_materialize_home_rejects_missing_and_extra_output_paths() -> None:
    with pytest.raises(
        ValueError,
        match=(
            r"materialized paths do not match managed set: "
            r"missing=\['missing.md'\], extra=\['extra.md'\]"
        ),
    ):
        _entries_in_managed_order(
            [{"path": "extra.md", "kind": "file", "content_utf8": "extra\n"}],
            ["missing.md"],
        )


def test_materialize_home_rejects_duplicate_output_paths() -> None:
    profile = _profile_file(
        "profile.yaml", "id: developer\nname: Developer\nversion: 0.1.0\n"
    )

    with pytest.raises(ValueError, match="duplicate materialized path"):
        materialize_home(
            [profile, profile],
            profile_ref="developer",
            profile_version="0.1.0",
            profile_digest="sha256:d",
            source_blueprint_ref=None,
            source_blueprint_version=None,
            source_blueprint_digest=None,
        )


def test_materialize_home_sibling_free_skill_keeps_files_and_uses_directory_harness_link() -> None:
    profile_yaml = """id: developer
name: Developer
version: 0.1.0
skills:
  - path: skills/implement/SKILL.md
    kind: skill
"""
    files = [
        _profile_file("profile.yaml", profile_yaml),
        _profile_file("skills/implement/SKILL.md", "# Implement\n"),
    ]

    entries = materialize_home(
        files,
        profile_ref="developer",
        profile_version="0.1.0",
        profile_digest="sha256:d",
        source_blueprint_ref=None,
        source_blueprint_version=None,
        source_blueprint_digest=None,
    )
    produced = {entry["path"]: entry for entry in entries}

    assert produced["skills/implement/SKILL.md"] == {
        "path": "skills/implement/SKILL.md",
        "kind": "file",
        "content_utf8": "# Implement\n",
    }
    assert produced[".aw/profile/skills/implement/SKILL.md"]["kind"] == "file"
    assert produced[".claude/skills/implement"] == {
        "path": ".claude/skills/implement",
        "kind": "symlink",
        "target": "../../skills/implement",
    }
    assert ".claude/skills/implement/SKILL.md" not in produced


def test_materialize_home_interpolates_proposal_target() -> None:
    # The Memory section names the profile's own proposal_target (not a hardcoded
    # "library"), per the composition contract.
    profile_yaml = (
        "id: minimal\nname: Minimal\nversion: 0.1.0\nmission: Do one thing.\n"
        "memory_policy:\n  mode: reviewed-learning\n  proposal_target: my-team-curator\n"
    )
    files = [{"content_utf8": profile_yaml, "path": "profile.yaml", "sha256": "sha256:x"}]
    entries = materialize_home(
        files,
        profile_ref="minimal",
        profile_version="0.1.0",
        profile_digest="sha256:d",
        source_blueprint_ref=None,
        source_blueprint_version=None,
        source_blueprint_digest=None,
    )
    agents = next(e for e in entries if e["path"] == "AGENTS.md")["content_utf8"]
    assert "Proposal target: my-team-curator" in agents
    assert "my-team-curator reviews and mints it." in agents
    assert "library reviews and mints it." not in agents


def test_parse_rejects_wrong_schema() -> None:
    with pytest.raises(ValueError):
        parse_import_payload({"files": collect_files(_SOURCE), "schema": "bogus"})
