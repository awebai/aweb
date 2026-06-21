"""Pure per-part 3-way merge: take theirs only where ours is un-evolved."""

from __future__ import annotations

import hashlib

import yaml

from library.blueprint import parse_profile_payload, part_baselines, three_way_merge


def _file(path: str, content: str) -> dict[str, str]:
    return {
        "content_utf8": content,
        "path": path,
        "sha256": "sha256:" + hashlib.sha256(content.encode("utf-8")).hexdigest(),
    }


def _profile(*, mission: str, instructions: str, apps: list[str], version: str = "0.1.0") -> list[dict[str, str]]:
    doc = {
        "id": "dev",
        "name": "Dev",
        "version": version,
        "mission": mission,
        "instructions": "instructions.md",
        "expected_apps": apps,
    }
    return [
        _file("profile.yaml", yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)),
        _file("instructions.md", instructions),
    ]


def _merged_doc(result) -> dict:
    profile_yaml = next(f for f in result.files if f["path"] == "profile.yaml")["content_utf8"]
    return yaml.safe_load(profile_yaml)


def test_takes_theirs_for_unevolved_parts_keeps_ours_for_evolved() -> None:
    baseline = _profile(mission="A", instructions="base", apps=["x"])
    baselines = part_baselines(parse_profile_payload(baseline))

    # ours: mission un-evolved (still A), instructions evolved locally.
    ours = _profile(mission="A", instructions="local edit", apps=["x"])
    # theirs: both changed upstream.
    theirs = _profile(mission="B", instructions="upstream edit", apps=["x", "y"])

    result = three_way_merge(ours_files=ours, theirs_files=theirs, baselines=baselines, target_version="0.2.0")

    assert "field:mission" in result.updated_parts
    assert "field:expected_apps" in result.updated_parts
    assert "file:instructions.md" in result.preserved_parts

    doc = _merged_doc(result)
    assert doc["mission"] == "B"  # un-evolved field pulled upstream
    assert doc["expected_apps"] == ["x", "y"]  # un-evolved field pulled upstream
    assert doc["version"] == "0.2.0"  # minted under target_version
    instructions = next(f for f in result.files if f["path"] == "instructions.md")["content_utf8"]
    assert instructions == "local edit"  # evolved file preserved


def test_no_op_when_upstream_unchanged() -> None:
    baseline = _profile(mission="A", instructions="base", apps=["x"])
    baselines = part_baselines(parse_profile_payload(baseline))
    ours = _profile(mission="A", instructions="local edit", apps=["x"])
    theirs = baseline  # source blueprint did not change

    result = three_way_merge(ours_files=ours, theirs_files=theirs, baselines=baselines, target_version="0.2.0")
    assert result.updated_parts == []  # nothing pullable -> caller treats as no-op


def test_pulls_new_upstream_file() -> None:
    baseline = _profile(mission="A", instructions="base", apps=["x"])
    baselines = part_baselines(parse_profile_payload(baseline))
    ours = _profile(mission="A", instructions="base", apps=["x"])
    theirs = _profile(mission="A", instructions="base", apps=["x"])
    theirs.append(_file("skills/new/SKILL.md", "a new skill"))

    result = three_way_merge(ours_files=ours, theirs_files=theirs, baselines=baselines, target_version="0.2.0")
    assert "file:skills/new/SKILL.md" in result.updated_parts
    assert any(f["path"] == "skills/new/SKILL.md" for f in result.files)
    # The reconstructed profile.yaml lists the pulled skill.
    doc = _merged_doc(result)
    assert {"path": "skills/new/SKILL.md"} in doc["skills"]
