from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import library_prod_gate as gate


def payload(runtime: str, *, managed: list[str] | None = None) -> dict:
    paths = [".aw/profile/ref.json", "AGENTS.md", "CLAUDE.md"]
    ref = {
        "profile_ref": "developer",
        "profile_version": "0.1.8",
        "runtime_kind": runtime,
        "managed_set": paths if managed is None else managed,
        "source_blueprint_ref": "aweb.team",
        "source_blueprint_version": "0.1.12",
    }
    return {
        "home_files": [
            {"path": paths[0], "content_utf8": json.dumps(ref)},
            {"path": paths[1], "content_utf8": "# Developer\n"},
            {"path": paths[2], "kind": "symlink", "target": "AGENTS.md"},
        ]
    }


def test_candidate_requires_positional_managed_set() -> None:
    summary = gate.validate_candidate_payload(payload("claude-code"), "claude-code")
    assert summary["managed_set_count"] == 3
    same_set_wrong_order = ["AGENTS.md", "CLAUDE.md", ".aw/profile/ref.json"]
    with pytest.raises(gate.GateError, match="index 0"):
        gate.validate_candidate_payload(
            payload("claude-code", managed=same_set_wrong_order), "claude-code"
        )


def test_candidate_rejects_duplicates() -> None:
    with pytest.raises(gate.GateError, match="duplicate"):
        gate.validate_candidate_payload(
            payload("pi", managed=[".aw/profile/ref.json", "AGENTS.md", "AGENTS.md"]), "pi"
        )


def test_recovery_requires_known_old_fingerprint() -> None:
    old = payload("pi")
    ref_entry = old["home_files"][0]
    ref = json.loads(ref_entry["content_utf8"])
    ref.pop("runtime_kind")
    ref.pop("managed_set")
    ref_entry["content_utf8"] = json.dumps(ref)
    summary = gate.validate_recovery_payload(old, "pi")
    assert summary["gate"] == "raw-recovery"
    with pytest.raises(gate.GateError, match="not the known"):
        gate.validate_recovery_payload(payload("pi"), "pi")


def test_materialized_ref_is_strict(tmp_path: Path) -> None:
    path = tmp_path / "ref.json"
    path.write_text(
        json.dumps(
            {
                "profile_ref": "developer",
                "profile_version": "0.1.8",
                "runtime_kind": "pi",
                "managed_set": ["AGENTS.md"],
            }
        )
    )
    assert gate.validate_materialized_ref(path, "pi")["runtime_kind"] == "pi"
    with pytest.raises(gate.GateError, match="mismatch"):
        gate.validate_materialized_ref(path, "claude-code")


def test_clone_auth_home_removes_profile_and_delivery_state(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    (source / ".aw" / "profile").mkdir(parents=True)
    (source / ".aw" / "profile" / "ref.json").write_text("{}")
    (source / ".aw" / "signing.key").write_text("secret")
    (source / ".aw" / "interaction-log.jsonl").write_text("private")
    destination.mkdir()
    gate.clone_auth_home(source, destination)
    assert (destination / ".aw" / "signing.key").read_text() == "secret"
    assert not (destination / ".aw" / "profile").exists()
    assert not (destination / ".aw" / "interaction-log.jsonl").exists()
