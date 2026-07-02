from __future__ import annotations

import json
from pathlib import Path

import pytest

from library.aweb_manifest import canonical_bytes
from library.digest import (
    BLUEPRINT_PAYLOAD_SCHEMA,
    blueprint_digest,
    collect_files,
    payload,
    profile_digest,
)

# Vendored .2.9 engineering fixture (aw/cli 21afcb4c) — the cross-lane digest
# contract shared with aw. Library does not depend on the aweb monorepo.
_FIXTURE = Path(__file__).parent / "vectors" / "blueprints" / "engineering"
_SOURCE = _FIXTURE / "source"


def _expected_blueprint_digest() -> str:
    return (_FIXTURE / "expected" / "import-payload.digest").read_text(encoding="utf-8").strip()


def test_blueprint_payload_reproduces_committed_canonical_bytes() -> None:
    committed = (_FIXTURE / "expected" / "import-payload.canonical.json").read_bytes()
    assert canonical_bytes(payload(collect_files(_SOURCE), BLUEPRINT_PAYLOAD_SCHEMA)) == committed


def test_blueprint_digest_matches_fixture() -> None:
    assert blueprint_digest(_SOURCE) == _expected_blueprint_digest()


def test_profile_digests_match_fixture_profile_relative() -> None:
    inputs = json.loads((_FIXTURE / "expected" / "digest-inputs.json").read_text(encoding="utf-8"))
    expected = {item["profile_ref"]: item["digest"] for item in inputs["profile_digests"]}
    assert expected, "fixture must declare profile digests"
    for profile_ref, digest in expected.items():
        assert profile_digest(_SOURCE / "profiles" / profile_ref) == digest, profile_ref


def test_import_return_digest_matches_blueprint_digest() -> None:
    import_return = json.loads((_FIXTURE / "expected" / "import-return.json").read_text(encoding="utf-8"))
    assert import_return["digest"] == _expected_blueprint_digest()


def test_collect_files_rejects_symlinked_file_with_offending_path(tmp_path: Path) -> None:
    target = tmp_path / "outside.txt"
    target.write_text("outside", encoding="utf-8")
    root = tmp_path / "payload"
    root.mkdir()
    link = root / "linked-file.txt"
    link.symlink_to(target)

    with pytest.raises(ValueError, match="linked-file.txt"):
        collect_files(root)


def test_collect_files_rejects_symlinked_directory_with_offending_path(tmp_path: Path) -> None:
    target = tmp_path / "outside-dir"
    target.mkdir()
    (target / "outside.txt").write_text("outside", encoding="utf-8")
    root = tmp_path / "payload"
    root.mkdir()
    link = root / "linked-dir"
    link.symlink_to(target, target_is_directory=True)

    with pytest.raises(ValueError, match="linked-dir"):
        collect_files(root)


def test_collect_files_ignores_symlink_inside_excluded_directory(tmp_path: Path) -> None:
    target = tmp_path / "outside.txt"
    target.write_text("outside", encoding="utf-8")
    root = tmp_path / "payload"
    root.mkdir()
    (root / "profile.yaml").write_text("id: test\n", encoding="utf-8")
    ignored = root / "node_modules"
    ignored.mkdir()
    link = ignored / "linked-file.txt"
    link.symlink_to(target)

    assert collect_files(root) == [
        {
            "content_utf8": "id: test\n",
            "path": "profile.yaml",
            "sha256": "sha256:edc799fc83e4983748bc9194467a210716b5e1a1a5f3d1d2c96a0aaafd6efa0d",
        }
    ]


def test_collect_files_rejects_symlinked_excluded_directory_with_offending_path(tmp_path: Path) -> None:
    target = tmp_path / "outside-node-modules"
    target.mkdir()
    root = tmp_path / "payload"
    root.mkdir()
    link = root / "node_modules"
    link.symlink_to(target, target_is_directory=True)

    with pytest.raises(ValueError, match="node_modules"):
        collect_files(root)


def test_collect_files_rejects_non_utf8_file_with_offending_path(tmp_path: Path) -> None:
    root = tmp_path / "payload"
    nested = root / "profiles" / "developer"
    nested.mkdir(parents=True)
    invalid = nested / "invalid.txt"
    invalid.write_bytes(b"valid prefix \xff invalid utf-8")

    with pytest.raises(ValueError) as excinfo:
        collect_files(root)
    assert (
        str(excinfo.value)
        == "profiles/developer/invalid.txt: blueprint canonical import payload requires UTF-8 text"
    )


def test_collect_files_ignores_non_utf8_file_inside_excluded_directory(tmp_path: Path) -> None:
    root = tmp_path / "payload"
    root.mkdir()
    (root / "profile.yaml").write_text("id: test\n", encoding="utf-8")
    ignored = root / "node_modules"
    ignored.mkdir()
    (ignored / "invalid.txt").write_bytes(b"\xff")

    assert collect_files(root) == [
        {
            "content_utf8": "id: test\n",
            "path": "profile.yaml",
            "sha256": "sha256:edc799fc83e4983748bc9194467a210716b5e1a1a5f3d1d2c96a0aaafd6efa0d",
        }
    ]


def test_payload_is_content_only_no_access_control_fields() -> None:
    # visibility/owner_team are Library record columns, never part of the hashed
    # payload — so a private->public flip cannot change the digest.
    canonical = payload(collect_files(_SOURCE), BLUEPRINT_PAYLOAD_SCHEMA)
    assert set(canonical) == {"files", "schema"}
    for entry in canonical["files"]:
        assert set(entry) == {"content_utf8", "path", "sha256"}
