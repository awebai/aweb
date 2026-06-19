from __future__ import annotations

import json
from pathlib import Path

from library.digest import PACK_PAYLOAD_SCHEMA, collect_files
from library.profile_pack import (
    import_return,
    materialize_home_files,
    parse_import_payload,
    parse_profile_payload,
)

_FIXTURE = Path(__file__).parent / "vectors" / "profile-packs" / "engineering"
_SOURCE = _FIXTURE / "source"
_MATERIALIZED = _FIXTURE / "expected" / "materialized-home"


def _import_payload() -> dict:
    # The payload aw uploads on import.
    return {"files": collect_files(_SOURCE), "schema": PACK_PAYLOAD_SCHEMA}


def test_parse_import_payload_yields_pack_metadata() -> None:
    pack = parse_import_payload(_import_payload())
    assert pack.pack_ref == "aweb.engineering-pack"
    assert pack.version == "0.1.0"
    assert [p.profile_ref for p in pack.profiles] == ["coordinator", "developer", "reviewer"]
    coordinator = pack.profiles[0]
    assert coordinator.name == "Coordinator"
    assert coordinator.mission.startswith("Coordinate the team")
    assert "planning" in coordinator.accepted_work


def test_import_return_matches_fixture_exactly() -> None:
    expected = json.loads((_FIXTURE / "expected" / "import-return.json").read_text(encoding="utf-8"))
    assert import_return(parse_import_payload(_import_payload())) == expected


def test_materialize_home_files_match_fixture_byte_exact() -> None:
    pack = parse_import_payload(_import_payload())
    for profile in pack.profiles:
        home_files = materialize_home_files(
            profile,
            source_profile_pack_ref=pack.pack_ref,
            source_profile_pack_version=pack.version,
            source_profile_pack_digest=pack.digest,
        )
        produced = {entry["path"]: entry["content_utf8"] for entry in home_files}
        home_dir = _MATERIALIZED / profile.profile_ref
        expected_paths = sorted(p.relative_to(home_dir).as_posix() for p in home_dir.rglob("*") if p.is_file())
        assert sorted(produced) == expected_paths, profile.profile_ref
        for rel, content in produced.items():
            assert content == (home_dir / rel).read_text(encoding="utf-8"), (profile.profile_ref, rel)


def test_materialize_ref_json_carries_source_pack_provenance() -> None:
    pack = parse_import_payload(_import_payload())
    home = materialize_home_files(
        pack.profiles[0],
        source_profile_pack_ref=pack.pack_ref,
        source_profile_pack_version=pack.version,
        source_profile_pack_digest=pack.digest,
    )
    ref_entry = next(f for f in home if f["path"] == ".aw/profile/ref.json")
    ref = json.loads(ref_entry["content_utf8"])
    assert ref["profile_ref"] == "coordinator"
    assert ref["profile_digest"] == pack.profiles[0].digest
    assert ref["source_profile_pack_digest"] == pack.digest


def test_parse_profile_payload_reproduces_a_profile() -> None:
    profile = parse_profile_payload(collect_files(_SOURCE / "profiles" / "coordinator"))
    assert profile.profile_ref == "coordinator"
    assert profile.version == "0.1.0"
    assert profile.digest == "sha256:34d0305a43753bed042d7bfbdbdae77c19bdb89d4353ea103a9e1b0faa8be619"
    assert profile.mission.startswith("Coordinate")
    assert "planning" in profile.accepted_work


def test_parse_rejects_wrong_schema() -> None:
    import pytest

    with pytest.raises(ValueError):
        parse_import_payload({"files": collect_files(_SOURCE), "schema": "bogus"})
