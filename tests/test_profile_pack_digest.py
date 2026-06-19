from __future__ import annotations

import json
from pathlib import Path

from library.aweb_manifest import canonical_bytes
from library.digest import (
    PACK_PAYLOAD_SCHEMA,
    collect_files,
    pack_digest,
    payload,
    profile_digest,
)

# Vendored .2.9 engineering fixture (aw/cli 21afcb4c) — the cross-lane digest
# contract shared with aw. Library does not depend on the aweb monorepo.
_FIXTURE = Path(__file__).parent / "vectors" / "profile-packs" / "engineering"
_SOURCE = _FIXTURE / "source"


def _expected_pack_digest() -> str:
    return (_FIXTURE / "expected" / "import-payload.digest").read_text(encoding="utf-8").strip()


def test_pack_payload_reproduces_committed_canonical_bytes() -> None:
    committed = (_FIXTURE / "expected" / "import-payload.canonical.json").read_bytes()
    assert canonical_bytes(payload(collect_files(_SOURCE), PACK_PAYLOAD_SCHEMA)) == committed


def test_pack_digest_matches_fixture() -> None:
    assert pack_digest(_SOURCE) == _expected_pack_digest()


def test_profile_digests_match_fixture_profile_relative() -> None:
    inputs = json.loads((_FIXTURE / "expected" / "digest-inputs.json").read_text(encoding="utf-8"))
    expected = {item["profile_ref"]: item["digest"] for item in inputs["profile_digests"]}
    assert expected, "fixture must declare profile digests"
    for profile_ref, digest in expected.items():
        assert profile_digest(_SOURCE / "profiles" / profile_ref) == digest, profile_ref


def test_import_return_digest_matches_pack_digest() -> None:
    import_return = json.loads((_FIXTURE / "expected" / "import-return.json").read_text(encoding="utf-8"))
    assert import_return["digest"] == _expected_pack_digest()


def test_payload_is_content_only_no_access_control_fields() -> None:
    # visibility/owner_team are Library record columns, never part of the hashed
    # payload — so a private->public flip cannot change the digest.
    canonical = payload(collect_files(_SOURCE), PACK_PAYLOAD_SCHEMA)
    assert set(canonical) == {"files", "schema"}
    for entry in canonical["files"]:
        assert set(entry) == {"content_utf8", "path", "sha256"}
