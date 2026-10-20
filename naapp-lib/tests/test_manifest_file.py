from __future__ import annotations

import json
from pathlib import Path

from aweb_naapp.manifest import (
    canonical_bytes,
    manifest_for_origin,
    read_manifest_bytes,
    write_manifest_file,
)

_HOSTED = "https://app.example.test"
_MANIFEST = {
    "manifest_version": 1,
    "app": {"id": "example", "version": "0.1.0", "origin": _HOSTED, "llms_txt": "/llms.txt"},
    "tools": [{"name": "list", "method": "GET", "path": "/v1/things", "description": "ü"}],
}


def _committed(tmp_path: Path) -> Path:
    path = tmp_path / "aweb-app.json"
    write_manifest_file(path, _MANIFEST)
    return path


def test_written_file_is_canonical_bytes_of_the_manifest(tmp_path: Path) -> None:
    path = _committed(tmp_path)
    assert path.read_bytes() == canonical_bytes(_MANIFEST)
    assert path.read_bytes() == canonical_bytes(json.loads(path.read_bytes()))


def test_hosted_origin_serves_the_committed_bytes_verbatim(tmp_path: Path) -> None:
    path = _committed(tmp_path)
    committed = path.read_bytes()
    assert read_manifest_bytes(path) == committed
    assert read_manifest_bytes(path, _HOSTED) == committed
    assert read_manifest_bytes(path, _HOSTED + "/") == committed


def test_committed_bytes_are_never_reserialized_for_the_hosted_origin(tmp_path: Path) -> None:
    # A committed file is the served artifact even where it is not this library's
    # canonical form: the hosted origin gets it as it is on disk.
    path = tmp_path / "aweb-app.json"
    path.write_bytes(json.dumps(_MANIFEST, indent=2).encode("utf-8"))
    assert read_manifest_bytes(path, _HOSTED) == path.read_bytes()


def test_other_origins_get_the_canonical_manifest_with_only_origin_changed(tmp_path: Path) -> None:
    path = _committed(tmp_path)
    origin = "http://self-hosted.test:8765/"
    custom = read_manifest_bytes(path, origin)
    assert custom == canonical_bytes(manifest_for_origin(_MANIFEST, origin))
    assert read_manifest_bytes(path, "http://self-hosted.test:8765") == custom
    served = json.loads(custom)
    assert served["app"]["origin"] == "http://self-hosted.test:8765"
    served["app"]["origin"] = _HOSTED
    assert served == _MANIFEST


def test_manifest_for_origin_leaves_the_authoring_manifest_unchanged() -> None:
    before = json.loads(json.dumps(_MANIFEST))
    retargeted = manifest_for_origin(_MANIFEST, "http://other.test/")
    assert retargeted["app"]["origin"] == "http://other.test"
    assert _MANIFEST == before
