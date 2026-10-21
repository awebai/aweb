from __future__ import annotations

import json
from pathlib import Path

from aweb_naapp.manifest import canonical_bytes, write_manifest_file

_MANIFEST = {
    "manifest_version": 1,
    "app": {"id": "example", "version": "0.1.0", "origin": "https://app.example.test", "llms_txt": "/llms.txt"},
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
