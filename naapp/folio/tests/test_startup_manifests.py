"""Folio starts on the manifest it is deployed with, v1 or v2, and emits with
the key that manifest declares for app events."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from awid.did import did_from_public_key
from fastapi.testclient import TestClient
from manifest_config import TEST_EMIT_DID_KEY
from nacl.signing import SigningKey

import folio.api as folio_api
from folio.config import Settings

_GENERATOR = Path(__file__).resolve().parents[3] / "scripts" / "e2e" / "folio_wakes_manifest.py"
_SEED_HEX = "01" * 32
_ORIGIN = "https://folio-wakes.test:8765"


def _deployment_manifest(tmp_path: Path, manifest_version: int) -> Path:
    # The wakes harness's own deployment manifest, generated the way it generates it.
    out = subprocess.run(
        [sys.executable, str(_GENERATOR), "0.2.0", "true", str(manifest_version)],
        env={**os.environ, "FOLIO_WAKES_ORIGIN": _ORIGIN},
        capture_output=True,
        text=True,
    )
    assert out.returncode == 0, out.stderr
    path = tmp_path / f"aweb-app-v{manifest_version}.json"
    path.write_text(out.stdout.strip(), encoding="utf-8")
    return path


@pytest.mark.parametrize("manifest_version", [1, 2])
def test_folio_starts_and_serves_a_v1_or_v2_manifest_declaring_its_emit_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, manifest_version: int
) -> None:
    manifest_path = _deployment_manifest(tmp_path, manifest_version)
    monkeypatch.setattr(folio_api, "MANIFEST_PATH", manifest_path)
    monkeypatch.setenv("FOLIO_APP_KEY_FILES", "{}")
    key_files = {}
    if manifest_version == 2:
        grant_key = tmp_path / "grant-read.hex"
        grant_key.write_text("03" * 32)
        grant_key.chmod(0o600)
        key_files["folio:grant-read-1"] = grant_key
    settings = Settings(
        _env_file=None,
        public_origin=_ORIGIN,
        app_events_origin="http://127.0.0.1:38000",
        app_key_files=key_files,
        app_emit_kid="folio:emit-test",
        app_emit_key_seed_hex=_SEED_HEX,
    )

    response = TestClient(folio_api.create_app(settings)).get("/aweb-app.json")

    assert response.status_code == 200
    served = json.loads(response.content)
    assert served["manifest_version"] == manifest_version
    field = "app_keys" if manifest_version == 2 else "event_emitters"
    entry = {"kid": "folio:emit-test", "did_key": TEST_EMIT_DID_KEY}
    if manifest_version == 2:
        entry["purposes"] = ["app-event"]
    expected = [entry]
    if manifest_version == 2:
        expected.insert(0, {
            "kid": "folio:grant-read-1", "purposes": ["app-grant-read"],
            "did_key": did_from_public_key(bytes(SigningKey(bytes.fromhex("03" * 32)).verify_key)),
        })
    assert served[field] == expected
    assert served["events"][0]["type"] == "doc.changed"
