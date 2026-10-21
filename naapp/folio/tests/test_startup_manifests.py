"""Folio starts on the manifest it is deployed with, v1 or v2, and emits with
the key that manifest declares for app events."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from manifest_config import TEST_EMIT_DID_KEY

import folio.api as folio_api
from folio.config import Settings

_GENERATOR = Path(__file__).resolve().parents[3] / "scripts" / "e2e" / "folio_wakes_manifest.py"
_SEED_HEX = "01" * 32


def _deployment_manifest(tmp_path: Path, manifest_version: int) -> Path:
    # The wakes harness's own deployment manifest, generated the way it generates it.
    out = subprocess.run(
        [sys.executable, str(_GENERATOR), "0.2.0", "true", str(manifest_version)],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    path = tmp_path / f"aweb-app-v{manifest_version}.json"
    path.write_text(out.strip(), encoding="utf-8")
    return path


@pytest.mark.parametrize("manifest_version", [1, 2])
def test_folio_starts_and_serves_a_v1_or_v2_manifest_declaring_its_emit_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, manifest_version: int
) -> None:
    manifest_path = _deployment_manifest(tmp_path, manifest_version)
    monkeypatch.setattr(folio_api, "MANIFEST_PATH", manifest_path)
    monkeypatch.setenv("FOLIO_APP_KEY_FILES", "{}")
    settings = Settings(
        _env_file=None,
        public_origin="http://127.0.0.1:38765",
        app_events_origin="http://127.0.0.1:38000",
        app_key_files={},
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
    assert served[field] == [entry]
    assert served["events"][0]["type"] == "doc.changed"
