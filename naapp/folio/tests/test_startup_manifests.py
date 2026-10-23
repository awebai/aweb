"""Production and wakes manifests start with distinct purpose-specific keys."""

import copy
import json
import os
import subprocess
import sys
from pathlib import Path

import httpx
import pytest
from aweb_naapp.manifest import canonical_bytes
from awid.did import did_from_public_key
from fastapi.testclient import TestClient
from manifest_config import TEST_EMIT_DID_KEY, TEST_EMIT_SEED_HEX, TEST_GRANT_DID_KEY
from nacl.signing import SigningKey
from pydantic import SecretStr
from test_record_runtime import configured

import folio.api as folio_api
from folio.aweb_manifest import MANIFEST
from folio.config import Settings


@pytest.mark.parametrize("emit_from_seed", [True, False])
async def test_folio_starts_with_separate_grant_key_and_existing_emit_seed_or_file(
    monkeypatch, tmp_path, test_db_factory, emit_from_seed,
):
    db = await test_db_factory.create_db(suffix="folio_manifest_startup")
    template = copy.deepcopy(MANIFEST)
    template["app_keys"][0]["kid"] = "folio:emit-test"
    path = tmp_path / "aweb-app.json"
    path.write_bytes(canonical_bytes(template))
    monkeypatch.setattr(folio_api, "MANIFEST_PATH", path)
    settings = configured(tmp_path, database_url=db.config.get_dsn(), db_schema=db.config.get_schema(),
                          public_origin="http://127.0.0.1:38765", app_events_origin="http://127.0.0.1:38000")
    emit_path = settings.app_key_files.pop("folio:emit-1")
    if emit_from_seed:
        settings.app_emit_kid = "folio:emit-test"
        settings.app_emit_key_seed_hex = SecretStr(TEST_EMIT_SEED_HEX)
    else:
        settings.app_key_files["folio:emit-test"] = emit_path
    app = folio_api.create_app(settings)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=settings.public_origin) as client:
            response = await client.get("/aweb-app.json")
            assert response.status_code == 200
            served = json.loads(response.content)
            assert served["manifest_version"] == 2
            assert served["app_keys"] == [
                {"kid": "folio:emit-test", "did_key": TEST_EMIT_DID_KEY, "purposes": ["app-event"]},
                {"kid": "folio:grant-read-1", "did_key": TEST_GRANT_DID_KEY, "purposes": ["app-grant-read"]},
            ]
            assert served["events"][0]["type"] == "doc.changed"
            assert (await client.get("/health")).json()["checks"]["database"]["ok"]


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


@pytest.mark.parametrize("requested_version", [1, 2])
def test_wakes_deployment_uses_current_manifest_and_declared_emit_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, requested_version: int
) -> None:
    manifest_path = _deployment_manifest(tmp_path, requested_version)
    manifest_version = max(requested_version, MANIFEST["manifest_version"])
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
