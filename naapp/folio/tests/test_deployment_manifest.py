"""Folio's real runtime fills its declared manifest from deployment settings."""

import json
from pathlib import Path

import pytest
from aweb_naapp.manifest import canonical_bytes
from awid.did import did_from_public_key
from fastapi.testclient import TestClient
from nacl.signing import SigningKey

from folio.aweb_manifest import MANIFEST
from folio.config import Settings


@pytest.mark.parametrize("source,seed", [("released-env", "01" * 32), ("file", "02" * 32)])
def test_folio_fills_template_kid_from_configured_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, source: str, seed: str
) -> None:
    import folio.api as folio_api

    grant = tmp_path / "grant.hex"
    grant.write_text("03" * 32)
    grant.chmod(0o600)
    keys = {"folio:grant-read-1": str(grant)}
    monkeypatch.setenv("FOLIO_APP_KEY_FILES", json.dumps(keys))
    monkeypatch.setenv("FOLIO_APP_EVENTS_ORIGIN", "http://127.0.0.1:1")
    if source == "released-env":
        # The existing production emit variables still configure app-event only.
        monkeypatch.setenv("FOLIO_APP_EMIT_KID", "folio:emit-1")
        monkeypatch.setenv("FOLIO_APP_EMIT_KEY_SEED_HEX", seed)
    else:
        path = tmp_path / "emit.hex"
        path.write_text(seed)
        path.chmod(0o600)
        monkeypatch.setenv("FOLIO_APP_KEY_FILES", json.dumps({**keys, "folio:emit-1": str(path)}))
    settings = Settings(_env_file=None, public_origin="https://folio.aweb.ai")
    assert MANIFEST["app_keys"][0] == {"kid": "folio:emit-1", "purposes": ["app-event"]}
    assert MANIFEST["events"][0]["type"] == "doc.changed"
    did_key = did_from_public_key(bytes(SigningKey(bytes.fromhex(seed)).verify_key))

    first = TestClient(folio_api.create_app(settings))
    response = first.get("/aweb-app.json")
    assert response.status_code == 200
    document = response.json()
    assert document["app"] == MANIFEST["app"]
    assert document["tools"] == MANIFEST["tools"]
    assert document["events"] == MANIFEST["events"]
    assert document["app_keys"][0] == {"kid": "folio:emit-1", "did_key": did_key, "purposes": ["app-event"]}
    assert document["app_keys"][1]["purposes"] == ["app-grant-read"]
    assert response.content == canonical_bytes(document)
    assert first.get("/manifests/v2.json").content == response.content
    # A separate construction with the same config serves byte-identical data.
    assert TestClient(folio_api.create_app(settings)).get("/aweb-app.json").content == response.content
