"""Folio starts on its configured v2 template, using purpose-specific keys."""

import copy
import json

import httpx
import pytest
from aweb_naapp.manifest import canonical_bytes
from manifest_config import TEST_EMIT_DID_KEY, TEST_EMIT_SEED_HEX, TEST_GRANT_DID_KEY
from manifest_config import configured_settings as configured
from pydantic import SecretStr

import folio.api as folio_api
from folio.aweb_manifest import MANIFEST


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
            assert app.state.folio_runtime.installation_grants() is app.state.folio_runtime.installation_grants()
            assert served["events"][0]["type"] == "doc.changed"
            assert (await client.get("/health")).json()["checks"]["database"]["ok"]


def test_missing_grant_read_key_refuses_startup(tmp_path):
    from aweb_naapp.runtime.app_keys import AppKeyError
    settings = configured(tmp_path)
    settings.app_key_files.pop("folio:grant-read-1")
    with pytest.raises(AppKeyError):
        folio_api.create_app(settings)
