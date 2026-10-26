"""The production Folio runtime declares and mounts the shared records boundary."""

import pytest
from aweb_naapp.runtime.app_keys import AppKeyError

from folio.api import create_app
from folio.config import Settings
from folio.record_tools import RECORD_TOOLS


def configured(tmp_path, **overrides):
    files = {}
    for kid, seed in (("folio:emit-1", "01" * 32), ("folio:grant-read-1", "02" * 32)):
        path = tmp_path / (kid.replace(":", "-") + ".hex")
        path.write_text(seed)
        path.chmod(0o600)
        files[kid] = path
    return Settings(_env_file=None, app_key_files=files, **overrides)


def test_records_manifest_declares_all_callable_schemas_and_separate_grant_read_key(tmp_path):
    app = create_app(configured(tmp_path))
    manifest = app.state.folio_runtime.manifest
    assert manifest.manifest_version == 2
    assert set(manifest.app_keys_for("app-grant-read")) == {"folio:grant-read-1"}
    declared = {tool["name"]: tool for tool in manifest.document["tools"]}
    for tool in RECORD_TOOLS:
        assert declared[tool["name"]] == tool


def test_record_routes_are_registered_before_runtime_startup_validation(tmp_path):
    app = create_app(configured(tmp_path))
    app.state.folio_runtime.check_authorized_routes(app)
    paths = {
        (method, route.path) for route in app.routes for method in getattr(route, "methods", ())
    }
    for tool in RECORD_TOOLS:
        assert (tool["method"], tool["path"]) in paths
    assert ("GET", "/present/edit/{link_id}/widgets/{widget_id}/records") in paths
    assert ("GET", "/present/{token}/widgets") in paths
    assert not any(path.startswith("/v1/links/") for _, path in paths)


def test_missing_record_grant_key_refuses_construction(tmp_path):
    settings = configured(tmp_path)
    settings.app_key_files.pop("folio:grant-read-1")
    with pytest.raises(AppKeyError):
        create_app(settings)
