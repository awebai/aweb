"""The served manifest is the deployment's own (aweb-acin).

The committed manifest is a template: kids, purposes, local event types and
the hosted app.id default. The runtime fills app.id from configuration and each
declared kid's did:key from the deployment's configured key, then serves the
canonical bytes.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from pathlib import Path
from typing import Any

import pytest
from awid.did import did_from_public_key
from nacl.signing import SigningKey
from pydantic_settings import SettingsConfigDict

from aweb_naapp.manifest import ManifestError, canonical_bytes, fill_manifest, load_manifest
from aweb_naapp.runtime.app import NaappRuntime
from aweb_naapp.runtime.app_keys import AppKeyError
from aweb_naapp.runtime.settings import NaappSettings

HOSTED_ORIGIN = "https://example.aweb.ai"
HOSTED_ID = "example"
TOOL = {"name": "create", "method": "POST", "path": "/v1/things", "scopes": ["example:write"]}


class ExampleSettings(NaappSettings):
    model_config = SettingsConfigDict(env_prefix="EXAMPLE_")

    database_url: str = "postgresql://localhost/unused"
    public_origin: str = HOSTED_ORIGIN
    app_id: str = HOSTED_ID


def _did_key(seed_hex: str) -> str:
    return did_from_public_key(bytes(SigningKey(bytes.fromhex(seed_hex)).verify_key))


def _key_file(directory: Path, name: str, seed_hex: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{name}.key"
    path.write_text(seed_hex + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def _v2_template(*keys: tuple[str, list[str]], **extra: Any) -> dict[str, Any]:
    return {
        "manifest_version": 2,
        "app": {"id": HOSTED_ID, "origin": HOSTED_ORIGIN},
        "tools": [TOOL],
        "app_keys": [{"kid": kid, "purposes": purposes} for kid, purposes in keys],
        **extra,
    }


def _runtime(tmp_path: Path, template: dict[str, Any], **settings: Any) -> NaappRuntime:
    path = tmp_path / "aweb-app.json"
    tmp_path.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_bytes(template))
    migrations = tmp_path / "migrations"
    migrations.mkdir(exist_ok=True)
    return NaappRuntime(
        ExampleSettings(_env_file=None, **settings),
        module_name="example",
        migrations_path=migrations,
        manifest_path=path,
    )


def test_app_id_comes_from_configuration_and_did_keys_from_the_configured_key_files(tmp_path: Path) -> None:
    events, requests = secrets.token_hex(32), secrets.token_hex(32)
    keys = tmp_path / "keys"
    template = _v2_template(("example:events", ["app-event"]), ("example:requests", ["app-request"]))
    runtime = _runtime(
        tmp_path / "app", template, app_id="acme-example", public_origin="https://example.acme.test",
        app_key_files={"example:events": _key_file(keys, "events", events),
                       "example:requests": _key_file(keys, "requests", requests)},
    )
    served = json.loads(runtime.manifest_bytes)
    assert served["app"] == {"id": "acme-example", "origin": "https://example.acme.test"}
    assert served["app_keys"] == [
        {"kid": "example:events", "did_key": _did_key(events), "purposes": ["app-event"]},
        {"kid": "example:requests", "did_key": _did_key(requests), "purposes": ["app-request"]},
    ]
    assert runtime.manifest.app_keys_for("app-request") == {"example:requests": _did_key(requests)}
    assert events not in runtime.manifest_bytes.decode() and requests not in runtime.manifest_bytes.decode()


def test_one_configuration_serves_byte_identical_manifest_and_catalog(tmp_path: Path) -> None:
    seed = secrets.token_hex(32)
    keys = {"example:events": _key_file(tmp_path / "keys", "events", seed)}
    template = _v2_template(("example:events", ["app-event"]))
    first = _runtime(tmp_path / "a", template, app_key_files=keys)
    second = _runtime(tmp_path / "b", template, app_key_files=keys)
    assert first.manifest_bytes == second.manifest_bytes
    assert first.catalog_bytes == second.catalog_bytes
    digest = "sha256:" + hashlib.sha256(first.manifest_bytes).hexdigest()
    assert json.loads(first.catalog_bytes or b"{}")["variants"][0]["digest"] == digest


def test_a_v1_event_emitter_is_filled_from_the_released_seed(tmp_path: Path) -> None:
    seed = secrets.token_hex(32)
    template = {
        "manifest_version": 1,
        "app": {"id": HOSTED_ID, "origin": HOSTED_ORIGIN},
        "tools": [TOOL],
        "event_emitters": [{"kid": "example:emit-1"}],
    }
    runtime = _runtime(
        tmp_path, template, app_emit_kid="example:emit-1", app_emit_key_seed_hex=seed,
        app_events_origin="https://core.example.test",
    )
    assert json.loads(runtime.manifest_bytes)["event_emitters"] == [
        {"kid": "example:emit-1", "did_key": _did_key(seed)}
    ]


def test_the_released_seed_fills_only_a_kid_declared_for_app_events(tmp_path: Path) -> None:
    template = _v2_template(("example:requests", ["app-request"]))
    with pytest.raises(AppKeyError, match="app-event"):
        _runtime(tmp_path, template, app_emit_kid="example:requests", app_emit_key_seed_hex=secrets.token_hex(32))


def test_a_template_that_commits_a_did_key_does_not_start(tmp_path: Path) -> None:
    seed = secrets.token_hex(32)
    template = _v2_template()
    template["app_keys"] = [{"kid": "example:events", "did_key": _did_key(seed), "purposes": ["app-event"]}]
    with pytest.raises(ManifestError, match="did_key"):
        _runtime(tmp_path, template, app_key_files={"example:events": _key_file(tmp_path / "k", "e", seed)})


def test_a_declared_kid_without_a_configured_key_does_not_start(tmp_path: Path) -> None:
    with pytest.raises(AppKeyError, match="example:events"):
        _runtime(tmp_path, _v2_template(("example:events", ["app-event"])))


def test_configuration_cannot_add_a_kid(tmp_path: Path) -> None:
    template = _v2_template(("example:events", ["app-event"]))
    keys = tmp_path / "keys"
    with pytest.raises(AppKeyError, match="example:extra"):
        _runtime(tmp_path / "app", template, app_key_files={
            "example:events": _key_file(keys, "events", secrets.token_hex(32)),
            "example:extra": _key_file(keys, "extra", secrets.token_hex(32)),
        })


@pytest.mark.parametrize("origin", ["https://example.self.test", "http://10.0.0.5:8770", "http://192.168.1.20"])
def test_the_hosted_app_id_is_refused_at_an_origin_others_can_reach(tmp_path: Path, origin: str) -> None:
    with pytest.raises(ValueError, match="app_id"):
        _runtime(tmp_path, _v2_template(), public_origin=origin)


@pytest.mark.parametrize("origin", ["http://127.0.0.1:8770", "http://localhost:8770", "http://example.localhost"])
def test_the_hosted_app_id_runs_at_a_loopback_origin(tmp_path: Path, origin: str) -> None:
    assert _runtime(tmp_path, _v2_template(), public_origin=origin).manifest.app_id == HOSTED_ID


def test_the_hosted_app_id_is_served_only_at_the_hosted_origin_or_loopback(tmp_path: Path) -> None:
    assert _runtime(tmp_path / "hosted", _v2_template()).manifest.app_id == HOSTED_ID
    own = _runtime(tmp_path / "own", _v2_template(), public_origin="https://example.self.test", app_id="self-example")
    assert own.manifest.app_id == "self-example"


def test_a_committed_event_type_must_be_local(tmp_path: Path) -> None:
    template = _v2_template(events=[{"type": "example/thing.changed", "default_delivery_intent": "ambient"}])
    with pytest.raises(ManifestError):
        _runtime(tmp_path, template, app_id="acme-example", public_origin="https://example.acme.test")


def test_the_filler_is_the_canonical_form_consumers_compare() -> None:
    seed = secrets.token_hex(32)
    template = _v2_template(("example:events", ["app-event"]))
    filled = fill_manifest(template, app_id=HOSTED_ID, origin=HOSTED_ORIGIN, did_keys={"example:events": _did_key(seed)})
    document = json.loads(filled)
    assert filled == canonical_bytes(document)
    assert load_manifest(filled).app_keys_for("app-event") == {"example:events": _did_key(seed)}
