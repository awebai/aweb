"""The runtime serves each shared manifest vector, taken as a deployment's
template, as the shared reader resolves it, with the did:keys the deployment's
configured keys give."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from awid.did import did_from_public_key
from nacl.signing import SigningKey
from pydantic_settings import SettingsConfigDict

from aweb_naapp.manifest import ManifestError, canonical_bytes, load_manifest, template_key_entries
from aweb_naapp.runtime.app import NaappRuntime
from aweb_naapp.runtime.settings import NaappSettings

from ..test_manifest_v2_vectors import RESERVED, V2, _manifest_bytes

# Valid manifests whose tool routes overlap: the runtime refuses them, because
# each request must authorize as exactly one tool.
OVERLAPPING_ROUTES = {"agent_catch_all_other_method_allowed", "surface_tool_on_answer_route_allowed"}


class ExampleSettings(NaappSettings):
    model_config = SettingsConfigDict(env_prefix="EXAMPLE_")

    database_url: str = "postgresql://localhost/unused"
    app_id: str = "fixture"


def _as_template(data: bytes, keys: Path) -> tuple[dict[str, Any], dict[str, Path], dict[str, str]]:
    """The vector manifest as a deployment's template: its did:keys removed, and a
    key file per declared kid, whose did:keys the runtime fills back in."""
    document = json.loads(data)
    _localize_event_types(document)
    files: dict[str, Path] = {}
    did_keys: dict[str, str] = {}
    for entry in template_key_entries(document):
        entry.pop("did_key", None)
        seed = hashlib.sha256(entry["kid"].encode()).hexdigest()
        keys.mkdir(exist_ok=True)
        path = keys / f"{hashlib.sha256(entry['kid'].encode()).hexdigest()[:16]}.key"
        path.write_text(seed + "\n", encoding="utf-8")
        path.chmod(0o600)
        files[entry["kid"]] = path
        did_keys[entry["kid"]] = did_from_public_key(bytes(SigningKey(bytes.fromhex(seed)).verify_key))
    return document, files, did_keys


def _event_bindings(document: dict[str, Any]) -> list[dict[str, Any]]:
    bindings = [event for event in document.get("events") or () if isinstance(event, dict)]
    for surface in document.get("surfaces") or ():
        if isinstance(surface, dict):
            bindings += [event for event in surface.get("events") or () if isinstance(event, dict)]
    return bindings


def _localize_event_types(document: dict[str, Any]) -> None:
    """Name event types as a template does: without the app's own prefix."""
    prefix = f"{document['app']['id']}/"
    for event in _event_bindings(document):
        if isinstance(event.get("type"), str):
            event["type"] = event["type"].removeprefix(prefix)


def _names_a_foreign_event_type(data: bytes) -> bool:
    document = json.loads(data)
    _localize_event_types(document)
    return any(isinstance(event.get("type"), str) and "/" in event["type"] for event in _event_bindings(document))


def _runtime(tmp_path: Path, document: dict[str, Any], files: dict[str, Path]) -> NaappRuntime:
    manifest_path = tmp_path / "aweb-app.json"
    manifest_path.write_bytes(canonical_bytes(document))
    migrations = tmp_path / "migrations"
    migrations.mkdir()
    runtime = NaappRuntime(
        ExampleSettings(
            _env_file=None, app_id=document["app"]["id"], public_origin=document["app"]["origin"],
            app_key_files=files,
        ),
        module_name="fixture",
        migrations_path=migrations,
        manifest_path=manifest_path,
    )
    # The vector supplies the installing consumer's root namespace; the runtime
    # itself owns no CLI root commands. Apply that same input to the filled bytes.
    load_manifest(runtime.manifest_bytes, reserved_names=RESERVED)
    return runtime


def _deployment_can_configure(data: bytes) -> bool:
    try:
        app = json.loads(data)["app"]
        return isinstance(app["id"], str) and isinstance(app["origin"], str)
    except (ValueError, KeyError, TypeError):
        return False


@pytest.mark.parametrize("case", V2["cases"], ids=lambda c: c["name"])
def test_the_runtime_serves_each_vector_template_as_the_shared_reader_resolves_it(
    tmp_path: Path, case: dict[str, Any]
) -> None:
    data = _manifest_bytes(case)
    expected = case["expected"]
    if not _deployment_can_configure(data):
        pytest.skip("a deployment configures a string app id and origin")
    if any("did_key" in mutation["path"] for mutation in case.get("mutations", [])):
        pytest.skip("did:keys come from the deployment's configured keys, not the template")
    if _names_a_foreign_event_type(data):
        pytest.skip("a template names its event types locally; another app's prefix cannot be written in one")
    document, files, did_keys = _as_template(data, tmp_path / "keys")
    if not expected["accepted"]:
        with pytest.raises(ManifestError) as refused:
            _runtime(tmp_path, document, files)
        assert refused.value.code == expected["error"]
        return
    if case["name"] in OVERLAPPING_ROUTES:
        with pytest.raises(ValueError, match="match the same requests"):
            _runtime(tmp_path, document, files)
        return
    runtime = _runtime(tmp_path, document, files)
    resolved = {
        **expected["resolved"],
        "app_keys": [{**key, "did_key": did_keys[key["kid"]]} for key in expected["resolved"]["app_keys"]],
    }
    for context in ("agent", "surface", "hook"):
        declared = sorted(tool.name for tool in runtime.declared_tools if context in tool.contexts)
        assert declared == sorted(resolved[f"{context}_tools"]), context
    assert runtime.manifest.view() == resolved
