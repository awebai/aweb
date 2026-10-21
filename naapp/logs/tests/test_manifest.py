"""logs' manifest template (audit-substrate.md §B1; the per-deployment manifest ruling, aweb-acin).

The committed manifest is a template: kids and purposes, never did:keys. A
deployment fills each kid's did:key from its configured key file. These tests
fill keys generated here and read the result with the shared manifest reader.
"""

from __future__ import annotations

import json
import secrets
from pathlib import Path
from typing import Any

from aweb_naapp.hooks.catalog import load_catalog
from aweb_naapp.manifest import load_manifest
from aweb_naapp.runtime.app_keys import load_app_key
from awid.did import did_from_public_key
from nacl.signing import SigningKey

from aweb_logs import MANIFEST_PATH
from aweb_logs.chain import CHECKPOINT_PURPOSE, RECEIPT_PURPOSE
from aweb_logs.config import LogsSettings

AWEB_ROOT = Path(__file__).resolve().parents[3]
CATALOG = load_catalog((AWEB_ROOT / "docs" / "vectors" / "hook-catalog-v1.json").read_bytes())


def _template() -> dict[str, Any]:
    return json.loads(MANIFEST_PATH.read_bytes())


def _did_key(seed_hex: str) -> str:
    return did_from_public_key(bytes(SigningKey(bytes.fromhex(seed_hex)).verify_key))


def _filled(seeds: dict[str, str] | None = None) -> Any:
    """The template with each kid's did:key derived from its seed, as a
    deployment fills it from its key files; a generated key by default."""
    manifest = _template()
    for entry in manifest["app_keys"]:
        seed = (seeds or {}).get(entry["kid"]) or secrets.token_hex(32)
        entry["did_key"] = _did_key(seed)
    return load_manifest(json.dumps(manifest).encode())


def test_the_template_commits_no_keys() -> None:
    assert all(set(entry) == {"kid", "purposes"} for entry in _template()["app_keys"])


def test_ingest_is_logs_only_tool_and_takes_hook_deliveries_only() -> None:
    manifest = _filled()
    assert manifest.manifest_version == 2
    assert manifest.hook_tools == ("ingest",)
    assert manifest.agent_tools == () and manifest.surface_tools == ()


def test_ingest_is_registered_on_every_hook_of_the_catalog() -> None:
    hooks = _filled().hooks
    assert hooks is not None
    registered = {
        (reg["catalog_id"], reg["catalog_version"], reg["hook"], reg["tool"])
        for reg in hooks["registrations"]
    }
    assert registered == {(CATALOG.id, CATALOG.version, hook, "ingest") for hook in CATALOG.hooks}
    assert hooks["productions"] == []


def test_logs_subscribes_to_no_app_events() -> None:
    template = _template()
    assert "events" not in template and "event_emitters" not in template
    assert _filled().app_keys_for("app-event") == {}


def test_logs_declares_its_signing_and_resolution_keys_by_purpose() -> None:
    manifest = _filled()
    assert set(manifest.app_keys_for(RECEIPT_PURPOSE)) == set(
        manifest.app_keys_for(CHECKPOINT_PURPOSE)
    )
    assert len(manifest.app_keys_for(RECEIPT_PURPOSE)) == 1
    assert len(manifest.app_keys_for("hook-resolve")) == 1
    assert not set(manifest.app_keys_for("hook-resolve")) & set(
        manifest.app_keys_for(RECEIPT_PURPOSE)
    )


def test_kids_and_purposes_come_from_the_file_and_keys_from_configuration(
    tmp_path: Path,
) -> None:
    template_keys = {entry["kid"]: entry["purposes"] for entry in _template()["app_keys"]}
    seeds = {kid: secrets.token_hex(32) for kid in template_keys}
    key_files = {}
    for index, (kid, seed) in enumerate(seeds.items()):
        path = tmp_path / f"key-{index}"
        path.write_text(seed + "\n", encoding="utf-8")
        path.chmod(0o600)
        key_files[kid] = path
    settings = LogsSettings(
        _env_file=None,
        database_url="postgresql://localhost/logs",
        public_origin="https://logs.example.test",
        app_key_files=key_files,
    )
    manifest = _filled(seeds)

    assert {kid: list(purposes) for kid, _, purposes in manifest.app_keys} == template_keys
    for purpose in (RECEIPT_PURPOSE, CHECKPOINT_PURPOSE, "hook-resolve"):
        key = load_app_key(settings, manifest, purpose)
        assert purpose in template_keys[key.kid]
        assert key.did_key == _did_key(seeds[key.kid])
