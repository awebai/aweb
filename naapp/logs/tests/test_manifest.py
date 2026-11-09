"""logs' manifest template (audit-substrate.md §B1; the per-deployment manifest ruling, aweb-acin).

The committed manifest is a template: kids and purposes, never did:keys. A
deployment fills each kid's did:key from its configured key file. These tests
fill keys generated here and read the result with the shared manifest reader.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aweb_naapp.hooks.catalog import load_catalog
from aweb_naapp.manifest import load_manifest
from aweb_naapp.runtime.app_keys import load_app_key

from aweb_logs.chain import CHECKPOINT_PURPOSE, RECEIPT_PURPOSE
from aweb_logs.config import LogsSettings

from .deployment import did_key_of, served_manifest, template, write_key_files

AWEB_ROOT = Path(__file__).resolve().parents[3]
ORIGIN = "https://logs.example.test"
CATALOG = load_catalog((AWEB_ROOT / "docs" / "vectors" / "hook-catalog-v1.json").read_bytes())


def _filled(tmp_path: Path) -> Any:
    return load_manifest(served_manifest(write_key_files(tmp_path), origin=ORIGIN))


def test_the_template_commits_no_keys() -> None:
    assert all(set(entry) == {"kid", "purposes"} for entry in template()["app_keys"])


def test_ingest_is_logs_only_hook_tool(tmp_path: Path) -> None:
    manifest = _filled(tmp_path)
    assert manifest.manifest_version == 2
    assert manifest.hook_tools == ("ingest",)
    assert manifest.surface_tools == ()


def test_members_granted_readers_ask_for_a_reader_slot_and_remove_a_reader(
    tmp_path: Path,
) -> None:
    manifest = _filled(tmp_path)
    assert set(manifest.agent_tools) == {"reader-slot", "remove-reader"}
    routes = {
        (tool["name"], tool["method"], tool["path"], tuple(tool["scopes"]), tool["mutation"])
        for tool in template()["tools"]
        if tool["name"] in manifest.agent_tools
    }
    assert routes == {
        ("reader-slot", "POST", "/v1/reader-slots", ("logs.readers",), True),
        ("remove-reader", "POST", "/v1/reader-removals", ("logs.readers",), True),
    }


def test_ingest_is_registered_on_every_hook_of_the_catalog(tmp_path: Path) -> None:
    hooks = _filled(tmp_path).hooks
    assert hooks is not None
    registered = {
        (reg["catalog_id"], reg["catalog_version"], reg["hook"], reg["tool"])
        for reg in hooks["registrations"]
    }
    assert registered == {(CATALOG.id, CATALOG.version, hook, "ingest") for hook in CATALOG.hooks}


def test_logs_produces_only_its_readers_governance_events(tmp_path: Path) -> None:
    hooks = _filled(tmp_path).hooks
    assert hooks is not None
    assert [
        (production["catalog_id"], production["catalog_version"], production["hook"])
        for production in hooks["productions"]
    ] == [(CATALOG.id, CATALOG.version, "post-governance-hook")]


def test_logs_subscribes_to_no_app_events(tmp_path: Path) -> None:
    committed = template()
    assert "events" not in committed and "event_emitters" not in committed
    assert _filled(tmp_path).app_keys_for("app-event") == {}


def test_logs_declares_its_signing_and_resolution_keys_by_purpose(tmp_path: Path) -> None:
    manifest = _filled(tmp_path)
    assert set(manifest.app_keys_for(RECEIPT_PURPOSE)) == set(
        manifest.app_keys_for(CHECKPOINT_PURPOSE)
    )
    assert len(manifest.app_keys_for(RECEIPT_PURPOSE)) == 1
    assert len(manifest.app_keys_for("hook-resolve")) == 1
    assert not set(manifest.app_keys_for("hook-resolve")) & set(
        manifest.app_keys_for(RECEIPT_PURPOSE)
    )


def test_installation_grants_and_governance_events_have_keys_of_their_own(
    tmp_path: Path,
) -> None:
    manifest = _filled(tmp_path)
    grants = set(manifest.app_keys_for("app-grant-read"))
    governance = set(manifest.app_keys_for("hook-event"))
    assert len(grants) == 1 and len(governance) == 1
    others = set(manifest.app_keys_for(RECEIPT_PURPOSE)) | set(
        manifest.app_keys_for("hook-resolve")
    )
    assert not grants & governance and not (grants | governance) & others


def test_kids_and_purposes_come_from_the_file_and_keys_from_configuration(
    tmp_path: Path,
) -> None:
    template_keys = {entry["kid"]: entry["purposes"] for entry in template()["app_keys"]}
    key_files = write_key_files(tmp_path)
    settings = LogsSettings(
        _env_file=None,
        database_url="postgresql://localhost/logs",
        public_origin=ORIGIN,
        console_origin="https://console.logs.example.test",
        app_key_files=key_files,
    )
    manifest = load_manifest(served_manifest(key_files, origin=ORIGIN))

    assert {kid: list(purposes) for kid, _, purposes in manifest.app_keys} == template_keys
    for purpose in (RECEIPT_PURPOSE, CHECKPOINT_PURPOSE, "hook-resolve", "app-grant-read", "hook-event"):
        key = load_app_key(settings, manifest, purpose)
        assert purpose in template_keys[key.kid]
        assert key.did_key == did_key_of(key_files[key.kid])
