"""logs' manifest template (audit-substrate.md §B1; the per-deployment manifest ruling, aweb-acin).

The committed manifest is a template: kids and purposes, never did:keys. A
deployment fills each kid's did:key from its configured key file. These tests
fill keys generated here and read the result with the shared manifest reader.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aweb_naapp.hooks.catalog import load_catalog
from aweb_naapp.manifest import load_manifest, tool_params
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


def test_only_ingest_takes_hooks_and_only_delegation_tools_are_agent_invocable(tmp_path: Path) -> None:
    manifest = _filled(tmp_path)
    assert manifest.manifest_version == 2
    assert manifest.hook_tools == ("ingest",)
    assert set(manifest.agent_tools) == {"verify", "reader-slot"}
    assert manifest.surface_tools == ()
    assert manifest.tool_contexts("ingest") == frozenset({"hook"})
    for name in manifest.agent_tools:
        assert manifest.tool_contexts(name) == frozenset({"agent"})


def test_ingest_is_registered_on_every_hook_of_the_catalog(tmp_path: Path) -> None:
    hooks = _filled(tmp_path).hooks
    assert hooks is not None
    registered = {
        (reg["catalog_id"], reg["catalog_version"], reg["hook"], reg["tool"])
        for reg in hooks["registrations"]
    }
    assert registered == {(CATALOG.id, CATALOG.version, hook, "ingest") for hook in CATALOG.hooks}
    assert hooks["productions"] == []


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


def test_kids_and_purposes_come_from_the_file_and_keys_from_configuration(
    tmp_path: Path,
) -> None:
    template_keys = {entry["kid"]: entry["purposes"] for entry in template()["app_keys"]}
    key_files = write_key_files(tmp_path)
    settings = LogsSettings(
        _env_file=None,
        database_url="postgresql://localhost/logs",
        public_origin=ORIGIN,
        app_key_files=key_files,
    )
    manifest = load_manifest(served_manifest(key_files, origin=ORIGIN))

    assert {kid: list(purposes) for kid, _, purposes in manifest.app_keys} == template_keys
    for purpose in (RECEIPT_PURPOSE, CHECKPOINT_PURPOSE, "hook-resolve"):
        key = load_app_key(settings, manifest, purpose)
        assert purpose in template_keys[key.kid]
        assert key.did_key == did_key_of(key_files[key.kid])


def test_delegated_verify_exposes_only_the_optional_epoch_selector(tmp_path: Path) -> None:
    manifest = _filled(tmp_path)
    verify = manifest.tools_by_name()["verify"]
    assert (verify["method"], verify["path"], verify["mutation"]) == ("POST", "/v1/integrity", False)
    assert list(verify["scopes"]) == ["logs.verify"]
    assert verify["body"]["mode"] == "json"
    assert tool_params(verify) == ([], ["chain_epoch"])
    assert set(verify["input_schema"]["properties"]) == {"chain_epoch"}
    epoch = verify["input_schema"]["properties"]["chain_epoch"]
    assert epoch["type"] == "integer" and epoch["minimum"] == 1
    assert verify["input_schema"]["additionalProperties"] is False
    assert list(verify["params"]) == [{"name": "chain_epoch", "in": "body"}]
    assert verify.get("auth") != "none"


def test_reader_slot_takes_only_the_required_contact_commitment(tmp_path: Path) -> None:
    slot = _filled(tmp_path).tools_by_name()["reader-slot"]
    assert (slot["method"], slot["path"], slot["mutation"]) == ("POST", "/v1/reader-slots", True)
    assert list(slot["scopes"]) == ["logs.readers"]
    assert slot["body"]["mode"] == "json"
    assert tool_params(slot) == (["contact_sha256"], [])
    assert set(slot["input_schema"]["properties"]) == {"contact_sha256"}
    assert slot["input_schema"]["additionalProperties"] is False
    assert list(slot["params"]) == [{"name": "contact_sha256", "in": "body"}]
    assert slot.get("auth") != "none"
