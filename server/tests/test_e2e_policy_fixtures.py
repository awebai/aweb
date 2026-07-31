from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
E2E_FIXTURE_DIR = ROOT / "test-vectors" / "e2e"
CONSUMED_POLICY_FIXTURES = {
    "legacy-plaintext-migration-v1.json",
    "metadata-only-usage-v1.json",
    "mixed-version-rollout-v1.json",
}


def _fixture(name: str) -> dict:
    assert name in CONSUMED_POLICY_FIXTURES
    return json.loads((E2E_FIXTURE_DIR / name).read_text(encoding="utf-8"))


def _object_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {
            key
            for child_key, child in value.items()
            if child_key != "forbidden_plaintext_fields"
            for key in _object_keys(child)
        }
    if isinstance(value, list):
        return {key for child in value for key in _object_keys(child)}
    return set()


def test_e2e_policy_fixture_census_is_fully_consumed():
    assert {
        path.name for path in E2E_FIXTURE_DIR.glob("*.json")
    } == CONSUMED_POLICY_FIXTURES


def test_legacy_plaintext_policy_fixture_pins_no_downgrade_vocabulary():
    fixture = _fixture("legacy-plaintext-migration-v1.json")

    assert fixture["stored_content_modes"] == ["legacy_plaintext_v1", "encrypted_v2"]
    assert fixture["hosted_boundary_label"] == "server_readable_hosted"
    assert "server-readable" in fixture["legacy_display_label"]
    assert fixture["explicit_plaintext_escape_hatch"] == "--plaintext"
    assert fixture["deprecated_plaintext_alias"] == "--legacy-plaintext"

    cases = {case["name"]: case for case in fixture["downgrade_cases"]}
    for name in [
        "missing_recipient_key",
        "stale_recipient_key",
        "old_server_no_v2_route",
    ]:
        assert cases[name]["result"] == "reject"
        assert cases[name]["legacy_plaintext_allowed_without_explicit_flag"] is False

    assert cases["explicit_legacy_plaintext"]["requires_flag"] == "--plaintext"
    assert cases["hosted_server_readable"]["must_not_call_e2ee"] is True


def test_encrypted_read_fixture_excludes_plaintext_fields():
    fixture = _fixture("legacy-plaintext-migration-v1.json")
    encrypted = fixture["encrypted_read_response"]

    assert encrypted["content_mode"] == "encrypted_v2"
    assert encrypted["message_version"] == 2
    for field in fixture["forbidden_encrypted_response_fields"]:
        assert field not in encrypted


def test_operational_metadata_fixture_uses_current_mode_and_excludes_plaintext():
    fixture = _fixture("metadata-only-usage-v1.json")

    assert fixture["message"]["content_mode"] == "encrypted_v2"
    assert set(fixture["forbidden_plaintext_fields"]).isdisjoint(_object_keys(fixture))


def test_mixed_version_rollout_fixture_is_complete_and_explicitly_non_current():
    fixture = _fixture("mixed-version-rollout-v1.json")

    assert fixture["status"] == "rollout_requirements_not_current_capability_inventory"
    assert {
        "new_sender_new_recipient_new_server",
        "new_sender_old_recipient_missing_key",
        "new_client_old_server",
        "duplicate_message_id_same_signed_envelope",
        "duplicate_message_id_different_signed_envelope",
        "stale_timestamp_at_ingestion",
        "rollback_after_v2_messages_exist",
    } <= {case["id"] for case in fixture["cases"]}
    assert all(case["release_blocker"] is True for case in fixture["cases"])
    assert all(case["plaintext_fallback_allowed"] is False for case in fixture["cases"])
    assert fixture["legacy_plaintext_naming"]["current_cli_flag"] == "--plaintext"
    assert (
        fixture["legacy_plaintext_naming"]["deprecated_cli_alias"]
        == "--legacy-plaintext"
    )
    for path in fixture["contract_docs"]:
        assert (ROOT / path).is_file(), path
