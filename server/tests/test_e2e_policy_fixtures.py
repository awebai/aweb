from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_legacy_plaintext_policy_fixture_pins_no_downgrade_vocabulary():
    fixture = json.loads(
        (ROOT / "test-vectors" / "e2e" / "legacy-plaintext-migration-v1.json").read_text(
            encoding="utf-8"
        )
    )

    assert fixture["content_modes"] == [
        "legacy_plaintext_v1",
        "encrypted_v2",
        "server_readable_hosted",
    ]
    assert "server-readable" in fixture["legacy_display_label"]
    assert fixture["explicit_legacy_escape_hatch"] == "--legacy-plaintext"

    cases = {case["name"]: case for case in fixture["downgrade_cases"]}
    for name in ["missing_recipient_key", "stale_recipient_key", "old_server_no_v2_route"]:
        assert cases[name]["result"] == "reject"
        assert cases[name]["legacy_plaintext_allowed_without_explicit_flag"] is False

    assert cases["explicit_legacy_plaintext"]["requires_flag"] == "--legacy-plaintext"
    assert cases["hosted_server_readable"]["must_not_call_e2ee"] is True


def test_encrypted_read_fixture_excludes_plaintext_fields():
    fixture = json.loads(
        (ROOT / "test-vectors" / "e2e" / "legacy-plaintext-migration-v1.json").read_text(
            encoding="utf-8"
        )
    )
    encrypted = fixture["encrypted_read_response"]

    assert encrypted["content_mode"] == "encrypted_v2"
    assert encrypted["message_version"] == 2
    for field in fixture["forbidden_encrypted_response_fields"]:
        assert field not in encrypted
