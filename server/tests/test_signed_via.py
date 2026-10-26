"""P1 uses the unchanged P0 bytes in the actual native composers and crypto."""

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from awid.signing import canonical_payload, sign_message, verify_signature, VerifyResult
from aweb.e2ee_messages import (
    E2EEEnvelopeError, _inner_header_hash, decrypt_e2ee_message,
    encrypt_e2ee_message,
)
from test_e2ee_crypto_helpers import _identity, _recipient, _decrypt_identity

ROOT = Path(__file__).resolve().parents[2]
VECTORS = json.loads((ROOT / "docs/vectors/human-channels-v1.json").read_text())
NATIVE = [c for c in VECTORS["valid"] if c["name"].startswith(("NativePlaintext_", "native_existing_"))]


@pytest.mark.parametrize("case", NATIVE, ids=lambda c: c["name"])
def test_native_composer_preserves_frozen_via_bytes(case):
    payload = canonical_payload(case["value"])
    assert payload.decode() == case["canonical"]
    signature = sign_message(bytes.fromhex(VECTORS["public_test_seed_hex"]), payload)
    assert signature == case["signature"]
    assert verify_signature(case["value"]["from_did"], payload, signature) == VerifyResult.VERIFIED
    changed = dict(case["value"], via="msteams" if case["value"].get("via") != "msteams" else "telegram")
    assert verify_signature(case["value"]["from_did"], canonical_payload(changed), signature) == VerifyResult.FAILED


@pytest.mark.parametrize("via", ["", None, "Telegram", "telegram:user", "a" * 33, {}, "telegram\n"])
def test_native_composer_refuses_malformed_supplied_via(via):
    with pytest.raises(ValueError):
        sign_message(bytes.fromhex(VECTORS["public_test_seed_hex"]), canonical_payload({"type": "mail", "via": via}))


@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("via", ["telegram", "msteams", "future_chat"])
def test_via_is_protected_inner_content_and_not_fixed_header(kind, via):
    alice, bob = _identity("alice"), _identity("bob")
    envelope = encrypt_e2ee_message(
        kind=kind, sender=alice, recipients=[_recipient(bob)],
        subject="subject", body="body", via=via,
        message_id="11111111-1111-4111-8111-111111111111",
        conversation_id="22222222-2222-4222-8222-222222222222",
        created_at=datetime(2026, 5, 27, 12, 1, tzinfo=timezone.utc),
    )
    assert "via" not in envelope
    plain = decrypt_e2ee_message(envelope, _decrypt_identity(bob))
    assert plain["via"] == via
    assert plain["body"] == "body"
    assert decrypt_e2ee_message(envelope, _decrypt_identity(alice)) == plain
    header = _inner_header_hash(plain)
    del plain["via"]
    assert _inner_header_hash(plain) == header


@pytest.mark.parametrize("via", ["", None, "Telegram", "telegram\n", {}])
def test_encryption_refuses_malformed_via_without_plaintext_retry(via):
    alice, bob = _identity("alice"), _identity("bob")
    with pytest.raises(E2EEEnvelopeError):
        encrypt_e2ee_message(
            kind="mail", sender=alice, recipients=[_recipient(bob)], body="body",
            via=via, message_id="11111111-1111-4111-8111-111111111111",
            conversation_id="22222222-2222-4222-8222-222222222222",
            created_at=datetime(2026, 5, 27, 12, 1, tzinfo=timezone.utc),
        )
