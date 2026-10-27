"""P1 uses the unchanged P0 bytes in the actual native composers and crypto."""

import json
import base64
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

import pytest

from awid.signing import canonical_payload, canonical_json_bytes, sign_message, verify_signature, VerifyResult
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
    if "via" in case["value"]:
        stripped = {key: value for key, value in case["value"].items() if key != "via"}
        assert verify_signature(case["value"]["from_did"], canonical_payload(stripped), signature) == VerifyResult.FAILED


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


CRYPTO = json.loads((ROOT / "docs/vectors/human-channels-signed-via-crypto-v1.json").read_text())
AGREEMENT = json.loads((ROOT / "docs/vectors/human-channels-signed-via-v1.json").read_text())


@pytest.mark.parametrize("case", AGREEMENT["cases"], ids=lambda c: c["name"])
def test_p1_signing_agrees_with_published_native_record(case):
    from aweb.human_channels import canonical_record, decode_record
    payload = canonical_payload(case["payload"])
    assert payload.decode() == case["signed_bytes"]
    assert sign_message(bytes.fromhex(AGREEMENT["public_test_seed_hex"]), payload) == case["signature"]
    record = decode_record("NativePlaintext", canonical_json_bytes(case["payload"]))
    assert canonical_record(record) == payload


@pytest.mark.parametrize("case", CRYPTO["cases"], ids=lambda c: f'{c["producer"]}/{c["kind"]}/{c["via"] or "absent"}')
def test_python_reads_both_native_crypto_producers(case):
    for alias in ("bob", "alice"):
        identity = CRYPTO["identities"][alias]
        reader = dict(identity, private_key=base64.b64decode(identity["x25519_private"] + "="),
                      encryption_key_id=identity["encryption_key"]["encryption_key_id"])
        plain = decrypt_e2ee_message(case["envelope"], reader)
        assert plain.get("via", "") == case["via"]
        assert plain["body"] == "P1 public test body"
        tampered = deepcopy(case["envelope"])
        ciphertext = tampered["ciphertext"]
        tampered["ciphertext"] = ("A" if ciphertext[0] != "A" else "B") + ciphertext[1:]
        with pytest.raises(E2EEEnvelopeError):
            decrypt_e2ee_message(tampered, reader)
