from __future__ import annotations

import base64
import hashlib

from nacl.signing import SigningKey

from awid.did import did_from_public_key, stable_id_from_public_key
from awid.signing import canonical_json_bytes
from aweb.e2ee_messages import (
    E2EE_SUITE,
    E2EEEnvelopeError,
    _envelope_map,
    _hash_canonical,
    _key_wrap_map,
    validate_e2ee_mail_envelope,
)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).rstrip(b"=").decode("ascii")


def _hash(data: bytes) -> str:
    return "sha256:" + _b64(hashlib.sha256(data).digest())


def _signed_test_envelope():
    sender = SigningKey.generate()
    sender_pub = bytes(sender.verify_key)
    sender_did = did_from_public_key(sender_pub)
    sender_stable = stable_id_from_public_key(sender_pub)
    recipient = SigningKey.generate()
    recipient_pub = bytes(recipient.verify_key)
    recipient_did = did_from_public_key(recipient_pub)
    recipient_stable = stable_id_from_public_key(recipient_pub)

    ciphertext = b"opaque-ciphertext-with-tag"
    wrap = {
        "wrap_id": _hash(b"wrap-binding"),
        "recipient_stable_id": recipient_stable,
        "recipient_did": recipient_did,
        "recipient_address": "example.com/bob",
        "recipient_encryption_key_id": "sha256:" + _b64(b"r" * 32),
        "sender_encryption_key_id": "sha256:" + _b64(b"s" * 32),
        "sender_did": sender_did,
        "sender_stable_id": sender_stable,
        "wrap_purpose": "delivery",
        "algorithm": "hpke-base-x25519-hkdf-sha256-aes256gcm",
        "encapsulated_key": _b64(b"e" * 32),
        "wrapped_cek": _b64(b"wrapped"),
    }
    envelope = {
        "message_version": 2,
        "envelope_type": "aweb.e2ee.message",
        "kind": "mail",
        "message_id": "11111111-1111-4111-8111-111111111111",
        "conversation_id": "22222222-2222-4222-8222-222222222222",
        "created_at": "2026-05-26T12:00:00Z",
        "expires_at": "2026-05-26T12:05:00Z",
        "from": {
            "address": "example.com/alice",
            "did": sender_did,
            "stable_id": sender_stable,
            "encryption_key_id": "sha256:" + _b64(b"s" * 32),
        },
        "recipients": [
            {
                "address": "example.com/bob",
                "did": recipient_did,
                "stable_id": recipient_stable,
                "encryption_key_id": "sha256:" + _b64(b"r" * 32),
                "wrap_id": wrap["wrap_id"],
            }
        ],
        "routing": {
            "to": "example.com/bob",
            "to_did": recipient_did,
            "to_stable_id": recipient_stable,
            "sender_observed_inbound_mode": "open",
        },
        "policy": {
            "requires_e2ee": True,
            "legacy_plaintext_allowed": False,
        },
        "crypto": {
            "suite": E2EE_SUITE,
            "content_nonce": _b64(b"n" * 12),
            "ciphertext_hash": _hash(ciphertext),
            "ciphertext_size": len(ciphertext),
            "inner_header_hash": _hash(b"inner-header"),
            "key_wraps_hash": _hash_canonical("key_wraps", [_key_wrap_map(wrap)]),
        },
        "key_wraps": [wrap],
        "ciphertext": _b64(ciphertext),
        "signing_key_id": sender_did,
    }
    payload = canonical_json_bytes(
        _envelope_map(
            envelope,
            include_signature=False,
            include_ciphertext=True,
            include_ciphertext_hash=True,
        )
    )
    envelope["signature"] = _b64(sender.sign(payload).signature)
    return envelope, sender_did, sender_stable, recipient_did, recipient_stable


def test_validate_e2ee_mail_envelope_accepts_signed_opaque_content():
    envelope, sender_did, sender_stable, recipient_did, recipient_stable = _signed_test_envelope()

    validate_e2ee_mail_envelope(
        envelope,
        message_id=envelope["message_id"],
        conversation_id=envelope["conversation_id"],
        sender_did=sender_did,
        sender_stable_id=sender_stable,
        recipient_did=recipient_did,
        recipient_stable_id=recipient_stable,
        recipient_address="example.com/bob",
    )


def test_validate_e2ee_mail_envelope_recomputes_ciphertext_hash():
    envelope, sender_did, sender_stable, recipient_did, recipient_stable = _signed_test_envelope()
    envelope["ciphertext"] = _b64(b"other-ciphertext")

    try:
        validate_e2ee_mail_envelope(
            envelope,
            message_id=envelope["message_id"],
            conversation_id=envelope["conversation_id"],
            sender_did=sender_did,
            sender_stable_id=sender_stable,
            recipient_did=recipient_did,
            recipient_stable_id=recipient_stable,
            recipient_address="example.com/bob",
        )
    except E2EEEnvelopeError as exc:
        assert "ciphertext hash mismatch" in str(exc)
    else:
        raise AssertionError("expected ciphertext hash rejection")

