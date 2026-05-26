from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timedelta, timezone

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
    delivery_wrap = {
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
        "wrapped_cek": _b64(b"w" * 48),
    }
    sender_copy_wrap = {
        "wrap_id": _hash(b"sender-copy-wrap-binding"),
        "recipient_stable_id": sender_stable,
        "recipient_did": sender_did,
        "recipient_address": "example.com/alice",
        "recipient_encryption_key_id": "sha256:" + _b64(b"s" * 32),
        "sender_encryption_key_id": "sha256:" + _b64(b"s" * 32),
        "sender_did": sender_did,
        "sender_stable_id": sender_stable,
        "wrap_purpose": "sender_copy",
        "algorithm": "hpke-base-x25519-hkdf-sha256-aes256gcm",
        "encapsulated_key": _b64(b"E" * 32),
        "wrapped_cek": _b64(b"W" * 48),
    }
    created_at = datetime.now(timezone.utc).replace(microsecond=0)
    expires_at = created_at + timedelta(minutes=5)
    envelope = {
        "message_version": 2,
        "envelope_type": "aweb.e2ee.message",
        "kind": "mail",
        "message_id": "11111111-1111-4111-8111-111111111111",
        "conversation_id": "22222222-2222-4222-8222-222222222222",
        "created_at": created_at.isoformat().replace("+00:00", "Z"),
        "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
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
                "wrap_id": delivery_wrap["wrap_id"],
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
            "key_wraps_hash": _hash_canonical(
                "key_wraps",
                [_key_wrap_map(delivery_wrap), _key_wrap_map(sender_copy_wrap)],
            ),
        },
        "key_wraps": [delivery_wrap, sender_copy_wrap],
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


def _assert_rejects(envelope, sender_did, sender_stable, recipient_did, recipient_stable, expected: str):
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
        assert expected in str(exc)
    else:
        raise AssertionError(f"expected rejection containing {expected!r}")


def test_validate_e2ee_mail_envelope_rejects_downgrade_policy():
    envelope, sender_did, sender_stable, recipient_did, recipient_stable = _signed_test_envelope()
    envelope["policy"]["requires_e2ee"] = False
    _assert_rejects(envelope, sender_did, sender_stable, recipient_did, recipient_stable, "require e2ee")

    envelope, sender_did, sender_stable, recipient_did, recipient_stable = _signed_test_envelope()
    envelope["policy"]["legacy_plaintext_allowed"] = True
    _assert_rejects(envelope, sender_did, sender_stable, recipient_did, recipient_stable, "forbid legacy")


def test_validate_e2ee_mail_envelope_rejects_stale_timestamps():
    envelope, sender_did, sender_stable, recipient_did, recipient_stable = _signed_test_envelope()
    now = datetime.now(timezone.utc)
    envelope["created_at"] = (now - timedelta(minutes=10)).isoformat().replace("+00:00", "Z")
    envelope["expires_at"] = (now - timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
    _assert_rejects(envelope, sender_did, sender_stable, recipient_did, recipient_stable, "expired")

    envelope, sender_did, sender_stable, recipient_did, recipient_stable = _signed_test_envelope()
    envelope["expires_at"] = (datetime.now(timezone.utc) + timedelta(minutes=6)).isoformat().replace("+00:00", "Z")
    _assert_rejects(envelope, sender_did, sender_stable, recipient_did, recipient_stable, "expiration exceeds")


def test_validate_e2ee_mail_envelope_requires_strict_base64_and_wrap_shape():
    envelope, sender_did, sender_stable, recipient_did, recipient_stable = _signed_test_envelope()
    envelope["ciphertext"] = "%%%not-base64%%%"
    _assert_rejects(envelope, sender_did, sender_stable, recipient_did, recipient_stable, "invalid ciphertext")

    envelope, sender_did, sender_stable, recipient_did, recipient_stable = _signed_test_envelope()
    envelope["key_wraps"][0]["algorithm"] = "none"
    _assert_rejects(envelope, sender_did, sender_stable, recipient_did, recipient_stable, "unsupported algorithm")

    envelope, sender_did, sender_stable, recipient_did, recipient_stable = _signed_test_envelope()
    envelope["key_wraps"] = [envelope["key_wraps"][0]]
    _assert_rejects(envelope, sender_did, sender_stable, recipient_did, recipient_stable, "sender_copy")


def test_validate_e2ee_mail_envelope_requires_exact_recipient_binding():
    envelope, sender_did, sender_stable, recipient_did, recipient_stable = _signed_test_envelope()
    envelope["recipients"][0]["did"] = "did:key:wrong"
    _assert_rejects(envelope, sender_did, sender_stable, recipient_did, recipient_stable, "recipient did mismatch")

    envelope, sender_did, sender_stable, recipient_did, recipient_stable = _signed_test_envelope()
    envelope["key_wraps"][0]["recipient_encryption_key_id"] = "sha256:" + _b64(b"x" * 32)
    _assert_rejects(envelope, sender_did, sender_stable, recipient_did, recipient_stable, "recipient key mismatch")

    envelope, sender_did, sender_stable, recipient_did, recipient_stable = _signed_test_envelope()
    envelope["key_wraps"][1]["recipient_did"] = recipient_did
    _assert_rejects(envelope, sender_did, sender_stable, recipient_did, recipient_stable, "sender_copy recipient did")
