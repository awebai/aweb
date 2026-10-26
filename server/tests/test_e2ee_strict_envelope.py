"""Closed envelope validation uses real builders, crypto and trusted bindings."""

import base64
from copy import deepcopy
from datetime import datetime
import json
from pathlib import Path

import pytest

import aweb.e2ee_messages as e2ee


VECTOR = json.loads((
    Path(__file__).resolve().parents[2] / "docs/vectors/e2ee-v2-cross-language.json"
).read_text())
NOW = datetime.fromisoformat(VECTOR["python_mail_envelope"]["created_at"].replace("Z", "+00:00"))


def _decode(value):
    return base64.b64decode(value + "=" * (-len(value) % 4), validate=True)


def _build(monkeypatch, kind, *, addressless=True, body="Done"):
    sender, recipient = (deepcopy(VECTOR["identities"][name]) for name in ("alice", "bob"))
    sender["signing_key"] = _decode(sender["signing_seed"])
    if addressless:
        sender["address"] = ""  # includes the real signed sender_encryption_key
    # Fixed disposable CEK/nonce make collision preconditions deterministic.
    # HPKE, AES-GCM, hashes and Ed25519 still use their real implementations.
    original_random = e2ee.os.urandom
    nonce = _decode("DoneAAAAAAAAAAAA")
    monkeypatch.setattr(e2ee.os, "urandom", lambda size: (
        nonce if size == 12 else b"c" * 32 if size == 32 else original_random(size)
    ))
    message_id = "11111111-1111-4111-8111-111111111111"
    conversation_id = "22222222-2222-4222-8222-222222222222"
    envelope = e2ee.encrypt_e2ee_message(
        kind=kind, sender=sender, recipients=[recipient], body=body,
        subject=body if kind == "mail" else "",
        message_id=message_id, conversation_id=conversation_id, created_at=NOW,
    )
    expected = {
        "kind": kind, "message_id": message_id, "conversation_id": conversation_id,
        "sender_did": sender["did"], "sender_stable_id": sender["stable_id"],
        "recipients": [{key: recipient[key] for key in ("did", "stable_id", "address")}],
        "now": NOW,
    }
    decrypt_identity = {
        "address": recipient["address"], "did": recipient["did"], "stable_id": recipient["stable_id"],
        "encryption_key_id": recipient["encryption_key"]["encryption_key_id"],
        "private_key": _decode(recipient["x25519_private"]),
    }
    return envelope, expected, decrypt_identity


def _at(value, path):
    for component in path:
        value = value[component]
    return value


@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("addressless", [False, True])
def test_strict_validator_accepts_real_builder_output_without_changing_it(monkeypatch, kind, addressless):
    envelope, expected, identity = _build(monkeypatch, kind, addressless=addressless)
    original = deepcopy(envelope)
    assert ("sender_encryption_key" in envelope) is addressless
    assert envelope["routing"]["delivery_origin"] == ""
    e2ee.validate_strict_e2ee_message_envelope(envelope, **expected)
    assert envelope == original
    assert e2ee.decrypt_e2ee_message(envelope, identity)["body"] == "Done"


@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("path", [
    (), ("from",), ("recipients", 0), ("routing",), ("policy",), ("crypto",),
    ("key_wraps", 0), ("key_wraps", 1), ("sender_encryption_key",),
])
def test_strict_validator_refuses_unknown_fields_at_every_object(monkeypatch, kind, path):
    envelope, expected, _ = _build(monkeypatch, kind)
    _at(envelope, path)["unexpected_plaintext"] = {"body": "private text"}
    with pytest.raises(e2ee.E2EEEnvelopeError, match="unknown fields") as error:
        e2ee.validate_strict_e2ee_message_envelope(envelope, **expected)
    assert "private text" not in str(error.value)
    assert "unexpected_plaintext" not in str(error.value)


@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("path,replace", [
    (("message_version",), str),
    (("message_version",), float),
    (("message_version",), lambda _: True),
    (("crypto", "ciphertext_size"), str),
    (("crypto", "ciphertext_size"), float),
    (("from", "address"), lambda _: None),
    (("routing", "delivery_origin"), lambda _: False),
    (("recipients",), tuple),
    (("key_wraps",), tuple),
    (("key_wraps", 0), lambda _: []),
    (("key_wraps", 1, "recipient_address"), lambda _: []),
    (("sender_encryption_key", "created_at"), lambda _: NOW),
    (("sender_encryption_key",), lambda _: None),
    (("policy", "requires_e2ee"), lambda _: 1),
])
def test_strict_validator_never_coerces_field_types(monkeypatch, kind, path, replace):
    envelope, expected, _ = _build(monkeypatch, kind)
    parent = _at(envelope, path[:-1])
    parent[path[-1]] = replace(parent[path[-1]])
    with pytest.raises(e2ee.E2EEEnvelopeError, match="must (have type|be an (object|array))"):
        e2ee.validate_strict_e2ee_message_envelope(envelope, **expected)


@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("collision", ["nonce", "ciphertext"])
def test_strict_validator_allows_message_text_in_valid_binary_encodings(monkeypatch, kind, collision):
    body = "Done" if collision == "nonce" else "A"
    envelope, expected, identity = _build(monkeypatch, kind, body=body)
    # Ciphertext prefix excludes the tag, whose AAD includes random HPKE wraps.
    encoded = envelope["crypto"]["content_nonce"] if collision == "nonce" else envelope["ciphertext"][:-24]
    assert body in encoded
    e2ee.validate_strict_e2ee_message_envelope(envelope, **expected)
    assert e2ee.decrypt_e2ee_message(envelope, identity)["body"] == body


@pytest.mark.parametrize("kind", ["mail", "chat"])
@pytest.mark.parametrize("corruption", ["ciphertext", "signature", "binding"])
def test_strict_validator_keeps_crypto_and_trusted_binding_checks(monkeypatch, kind, corruption):
    envelope, expected, _ = _build(monkeypatch, kind)
    if corruption == "binding":
        expected["message_id"] = "33333333-3333-4333-8333-333333333333"
        reason = "message_id mismatch"
    elif corruption == "ciphertext":
        envelope["ciphertext"] = base64.b64encode(b"changed ciphertext with a tag").decode().rstrip("=")
        reason = "ciphertext hash mismatch"
    else:
        envelope["signature"] = ("A" if envelope["signature"][0] != "A" else "B") + envelope["signature"][1:]
        reason = "invalid encrypted envelope signature"
    with pytest.raises(e2ee.E2EEEnvelopeError, match=reason):
        e2ee.validate_strict_e2ee_message_envelope(envelope, **expected)


@pytest.mark.parametrize("kind", ["mail", "chat"])
def test_existing_validator_remains_compatible_for_released_callers(monkeypatch, kind):
    envelope, expected, _ = _build(monkeypatch, kind)
    envelope["message_version"] = str(envelope["message_version"])
    envelope["crypto"]["ciphertext_size"] = str(envelope["crypto"]["ciphertext_size"])
    envelope["body"] = "an unsigned extra field"
    e2ee.validate_e2ee_message_envelope(envelope, **expected)
    with pytest.raises(e2ee.E2EEEnvelopeError):
        e2ee.validate_strict_e2ee_message_envelope(envelope, **expected)
