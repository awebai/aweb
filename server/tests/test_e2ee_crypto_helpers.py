from __future__ import annotations

import base64
import json
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

import pytest

from awid.did import did_from_public_key, generate_keypair, stable_id_from_public_key
from awid.e2ee_keys import build_encryption_key_assertion
from aweb.e2ee_messages import (
    E2EEEnvelopeError,
    decrypt_e2ee_message,
    encrypt_e2ee_chat,
    encrypt_e2ee_mail,
    generate_x25519_keypair,
)


_ROOT = Path(__file__).resolve().parents[2]
_CROSS_LANGUAGE_VECTOR = _ROOT / "docs" / "vectors" / "e2ee-v2-cross-language.json"


def _raw_b64_decode(value: str) -> bytes:
    return base64.b64decode(value + "=" * (-len(value) % 4), validate=True)


def _identity(name: str) -> dict:
    signing_key, public_key = generate_keypair()
    did = did_from_public_key(public_key)
    stable_id = stable_id_from_public_key(public_key)
    e2ee_private, e2ee_public = generate_x25519_keypair()
    now = datetime(2026, 5, 27, 12, 0, 0, tzinfo=timezone.utc)
    assertion = build_encryption_key_assertion(
        signing_key=signing_key,
        identity_did=did,
        identity_stable_id=stable_id,
        encryption_public_key=e2ee_public,
        custody="self",
        now=now,
    )
    return {
        "address": f"example.com/{name}",
        "did": did,
        "stable_id": stable_id,
        "team_id": "dev:example.com",
        "signing_key": signing_key,
        "private_key": e2ee_private,
        "encryption_key": assertion,
    }


def _recipient(identity: dict) -> dict:
    return {
        "address": identity["address"],
        "did": identity["did"],
        "stable_id": identity["stable_id"],
        "team_id": identity["team_id"],
        "encryption_key": identity["encryption_key"],
    }


def _decrypt_identity(identity: dict) -> dict:
    return {
        "address": identity["address"],
        "did": identity["did"],
        "stable_id": identity["stable_id"],
        "encryption_key_id": identity["encryption_key"]["encryption_key_id"],
        "private_key": identity["private_key"],
    }


def test_python_decrypts_go_encrypted_v2_fixture():
    fixture = json.loads(_CROSS_LANGUAGE_VECTOR.read_text(encoding="utf-8"))
    bob = fixture["identities"]["bob"]

    plain = decrypt_e2ee_message(
        fixture["go_mail_envelope"],
        {
            "address": bob["address"],
            "did": bob["did"],
            "stable_id": bob["stable_id"],
            "encryption_key_id": bob["encryption_key"]["encryption_key_id"],
            "private_key": _raw_b64_decode(bob["x25519_private"]),
        },
    )

    assert plain["subject"] == "go fixture subject"
    assert plain["body"] == "go fixture body"
    assert "go fixture body" not in str(fixture["go_mail_envelope"])
    assert bob["encryption_key"]["custody"] == "self"


def test_python_encrypt_decrypt_e2ee_mail_round_trip():
    alice = _identity("alice")
    bob = _identity("bob")
    env = encrypt_e2ee_mail(
        sender=alice,
        recipients=[_recipient(bob)],
        subject="secret subject",
        body="secret body",
        message_id="00000000-0000-0000-0000-000000000001",
        conversation_id="00000000-0000-0000-0000-000000000002",
        created_at=datetime(2026, 5, 27, 12, 1, 0, tzinfo=timezone.utc),
    )

    assert env["kind"] == "mail"
    assert env["ciphertext"]
    assert env["crypto"]["ciphertext_hash"].startswith("sha256:")
    assert "secret body" not in str(env)
    assert env["recipients"][0]["wrap_id"]

    bob_plain = decrypt_e2ee_message(env, _decrypt_identity(bob))
    assert bob_plain["subject"] == "secret subject"
    assert bob_plain["body"] == "secret body"

    alice_plain = decrypt_e2ee_message(env, _decrypt_identity(alice))
    assert alice_plain["body"] == "secret body"


def test_python_encrypt_decrypt_e2ee_chat_group_round_trip():
    alice = _identity("alice")
    bob = _identity("bob")
    carol = _identity("carol")
    env = encrypt_e2ee_chat(
        sender=alice,
        recipients=[_recipient(bob), _recipient(carol)],
        body="group secret",
        message_id="00000000-0000-0000-0000-000000000011",
        conversation_id="00000000-0000-0000-0000-000000000012",
        created_at=datetime(2026, 5, 27, 12, 2, 0, tzinfo=timezone.utc),
    )

    assert env["kind"] == "chat"
    assert len([wrap for wrap in env["key_wraps"] if wrap["wrap_purpose"] == "delivery"]) == 2
    assert len([wrap for wrap in env["key_wraps"] if wrap["wrap_purpose"] == "sender_copy"]) == 1
    assert decrypt_e2ee_message(env, _decrypt_identity(bob))["body"] == "group secret"
    assert decrypt_e2ee_message(env, _decrypt_identity(carol))["body"] == "group secret"


def test_python_decrypt_rejects_wrong_recipient_and_tampering():
    alice = _identity("alice")
    bob = _identity("bob")
    carol = _identity("carol")
    env = encrypt_e2ee_mail(
        sender=alice,
        recipients=[_recipient(bob)],
        subject="secret subject",
        body="secret body",
        message_id="00000000-0000-0000-0000-000000000021",
        conversation_id="00000000-0000-0000-0000-000000000022",
        created_at=datetime(2026, 5, 27, 12, 3, 0, tzinfo=timezone.utc),
    )

    with pytest.raises(E2EEEnvelopeError, match="not a recipient"):
        decrypt_e2ee_message(env, _decrypt_identity(carol))

    tampered = deepcopy(env)
    tampered["ciphertext"] = tampered["ciphertext"][:-1] + (
        "A" if tampered["ciphertext"][-1] != "A" else "B"
    )
    with pytest.raises(E2EEEnvelopeError, match="invalid e2ee envelope signature"):
        decrypt_e2ee_message(tampered, _decrypt_identity(bob))

    tampered = deepcopy(env)
    tampered["key_wraps"][0]["recipient_encryption_key_id"] = alice["encryption_key"][
        "encryption_key_id"
    ]
    with pytest.raises(E2EEEnvelopeError, match="invalid e2ee envelope signature"):
        decrypt_e2ee_message(tampered, _decrypt_identity(bob))
