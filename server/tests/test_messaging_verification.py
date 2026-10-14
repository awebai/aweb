from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from nacl.signing import SigningKey

from awid.did import did_from_public_key, generate_keypair, stable_id_from_public_key
from awid.e2ee_keys import build_encryption_key_assertion
from awid.signing import canonical_json_bytes, sign_message
from aweb.e2ee_messages import encrypt_e2ee_chat, generate_x25519_keypair
from aweb.messaging.verification import message_verification_status


def _make_keypair():
    sk = SigningKey.generate()
    pk = bytes(sk.verify_key)
    return bytes(sk), did_from_public_key(pk)


def test_message_verification_uses_signed_payload_did_when_row_has_stable_did():
    sender_sk, sender_did_key = _make_keypair()
    sender_did_aw = "did:aw:alice-stable"
    recipient_did_key = "did:key:z6MkBobCurrent"
    recipient_did_aw = "did:aw:bob-stable"
    conversation_id = str(uuid4())
    message_id = str(uuid4())
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    signed_payload = canonical_json_bytes(
        {
            "body": "hello",
            "conversation_id": conversation_id,
            "from": "myco/alice",
            "from_did": sender_did_key,
            "from_stable_id": sender_did_aw,
            "message_id": message_id,
            "subject": "stable sender row",
            "timestamp": timestamp,
            "to": "otherco/bob",
            "to_did": recipient_did_key,
            "to_stable_id": recipient_did_aw,
            "type": "mail",
        }
    )

    status = message_verification_status(
        {
            "message_id": message_id,
            "conversation_id": conversation_id,
            "from_did": sender_did_aw,
            "to_did": recipient_did_aw,
            "signature": sign_message(sender_sk, signed_payload),
            "signed_payload": signed_payload.decode(),
        }
    )

    assert status == "verified"


def _envelope_identity(name: str) -> dict:
    signing_key, public_key = generate_keypair()
    did = did_from_public_key(public_key)
    stable_id = stable_id_from_public_key(public_key)
    e2ee_private, e2ee_public = generate_x25519_keypair()
    return {
        "address": f"example.com/{name}",
        "did": did,
        "stable_id": stable_id,
        "team_id": "dev:example.com",
        "signing_key": signing_key,
        "private_key": e2ee_private,
        "encryption_key": build_encryption_key_assertion(
            signing_key=signing_key,
            identity_did=did,
            identity_stable_id=stable_id,
            encryption_public_key=e2ee_public,
            custody="self",
            now=datetime.now(timezone.utc),
        ),
    }


def _encrypted_chat_row() -> dict:
    alice = _envelope_identity("alice")
    bob = _envelope_identity("bob")
    message_id = str(uuid4())
    conversation_id = str(uuid4())
    envelope = encrypt_e2ee_chat(
        sender=alice,
        recipients=[{key: bob[key] for key in ("address", "did", "stable_id", "team_id", "encryption_key")}],
        body="sealed",
        message_id=message_id,
        conversation_id=conversation_id,
    )
    return {
        "message_id": message_id,
        "conversation_id": conversation_id,
        "from_did": alice["did"],
        "signature": None,
        "signed_payload": None,
        "content_mode": "encrypted_v2",
        "encrypted_envelope": envelope,
    }


def test_encrypted_message_with_a_valid_envelope_signature_is_verified():
    row = _encrypted_chat_row()

    assert message_verification_status(row) == "verified"
    assert message_verification_status({**row, "encrypted_envelope": json.dumps(row["encrypted_envelope"])}) == "verified"
    assert message_verification_status({**row, "from_did": row["encrypted_envelope"]["from"]["stable_id"]}) == "verified"


def test_encrypted_message_with_a_tampered_envelope_fails():
    row = _encrypted_chat_row()
    tampered = deepcopy(row["encrypted_envelope"])
    tampered["ciphertext"] = tampered["ciphertext"][:-4] + "AAAA"

    assert message_verification_status({**row, "encrypted_envelope": tampered}) == "failed"
    assert message_verification_status({**row, "encrypted_envelope": "{not json"}) == "failed"


@pytest.mark.parametrize("field", ["message_id", "conversation_id", "from_did"])
def test_encrypted_message_whose_envelope_belongs_to_another_row_fails(field):
    row = _encrypted_chat_row()
    other = str(uuid4()) if field != "from_did" else _envelope_identity("mallory")["did"]

    assert message_verification_status({**row, field: other}) == "failed"


@pytest.mark.parametrize("envelope", [None, {}, ""])
def test_encrypted_message_without_an_envelope_is_unverified(envelope):
    row = _encrypted_chat_row()

    assert message_verification_status({**row, "encrypted_envelope": envelope}) == "unverified"
