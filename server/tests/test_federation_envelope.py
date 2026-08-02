from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from awid.did import did_from_public_key, generate_keypair, stable_id_from_did_key
from awid.signing import canonical_json_bytes, sign_message
from aweb.federation.envelope import (
    FederationEnvelopeError,
    enforce_message_timestamp_skew,
    verify_federation_envelope,
)


def _timestamp(offset_seconds: int = 0) -> str:
    return (
        (datetime.now(timezone.utc).replace(microsecond=0) + timedelta(seconds=offset_seconds))
        .isoformat()
        .replace("+00:00", "Z")
    )


def _envelope(sender_did_key: str) -> dict:
    target_did_key = "did:key:z6Mktarget"
    message_id = str(uuid4())
    timestamp = _timestamp()
    conversation_id = str(uuid4())
    signed_payload = canonical_json_bytes(
        {
            "body": "hello",
            "conversation_id": conversation_id,
            "from": "alpha.example/alice",
            "from_did": sender_did_key,
            "from_stable_id": stable_id_from_did_key(sender_did_key),
            "message_id": message_id,
            "subject": "Federation",
            "timestamp": timestamp,
            "to": "beta.example/bob",
            "to_did": target_did_key,
            "to_stable_id": "did:aw:target",
            "type": "mail",
        }
    ).decode()
    envelope = {
        "version": 1,
        "type": "mail",
        "sender_did_aw": stable_id_from_did_key(sender_did_key),
        "sender_current_did_key": sender_did_key,
        "sender_address": "alpha.example/alice",
        "target_address": "beta.example/bob",
        "target_did_aw": "did:aw:target",
        "target_current_did_key": target_did_key,
        "target_delivery_origin": "https://AWEB.BETA.EXAMPLE/",
        "body": "hello",
        "subject": "Federation",
        "priority": "normal",
        "message_id": message_id,
        "timestamp": timestamp,
        "signed_payload": signed_payload,
        "conversation_id": conversation_id,
    }
    return envelope


def _sign(envelope: dict, signing_key: bytes) -> str:
    return sign_message(signing_key, envelope["signed_payload"].encode())


def _deprecated_v1_fields() -> dict:
    return {
        "sender_active_team_id": "backend:alpha.example",
        "sender_team_certificate": {
            "team_id": "backend:alpha.example",
            "member_did": "did:aw:alice",
            "signature": "deprecated-and-ignored",
        },
        "target_address_lookup_authorization": "Bearer deprecated-private-lookup-token",
        "target_address_lookup_timestamp": _timestamp(),
    }


def test_verify_federation_envelope_accepts_signed_mail_payload():
    signing_key, public_key = generate_keypair()
    sender_did_key = did_from_public_key(public_key)
    envelope = _envelope(sender_did_key)
    signature = _sign(envelope, signing_key)

    verified = verify_federation_envelope(
        envelope,
        signature,
        expected={
            "type": "mail",
            "target_address": "beta.example/bob",
            "target_did_aw": "did:aw:target",
            "target_current_did_key": "did:key:z6Mktarget",
            "target_delivery_origin": "https://aweb.beta.example",
            "body": "hello",
            "message_id": envelope["message_id"],
            "conversation_id": envelope["conversation_id"],
        },
    )

    assert verified.target_delivery_origin == "https://aweb.beta.example"


def test_verify_federation_envelope_rejects_non_base64_message_signature_shape():
    signing_key, public_key = generate_keypair()
    sender_did_key = did_from_public_key(public_key)
    envelope = _envelope(sender_did_key)
    signature = _sign(envelope, signing_key) + "!!!!"

    with pytest.raises(FederationEnvelopeError, match="signature must be valid base64"):
        verify_federation_envelope(envelope, signature)


def test_verify_federation_envelope_accepts_deprecated_v1_fields_as_ignored_compatibility():
    signing_key, public_key = generate_keypair()
    sender_did_key = did_from_public_key(public_key)
    envelope = _envelope(sender_did_key) | _deprecated_v1_fields()
    signature = _sign(envelope, signing_key)

    verified = verify_federation_envelope(envelope, signature)

    assert verified.sender_active_team_id == "backend:alpha.example"
    assert verified.sender_team_certificate is not None
    assert verified.target_address_lookup_authorization is not None
    assert verified.target_address_lookup_timestamp is not None
    assert verified.target_did_aw == "did:aw:target"


def test_verify_federation_envelope_still_forbids_other_unknown_fields():
    signing_key, public_key = generate_keypair()
    sender_did_key = did_from_public_key(public_key)
    envelope = _envelope(sender_did_key) | {"unexpected_legacy_field": "nope"}
    signature = _sign(envelope, signing_key)

    with pytest.raises(ValidationError):
        verify_federation_envelope(envelope, signature)


def test_deprecated_sender_team_certificate_does_not_authorize_unbound_payload():
    signing_key, public_key = generate_keypair()
    sender_did_key = did_from_public_key(public_key)
    envelope = _envelope(sender_did_key) | _deprecated_v1_fields()
    signed_payload = canonical_json_bytes(
        {
            "body": "hello",
            "conversation_id": envelope["conversation_id"],
            "from": "alpha.example/alice",
            "from_did": sender_did_key,
            "from_stable_id": stable_id_from_did_key(sender_did_key),
            "message_id": envelope["message_id"],
            "subject": "Federation",
            "timestamp": envelope["timestamp"],
            "to": "did:aw:mallory",
            "to_did": envelope["target_current_did_key"],
            "to_stable_id": envelope["target_did_aw"],
            "type": "mail",
        }
    ).decode()
    envelope["signed_payload"] = signed_payload
    signature = _sign(envelope, signing_key)

    with pytest.raises(FederationEnvelopeError, match="to does not match"):
        verify_federation_envelope(envelope, signature)


@pytest.mark.parametrize("signed_to", ["did:aw:target", "did:key:z6Mktarget"])
def test_verify_federation_envelope_accepts_identity_bound_continuation_to(signed_to):
    signing_key, public_key = generate_keypair()
    sender_did_key = did_from_public_key(public_key)
    envelope = _envelope(sender_did_key)
    signed_payload = canonical_json_bytes(
        {
            "body": "hello",
            "conversation_id": envelope["conversation_id"],
            "from": "alpha.example/alice",
            "from_did": sender_did_key,
            "from_stable_id": stable_id_from_did_key(sender_did_key),
            "message_id": envelope["message_id"],
            "subject": "Federation",
            "timestamp": envelope["timestamp"],
            "to": signed_to,
            "to_did": envelope["target_current_did_key"],
            "to_stable_id": envelope["target_did_aw"],
            "type": "mail",
        }
    ).decode()
    envelope["signed_payload"] = signed_payload
    signature = _sign(envelope, signing_key)

    verified = verify_federation_envelope(envelope, signature)

    assert verified.target_address == "beta.example/bob"
    assert verified.target_did_aw == "did:aw:target"


def test_verify_federation_envelope_accepts_stable_signed_to_did():
    signing_key, public_key = generate_keypair()
    sender_did_key = did_from_public_key(public_key)
    envelope = _envelope(sender_did_key)
    signed_payload = canonical_json_bytes(
        {
            "body": "hello",
            "conversation_id": envelope["conversation_id"],
            "from": "alpha.example/alice",
            "from_did": sender_did_key,
            "from_stable_id": stable_id_from_did_key(sender_did_key),
            "message_id": envelope["message_id"],
            "subject": "Federation",
            "timestamp": envelope["timestamp"],
            "to": envelope["target_did_aw"],
            "to_did": envelope["target_did_aw"],
            "to_stable_id": envelope["target_did_aw"],
            "type": "mail",
        }
    ).decode()
    envelope["signed_payload"] = signed_payload
    signature = _sign(envelope, signing_key)

    verified = verify_federation_envelope(envelope, signature)

    assert verified.target_current_did_key == "did:key:z6Mktarget"
    assert verified.target_did_aw == "did:aw:target"


def test_verify_federation_envelope_accepts_stored_route_stable_binding_without_to_did():
    signing_key, public_key = generate_keypair()
    sender_did_key = did_from_public_key(public_key)
    envelope = _envelope(sender_did_key)
    signed_payload = canonical_json_bytes(
        {
            "body": "hello",
            "conversation_id": envelope["conversation_id"],
            "from": "alpha.example/alice",
            "from_did": sender_did_key,
            "from_stable_id": stable_id_from_did_key(sender_did_key),
            "message_id": envelope["message_id"],
            "subject": "Federation",
            "timestamp": envelope["timestamp"],
            "to": envelope["target_did_aw"],
            "to_did": "",
            "to_stable_id": envelope["target_did_aw"],
            "type": "mail",
        }
    ).decode()
    envelope["signed_payload"] = signed_payload
    signature = _sign(envelope, signing_key)

    verified = verify_federation_envelope(envelope, signature)

    assert verified.target_current_did_key == "did:key:z6Mktarget"
    assert verified.target_did_aw == "did:aw:target"


def test_verify_federation_envelope_rejects_unbound_signed_to():
    signing_key, public_key = generate_keypair()
    sender_did_key = did_from_public_key(public_key)
    envelope = _envelope(sender_did_key)
    signed_payload = canonical_json_bytes(
        {
            "body": "hello",
            "conversation_id": envelope["conversation_id"],
            "from": "alpha.example/alice",
            "from_did": sender_did_key,
            "from_stable_id": stable_id_from_did_key(sender_did_key),
            "message_id": envelope["message_id"],
            "subject": "Federation",
            "timestamp": envelope["timestamp"],
            "to": "did:aw:mallory",
            "to_did": envelope["target_current_did_key"],
            "to_stable_id": envelope["target_did_aw"],
            "type": "mail",
        }
    ).decode()
    envelope["signed_payload"] = signed_payload
    signature = _sign(envelope, signing_key)

    with pytest.raises(FederationEnvelopeError, match="to does not match"):
        verify_federation_envelope(envelope, signature)


def test_verify_federation_envelope_rejects_unbound_signed_to_did():
    signing_key, public_key = generate_keypair()
    sender_did_key = did_from_public_key(public_key)
    envelope = _envelope(sender_did_key)
    signed_payload = canonical_json_bytes(
        {
            "body": "hello",
            "conversation_id": envelope["conversation_id"],
            "from": "alpha.example/alice",
            "from_did": sender_did_key,
            "from_stable_id": stable_id_from_did_key(sender_did_key),
            "message_id": envelope["message_id"],
            "subject": "Federation",
            "timestamp": envelope["timestamp"],
            "to": envelope["target_did_aw"],
            "to_did": "did:aw:mallory",
            "to_stable_id": envelope["target_did_aw"],
            "type": "mail",
        }
    ).decode()
    envelope["signed_payload"] = signed_payload
    signature = _sign(envelope, signing_key)

    with pytest.raises(FederationEnvelopeError, match="to_did does not match"):
        verify_federation_envelope(envelope, signature)


def test_verify_federation_envelope_rejects_malformed_signed_to_cleanly():
    signing_key, public_key = generate_keypair()
    sender_did_key = did_from_public_key(public_key)
    envelope = _envelope(sender_did_key)
    signed_payload = canonical_json_bytes(
        {
            "body": "hello",
            "conversation_id": envelope["conversation_id"],
            "from": "alpha.example/alice",
            "from_did": sender_did_key,
            "from_stable_id": stable_id_from_did_key(sender_did_key),
            "message_id": envelope["message_id"],
            "subject": "Federation",
            "timestamp": envelope["timestamp"],
            "to": [],
            "to_did": envelope["target_current_did_key"],
            "to_stable_id": envelope["target_did_aw"],
            "type": "mail",
        }
    ).decode()
    envelope["signed_payload"] = signed_payload
    signature = _sign(envelope, signing_key)

    with pytest.raises(FederationEnvelopeError, match="to does not match"):
        verify_federation_envelope(envelope, signature)


def test_verify_federation_envelope_rejects_behavior_field_mismatch():
    signing_key, public_key = generate_keypair()
    sender_did_key = did_from_public_key(public_key)
    envelope = _envelope(sender_did_key)
    signature = _sign(envelope, signing_key)

    with pytest.raises(FederationEnvelopeError, match="body does not match"):
        verify_federation_envelope(envelope, signature, expected={"body": "changed"})


def test_verify_federation_envelope_rejects_sender_address_mismatch():
    signing_key, public_key = generate_keypair()
    sender_did_key = did_from_public_key(public_key)
    envelope = _envelope(sender_did_key) | {"sender_address": "alpha.example/mallory"}
    signature = _sign(envelope, signing_key)

    with pytest.raises(FederationEnvelopeError, match="from does not match"):
        verify_federation_envelope(envelope, signature)


def test_verify_federation_envelope_uses_signed_address_when_wrapper_is_absent():
    signing_key, public_key = generate_keypair()
    sender_did_key = did_from_public_key(public_key)
    envelope = _envelope(sender_did_key)
    envelope.pop("sender_address")
    signature = _sign(envelope, signing_key)

    verified = verify_federation_envelope(envelope, signature)

    assert verified.sender_address == "alpha.example/alice"


def test_verify_federation_envelope_rejects_invalid_signature():
    signing_key, public_key = generate_keypair()
    sender_did_key = did_from_public_key(public_key)
    other_key, _ = generate_keypair()
    envelope = _envelope(sender_did_key)
    signature = _sign(envelope, other_key)

    with pytest.raises(FederationEnvelopeError, match="Invalid federation message signature"):
        verify_federation_envelope(envelope, signature)


def test_message_timestamp_skew_window_is_exactly_300_seconds():
    now = datetime(2026, 7, 25, 12, 0, tzinfo=timezone.utc)

    enforce_message_timestamp_skew(now - timedelta(seconds=300), now=now)
    enforce_message_timestamp_skew(now + timedelta(seconds=300), now=now)
    with pytest.raises(FederationEnvelopeError, match="timestamp outside accepted skew"):
        enforce_message_timestamp_skew(now - timedelta(seconds=301), now=now)
    with pytest.raises(FederationEnvelopeError, match="timestamp outside accepted skew"):
        enforce_message_timestamp_skew(now + timedelta(seconds=301), now=now)


def test_verify_federation_envelope_rejects_stale_timestamp():
    signing_key, public_key = generate_keypair()
    sender_did_key = did_from_public_key(public_key)
    envelope = _envelope(sender_did_key) | {"timestamp": _timestamp(-600)}
    signature = _sign(envelope, signing_key)

    with pytest.raises(FederationEnvelopeError, match="timestamp outside accepted skew"):
        verify_federation_envelope(envelope, signature)
