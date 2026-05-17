from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from awid.did import did_from_public_key, generate_keypair, stable_id_from_did_key
from awid.signing import canonical_json_bytes, sign_message
from aweb.federation.envelope import (
    FederationEnvelopeError,
    require_team_certificate_for_non_public_reachability,
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
        "sender_active_team_id": "default:alpha.example",
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
    assert verified.sender_active_team_id == "default:alpha.example"


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


def test_verify_federation_envelope_rejects_invalid_signature():
    signing_key, public_key = generate_keypair()
    sender_did_key = did_from_public_key(public_key)
    other_key, _ = generate_keypair()
    envelope = _envelope(sender_did_key)
    signature = _sign(envelope, other_key)

    with pytest.raises(FederationEnvelopeError, match="Invalid federation message signature"):
        verify_federation_envelope(envelope, signature)


def test_verify_federation_envelope_rejects_stale_timestamp():
    signing_key, public_key = generate_keypair()
    sender_did_key = did_from_public_key(public_key)
    envelope = _envelope(sender_did_key) | {"timestamp": _timestamp(-600)}
    signature = _sign(envelope, signing_key)

    with pytest.raises(FederationEnvelopeError, match="timestamp outside accepted skew"):
        verify_federation_envelope(envelope, signature)


def test_non_public_reachability_requires_carried_team_certificate():
    signing_key, public_key = generate_keypair()
    sender_did_key = did_from_public_key(public_key)
    envelope = _envelope(sender_did_key)
    signature = _sign(envelope, signing_key)
    verified = verify_federation_envelope(envelope, signature)

    with pytest.raises(FederationEnvelopeError, match="missing sender_team_certificate"):
        require_team_certificate_for_non_public_reachability(
            verified,
            reachability="team_members_only",
        )

    envelope["sender_team_certificate"] = {
        "version": 1,
        "team_id": "default:alpha.example",
        "certificate_id": "cert-1",
    }
    signature = _sign(envelope, signing_key)
    verified = verify_federation_envelope(envelope, signature)

    require_team_certificate_for_non_public_reachability(
        verified,
        reachability="team_members_only",
    )
