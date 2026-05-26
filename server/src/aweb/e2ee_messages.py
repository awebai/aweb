from __future__ import annotations

import base64
import hashlib
from typing import Any

from awid.signing import VerifyResult, canonical_json_bytes, verify_signature


E2EE_MESSAGE_VERSION = 2
E2EE_ENVELOPE_TYPE = "aweb.e2ee.message"
E2EE_SUITE = "aweb-e2ee-v2.x25519-hkdf-sha256-aes256gcm-ed25519"


class E2EEEnvelopeError(ValueError):
    pass


def _b64_raw_decode(value: str, *, field: str) -> bytes:
    try:
        return base64.b64decode(str(value or "") + "=" * (-len(str(value or "")) % 4))
    except Exception as exc:
        raise E2EEEnvelopeError(f"invalid {field}") from exc


def _hash_bytes(data: bytes) -> str:
    return "sha256:" + base64.b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")


def _non_empty(value: Any) -> str:
    return str(value or "").strip()


def _add_non_empty(out: dict[str, Any], key: str, value: Any) -> None:
    value = _non_empty(value)
    if value:
        out[key] = value


def _identity_ref_map(ref: dict[str, Any], *, include_key_id: bool) -> dict[str, Any]:
    out: dict[str, Any] = {}
    _add_non_empty(out, "address", ref.get("address"))
    _add_non_empty(out, "did", ref.get("did"))
    _add_non_empty(out, "stable_id", ref.get("stable_id"))
    _add_non_empty(out, "team_id", ref.get("team_id"))
    if include_key_id:
        _add_non_empty(out, "encryption_key_id", ref.get("encryption_key_id"))
    return out


def _recipient_ref_map(ref: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    _add_non_empty(out, "address", ref.get("address"))
    _add_non_empty(out, "did", ref.get("did"))
    _add_non_empty(out, "stable_id", ref.get("stable_id"))
    _add_non_empty(out, "team_id", ref.get("team_id"))
    _add_non_empty(out, "encryption_key_id", ref.get("encryption_key_id"))
    _add_non_empty(out, "wrap_id", ref.get("wrap_id"))
    return out


def _routing_map(routing: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    _add_non_empty(out, "to", routing.get("to"))
    _add_non_empty(out, "to_did", routing.get("to_did"))
    _add_non_empty(out, "to_stable_id", routing.get("to_stable_id"))
    _add_non_empty(out, "delivery_origin", routing.get("delivery_origin"))
    _add_non_empty(out, "sender_observed_inbound_mode", routing.get("sender_observed_inbound_mode"))
    return out


def _crypto_map(crypto: dict[str, Any], *, include_ciphertext_hash: bool) -> dict[str, Any]:
    out = {
        "suite": _non_empty(crypto.get("suite")),
        "content_nonce": _non_empty(crypto.get("content_nonce")),
        "ciphertext_size": int(crypto.get("ciphertext_size") or 0),
        "inner_header_hash": _non_empty(crypto.get("inner_header_hash")),
        "key_wraps_hash": _non_empty(crypto.get("key_wraps_hash")),
    }
    if include_ciphertext_hash:
        _add_non_empty(out, "ciphertext_hash", crypto.get("ciphertext_hash"))
    return out


def _key_wrap_map(wrap: dict[str, Any]) -> dict[str, Any]:
    out = {
        "wrap_id": _non_empty(wrap.get("wrap_id")),
        "recipient_encryption_key_id": _non_empty(wrap.get("recipient_encryption_key_id")),
        "sender_encryption_key_id": _non_empty(wrap.get("sender_encryption_key_id")),
        "sender_did": _non_empty(wrap.get("sender_did")),
        "wrap_purpose": _non_empty(wrap.get("wrap_purpose")),
        "algorithm": _non_empty(wrap.get("algorithm")),
        "encapsulated_key": _non_empty(wrap.get("encapsulated_key")),
        "wrapped_cek": _non_empty(wrap.get("wrapped_cek")),
    }
    _add_non_empty(out, "recipient_stable_id", wrap.get("recipient_stable_id"))
    _add_non_empty(out, "recipient_did", wrap.get("recipient_did"))
    _add_non_empty(out, "recipient_address", wrap.get("recipient_address"))
    _add_non_empty(out, "sender_stable_id", wrap.get("sender_stable_id"))
    return out


def _envelope_map(
    envelope: dict[str, Any],
    *,
    include_signature: bool,
    include_ciphertext: bool,
    include_ciphertext_hash: bool,
) -> dict[str, Any]:
    crypto = envelope.get("crypto")
    if not isinstance(crypto, dict):
        raise E2EEEnvelopeError("encrypted envelope crypto must be an object")
    policy = envelope.get("policy")
    if not isinstance(policy, dict):
        raise E2EEEnvelopeError("encrypted envelope policy must be an object")
    out: dict[str, Any] = {
        "message_version": int(envelope.get("message_version") or 0),
        "envelope_type": _non_empty(envelope.get("envelope_type")),
        "kind": _non_empty(envelope.get("kind")),
        "message_id": _non_empty(envelope.get("message_id")),
        "conversation_id": _non_empty(envelope.get("conversation_id")),
        "created_at": _non_empty(envelope.get("created_at")),
        "expires_at": _non_empty(envelope.get("expires_at")),
        "from": _identity_ref_map(envelope.get("from") or {}, include_key_id=True),
        "recipients": [_recipient_ref_map(item) for item in envelope.get("recipients") or []],
        "routing": _routing_map(envelope.get("routing") or {}),
        "policy": {
            "requires_e2ee": bool(policy.get("requires_e2ee")),
            "legacy_plaintext_allowed": bool(policy.get("legacy_plaintext_allowed")),
        },
        "crypto": _crypto_map(crypto, include_ciphertext_hash=include_ciphertext_hash),
        "key_wraps": [_key_wrap_map(item) for item in envelope.get("key_wraps") or []],
        "signing_key_id": _non_empty(envelope.get("signing_key_id")),
    }
    _add_non_empty(out, "reply_to_message_id", envelope.get("reply_to_message_id"))
    if include_ciphertext:
        out["ciphertext"] = _non_empty(envelope.get("ciphertext"))
    if include_signature:
        _add_non_empty(out, "signature", envelope.get("signature"))
    return out


def _hash_canonical(label: str, value: Any) -> str:
    try:
        return _hash_bytes(canonical_json_bytes(value))
    except Exception as exc:
        raise E2EEEnvelopeError(f"canonicalize {label}: {exc}") from exc


def validate_e2ee_mail_envelope(
    envelope: dict[str, Any],
    *,
    message_id: str,
    conversation_id: str,
    sender_did: str,
    sender_stable_id: str | None,
    recipient_did: str,
    recipient_stable_id: str | None,
    recipient_address: str | None,
) -> None:
    if not isinstance(envelope, dict):
        raise E2EEEnvelopeError("encrypted_envelope must be an object")
    if int(envelope.get("message_version") or 0) != E2EE_MESSAGE_VERSION:
        raise E2EEEnvelopeError("unsupported encrypted message_version")
    if _non_empty(envelope.get("envelope_type")) != E2EE_ENVELOPE_TYPE:
        raise E2EEEnvelopeError("unsupported encrypted envelope_type")
    if _non_empty(envelope.get("kind")) != "mail":
        raise E2EEEnvelopeError("encrypted envelope kind must be mail")
    if _non_empty(envelope.get("message_id")) != str(message_id):
        raise E2EEEnvelopeError("encrypted envelope message_id mismatch")
    if _non_empty(envelope.get("conversation_id")) != str(conversation_id):
        raise E2EEEnvelopeError("encrypted envelope conversation_id mismatch")

    from_ref = envelope.get("from") or {}
    if _non_empty(from_ref.get("did")) != sender_did:
        raise E2EEEnvelopeError("encrypted envelope sender did mismatch")
    if sender_stable_id and _non_empty(from_ref.get("stable_id")) != sender_stable_id:
        raise E2EEEnvelopeError("encrypted envelope sender stable id mismatch")
    if _non_empty(envelope.get("signing_key_id")) != sender_did:
        raise E2EEEnvelopeError("encrypted envelope signing key mismatch")

    recipients = envelope.get("recipients") or []
    if len(recipients) != 1:
        raise E2EEEnvelopeError("encrypted mail requires exactly one delivery recipient")
    recipient = recipients[0]
    recipient_dids = {v for v in (_non_empty(recipient.get("did")), _non_empty(recipient.get("stable_id"))) if v}
    expected_dids = {v for v in (recipient_did, recipient_stable_id or "") if v}
    if recipient_dids and not (recipient_dids & expected_dids):
        raise E2EEEnvelopeError("encrypted envelope recipient mismatch")
    if recipient_address and _non_empty(recipient.get("address")) and _non_empty(recipient.get("address")) != recipient_address:
        raise E2EEEnvelopeError("encrypted envelope recipient address mismatch")

    crypto = envelope.get("crypto") or {}
    if _non_empty(crypto.get("suite")) != E2EE_SUITE:
        raise E2EEEnvelopeError("unsupported encrypted crypto suite")
    ciphertext = _b64_raw_decode(_non_empty(envelope.get("ciphertext")), field="ciphertext")
    if _hash_bytes(ciphertext) != _non_empty(crypto.get("ciphertext_hash")):
        raise E2EEEnvelopeError("ciphertext hash mismatch")
    if len(ciphertext) != int(crypto.get("ciphertext_size") or 0):
        raise E2EEEnvelopeError("ciphertext size mismatch")
    key_wraps_hash = _hash_canonical(
        "key_wraps",
        [_key_wrap_map(item) for item in envelope.get("key_wraps") or []],
    )
    if key_wraps_hash != _non_empty(crypto.get("key_wraps_hash")):
        raise E2EEEnvelopeError("key_wraps hash mismatch")

    payload = canonical_json_bytes(
        _envelope_map(
            envelope,
            include_signature=False,
            include_ciphertext=True,
            include_ciphertext_hash=True,
        )
    )
    if verify_signature(sender_did, payload, _non_empty(envelope.get("signature"))) != VerifyResult.VERIFIED:
        raise E2EEEnvelopeError("invalid encrypted envelope signature")


def encrypted_message_storage_metadata(envelope: dict[str, Any]) -> dict[str, Any]:
    crypto = envelope.get("crypto") or {}
    signed_payload = canonical_json_bytes(
        _envelope_map(
            envelope,
            include_signature=False,
            include_ciphertext=True,
            include_ciphertext_hash=True,
        )
    )
    return {
        "encrypted_ciphertext": _non_empty(envelope.get("ciphertext")),
        "encrypted_key_wraps": [_key_wrap_map(item) for item in envelope.get("key_wraps") or []],
        "encrypted_ciphertext_hash": _non_empty(crypto.get("ciphertext_hash")),
        "encrypted_ciphertext_size": int(crypto.get("ciphertext_size") or 0),
        "encrypted_key_wraps_hash": _non_empty(crypto.get("key_wraps_hash")),
        "encrypted_inner_header_hash": _non_empty(crypto.get("inner_header_hash")),
        "encrypted_suite": _non_empty(crypto.get("suite")),
        "encrypted_signing_key_id": _non_empty(envelope.get("signing_key_id")),
        "signed_envelope_hash": _hash_bytes(signed_payload),
    }
