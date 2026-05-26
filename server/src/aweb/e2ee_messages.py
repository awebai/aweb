from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Any

from awid.signing import VerifyResult, canonical_json_bytes, verify_signature


E2EE_MESSAGE_VERSION = 2
E2EE_ENVELOPE_TYPE = "aweb.e2ee.message"
E2EE_SUITE = "aweb-e2ee-v2.x25519-hkdf-sha256-aes256gcm-ed25519"
E2EE_KEY_WRAP_ALGORITHM = "hpke-base-x25519-hkdf-sha256-aes256gcm"
E2EE_INGESTION_WINDOW = timedelta(minutes=5)


class E2EEEnvelopeError(ValueError):
    pass


def _b64_raw_decode(value: str, *, field: str) -> bytes:
    value = str(value or "").strip()
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4), validate=True)
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


def _parse_timestamp(value: Any, *, field: str) -> datetime:
    raw = _non_empty(value)
    if not raw:
        raise E2EEEnvelopeError(f"encrypted envelope {field} is required")
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except Exception as exc:
        raise E2EEEnvelopeError(f"invalid encrypted envelope {field}") from exc
    if dt.tzinfo is None:
        raise E2EEEnvelopeError(f"encrypted envelope {field} must include timezone")
    return dt.astimezone(timezone.utc)


def _validate_policy(policy: dict[str, Any]) -> None:
    if policy.get("requires_e2ee") is not True:
        raise E2EEEnvelopeError("encrypted envelope policy must require e2ee")
    if policy.get("legacy_plaintext_allowed") is not False:
        raise E2EEEnvelopeError("encrypted envelope policy must forbid legacy plaintext")


def _validate_ingestion_window(envelope: dict[str, Any], *, now: datetime | None = None) -> None:
    created_at = _parse_timestamp(envelope.get("created_at"), field="created_at")
    expires_at = _parse_timestamp(envelope.get("expires_at"), field="expires_at")
    now_utc = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if expires_at <= created_at:
        raise E2EEEnvelopeError("encrypted envelope expires_at must be after created_at")
    if expires_at - created_at > E2EE_INGESTION_WINDOW:
        raise E2EEEnvelopeError("encrypted envelope expiration exceeds ingestion window")
    if now_utc > expires_at:
        raise E2EEEnvelopeError("encrypted envelope expired")
    if created_at - now_utc > E2EE_INGESTION_WINDOW:
        raise E2EEEnvelopeError("encrypted envelope created_at is too far in the future")


def _validate_hash(value: Any, *, field: str) -> str:
    value = _non_empty(value)
    if not value.startswith("sha256:"):
        raise E2EEEnvelopeError(f"encrypted envelope {field} must be a sha256 hash")
    encoded = value.removeprefix("sha256:")
    decoded = _b64_raw_decode(encoded, field=field)
    if len(decoded) != 32:
        raise E2EEEnvelopeError(f"encrypted envelope {field} must be 32 bytes")
    return value


def _validate_key_wrap_structure(wrap: dict[str, Any], *, index: int) -> None:
    if not isinstance(wrap, dict):
        raise E2EEEnvelopeError("encrypted envelope key_wraps must contain objects")
    purpose = _non_empty(wrap.get("wrap_purpose"))
    if purpose not in {"delivery", "sender_copy"}:
        raise E2EEEnvelopeError("encrypted envelope key wrap has invalid purpose")
    if _non_empty(wrap.get("algorithm")) != E2EE_KEY_WRAP_ALGORITHM:
        raise E2EEEnvelopeError("encrypted envelope key wrap has unsupported algorithm")
    for field in (
        "wrap_id",
        "recipient_encryption_key_id",
        "sender_encryption_key_id",
        "sender_did",
    ):
        if not _non_empty(wrap.get(field)):
            raise E2EEEnvelopeError(f"encrypted envelope key wrap {index} missing {field}")
    _validate_hash(wrap.get("wrap_id"), field=f"key_wraps[{index}].wrap_id")
    _validate_hash(
        wrap.get("recipient_encryption_key_id"),
        field=f"key_wraps[{index}].recipient_encryption_key_id",
    )
    _validate_hash(
        wrap.get("sender_encryption_key_id"),
        field=f"key_wraps[{index}].sender_encryption_key_id",
    )
    if len(_b64_raw_decode(_non_empty(wrap.get("encapsulated_key")), field=f"key_wraps[{index}].encapsulated_key")) != 32:
        raise E2EEEnvelopeError("encrypted envelope key wrap encapsulated key must be 32 bytes")
    if len(_b64_raw_decode(_non_empty(wrap.get("wrapped_cek")), field=f"key_wraps[{index}].wrapped_cek")) < 48:
        raise E2EEEnvelopeError("encrypted envelope key wrap wrapped CEK is too short")


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
    now: datetime | None = None,
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
    policy = envelope.get("policy")
    if not isinstance(policy, dict):
        raise E2EEEnvelopeError("encrypted envelope policy must be an object")
    _validate_policy(policy)
    _validate_ingestion_window(envelope, now=now)

    from_ref = envelope.get("from") or {}
    if not isinstance(from_ref, dict):
        raise E2EEEnvelopeError("encrypted envelope sender must be an object")
    if _non_empty(from_ref.get("did")) != sender_did:
        raise E2EEEnvelopeError("encrypted envelope sender did mismatch")
    if sender_stable_id and _non_empty(from_ref.get("stable_id")) != sender_stable_id:
        raise E2EEEnvelopeError("encrypted envelope sender stable id mismatch")
    if _non_empty(envelope.get("signing_key_id")) != sender_did:
        raise E2EEEnvelopeError("encrypted envelope signing key mismatch")
    sender_key_id = _non_empty(from_ref.get("encryption_key_id"))
    if not sender_key_id:
        raise E2EEEnvelopeError("encrypted envelope sender missing key binding")

    recipients = envelope.get("recipients") or []
    if len(recipients) != 1:
        raise E2EEEnvelopeError("encrypted mail requires exactly one delivery recipient")
    recipient = recipients[0]
    if not isinstance(recipient, dict):
        raise E2EEEnvelopeError("encrypted envelope recipient must be an object")
    if _non_empty(recipient.get("did")) != recipient_did:
        raise E2EEEnvelopeError("encrypted envelope recipient did mismatch")
    if recipient_stable_id and _non_empty(recipient.get("stable_id")) != recipient_stable_id:
        raise E2EEEnvelopeError("encrypted envelope recipient stable id mismatch")
    if recipient_address and _non_empty(recipient.get("address")) != recipient_address:
        raise E2EEEnvelopeError("encrypted envelope recipient address mismatch")
    recipient_key_id = _non_empty(recipient.get("encryption_key_id"))
    recipient_wrap_id = _non_empty(recipient.get("wrap_id"))
    if not recipient_key_id or not recipient_wrap_id:
        raise E2EEEnvelopeError("encrypted envelope recipient missing key binding")

    crypto = envelope.get("crypto") or {}
    if _non_empty(crypto.get("suite")) != E2EE_SUITE:
        raise E2EEEnvelopeError("unsupported encrypted crypto suite")
    if len(_b64_raw_decode(_non_empty(crypto.get("content_nonce")), field="content_nonce")) != 12:
        raise E2EEEnvelopeError("encrypted envelope content_nonce must be 12 bytes")
    for field in ("ciphertext_hash", "inner_header_hash", "key_wraps_hash"):
        _validate_hash(crypto.get(field), field=field)
    ciphertext = _b64_raw_decode(_non_empty(envelope.get("ciphertext")), field="ciphertext")
    if len(ciphertext) < 16:
        raise E2EEEnvelopeError("encrypted envelope ciphertext is too short")
    if _hash_bytes(ciphertext) != _non_empty(crypto.get("ciphertext_hash")):
        raise E2EEEnvelopeError("ciphertext hash mismatch")
    if len(ciphertext) != int(crypto.get("ciphertext_size") or 0):
        raise E2EEEnvelopeError("ciphertext size mismatch")
    key_wraps = envelope.get("key_wraps") or []
    if not isinstance(key_wraps, list):
        raise E2EEEnvelopeError("encrypted envelope key_wraps must be an array")
    for index, wrap in enumerate(key_wraps):
        _validate_key_wrap_structure(wrap, index=index)
    delivery_wraps = [
        wrap for wrap in key_wraps
        if isinstance(wrap, dict) and _non_empty(wrap.get("wrap_purpose")) == "delivery"
    ]
    sender_copy_wraps = [
        wrap for wrap in key_wraps
        if isinstance(wrap, dict) and _non_empty(wrap.get("wrap_purpose")) == "sender_copy"
    ]
    if len(delivery_wraps) != 1:
        raise E2EEEnvelopeError("encrypted envelope requires exactly one delivery key wrap")
    if len(sender_copy_wraps) != 1:
        raise E2EEEnvelopeError("encrypted envelope requires exactly one sender_copy key wrap")
    delivery_wrap = delivery_wraps[0]
    if _non_empty(delivery_wrap.get("recipient_did")) != recipient_did:
        raise E2EEEnvelopeError("encrypted envelope delivery wrap recipient did mismatch")
    if recipient_stable_id and _non_empty(delivery_wrap.get("recipient_stable_id")) != recipient_stable_id:
        raise E2EEEnvelopeError("encrypted envelope delivery wrap recipient stable id mismatch")
    if recipient_address and _non_empty(delivery_wrap.get("recipient_address")) != recipient_address:
        raise E2EEEnvelopeError("encrypted envelope delivery wrap recipient address mismatch")
    if _non_empty(delivery_wrap.get("recipient_encryption_key_id")) != recipient_key_id:
        raise E2EEEnvelopeError("encrypted envelope delivery wrap recipient key mismatch")
    if _non_empty(delivery_wrap.get("wrap_id")) != recipient_wrap_id:
        raise E2EEEnvelopeError("encrypted envelope delivery wrap id mismatch")
    sender_copy_wrap = sender_copy_wraps[0]
    if _non_empty(sender_copy_wrap.get("sender_did")) != sender_did:
        raise E2EEEnvelopeError("encrypted envelope sender_copy sender did mismatch")
    if sender_stable_id and _non_empty(sender_copy_wrap.get("sender_stable_id")) != sender_stable_id:
        raise E2EEEnvelopeError("encrypted envelope sender_copy sender stable id mismatch")
    if _non_empty(sender_copy_wrap.get("recipient_did")) != sender_did:
        raise E2EEEnvelopeError("encrypted envelope sender_copy recipient did mismatch")
    if sender_stable_id and _non_empty(sender_copy_wrap.get("recipient_stable_id")) != sender_stable_id:
        raise E2EEEnvelopeError("encrypted envelope sender_copy recipient stable id mismatch")
    if _non_empty(sender_copy_wrap.get("recipient_encryption_key_id")) != sender_key_id:
        raise E2EEEnvelopeError("encrypted envelope sender_copy recipient key mismatch")
    key_wraps_hash = _hash_canonical(
        "key_wraps",
        [_key_wrap_map(item) for item in key_wraps],
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
