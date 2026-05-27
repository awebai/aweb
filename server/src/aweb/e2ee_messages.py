from __future__ import annotations

import base64
import hashlib
import hmac
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from nacl.signing import SigningKey

from awid.did import did_from_public_key
from awid.e2ee_keys import encryption_key_id, validate_encryption_key_assertion
from awid.signing import VerifyResult, canonical_json_bytes, sign_message, verify_signature


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


def _encryption_key_assertion_map(assertion: dict[str, Any]) -> dict[str, Any]:
    out = {
        "operation": _non_empty(assertion.get("operation")),
        "version": _non_empty(assertion.get("version")),
        "identity_did": _non_empty(assertion.get("identity_did")),
        "encryption_key_id": _non_empty(assertion.get("encryption_key_id")),
        "encryption_public_key": _non_empty(assertion.get("encryption_public_key")),
        "algorithm": _non_empty(assertion.get("algorithm")),
        "created_at": _non_empty(assertion.get("created_at")),
        "not_before": _non_empty(assertion.get("not_before")),
        "expires_at": _non_empty(assertion.get("expires_at")),
        "signature": _non_empty(assertion.get("signature")),
    }
    _add_non_empty(out, "identity_stable_id", assertion.get("identity_stable_id"))
    _add_non_empty(out, "custody", assertion.get("custody"))
    _add_non_empty(out, "previous_encryption_key_id", assertion.get("previous_encryption_key_id"))
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
        "routing": _routing_map(envelope.get("routing") or {}),
        "policy": {
            "requires_e2ee": bool(policy.get("requires_e2ee")),
            "legacy_plaintext_allowed": bool(policy.get("legacy_plaintext_allowed")),
        },
        "crypto": _crypto_map(crypto, include_ciphertext_hash=include_ciphertext_hash),
        "key_wraps": [_key_wrap_map(item) for item in envelope.get("key_wraps") or []],
        "signing_key_id": _non_empty(envelope.get("signing_key_id")),
    }
    sender_key = envelope.get("sender_encryption_key")
    if sender_key is not None:
        if not isinstance(sender_key, dict):
            raise E2EEEnvelopeError("encrypted envelope sender_encryption_key must be an object")
        out["sender_encryption_key"] = _encryption_key_assertion_map(sender_key)
    out["recipients"] = [_recipient_ref_map(item) for item in envelope.get("recipients") or []]
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


def _b64_raw_encode(value: bytes) -> str:
    return base64.b64encode(value).rstrip(b"=").decode("ascii")


def generate_x25519_keypair() -> tuple[bytes, bytes]:
    private_key = x25519.X25519PrivateKey.generate()
    private_bytes = private_key.private_bytes_raw()
    public_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return private_bytes, public_bytes


def _x25519_private(raw: bytes) -> x25519.X25519PrivateKey:
    if len(raw) != 32:
        raise E2EEEnvelopeError("x25519 private key must be 32 bytes")
    return x25519.X25519PrivateKey.from_private_bytes(raw)


def _x25519_public(raw: bytes) -> x25519.X25519PublicKey:
    if len(raw) != 32:
        raise E2EEEnvelopeError("x25519 public key must be 32 bytes")
    return x25519.X25519PublicKey.from_public_bytes(raw)


def _format_contract_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _inner_payload_map(inner: dict[str, Any], *, include_content: bool) -> dict[str, Any]:
    out: dict[str, Any] = {
        "inner_version": int(inner.get("inner_version") or 0),
        "kind": _non_empty(inner.get("kind")),
        "message_id": _non_empty(inner.get("message_id")),
        "conversation_id": _non_empty(inner.get("conversation_id")),
        "created_at": _non_empty(inner.get("created_at")),
        "from": _identity_ref_map(inner.get("from") or {}, include_key_id=False),
        "recipients": [
            _identity_ref_map(item, include_key_id=False)
            for item in (inner.get("recipients") or [])
        ],
    }
    _add_non_empty(out, "reply_to_message_id", inner.get("reply_to_message_id"))
    if include_content:
        if _non_empty(inner.get("kind")) == "mail":
            out["subject"] = str(inner.get("subject") or "")
        out["body"] = str(inner.get("body") or "")
    return out


def _inner_payload_canonical(inner: dict[str, Any]) -> bytes:
    return canonical_json_bytes(_inner_payload_map(inner, include_content=True))


def _inner_header_hash(inner: dict[str, Any]) -> str:
    return _hash_canonical("inner_header", _inner_payload_map(inner, include_content=False))


def _identity_refs_equal(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return (
        _non_empty(left.get("address")) == _non_empty(right.get("address"))
        and _non_empty(left.get("did")) == _non_empty(right.get("did"))
        and _non_empty(left.get("stable_id")) == _non_empty(right.get("stable_id"))
        and _non_empty(left.get("team_id")) == _non_empty(right.get("team_id"))
    )


def _verify_inner_header(envelope: dict[str, Any], inner: dict[str, Any]) -> None:
    if int(inner.get("inner_version") or 0) != E2EE_MESSAGE_VERSION:
        raise E2EEEnvelopeError("inner header does not match outer envelope")
    for field in ("kind", "message_id", "conversation_id", "reply_to_message_id", "created_at"):
        if _non_empty(inner.get(field)) != _non_empty(envelope.get(field)):
            raise E2EEEnvelopeError("inner header does not match outer envelope")
    if not _identity_refs_equal(inner.get("from") or {}, envelope.get("from") or {}):
        raise E2EEEnvelopeError("inner sender does not match outer envelope")
    inner_recipients = inner.get("recipients") or []
    envelope_recipients = envelope.get("recipients") or []
    if len(inner_recipients) != len(envelope_recipients):
        raise E2EEEnvelopeError("inner recipients do not match outer envelope")
    for left, right in zip(inner_recipients, envelope_recipients, strict=True):
        if not _identity_refs_equal(left, right):
            raise E2EEEnvelopeError("inner recipients do not match outer envelope")


E2EE_WRAP_VERSION = "aweb-e2ee-wrap-v1"
_E2EE_WRAP_INFO_PREFIX = b"aweb-e2ee-v2 key-wrap\n"
_HPKE_KEM_ID = b"\x00\x20"
_HPKE_KDF_ID = b"\x00\x01"
_HPKE_AEAD_ID = b"\x00\x02"
_HPKE_SUITE_ID = b"HPKE" + _HPKE_KEM_ID + _HPKE_KDF_ID + _HPKE_AEAD_ID
_KEM_SUITE_ID = b"KEM" + _HPKE_KEM_ID


def _hkdf_extract(suite_id: bytes, salt: bytes | None, label: str, ikm: bytes) -> bytes:
    labeled_ikm = b"HPKE-v1" + suite_id + label.encode("ascii") + ikm
    return hmac.new(salt or b"\x00" * 32, labeled_ikm, hashlib.sha256).digest()


def _hkdf_expand(suite_id: bytes, prk: bytes, label: str, info: bytes, length: int) -> bytes:
    labeled_info = (
        length.to_bytes(2, "big")
        + b"HPKE-v1"
        + suite_id
        + label.encode("ascii")
        + info
    )
    out = b""
    previous = b""
    counter = 1
    while len(out) < length:
        previous = hmac.new(prk, previous + labeled_info + bytes([counter]), hashlib.sha256).digest()
        out += previous
        counter += 1
    return out[:length]


def _hpke_dhkem_extract_and_expand(
    private_key: x25519.X25519PrivateKey,
    public_key: x25519.X25519PublicKey,
    enc: bytes,
    pk_rm: bytes,
) -> bytes:
    dh = private_key.exchange(public_key)
    eae_prk = _hkdf_extract(_KEM_SUITE_ID, None, "eae_prk", dh)
    return _hkdf_expand(_KEM_SUITE_ID, eae_prk, "shared_secret", enc + pk_rm, 32)


def _hpke_key_schedule(shared_secret: bytes, info: bytes) -> tuple[bytes, bytes]:
    psk_id_hash = _hkdf_extract(_HPKE_SUITE_ID, None, "psk_id_hash", b"")
    info_hash = _hkdf_extract(_HPKE_SUITE_ID, None, "info_hash", info)
    context = b"\x00" + psk_id_hash + info_hash
    secret = _hkdf_extract(_HPKE_SUITE_ID, shared_secret, "secret", b"")
    key = _hkdf_expand(_HPKE_SUITE_ID, secret, "key", context, 32)
    nonce = _hkdf_expand(_HPKE_SUITE_ID, secret, "base_nonce", context, 12)
    return key, nonce


def _hpke_base_seal(recipient_public_key: bytes, info: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    recipient_pub = _x25519_public(recipient_public_key)
    ephemeral_private = x25519.X25519PrivateKey.generate()
    enc = ephemeral_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    shared_secret = _hpke_dhkem_extract_and_expand(
        ephemeral_private,
        recipient_pub,
        enc,
        recipient_public_key,
    )
    key, nonce = _hpke_key_schedule(shared_secret, info)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return enc, ciphertext


def _hpke_base_open(
    recipient_private_key: x25519.X25519PrivateKey,
    enc: bytes,
    info: bytes,
    ciphertext: bytes,
) -> bytes:
    ephemeral_public = _x25519_public(enc)
    recipient_public_key = recipient_private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    shared_secret = _hpke_dhkem_extract_and_expand(
        recipient_private_key,
        ephemeral_public,
        enc,
        recipient_public_key,
    )
    key, nonce = _hpke_key_schedule(shared_secret, info)
    return AESGCM(key).decrypt(nonce, ciphertext, None)


def _key_wrap_binding_map(
    *,
    message_id: str,
    conversation_id: str,
    sender: dict[str, Any],
    recipient: dict[str, Any],
    purpose: str,
) -> dict[str, Any]:
    out = {
        "version": E2EE_WRAP_VERSION,
        "message_id": _non_empty(message_id),
        "conversation_id": _non_empty(conversation_id),
        "recipient_did": _non_empty(recipient.get("did")),
        "recipient_encryption_key_id": _non_empty(recipient.get("encryption_key_id")),
        "sender_did": _non_empty(sender.get("did")),
        "sender_encryption_key_id": _non_empty(sender.get("encryption_key_id")),
        "wrap_purpose": _non_empty(purpose),
        "suite": E2EE_SUITE,
    }
    _add_non_empty(out, "recipient_stable_id", recipient.get("stable_id"))
    _add_non_empty(out, "recipient_address", recipient.get("address"))
    _add_non_empty(out, "sender_stable_id", sender.get("stable_id"))
    return out


def _build_key_wrap(
    *,
    cek: bytes,
    message_id: str,
    conversation_id: str,
    sender: dict[str, Any],
    recipient: dict[str, Any],
    purpose: str,
    assertion: dict[str, Any],
) -> dict[str, Any]:
    if len(cek) != 32:
        raise E2EEEnvelopeError("content key must be 32 bytes")
    if _non_empty(assertion.get("encryption_key_id")) != _non_empty(recipient.get("encryption_key_id")):
        raise E2EEEnvelopeError("recipient encryption key id mismatch")
    binding = _key_wrap_binding_map(
        message_id=message_id,
        conversation_id=conversation_id,
        sender=sender,
        recipient=recipient,
        purpose=purpose,
    )
    binding_bytes = canonical_json_bytes(binding)
    recipient_public_key = _b64_raw_decode(
        _non_empty(assertion.get("encryption_public_key")),
        field="recipient encryption_public_key",
    )
    enc, wrapped = _hpke_base_seal(
        recipient_public_key,
        _E2EE_WRAP_INFO_PREFIX + binding_bytes,
        cek,
    )
    return {
        "wrap_id": _hash_bytes(binding_bytes),
        "recipient_stable_id": _non_empty(recipient.get("stable_id")),
        "recipient_did": _non_empty(recipient.get("did")),
        "recipient_address": _non_empty(recipient.get("address")),
        "recipient_encryption_key_id": _non_empty(recipient.get("encryption_key_id")),
        "sender_encryption_key_id": _non_empty(sender.get("encryption_key_id")),
        "sender_did": _non_empty(sender.get("did")),
        "sender_stable_id": _non_empty(sender.get("stable_id")),
        "wrap_purpose": _non_empty(purpose),
        "algorithm": E2EE_KEY_WRAP_ALGORITHM,
        "encapsulated_key": _b64_raw_encode(enc),
        "wrapped_cek": _b64_raw_encode(wrapped),
    }


def _routing_to(recipients: list[dict[str, Any]]) -> str:
    values = []
    for recipient in recipients:
        value = (
            _non_empty(recipient.get("address"))
            or _non_empty(recipient.get("stable_id"))
            or _non_empty(recipient.get("did"))
        )
        if value:
            values.append(value)
    return ",".join(values)


def _single_recipient_field(recipients: list[dict[str, Any]], field: str) -> str:
    if len(recipients) != 1:
        return ""
    return _non_empty(recipients[0].get(field))


def _content_aad(envelope: dict[str, Any]) -> bytes:
    return canonical_json_bytes(
        _envelope_map(
            envelope,
            include_signature=False,
            include_ciphertext=False,
            include_ciphertext_hash=False,
        )
    )


def encrypt_e2ee_message(
    *,
    kind: str,
    sender: dict[str, Any],
    recipients: list[dict[str, Any]],
    body: str,
    subject: str = "",
    message_id: str,
    conversation_id: str,
    reply_to_message_id: str = "",
    created_at: datetime | None = None,
    delivery_origin: str = "",
    observed_inbound_mode: str = "",
) -> dict[str, Any]:
    kind = _non_empty(kind) or "mail"
    if kind not in {"mail", "chat"}:
        raise E2EEEnvelopeError(f"unsupported E2E message kind {kind!r}")
    if kind == "mail" and len(recipients) != 1:
        raise E2EEEnvelopeError("E2E mail requires exactly one delivery recipient")
    if not recipients:
        raise E2EEEnvelopeError("at least one delivery recipient is required")
    signing_key = sender.get("signing_key")
    if not isinstance(signing_key, bytes):
        raise E2EEEnvelopeError("sender signing key is required")
    sender_assertion = sender.get("encryption_key")
    if not isinstance(sender_assertion, dict):
        raise E2EEEnvelopeError("sender encryption key is required")
    created = (created_at or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(microsecond=0)
    expires = created + E2EE_INGESTION_WINDOW
    verify_key = bytes(SigningKey(signing_key).verify_key)
    from_ref = {
        "address": _non_empty(sender.get("address")),
        "did": _non_empty(sender.get("did")),
        "stable_id": _non_empty(sender.get("stable_id")),
        "team_id": _non_empty(sender.get("team_id")),
        "encryption_key_id": _non_empty(sender_assertion.get("encryption_key_id")),
    }
    if did_from_public_key(verify_key) != from_ref["did"]:
        raise E2EEEnvelopeError("sender signing key does not match sender did")
    validate_encryption_key_assertion(
        sender_assertion,
        current_did_key=from_ref["did"],
        stable_id=from_ref["stable_id"] or None,
        now=created,
    )

    recipient_refs: list[dict[str, Any]] = []
    inner_recipients: list[dict[str, Any]] = []
    for index, recipient in enumerate(recipients):
        assertion = recipient.get("encryption_key")
        if not isinstance(assertion, dict):
            raise E2EEEnvelopeError(f"recipient {index} encryption key is required")
        recipient_ref = {
            "address": _non_empty(recipient.get("address")),
            "did": _non_empty(recipient.get("did")),
            "stable_id": _non_empty(recipient.get("stable_id")),
            "team_id": _non_empty(recipient.get("team_id")),
            "encryption_key_id": _non_empty(assertion.get("encryption_key_id")),
        }
        if not recipient_ref["did"] or not recipient_ref["encryption_key_id"]:
            raise E2EEEnvelopeError(f"recipient {index} did and encryption key are required")
        validate_encryption_key_assertion(
            assertion,
            current_did_key=recipient_ref["did"],
            stable_id=recipient_ref["stable_id"] or None,
            now=created,
        )
        recipient_refs.append(recipient_ref)
        inner_recipients.append(_identity_ref_map(recipient_ref, include_key_id=False))

    inner = {
        "inner_version": E2EE_MESSAGE_VERSION,
        "kind": kind,
        "message_id": _non_empty(message_id),
        "conversation_id": _non_empty(conversation_id),
        "reply_to_message_id": _non_empty(reply_to_message_id),
        "created_at": _format_contract_time(created),
        "from": from_ref,
        "recipients": inner_recipients,
        "subject": subject if kind == "mail" else "",
        "body": body,
    }
    inner_header_hash = _inner_header_hash(inner)
    cek = os.urandom(32)
    content_nonce = os.urandom(12)
    if content_nonce == b"\x00" * 12:
        raise E2EEEnvelopeError("generated all-zero content nonce")

    key_wraps: list[dict[str, Any]] = []
    for index, recipient in enumerate(recipients):
        delivery_wrap = _build_key_wrap(
            cek=cek,
            message_id=message_id,
            conversation_id=conversation_id,
            sender=from_ref,
            recipient=recipient_refs[index],
            purpose="delivery",
            assertion=recipient["encryption_key"],
        )
        key_wraps.append(delivery_wrap)
        recipient_refs[index]["wrap_id"] = delivery_wrap["wrap_id"]
    sender_as_recipient = {
        "address": from_ref["address"],
        "did": from_ref["did"],
        "stable_id": from_ref["stable_id"],
        "team_id": from_ref["team_id"],
        "encryption_key_id": from_ref["encryption_key_id"],
    }
    key_wraps.append(
        _build_key_wrap(
            cek=cek,
            message_id=message_id,
            conversation_id=conversation_id,
            sender=from_ref,
            recipient=sender_as_recipient,
            purpose="sender_copy",
            assertion=sender_assertion,
        )
    )
    key_wraps_hash = _hash_canonical("key_wraps", [_key_wrap_map(item) for item in key_wraps])
    inner_bytes = _inner_payload_canonical(inner)
    envelope: dict[str, Any] = {
        "message_version": E2EE_MESSAGE_VERSION,
        "envelope_type": E2EE_ENVELOPE_TYPE,
        "kind": kind,
        "message_id": _non_empty(message_id),
        "conversation_id": _non_empty(conversation_id),
        "created_at": _format_contract_time(created),
        "expires_at": _format_contract_time(expires),
        "from": from_ref,
        "recipients": recipient_refs,
        "routing": {
            "to": _routing_to(recipient_refs),
            "to_did": _single_recipient_field(recipient_refs, "did"),
            "to_stable_id": _single_recipient_field(recipient_refs, "stable_id"),
            "delivery_origin": _non_empty(delivery_origin),
            "sender_observed_inbound_mode": _non_empty(observed_inbound_mode),
        },
        "policy": {"requires_e2ee": True, "legacy_plaintext_allowed": False},
        "crypto": {
            "suite": E2EE_SUITE,
            "content_nonce": _b64_raw_encode(content_nonce),
            "ciphertext_size": len(inner_bytes) + 16,
            "inner_header_hash": inner_header_hash,
            "key_wraps_hash": key_wraps_hash,
        },
        "key_wraps": key_wraps,
        "signing_key_id": from_ref["did"],
    }
    _add_non_empty(envelope, "reply_to_message_id", reply_to_message_id)
    if not from_ref["address"]:
        envelope["sender_encryption_key"] = sender_assertion
    aad = _content_aad(envelope)
    ciphertext = AESGCM(cek).encrypt(content_nonce, inner_bytes, aad)
    envelope["ciphertext"] = _b64_raw_encode(ciphertext)
    envelope["crypto"]["ciphertext_hash"] = _hash_bytes(ciphertext)
    signed_payload = canonical_json_bytes(
        _envelope_map(
            envelope,
            include_signature=False,
            include_ciphertext=True,
            include_ciphertext_hash=True,
        )
    )
    envelope["signature"] = sign_message(signing_key, signed_payload)
    return envelope


def encrypt_e2ee_mail(**kwargs: Any) -> dict[str, Any]:
    kwargs["kind"] = "mail"
    return encrypt_e2ee_message(**kwargs)


def encrypt_e2ee_chat(**kwargs: Any) -> dict[str, Any]:
    kwargs["kind"] = "chat"
    kwargs.setdefault("subject", "")
    return encrypt_e2ee_message(**kwargs)


def _select_key_wrap(envelope: dict[str, Any], identity: dict[str, Any]) -> dict[str, Any]:
    key_id = _non_empty(identity.get("encryption_key_id"))
    private_key = identity.get("private_key")
    if not key_id and isinstance(private_key, bytes):
        public_key = _x25519_private(private_key).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        key_id = encryption_key_id(_b64_raw_encode(public_key))
    for wrap in envelope.get("key_wraps") or []:
        if _non_empty(wrap.get("recipient_encryption_key_id")) != key_id:
            continue
        if not _identity_field_matches(wrap.get("recipient_did"), identity.get("did")):
            continue
        if not _identity_field_matches(wrap.get("recipient_stable_id"), identity.get("stable_id")):
            continue
        if not _identity_field_matches(wrap.get("recipient_address"), identity.get("address")):
            continue
        return wrap
    raise E2EEEnvelopeError("not a recipient")


def _identity_field_matches(wrap_value: Any, local_value: Any) -> bool:
    wrap_value = _non_empty(wrap_value)
    local_value = _non_empty(local_value)
    return not wrap_value or (bool(local_value) and wrap_value == local_value)


def _open_key_wrap(
    *,
    wrap: dict[str, Any],
    envelope: dict[str, Any],
    identity: dict[str, Any],
) -> bytes:
    if _non_empty(wrap.get("algorithm")) != E2EE_KEY_WRAP_ALGORITHM:
        raise E2EEEnvelopeError("unsupported key wrap algorithm")
    private_key = identity.get("private_key")
    if not isinstance(private_key, bytes):
        raise E2EEEnvelopeError("missing local encryption private key")
    recipient = {
        "address": _non_empty(wrap.get("recipient_address")),
        "did": _non_empty(wrap.get("recipient_did")),
        "stable_id": _non_empty(wrap.get("recipient_stable_id")),
        "encryption_key_id": _non_empty(wrap.get("recipient_encryption_key_id")),
    }
    binding = _key_wrap_binding_map(
        message_id=_non_empty(envelope.get("message_id")),
        conversation_id=_non_empty(envelope.get("conversation_id")),
        sender=envelope.get("from") or {},
        recipient=recipient,
        purpose=_non_empty(wrap.get("wrap_purpose")),
    )
    binding_bytes = canonical_json_bytes(binding)
    if _hash_bytes(binding_bytes) != _non_empty(wrap.get("wrap_id")):
        raise E2EEEnvelopeError("key wrap binding mismatch")
    enc = _b64_raw_decode(_non_empty(wrap.get("encapsulated_key")), field="encapsulated_key")
    wrapped = _b64_raw_decode(_non_empty(wrap.get("wrapped_cek")), field="wrapped_cek")
    cek = _hpke_base_open(
        _x25519_private(private_key),
        enc,
        _E2EE_WRAP_INFO_PREFIX + binding_bytes,
        wrapped,
    )
    if len(cek) != 32:
        raise E2EEEnvelopeError("invalid content key size")
    return cek


def verify_e2ee_message_envelope_signature(envelope: dict[str, Any]) -> None:
    from_did = _non_empty((envelope.get("from") or {}).get("did"))
    if _non_empty(envelope.get("signing_key_id")) != from_did:
        raise E2EEEnvelopeError("e2ee envelope signing key does not match sender did")
    payload = canonical_json_bytes(
        _envelope_map(
            envelope,
            include_signature=False,
            include_ciphertext=True,
            include_ciphertext_hash=True,
        )
    )
    if verify_signature(from_did, payload, _non_empty(envelope.get("signature"))) != VerifyResult.VERIFIED:
        raise E2EEEnvelopeError("invalid e2ee envelope signature")


def decrypt_e2ee_message(envelope: dict[str, Any], identity: dict[str, Any]) -> dict[str, Any]:
    if int(envelope.get("message_version") or 0) != E2EE_MESSAGE_VERSION:
        raise E2EEEnvelopeError("unsupported e2ee envelope version")
    if _non_empty(envelope.get("envelope_type")) != E2EE_ENVELOPE_TYPE:
        raise E2EEEnvelopeError("unsupported e2ee envelope version")
    verify_e2ee_message_envelope_signature(envelope)
    crypto = envelope.get("crypto") or {}
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
    wrap = _select_key_wrap(envelope, identity)
    cek = _open_key_wrap(wrap=wrap, envelope=envelope, identity=identity)
    nonce = _b64_raw_decode(_non_empty(crypto.get("content_nonce")), field="content_nonce")
    aad = _content_aad(envelope)
    try:
        plain = AESGCM(cek).decrypt(nonce, ciphertext, aad)
    except Exception as exc:
        raise E2EEEnvelopeError("decrypt content") from exc
    import json

    inner = json.loads(plain)
    if _inner_header_hash(inner) != _non_empty(crypto.get("inner_header_hash")):
        raise E2EEEnvelopeError("inner header hash mismatch")
    _verify_inner_header(envelope, inner)
    return inner


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


def validate_e2ee_message_envelope(
    envelope: dict[str, Any],
    *,
    kind: str,
    message_id: str,
    conversation_id: str,
    sender_did: str,
    sender_stable_id: str | None,
    recipients: list[dict[str, str | None]],
    now: datetime | None = None,
) -> None:
    if not isinstance(envelope, dict):
        raise E2EEEnvelopeError("encrypted_envelope must be an object")
    kind = _non_empty(kind)
    if kind not in {"mail", "chat"}:
        raise E2EEEnvelopeError("unsupported encrypted envelope kind")
    if int(envelope.get("message_version") or 0) != E2EE_MESSAGE_VERSION:
        raise E2EEEnvelopeError("unsupported encrypted message_version")
    if _non_empty(envelope.get("envelope_type")) != E2EE_ENVELOPE_TYPE:
        raise E2EEEnvelopeError("unsupported encrypted envelope_type")
    if _non_empty(envelope.get("kind")) != kind:
        raise E2EEEnvelopeError(f"encrypted envelope kind must be {kind}")
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
    sender_encryption_key = envelope.get("sender_encryption_key")
    if sender_encryption_key is not None:
        if not isinstance(sender_encryption_key, dict):
            raise E2EEEnvelopeError("encrypted envelope sender_encryption_key must be an object")
        assertion_time = _parse_timestamp(envelope.get("created_at"), field="created_at")
        try:
            validate_encryption_key_assertion(
                sender_encryption_key,
                current_did_key=sender_did,
                stable_id=sender_stable_id,
                now=assertion_time,
            )
        except Exception as exc:
            raise E2EEEnvelopeError(f"sender encryption key assertion: {exc}") from exc
        if _non_empty(sender_encryption_key.get("encryption_key_id")) != sender_key_id:
            raise E2EEEnvelopeError("sender encryption key assertion id mismatch")

    if not recipients:
        raise E2EEEnvelopeError("encrypted envelope requires at least one delivery recipient")
    envelope_recipients = envelope.get("recipients") or []
    if len(envelope_recipients) != len(recipients):
        raise E2EEEnvelopeError("encrypted envelope recipient count mismatch")
    expected_by_did = {_non_empty(item.get("did")): item for item in recipients if _non_empty(item.get("did"))}
    if len(expected_by_did) != len(recipients):
        raise E2EEEnvelopeError("encrypted envelope expected recipients must have unique dids")
    envelope_recipients_by_did: dict[str, dict[str, Any]] = {}
    for recipient in envelope_recipients:
        if not isinstance(recipient, dict):
            raise E2EEEnvelopeError("encrypted envelope recipient must be an object")
        recipient_did = _non_empty(recipient.get("did"))
        if not recipient_did:
            raise E2EEEnvelopeError("encrypted envelope recipient did is required")
        if recipient_did in envelope_recipients_by_did:
            raise E2EEEnvelopeError("encrypted envelope duplicate recipient did")
        envelope_recipients_by_did[recipient_did] = recipient
    if set(envelope_recipients_by_did) != set(expected_by_did):
        raise E2EEEnvelopeError("encrypted envelope recipient did mismatch")
    for recipient_did, expected in expected_by_did.items():
        recipient = envelope_recipients_by_did[recipient_did]
        expected_stable_id = _non_empty(expected.get("stable_id"))
        expected_address = _non_empty(expected.get("address"))
        if recipient_did.startswith("did:key:") and not expected_stable_id:
            # A remote local-only did:key participant can carry server-visible
            # transport hints such as alias/address. Those hints are not AWID
            # identity authority and are intentionally omitted from the
            # encrypted recipient binding.
            expected_stable_id = ""
            expected_address = ""
        if expected_stable_id and _non_empty(recipient.get("stable_id")) != expected_stable_id:
            raise E2EEEnvelopeError("encrypted envelope recipient stable id mismatch")
        if expected_address and _non_empty(recipient.get("address")) != expected_address:
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
    if len(delivery_wraps) != len(envelope_recipients_by_did):
        raise E2EEEnvelopeError("encrypted envelope delivery key wrap count mismatch")
    if len(sender_copy_wraps) != 1:
        raise E2EEEnvelopeError("encrypted envelope requires exactly one sender_copy key wrap")
    delivery_wraps_by_did: dict[str, dict[str, Any]] = {}
    for wrap in delivery_wraps:
        wrap_recipient_did = _non_empty(wrap.get("recipient_did"))
        if wrap_recipient_did in delivery_wraps_by_did:
            raise E2EEEnvelopeError("encrypted envelope duplicate delivery wrap recipient")
        delivery_wraps_by_did[wrap_recipient_did] = wrap
    if set(delivery_wraps_by_did) != set(envelope_recipients_by_did):
        raise E2EEEnvelopeError("encrypted envelope delivery wrap recipient did mismatch")
    for recipient_did, recipient in envelope_recipients_by_did.items():
        expected = expected_by_did[recipient_did]
        delivery_wrap = delivery_wraps_by_did[recipient_did]
        expected_stable_id = _non_empty(expected.get("stable_id"))
        expected_address = _non_empty(expected.get("address"))
        if recipient_did.startswith("did:key:") and not expected_stable_id:
            expected_stable_id = ""
            expected_address = ""
        recipient_key_id = _non_empty(recipient.get("encryption_key_id"))
        recipient_wrap_id = _non_empty(recipient.get("wrap_id"))
        if expected_stable_id and _non_empty(delivery_wrap.get("recipient_stable_id")) != expected_stable_id:
            raise E2EEEnvelopeError("encrypted envelope delivery wrap recipient stable id mismatch")
        if expected_address and _non_empty(delivery_wrap.get("recipient_address")) != expected_address:
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
    validate_e2ee_message_envelope(
        envelope,
        kind="mail",
        message_id=message_id,
        conversation_id=conversation_id,
        sender_did=sender_did,
        sender_stable_id=sender_stable_id,
        recipients=[
            {
                "did": recipient_did,
                "stable_id": recipient_stable_id,
                "address": recipient_address,
            }
        ],
        now=now,
    )


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
