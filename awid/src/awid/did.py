"""Ed25519 keypair generation, did:key encoding/decoding, and stable-id derivation."""

from __future__ import annotations

import base64
import hashlib

import base58 as b58
from nacl.signing import SigningKey

_MULTICODEC_ED25519 = b"\xed\x01"
_MULTICODEC_LEN = len(_MULTICODEC_ED25519)
_ED25519_KEY_LEN = 32
_DID_KEY_PREFIX = "did:key:z"


def generate_keypair() -> tuple[bytes, bytes]:
    signing_key = SigningKey.generate()
    return bytes(signing_key), bytes(signing_key.verify_key)


def did_from_public_key(public_key: bytes) -> str:
    if len(public_key) != _ED25519_KEY_LEN:
        raise ValueError(
            f"Ed25519 public key must be {_ED25519_KEY_LEN} bytes, got {len(public_key)}"
        )
    multicodec_key = _MULTICODEC_ED25519 + public_key
    return _DID_KEY_PREFIX + b58.b58encode(multicodec_key).decode("ascii")


def public_key_from_did(did: str) -> bytes:
    if not did.startswith(_DID_KEY_PREFIX):
        raise ValueError(f"DID must start with '{_DID_KEY_PREFIX}', got '{did[:20]}'")
    encoded = did[len(_DID_KEY_PREFIX) :]
    try:
        decoded = b58.b58decode(encoded)
    except Exception as e:
        raise ValueError(f"Invalid base58btc encoding: {e}") from e
    if len(decoded) != _MULTICODEC_LEN + _ED25519_KEY_LEN:
        raise ValueError(
            f"Decoded key must be {_MULTICODEC_LEN + _ED25519_KEY_LEN} bytes, got {len(decoded)}"
        )
    if decoded[:_MULTICODEC_LEN] != _MULTICODEC_ED25519:
        raise ValueError(
            f"Invalid multicodec prefix: expected 0xed01, got 0x{decoded[:_MULTICODEC_LEN].hex()}"
        )
    return decoded[_MULTICODEC_LEN:]


def validate_did(did: str) -> bool:
    try:
        public_key_from_did(did)
        return True
    except Exception:
        return False


def encode_public_key(public_key: bytes) -> str:
    if len(public_key) != _ED25519_KEY_LEN:
        raise ValueError(
            f"Ed25519 public key must be {_ED25519_KEY_LEN} bytes, got {len(public_key)}"
        )
    return base64.urlsafe_b64encode(public_key).rstrip(b"=").decode("ascii")


def decode_public_key(encoded: str) -> bytes:
    padded = encoded + "=" * (-len(encoded) % 4)
    try:
        raw = base64.b64decode(padded, altchars=b"-_", validate=True)
    except Exception:
        try:
            raw = base64.b64decode(padded, validate=True)
        except Exception:
            raise ValueError("public_key must be valid base64 (url-safe or standard) no-padding")
    if len(raw) != _ED25519_KEY_LEN:
        raise ValueError(f"Decoded key must be {_ED25519_KEY_LEN} bytes, got {len(raw)}")
    return raw


_STABLE_ID_PREFIX = "did:aw:"
_STABLE_ID_BYTES_LEN = 20


def stable_id_from_public_key(public_key: bytes) -> str:
    if len(public_key) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    digest = hashlib.sha256(public_key).digest()[:_STABLE_ID_BYTES_LEN]
    suffix = b58.b58encode(digest).decode("ascii")
    return f"{_STABLE_ID_PREFIX}{suffix}"


def stable_id_from_did_key(did_key: str) -> str:
    pubkey = public_key_from_did(did_key)
    return stable_id_from_public_key(pubkey)


def validate_stable_id(value: str) -> str:
    value = (value or "").strip()
    if not value:
        raise ValueError("stable_id must not be empty")
    if not value.startswith(_STABLE_ID_PREFIX):
        raise ValueError(f"stable_id must start with '{_STABLE_ID_PREFIX}'")
    suffix = value[len(_STABLE_ID_PREFIX) :]
    if not suffix:
        raise ValueError("stable_id suffix must not be empty")
    try:
        decoded = b58.b58decode(suffix)
    except Exception as exc:
        raise ValueError("stable_id suffix must be valid base58btc") from exc
    if len(decoded) != _STABLE_ID_BYTES_LEN:
        raise ValueError(f"stable_id suffix must decode to {_STABLE_ID_BYTES_LEN} bytes")
    return value
