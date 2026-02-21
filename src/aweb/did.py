"""Ed25519 keypair generation and did:key encoding/decoding.

Implements the did:key method per clawdid/sot.md §2.2:
multicodec 0xed01 prefix + base58btc encoding + "did:key:z" prefix.
"""

import base58 as b58
from nacl.signing import SigningKey

# Ed25519 multicodec prefix (varint-encoded 0xed)
_MULTICODEC_ED25519 = b"\xed\x01"
_MULTICODEC_LEN = len(_MULTICODEC_ED25519)
_ED25519_KEY_LEN = 32
_DID_KEY_PREFIX = "did:key:z"


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate an Ed25519 keypair. Returns (seed, public_key) as raw 32-byte values.

    The seed is the 32-byte NaCl/libsodium seed from which the signing key is derived.
    """
    signing_key = SigningKey.generate()
    return bytes(signing_key), bytes(signing_key.verify_key)


def did_from_public_key(public_key: bytes) -> str:
    """Construct a did:key from a raw 32-byte Ed25519 public key."""
    if len(public_key) != _ED25519_KEY_LEN:
        raise ValueError(
            f"Ed25519 public key must be {_ED25519_KEY_LEN} bytes, got {len(public_key)}"
        )
    multicodec_key = _MULTICODEC_ED25519 + public_key
    return _DID_KEY_PREFIX + b58.b58encode(multicodec_key).decode("ascii")


def public_key_from_did(did: str) -> bytes:
    """Extract the raw 32-byte Ed25519 public key from a did:key string."""
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
    """Check if a string is a valid did:key for Ed25519 without raising."""
    try:
        public_key_from_did(did)
        return True
    except Exception:
        return False
