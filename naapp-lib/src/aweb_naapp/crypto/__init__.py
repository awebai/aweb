"""RFC 9180 base-mode single-shot HPKE, X25519/HKDF-SHA256/ChaCha20-Poly1305.

Requires the separate ``crypto`` extra. The envelope is the 32-byte
encapsulated key followed by the authenticated ciphertext. AAD is empty. Context binding
(``info``) is mandatory; callers choose its protocol-specific bytes.
"""

from cryptography.hazmat.primitives import hpke
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

_SUITE = hpke.Suite(hpke.KEM.X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.CHACHA20_POLY1305)


def seal(public_key: bytes, plaintext: bytes, *, info: bytes) -> bytes:
    """Seal to raw X25519 public bytes, with a fresh encapsulation each time."""
    return _SUITE.encrypt(plaintext, X25519PublicKey.from_public_bytes(public_key), info)


def open_sealed(private_key: bytes, sealed: bytes, *, info: bytes) -> bytes:
    """Open with raw X25519 private bytes; authentication failures propagate."""
    return _SUITE.decrypt(sealed, X25519PrivateKey.from_private_bytes(private_key), info)
