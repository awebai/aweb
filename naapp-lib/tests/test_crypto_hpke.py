"""RFC 9180 known-answer decryption plus real random-key sealing and context binding."""

import json
import secrets
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from aweb_naapp.crypto import open_sealed, seal


def test_rfc9180_known_answer():
    v = json.loads((Path(__file__).parent / "vectors/hpke-rfc9180-base-x25519.json").read_text())
    e = v["encryption"]
    # Native HPKE's single-shot API fixes AAD to empty. First reproduce the
    # published AEAD answer exactly, then check its HPKE key schedule by
    # opening the same known key/nonce/plaintext with empty AAD.
    aead = ChaCha20Poly1305(bytes.fromhex(v["key"]))
    nonce, plaintext = bytes.fromhex(v["base_nonce"]), bytes.fromhex(e["pt"])
    assert aead.encrypt(nonce, plaintext, bytes.fromhex(e["aad"])) == bytes.fromhex(e["ct"])
    ciphertext = aead.encrypt(nonce, plaintext, b"")
    assert (
        open_sealed(
            bytes.fromhex(v["skRm"]),
            bytes.fromhex(v["enc"]) + ciphertext,
            info=bytes.fromhex(v["info"]),
        )
        == plaintext
    )


def test_seal_binds_recipient_and_info():
    key = X25519PrivateKey.generate()
    plaintext = secrets.token_bytes(48)
    sealed = seal(key.public_key().public_bytes_raw(), plaintext, info=b"context")
    assert open_sealed(key.private_bytes_raw(), sealed, info=b"context") == plaintext
    for private, info in [(key, b"other"), (X25519PrivateKey.generate(), b"context")]:
        with pytest.raises(InvalidTag):
            open_sealed(private.private_bytes_raw(), sealed, info=info)
