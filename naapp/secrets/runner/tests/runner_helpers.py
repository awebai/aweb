"""Real, dispatch-bound HPKE inputs for local runner process tests."""

from cryptography.hazmat.primitives import hpke
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from aweb_secrets_runner.jobs import CredentialInput
from aweb_secrets_runner.protocol import encode64


def credential(ref: str, plaintext: bytes, *, wrong_dispatch: bool = False) -> CredentialInput:
    key = X25519PrivateKey.generate()
    suite = hpke.Suite(hpke.KEM.X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.CHACHA20_POLY1305)
    dispatch = "dsp_" + "a" * 22
    sealed = encode64(suite.encrypt(plaintext, key.public_key(), dispatch.encode()))
    return CredentialInput(ref, sealed, key, dispatch + "wrong" if wrong_dispatch else dispatch)
