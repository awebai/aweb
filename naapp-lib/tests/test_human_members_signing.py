"""The test human members sign through awid's shared signer, and the bytes they
send are the raw Ed25519 signature that AWID verifies. No I/O."""

import pytest
from aweb_naapp_testing.human_members import _signature
from awid.did import did_from_public_key, generate_keypair
from awid.id_certificates import IDCertificateError, id_certificate_signing_bytes, verify_ed25519
from nacl.signing import SigningKey

CERTIFICATE = {
    "v": 1,
    "type": "aweb.id-certificate",
    "id": "did:aw:2Wq7mXn4kP9rT1vY5zA8bC3dE6",
    "domain": "readers.example",
    "parent": {"kind": "namespace", "id": "readers.example"},
    "kind": "human",
    "issuer_key": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    "issued_at": "2026-11-11T00:00:00Z",
}


def test_a_signature_verifies_under_the_signers_did_key():
    seed, public = generate_keypair()
    message = id_certificate_signing_bytes(CERTIFICATE)
    verify_ed25519(did_from_public_key(public), message, _signature(seed, message))


def test_a_signature_does_not_verify_for_other_bytes():
    seed, public = generate_keypair()
    message = id_certificate_signing_bytes(CERTIFICATE)
    with pytest.raises(IDCertificateError):
        verify_ed25519(did_from_public_key(public), message + b" ", _signature(seed, message))


def test_the_shared_signer_gives_the_raw_ed25519_signature():
    # Ed25519 is deterministic: the wire bytes are exactly the raw signature,
    # whatever text encoding the shared signer uses internally.
    seed = bytes(range(32))
    message = id_certificate_signing_bytes(CERTIFICATE)
    assert _signature(seed, message) == SigningKey(seed).sign(message).signature
