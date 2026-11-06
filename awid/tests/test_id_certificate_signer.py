"""Real Ed25519 callback signing; the SDK never takes custody of a key."""

import copy

from nacl.signing import SigningKey
import pytest

from awid.did import did_from_public_key, stable_id_from_public_key
from awid.id_certificates import (
    IDCertificateError,
    id_certificate_signing_bytes,
    sign_id_certificate,
    verify_id_certificate,
)


@pytest.fixture
def signing_case():
    issuer = SigningKey(bytes(range(32)))
    child = SigningKey(bytes(reversed(range(32))))
    certificate = {
        "v": 1,
        "type": "aweb.id-certificate",
        "id": stable_id_from_public_key(bytes(child.verify_key)),
        "domain": "example.com",
        "parent": {"kind": "namespace", "id": "example.com"},
        "kind": "human",
        "issuer_key": did_from_public_key(bytes(issuer.verify_key)),
        "issued_at": "2026-10-28T00:00:00Z",
    }
    return issuer, certificate


@pytest.mark.asyncio
@pytest.mark.parametrize("asynchronous", [False, True])
async def test_signs_once_and_returns_a_strictly_verifiable_certificate(signing_case, asynchronous):
    issuer, certificate = signing_case
    calls = []

    def sign(payload):
        calls.append(payload)
        return certificate["issuer_key"], issuer.sign(payload).signature

    async def async_sign(payload):
        return sign(payload)

    signed = await sign_id_certificate(certificate, signer=async_sign if asynchronous else sign)
    assert calls == [id_certificate_signing_bytes(certificate)]
    assert signed["certificate"] == certificate
    verify_id_certificate(signed, issuer_key=certificate["issuer_key"])


@pytest.mark.asyncio
async def test_shape_refusal_precedes_the_signer(signing_case):
    _, certificate = signing_case
    certificate["id"] = certificate["issuer_key"]  # A human cannot have a local ID.
    calls = []
    with pytest.raises(IDCertificateError) as caught:
        await sign_id_certificate(certificate, signer=lambda payload: calls.append(payload))
    assert caught.value.code == "invalid_shape"
    assert calls == []


@pytest.mark.asyncio
async def test_refusing_signer_exception_propagates_once(signing_case):
    _, certificate = signing_case
    refusal = RuntimeError("session revoked")
    calls = []

    def sign(payload):
        calls.append(payload)
        raise refusal

    with pytest.raises(RuntimeError) as caught:
        await sign_id_certificate(certificate, signer=sign)
    assert caught.value is refusal
    assert len(calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["other_key", "other_bytes", "short", "not_tuple", "not_bytes"])
async def test_bad_signer_result_never_becomes_a_signed_certificate(signing_case, failure):
    issuer, certificate = signing_case

    def sign(payload):
        did = certificate["issuer_key"]
        signature = issuer.sign(payload).signature
        if failure == "other_key":
            other = SigningKey(b"y" * 32)
            return did_from_public_key(bytes(other.verify_key)), other.sign(payload).signature
        if failure == "other_bytes":
            signature = issuer.sign(payload + b"changed").signature
        if failure == "short":
            signature = signature[:-1]
        if failure == "not_tuple":
            return [did, signature]
        if failure == "not_bytes":
            signature = signature.hex()
        return did, signature

    with pytest.raises(IDCertificateError) as caught:
        await sign_id_certificate(certificate, signer=sign)
    assert caught.value.code == "invalid_signature"


@pytest.mark.asyncio
@pytest.mark.parametrize("same_key", [False, True])
async def test_signer_key_subclass_cannot_override_binding(signing_case, same_key):
    issuer, certificate = signing_case
    answered_key = issuer if same_key else SigningKey(b"z" * 32)

    class MisleadingKey(str):
        def __ne__(self, other):
            return False

    def sign(payload):
        return (
            MisleadingKey(did_from_public_key(bytes(answered_key.verify_key))),
            answered_key.sign(payload).signature,
        )

    with pytest.raises(IDCertificateError) as caught:
        await sign_id_certificate(certificate, signer=sign)
    assert caught.value.code == "invalid_signature"


@pytest.mark.asyncio
async def test_returned_certificate_is_the_snapshot_actually_signed(signing_case):
    issuer, certificate = signing_case
    original = copy.deepcopy(certificate)

    async def sign(payload):
        certificate["parent"]["id"] = "other.example.com"
        return original["issuer_key"], issuer.sign(payload).signature

    signed = await sign_id_certificate(certificate, signer=sign)
    assert signed["certificate"] == original
    verify_id_certificate(signed, issuer_key=original["issuer_key"])
