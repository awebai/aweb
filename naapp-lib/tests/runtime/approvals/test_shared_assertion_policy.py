"""The shared assertion owner enforces counters, backup and signed CBOR policy."""

import hashlib

import cbor2
import pytest
from aweb_naapp_testing.webauthn import b64url, from_b64url
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from aweb_naapp.webauthn import (
    AssertionFailure,
    AssertionRefused,
    AuthenticatorFlags,
    BackupPolicy,
    verify_assertion,
)
from aweb_naapp.webauthn_cbor import LIMITS

from .test_webauthn import CHALLENGE, RP, assertion_options, enrolled


def signed_assertion(
    *, flags=AuthenticatorFlags.USER_PRESENT | AuthenticatorFlags.USER_VERIFIED, extension=b""
):
    device, credential = enrolled()
    proof = device.get(assertion_options())
    response = proof["response"]
    original = from_b64url(response["authenticatorData"])
    authenticator = original[:32] + bytes([flags]) + original[33:37] + extension
    client = from_b64url(response["clientDataJSON"])
    key = device.credentials[credential.credential_id].key
    response["authenticatorData"] = b64url(authenticator)
    response["signature"] = b64url(
        key.sign(authenticator + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
    )
    return proof, credential


def check(proof, credential, *, before=0, backup_policy=BackupPolicy.ALLOWED):
    return verify_assertion(
        proof,
        expected_challenge=CHALLENGE,
        expected_origin=RP.origin,
        expected_rp_id=RP.rp_id,
        credential_id=credential.credential_id,
        public_key=credential.public_key,
        sign_count=before,
        backup_policy=backup_policy,
    )


def test_shared_counter_refusal_is_distinct_from_invalid_signature():
    proof, credential = signed_assertion()
    assert check(proof, credential).new_sign_count == 1
    with pytest.raises(AssertionRefused) as refused:
        check(proof, credential, before=1)
    assert refused.value.reason is AssertionFailure.COUNTER_NOT_ADVANCED
    proof["response"]["signature"] = b64url(b"not a signature")
    with pytest.raises(AssertionRefused) as refused:
        check(proof, credential, before=1)
    assert refused.value.reason is AssertionFailure.INVALID


def test_shared_backup_policy_checks_a_cryptographically_valid_backup_eligible_key():
    flags = (
        AuthenticatorFlags.USER_PRESENT
        | AuthenticatorFlags.USER_VERIFIED
        | AuthenticatorFlags.BACKUP_ELIGIBLE
        | AuthenticatorFlags.BACKED_UP
    )
    proof, credential = signed_assertion(flags=flags)
    assert check(proof, credential).flags == flags
    with pytest.raises(AssertionRefused) as refused:
        check(proof, credential, backup_policy=BackupPolicy.FORBIDDEN)
    assert refused.value.reason is AssertionFailure.BACKUP_ELIGIBLE


@pytest.mark.parametrize(
    "extension",
    [
        cbor2.dumps([]),
        b"\xc0\xa0",  # a semantic tag, before the decoder can erase it
        b"\xa2ax\xf5ax\xf4",  # duplicate map keys
        b"\xa0\xa0",  # another value after the extension map
        cbor2.dumps({str(index): True for index in range(LIMITS["max_map_pairs"] + 1)}),
    ],
)
def test_shared_signed_extension_refusals(extension):
    proof, credential = signed_assertion(
        flags=AuthenticatorFlags.USER_PRESENT
        | AuthenticatorFlags.USER_VERIFIED
        | AuthenticatorFlags.EXTENSIONS,
        extension=extension,
    )
    with pytest.raises(AssertionRefused) as refused:
        check(proof, credential)
    assert refused.value.reason is AssertionFailure.INVALID


def test_shared_signed_extension_map_at_the_profile_boundary_remains_valid():
    extension = cbor2.dumps({str(index): True for index in range(LIMITS["max_map_pairs"])})
    flags = (
        AuthenticatorFlags.USER_PRESENT
        | AuthenticatorFlags.USER_VERIFIED
        | AuthenticatorFlags.EXTENSIONS
    )
    proof, credential = signed_assertion(flags=flags, extension=extension)
    assert check(proof, credential).flags == flags
