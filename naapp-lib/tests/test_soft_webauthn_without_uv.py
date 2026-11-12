"""aweb_naapp_testing.webauthn.without_user_verification: the same assertion,
signed again by its credential with only the user-verification flag cleared."""

import hashlib

import pytest
from aweb_naapp_testing.webauthn import (
    UV,
    SoftAuthenticator,
    from_b64url,
    without_user_verification,
)
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

ORIGIN = "https://human.example.com"


def enrolled():
    device = SoftAuthenticator(ORIGIN)
    device.create(
        {
            "rp": {"id": "human.example.com", "name": "x"},
            "user": {"id": "dXNlcg", "name": "u", "displayName": "u"},
            "challenge": "Y2hhbGxlbmdl",
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
        }
    )
    credential = next(iter(device.credentials.values()))
    assertion = device.get({"rpId": "human.example.com", "challenge": "bG9naW4"}, user_verified=True)
    return credential, assertion


def verifies(public_key, assertion) -> bool:
    response = assertion["response"]
    signed = from_b64url(response["authenticatorData"]) + hashlib.sha256(
        from_b64url(response["clientDataJSON"])
    ).digest()
    try:
        public_key.verify(from_b64url(response["signature"]), signed, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def test_only_the_uv_flag_and_the_signature_change_and_the_new_signature_is_the_credentials():
    credential, assertion = enrolled()
    changed = without_user_verification(assertion, credential.key)
    before, after = from_b64url(assertion["response"]["authenticatorData"]), from_b64url(
        changed["response"]["authenticatorData"]
    )
    assert before[32] & UV and not after[32] & UV
    # RP id hash, the other flags and the counter are untouched.
    assert after[:32] == before[:32] and after[32] == before[32] & ~UV and after[33:] == before[33:]
    for key in ("clientDataJSON", "userHandle"):
        assert changed["response"][key] == assertion["response"][key]
    assert {k: v for k, v in changed.items() if k != "response"} == {
        k: v for k, v in assertion.items() if k != "response"
    }
    assert changed["response"]["signature"] != assertion["response"]["signature"]
    assert verifies(credential.key.public_key(), changed)


def test_another_key_cannot_produce_it():
    credential, assertion = enrolled()
    stranger = ec.generate_private_key(ec.SECP256R1())
    assert not verifies(credential.key.public_key(), without_user_verification(assertion, stranger))


def test_an_assertion_already_without_uv_is_refused():
    credential, assertion = enrolled()
    once = without_user_verification(assertion, credential.key)
    with pytest.raises(ValueError, match="user verification"):
        without_user_verification(once, credential.key)
