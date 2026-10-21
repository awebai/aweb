"""Stateless WebAuthn verification over a caller-supplied challenge and relying party."""

from __future__ import annotations

import hashlib

import pytest

from aweb_naapp.runtime.passkeys import (
    RelyingParty,
    WebAuthnRefused,
    verify_assertion,
    verify_registration,
)
from tests.runtime.approvals.soft_authenticator import SoftAuthenticator, b64url

RP = RelyingParty(origin="https://app.example.com", name="Example")
OTHER_RP = RelyingParty(origin="https://other.example.com", name="Other")
CHALLENGE = hashlib.sha256(b"owner-act signing bytes").digest()


def registration_options(challenge: bytes = CHALLENGE, rp: RelyingParty = RP) -> dict:
    return {
        "rp": {"id": rp.rp_id, "name": rp.name},
        "user": {"id": b64url(b"owner-1"), "name": "owner", "displayName": "owner"},
        "challenge": b64url(challenge),
    }


def assertion_options(challenge: bytes = CHALLENGE, rp: RelyingParty = RP) -> dict:
    return {"rpId": rp.rp_id, "challenge": b64url(challenge)}


def enrolled():
    device = SoftAuthenticator(RP.origin)
    passkey = verify_registration(device.create(registration_options()), challenge=CHALLENGE, rp=RP)
    return device, passkey


def test_a_registration_over_the_callers_challenge_yields_the_devices_key():
    device = SoftAuthenticator(RP.origin)
    credential = device.create(registration_options())
    passkey = verify_registration(credential, challenge=CHALLENGE, rp=RP)
    [held] = device.credentials.values()
    assert passkey.credential_id == held.credential_id
    assert passkey.public_key == held.cose_public_key()
    assert passkey.sign_count == 0


def test_an_assertion_over_the_callers_challenge_verifies_with_the_registered_key():
    device, passkey = enrolled()
    verified = verify_assertion(
        device.get(assertion_options()),
        challenge=CHALLENGE,
        rp=RP,
        credential_id=passkey.credential_id,
        public_key=passkey.public_key,
        sign_count=passkey.sign_count,
    )
    assert verified.new_sign_count == 1


def test_a_registration_is_refused_for_another_challenge_origin_or_relying_party():
    other = hashlib.sha256(b"another act").digest()
    device = SoftAuthenticator(RP.origin)
    with pytest.raises(WebAuthnRefused):
        verify_registration(device.create(registration_options(other)), challenge=CHALLENGE, rp=RP)
    with pytest.raises(WebAuthnRefused):
        verify_registration(
            device.create(registration_options(), origin="https://evil.example"),
            challenge=CHALLENGE,
            rp=RP,
        )
    with pytest.raises(WebAuthnRefused):
        verify_registration(device.create(registration_options()), challenge=CHALLENGE, rp=OTHER_RP)


def test_a_registration_without_user_verification_is_refused():
    device = SoftAuthenticator(RP.origin)
    credential = device.create(registration_options(), user_verified=False)
    with pytest.raises(WebAuthnRefused):
        verify_registration(credential, challenge=CHALLENGE, rp=RP)


def test_an_assertion_is_refused_for_another_challenge_origin_relying_party_or_key():
    device, passkey = enrolled()
    other = hashlib.sha256(b"another act").digest()
    _, stranger = enrolled()
    attempts = [
        (device.get(assertion_options(other)), RP, passkey.public_key),
        (device.get(assertion_options(), origin="https://evil.example"), RP, passkey.public_key),
        (device.get(assertion_options()), OTHER_RP, passkey.public_key),
        (device.get(assertion_options()), RP, stranger.public_key),
    ]
    for proof, rp, public_key in attempts:
        with pytest.raises(WebAuthnRefused):
            verify_assertion(
                proof,
                challenge=CHALLENGE,
                rp=rp,
                credential_id=passkey.credential_id,
                public_key=public_key,
                sign_count=0,
            )


def test_an_assertion_naming_another_credential_than_the_stored_one_is_refused():
    device, passkey = enrolled()
    _, stranger = enrolled()
    with pytest.raises(WebAuthnRefused):
        verify_assertion(
            device.get(assertion_options()),
            challenge=CHALLENGE,
            rp=RP,
            credential_id=stranger.credential_id,
            public_key=passkey.public_key,
            sign_count=0,
        )
    relabelled = device.get(assertion_options())
    relabelled["id"] = relabelled["rawId"] = b64url(stranger.credential_id)
    with pytest.raises(WebAuthnRefused):
        verify_assertion(
            relabelled,
            challenge=CHALLENGE,
            rp=RP,
            credential_id=passkey.credential_id,
            public_key=passkey.public_key,
            sign_count=0,
        )


def test_an_assertion_without_user_verification_is_refused():
    device, passkey = enrolled()
    with pytest.raises(WebAuthnRefused):
        verify_assertion(
            device.get(assertion_options(), user_verified=False),
            challenge=CHALLENGE,
            rp=RP,
            credential_id=passkey.credential_id,
            public_key=passkey.public_key,
            sign_count=passkey.sign_count,
        )


def test_an_assertion_whose_counter_does_not_advance_is_refused():
    device, passkey = enrolled()
    first = verify_assertion(
        device.get(assertion_options()),
        challenge=CHALLENGE,
        rp=RP,
        credential_id=passkey.credential_id,
        public_key=passkey.public_key,
        sign_count=passkey.sign_count,
    )
    with pytest.raises(WebAuthnRefused):
        verify_assertion(
            device.get(assertion_options(), count_step=0),
            challenge=CHALLENGE,
            rp=RP,
            credential_id=passkey.credential_id,
            public_key=passkey.public_key,
            sign_count=first.new_sign_count,
        )


def test_an_assertion_against_a_corrupt_stored_key_is_refused():
    device, passkey = enrolled()
    for corrupt in (b"", b"garbage", b"\xa1\x01\x02"):
        with pytest.raises(WebAuthnRefused):
            verify_assertion(
                device.get(assertion_options()),
                challenge=CHALLENGE,
                rp=RP,
                credential_id=passkey.credential_id,
                public_key=corrupt,
                sign_count=0,
            )


def test_malformed_ceremonies_are_refused():
    _, passkey = enrolled()
    with pytest.raises(WebAuthnRefused):
        verify_registration({"id": "x"}, challenge=CHALLENGE, rp=RP)
    with pytest.raises(WebAuthnRefused):
        verify_assertion(
            {"rawId": "!"},
            challenge=CHALLENGE,
            rp=RP,
            credential_id=passkey.credential_id,
            public_key=passkey.public_key,
            sign_count=0,
        )
