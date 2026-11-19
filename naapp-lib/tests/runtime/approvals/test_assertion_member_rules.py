"""The app verifies exact signed client-data members, like portable approval."""

import hashlib
import json

import pytest
from aweb_naapp_testing.webauthn import b64url, from_b64url
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from aweb_naapp.runtime.passkeys import WebAuthnRefused, verify_assertion

from .test_webauthn import CHALLENGE, RP, assertion_options, enrolled


@pytest.mark.parametrize(
    "client_changes",
    [{"crossOrigin": True}, {"crossOrigin": True, "CROSSORIGIN": False}],
)
def test_cross_origin_assertions_are_refused_even_with_a_valid_signature(client_changes):
    device, credential = enrolled()
    assertion = device.get(assertion_options())
    response = assertion["response"]
    client = json.loads(from_b64url(response["clientDataJSON"]))
    client.update(client_changes)
    raw_client = json.dumps(client, separators=(",", ":")).encode()
    signed = from_b64url(response["authenticatorData"]) + hashlib.sha256(raw_client).digest()
    key = device.credentials[credential.credential_id].key
    response["clientDataJSON"] = b64url(raw_client)
    response["signature"] = b64url(key.sign(signed, ec.ECDSA(hashes.SHA256())))
    with pytest.raises(WebAuthnRefused):
        verify_assertion(
            assertion,
            challenge=CHALLENGE,
            rp=RP,
            credential_id=credential.credential_id,
            public_key=credential.public_key,
            sign_count=credential.sign_count,
        )
