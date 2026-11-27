"""Sender context ambiguity affects sends while retaining DID-scoped identity."""

from aweb.identity_auth_deps import MessagingAuth
from aweb.identity_address import AddressResolution, AddressResolutionState
from aweb.identity_binding import verified_key_sql, verified_projection
from aweb.messaging.sender_address import sender_address
from fastapi import HTTPException
import pytest


def test_multi_context_sender_refusal_names_the_selecting_credential():
    auth = MessagingAuth(
        did_key="did:key:signer",
        did_aw="did:aw:principal",
        address=None,
        address_resolution=AddressResolution(
            state=AddressResolutionState.CONTEXT_REQUIRED
        ),
    )
    assert auth.did_aw == "did:aw:principal"
    with pytest.raises(HTTPException) as refused:
        sender_address(auth)
    assert refused.value.status_code == 409
    text = refused.value.detail["message"]
    assert "X-AWID-Team-Certificate" in text
    assert "--team" in text and "aw 1.36.59 or later" in text


def test_empty_keys_never_verify_a_stored_global_claim():
    row = dict(
        did_key="",
        did_aw_verified_key="",
        did_aw="did:aw:claim",
        address="example.test/claim",
    )
    assert verified_projection(row)["did_aw"] is None
    assert "NULLIF(a.did_key, '') IS NOT NULL" in verified_key_sql("a")


@pytest.mark.parametrize(
    "code,action",
    [
        ("identity_binding_mismatch", "current public-key binding"),
        ("identity_binding_unavailable", "Retry"),
    ],
)
def test_typed_binding_refusal_retains_reason_and_action(code, action):
    from aweb.service_errors import IdentityBindingCode, IdentityBindingError

    error = IdentityBindingError(
        IdentityBindingCode(code), headers={"Retry-After": "7"}
    )
    assert error.detail == code
    assert action in error.message
    assert error.headers == {"Retry-After": "7"}
