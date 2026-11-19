"""WebAuthn ceremony verification at one relying party, holding no state.

The caller supplies the challenge it issued and the relying party it serves,
and keeps everything stateful: making each challenge single-use, storing the
credential, and advancing its counter atomically. User verification is always
required. Every failure, malformed input included, is a `WebAuthnRefused`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from webauthn import (
    generate_registration_options,
    verify_registration_response,
)
from webauthn.helpers import options_to_json_dict
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from aweb_naapp.runtime.passkeys.rp import RelyingParty
from aweb_naapp.webauthn import AssertionFailure, AssertionRefused
from aweb_naapp.webauthn import verify_assertion as verify_shared_assertion


class WebAuthnRefused(Exception):
    """The ceremony did not verify for this challenge, relying party and key."""


@dataclass(frozen=True)
class RegisteredPasskey:
    credential_id: bytes
    public_key: bytes
    sign_count: int


@dataclass(frozen=True)
class VerifiedAssertion:
    new_sign_count: int


def registration_options(
    *, rp: RelyingParty, subject: str, display_name: str, challenge: bytes, timeout: int
) -> dict[str, Any]:
    """B3 registration options; the caller owns the single-use challenge."""
    options = generate_registration_options(
        rp_id=rp.rp_id,
        rp_name=rp.name,
        user_id=subject.encode("utf-8"),
        user_name=display_name,
        user_display_name=display_name,
        challenge=challenge,
        timeout=timeout,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
    )
    return options_to_json_dict(options)


def verify_registration(
    credential: Mapping[str, Any], *, challenge: bytes, rp: RelyingParty
) -> RegisteredPasskey:
    """Verify a registration made over `challenge` at `rp`, with user verification."""
    try:
        verified = verify_registration_response(
            credential=dict(credential),
            expected_challenge=challenge,
            expected_rp_id=rp.rp_id,
            expected_origin=rp.origin,
            require_user_verification=True,
        )
    except (WebAuthnException, LookupError, TypeError, ValueError) as exc:
        raise WebAuthnRefused("registration did not verify") from exc
    return RegisteredPasskey(
        credential_id=verified.credential_id,
        public_key=verified.credential_public_key,
        sign_count=verified.sign_count,
    )


def verify_assertion(
    proof: Mapping[str, Any],
    *,
    challenge: bytes,
    rp: RelyingParty,
    credential_id: bytes,
    public_key: bytes,
    sign_count: int,
) -> VerifiedAssertion:
    """Verify an assertion over `challenge` at `rp` by the stored credential
    `credential_id`, holding `public_key`, with user verification, whose
    counter has moved past `sign_count` (both zero is a device that does not
    count).

    The proof's credential ID is not covered by its signature, so a proof
    naming any other credential is refused. The caller passes the stored
    credential it chose for the expected subject."""
    try:
        verified = verify_shared_assertion(
            proof,
            expected_challenge=challenge,
            expected_rp_id=rp.rp_id,
            expected_origin=rp.origin,
            public_key=public_key,
            credential_id=credential_id,
            sign_count=sign_count,
        )
    except AssertionRefused as exc:
        if exc.reason is AssertionFailure.CREDENTIAL_MISMATCH:
            raise WebAuthnRefused("assertion names another credential") from exc
        raise WebAuthnRefused("assertion did not verify") from exc
    return VerifiedAssertion(new_sign_count=verified.new_sign_count)
