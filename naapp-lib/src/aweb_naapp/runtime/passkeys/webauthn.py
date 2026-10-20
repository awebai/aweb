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

from webauthn import verify_authentication_response, verify_registration_response
from webauthn.helpers.exceptions import WebAuthnException

from aweb_naapp.runtime.passkeys.rp import RelyingParty


class WebAuthnRefused(Exception):
    """The ceremony did not verify for this challenge, relying party and key."""


@dataclass(frozen=True)
class RegisteredPasskey:
    credential_id: bytes
    public_key: bytes
    sign_count: int


@dataclass(frozen=True)
class VerifiedAssertion:
    credential_id: bytes
    new_sign_count: int


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
    public_key: bytes,
    sign_count: int,
) -> VerifiedAssertion:
    """Verify an assertion over `challenge` at `rp` by the credential holding
    `public_key`, with user verification, whose counter has moved past
    `sign_count` (both zero is a device that does not count).

    The caller binds the assertion to its subject: it takes `public_key` and
    `sign_count` from the stored credential whose ID the proof names, after
    checking that credential belongs to the expected subject."""
    try:
        verified = verify_authentication_response(
            credential=dict(proof),
            expected_challenge=challenge,
            expected_rp_id=rp.rp_id,
            expected_origin=rp.origin,
            credential_public_key=public_key,
            credential_current_sign_count=sign_count,
            require_user_verification=True,
        )
    # py_webauthn reports a corrupt stored key as a lookup error, not its own.
    except (WebAuthnException, LookupError, TypeError, ValueError) as exc:
        raise WebAuthnRefused("assertion did not verify") from exc
    return VerifiedAssertion(
        credential_id=verified.credential_id, new_sign_count=verified.new_sign_count
    )
