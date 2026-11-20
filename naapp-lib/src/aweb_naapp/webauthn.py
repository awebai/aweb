"""Stateless assertion verification shared by identity and app relying parties.

The caller supplies its trusted credential and expected ceremony. It owns
challenge consumption, counters, membership, grading and the resulting effect.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import IntFlag, StrEnum
from typing import Any

import cbor2
from webauthn import verify_authentication_response
from webauthn.helpers import base64url_to_bytes
from webauthn.helpers.exceptions import WebAuthnException

from ._webauthn_client_data import ClientDataInvalid, ClientDataType, verify_client_data
from .webauthn_cbor import decode_cbor_map

__all__ = [
    "AssertionFailure",
    "AssertionRefused",
    "AuthenticatorFlags",
    "BackupPolicy",
    "ClientDataInvalid",
    "ClientDataType",
    "VerifiedAssertion",
    "verify_assertion",
    "verify_client_data",
]


class BackupPolicy(StrEnum):
    ALLOWED = "allowed"
    FORBIDDEN = "forbidden"


class AuthenticatorFlags(IntFlag):
    USER_PRESENT = 0x01
    USER_VERIFIED = 0x04
    BACKUP_ELIGIBLE = 0x08
    BACKED_UP = 0x10
    ATTESTED_CREDENTIAL_DATA = 0x40
    EXTENSIONS = 0x80


class AssertionFailure(StrEnum):
    INVALID = "assertion_invalid"
    COUNTER_NOT_ADVANCED = "assertion_counter_not_advanced"
    CREDENTIAL_MISMATCH = "credential_not_enrolled"
    BACKUP_ELIGIBLE = "credential_backup_eligible"


class AssertionRefused(ValueError):
    def __init__(self, reason: AssertionFailure):
        self.reason = reason
        super().__init__(reason.value)


@dataclass(frozen=True)
class VerifiedAssertion:
    new_sign_count: int
    flags: AuthenticatorFlags


def _response_bytes(proof: Mapping[str, Any], field: str) -> bytes:
    response = proof.get("response")
    if not isinstance(response, Mapping):
        raise AssertionRefused(AssertionFailure.INVALID)
    encoded = response.get(field)
    if not isinstance(encoded, str) or len(encoded) > 2 << 20:
        raise AssertionRefused(AssertionFailure.INVALID)
    return base64url_to_bytes(encoded)


def _assertion_flags(raw: bytes) -> AuthenticatorFlags:
    """UP/UV and complete assertion data: hook-events.md:714-719, protocol:337-345."""
    if len(raw) < 37:
        raise AssertionRefused(AssertionFailure.INVALID)
    flags = AuthenticatorFlags(raw[32])
    required = AuthenticatorFlags.USER_PRESENT | AuthenticatorFlags.USER_VERIFIED
    if (
        flags & required != required
        or flags & AuthenticatorFlags.ATTESTED_CREDENTIAL_DATA
        or (flags & AuthenticatorFlags.BACKED_UP and not flags & AuthenticatorFlags.BACKUP_ELIGIBLE)
    ):
        raise AssertionRefused(AssertionFailure.INVALID)
    if flags & AuthenticatorFlags.EXTENSIONS:
        extensions = decode_cbor_map(raw[37:])
        if any(type(key) is not str for key in extensions):
            raise AssertionRefused(AssertionFailure.INVALID)
    elif len(raw) != 37:
        raise AssertionRefused(AssertionFailure.INVALID)
    return flags


def verify_assertion(
    proof: Mapping[str, Any],
    *,
    expected_challenge: bytes,
    expected_origin: str,
    expected_rp_id: str,
    credential_id: bytes,
    public_key: bytes,
    sign_count: int,
    backup_policy: BackupPolicy = BackupPolicy.ALLOWED,
) -> VerifiedAssertion:
    """Verify exact signed bytes under a caller-trusted credential and context.

    Implements docs/hook-events.md:705-719 and approval protocol.md:337-345.
    A live caller passes its locked counter; a portable proof passes its frozen
    before-counter. No state is read or changed here.
    """
    try:
        if not isinstance(proof, Mapping) or not isinstance(backup_policy, BackupPolicy):
            raise AssertionRefused(AssertionFailure.INVALID)
        verify_client_data(
            _response_bytes(proof, "clientDataJSON"),
            expected_type=ClientDataType.ASSERTION,
            expected_challenge=expected_challenge,
            expected_origin=expected_origin,
        )
        flags = _assertion_flags(_response_bytes(proof, "authenticatorData"))
        verified = verify_authentication_response(
            credential=dict(proof),
            expected_challenge=expected_challenge,
            expected_origin=expected_origin,
            expected_rp_id=expected_rp_id,
            credential_public_key=public_key,
            # Verify crypto once before comparing the caller's locked counter;
            # a zero baseline accepts either supported authenticator counter form.
            credential_current_sign_count=0,
            require_user_verification=True,
        )
        if type(sign_count) is not int or sign_count < 0:
            raise AssertionRefused(AssertionFailure.INVALID)
        if (
            verified.new_sign_count > 0 or sign_count > 0
        ) and verified.new_sign_count <= sign_count:
            raise AssertionRefused(AssertionFailure.COUNTER_NOT_ADVANCED)
        if verified.credential_id != credential_id:
            raise AssertionRefused(AssertionFailure.CREDENTIAL_MISMATCH)
        if backup_policy is BackupPolicy.FORBIDDEN and flags & (
            AuthenticatorFlags.BACKUP_ELIGIBLE | AuthenticatorFlags.BACKED_UP
        ):
            raise AssertionRefused(AssertionFailure.BACKUP_ELIGIBLE)
        return VerifiedAssertion(new_sign_count=verified.new_sign_count, flags=flags)
    except AssertionRefused:
        raise
    except (WebAuthnException, cbor2.CBORDecodeError, LookupError, TypeError, ValueError) as error:
        raise AssertionRefused(AssertionFailure.INVALID) from error
