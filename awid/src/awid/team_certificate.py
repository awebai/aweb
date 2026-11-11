"""Team certificates: decoding the transport header and checking the signature.

One implementation for every verifier that reads a team certificate: the
coordination server's team auth, the naapp team-auth verifier and the hook
delivery receiver. It imports only awid's did:key and canonical-JSON
primitives. Each caller maps ``TeamCertificateError.reason`` onto its own
refusal.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Collection
from typing import Any

from awid.did import public_key_from_did
from awid.signing import (
    VerifyResult,
    canonical_json_bytes,
    verify_signature_with_public_key,
)

__all__ = [
    "MAX_HEADER_BYTES",
    "REASONS",
    "REQUIRED_FIELDS",
    "TeamCertificateError",
    "check_team_certificate",
    "decode_team_certificate",
    "verify_team_certificate_signature",
]

# A real certificate header is well under 4 KiB. Anything longer is refused
# before it is decoded, so unauthenticated input never reaches the JSON parser
# at a size that could exhaust it.
MAX_HEADER_BYTES = 8192


# Why check_team_certificate refuses a certificate. Each is a fault of the
# certificate presented, so each is an invalid credential to the caller.
REASONS = (
    "malformed",
    "unsupported_version",
    "invalid_field",
    "member_key_mismatch",
    "bad_signature",
    "revoked",
    "unregistered",
)

CERTIFICATE_VERSION = 1

# The fields a certificate must carry, each a non-empty string. `version` is
# checked apart. Any other member is signed with the rest and is the reader's
# to interpret, not this module's to judge.
REQUIRED_FIELDS = ("certificate_id", "team_id", "member_did_key", "alias", "signature")


class TeamCertificateError(ValueError):
    """A certificate that cannot be read or does not verify.

    ``reason`` is one of REASONS, or ``invalid_team_key`` when the team key
    the caller supplied does not decode, which is no fault of the certificate.
    The two primitives also answer ``missing_signature``. ``field`` names the
    required field an ``invalid_field`` is about, from REQUIRED_FIELDS or
    ``version``. Nothing a certificate carries, key or value, is ever in the
    message.
    """

    def __init__(self, reason: str, field: str | None = None) -> None:
        super().__init__(reason if field is None else f"{reason}: {field}")
        self.reason = reason
        self.field = field


def decode_team_certificate(header: str) -> dict[str, Any]:
    """Decode the ``X-AWID-Team-Certificate`` header: base64 of a JSON object,
    at most MAX_HEADER_BYTES long."""
    if len(header) > MAX_HEADER_BYTES:
        raise TeamCertificateError("malformed")
    try:
        certificate = json.loads(base64.b64decode(header, validate=True).decode("utf-8"))
    except (binascii.Error, ValueError, UnicodeDecodeError, RecursionError):
        # RecursionError is what deep nesting raises on some Python versions.
        raise TeamCertificateError("malformed") from None
    if not isinstance(certificate, dict):
        raise TeamCertificateError("malformed")
    return certificate


def verify_team_certificate_signature(certificate: dict[str, Any], team_did_key: str) -> None:
    """Verify the certificate's signature, over its canonical JSON without the
    signature, under the team key ``team_did_key``."""
    signature = str(certificate.get("signature") or "")
    if not signature:
        raise TeamCertificateError("missing_signature")
    try:
        team_key = public_key_from_did(team_did_key)
    except Exception:
        raise TeamCertificateError("invalid_team_key") from None
    unsigned = {name: value for name, value in certificate.items() if name != "signature"}
    try:
        payload = canonical_json_bytes(unsigned)
    except (TypeError, ValueError):
        # A field that does not encode, such as a lone surrogate, can never
        # match what the team signed.
        raise TeamCertificateError("bad_signature") from None
    if verify_signature_with_public_key(team_key, payload, signature) is not VerifyResult.VERIFIED:
        raise TeamCertificateError("bad_signature")


def check_team_certificate(
    header: str,
    *,
    subject_did_key: str,
    team_did_key: str,
    revoked_certificate_ids: Collection[str],
    registered_certificate_ids: Collection[str] | None,
) -> dict[str, Any]:
    """Check one team certificate and return it.

    ``header`` is the transport header. ``subject_did_key`` is the key the
    certificate must name: a request's signer, or a delivery's producer.
    ``team_did_key`` is the team's current key and the two sets are the team's
    revoked and registered certificate ids, all from the registry and never
    from the certificate. A certificate has no expiry: revocation is its only
    end. The request that carries the certificate, the registry lookups and
    what the certificate's other fields mean are the caller's.

    ``team_did_key`` must be the registry's key for the team this certificate
    names. A caller resolves it from the certificate's ``team_id``, or compares
    that ``team_id`` with the team it resolved the key for, before it uses the
    ``team_id`` for anything: otherwise one team's controller could sign a
    certificate that names another team.

    ``registered_certificate_ids`` has no default. ``None`` says the caller has
    no registered set yet and leaves registration unchecked; it is legal only
    on a surface whose registered-certificate requirement is still switched
    off, and that surface passes the set as soon as the requirement is on.

    Raises TeamCertificateError with a reason from REASONS, in this order:
    the header's shape, the version, the required fields, the subject, the
    signature, revocation, registration.
    """
    certificate = decode_team_certificate(header)
    if "version" not in certificate:
        raise TeamCertificateError("invalid_field", "version")
    version = certificate["version"]
    if type(version) is not int or version != CERTIFICATE_VERSION:
        raise TeamCertificateError("unsupported_version")
    for name in REQUIRED_FIELDS:
        value = certificate.get(name)
        if not isinstance(value, str) or not value.strip():
            raise TeamCertificateError("invalid_field", name)
    if certificate["member_did_key"] != subject_did_key:
        raise TeamCertificateError("member_key_mismatch")
    verify_team_certificate_signature(certificate, team_did_key)
    if certificate["certificate_id"] in revoked_certificate_ids:
        raise TeamCertificateError("revoked")
    if registered_certificate_ids is not None and certificate["certificate_id"] not in registered_certificate_ids:
        raise TeamCertificateError("unregistered")
    return certificate
