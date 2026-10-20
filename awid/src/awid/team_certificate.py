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
from typing import Any

from awid.did import public_key_from_did
from awid.signing import VerifyResult, canonical_json_bytes, verify_signature_with_public_key

__all__ = ["TeamCertificateError", "decode_team_certificate", "verify_team_certificate_signature"]


class TeamCertificateError(ValueError):
    """A certificate that cannot be read or does not verify.

    ``reason`` is one of ``malformed``, ``missing_signature``,
    ``invalid_team_key`` and ``bad_signature``.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def decode_team_certificate(header: str) -> dict[str, Any]:
    """Decode the ``X-AWID-Team-Certificate`` header: base64 of a JSON object."""
    try:
        certificate = json.loads(base64.b64decode(header, validate=True).decode("utf-8"))
    except (binascii.Error, ValueError, UnicodeDecodeError):
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
    except (TypeError, ValueError):
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
