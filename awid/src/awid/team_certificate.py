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
import hashlib
import json
import re
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from types import MappingProxyType
from typing import Any
from uuid import uuid4

from awid.contract import normalize_identity_scope
from awid.did import did_key_from_signing_key, public_key_from_did
from awid.signing import (
    VerifyResult,
    canonical_json_bytes,
    sign_message,
    verify_signature_with_public_key,
)

__all__ = [
    "MAX_HEADER_BYTES",
    "REASONS",
    "REQUIRED_FIELDS",
    "TeamCertificateError",
    "TeamCertificateReason",
    "TeamCertificateStanding",
    "check_team_certificate",
    "decode_team_certificate",
    "issue_team_certificate",
    "CheckedTeamCertificate",
    "verify_team_certificate_claims",
    "check_team_certificate_evidence",
    "evaluate_team_certificate_standing",
    "refusal_answer",
    "verify_team_certificate_signature",
]

# A real certificate header is well under 4 KiB. Anything longer is refused
# before it is decoded, so unauthenticated input never reaches the JSON parser
# at a size that could exhaust it.
MAX_HEADER_BYTES = 8192


class TeamCertificateReason(StrEnum):
    """Why a team certificate could not be accepted."""

    MALFORMED = "malformed"
    UNSUPPORTED_VERSION = "unsupported_version"
    INVALID_FIELD = "invalid_field"
    MEMBER_KEY_MISMATCH = "member_key_mismatch"
    BAD_SIGNATURE = "bad_signature"
    REVOKED = "revoked"
    UNREGISTERED = "unregistered"
    CERTIFICATE_BINDING_MISMATCH = "certificate_binding_mismatch"
    MISSING_SIGNATURE = "missing_signature"
    INVALID_TEAM_KEY = "invalid_team_key"


# The certificate refusal catalog for check_team_certificate. The signature
# primitive also supplies MISSING_SIGNATURE and INVALID_TEAM_KEY to its callers.
REASONS = (
    TeamCertificateReason.MALFORMED.value,
    TeamCertificateReason.UNSUPPORTED_VERSION.value,
    TeamCertificateReason.INVALID_FIELD.value,
    TeamCertificateReason.MEMBER_KEY_MISMATCH.value,
    TeamCertificateReason.BAD_SIGNATURE.value,
    TeamCertificateReason.REVOKED.value,
    TeamCertificateReason.UNREGISTERED.value,
    TeamCertificateReason.CERTIFICATE_BINDING_MISMATCH.value,
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

    def __init__(self, reason: TeamCertificateReason | str, field: str | None = None) -> None:
        self.reason = TeamCertificateReason(reason)
        super().__init__(self.reason.value if field is None else f"{self.reason}: {field}")
        self.field = field


# A signature as every issuer writes it: standard base64 without padding.
_SIGNATURE = re.compile(r"[A-Za-z0-9+/]+")


def _refuse_constant(_name: str) -> None:
    raise ValueError("not JSON")


def _integer(text: str) -> int:
    """An integer as JSON spells it. -0 is refused: one reader keeps the sign
    when it re-serialises and another drops it."""
    if text == "-0":
        raise ValueError("not portable")
    return int(text)


def _has_only_portable_values(value: Any) -> bool:
    """Whether every verifier re-serialises ``value`` to the same bytes: no
    number that is not an integer, and no control character below U+0020 in a
    string or a key. Encoders write those differently."""
    if isinstance(value, dict):
        return all(
            _has_only_portable_values(k) and _has_only_portable_values(v)
            for k, v in value.items()
        )
    if isinstance(value, list):
        return all(_has_only_portable_values(item) for item in value)
    if isinstance(value, str):
        return not any(ord(character) < 0x20 for character in value)
    return not isinstance(value, float)


def decode_team_certificate(header: str) -> dict[str, Any]:
    """Decode the ``X-AWID-Team-Certificate`` header: base64 of a JSON object,
    at most MAX_HEADER_BYTES long, holding only values that every verifier
    re-serialises alike (_has_only_portable_values), no -0 and no NaN or
    Infinity."""
    if len(header) > MAX_HEADER_BYTES:
        raise TeamCertificateError("malformed")
    try:
        certificate = json.loads(
            base64.b64decode(header, validate=True).decode("utf-8"),
            parse_constant=_refuse_constant,
            parse_int=_integer,
        )
    except (binascii.Error, ValueError, UnicodeDecodeError, RecursionError):
        # RecursionError is what deep nesting raises on some Python versions.
        raise TeamCertificateError("malformed") from None
    if not isinstance(certificate, dict) or not _has_only_portable_values(certificate):
        raise TeamCertificateError("malformed")
    return certificate


def verify_team_certificate_signature(
    certificate: dict[str, Any], team_did_key: str
) -> None:
    """Verify the certificate's signature, over its canonical JSON without the
    signature, under the team key ``team_did_key``."""
    signature = str(certificate.get("signature") or "")
    if not signature:
        raise TeamCertificateError("missing_signature")
    try:
        team_key = public_key_from_did(team_did_key)
    except Exception:
        raise TeamCertificateError("invalid_team_key") from None
    unsigned = {
        name: value for name, value in certificate.items() if name != "signature"
    }
    try:
        payload = canonical_json_bytes(unsigned)
    except (TypeError, ValueError):
        # A field that does not encode, such as a lone surrogate, can never
        # match what the team signed.
        raise TeamCertificateError("bad_signature") from None
    if (
        verify_signature_with_public_key(team_key, payload, signature)
        is not VerifyResult.VERIFIED
    ):
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
    signature (``malformed`` when it is not unpadded standard base64, then
    ``bad_signature``), revocation, registration.
    """
    checked = verify_team_certificate_claims(
        header,
        subject_did_key=subject_did_key,
        team_did_key=team_did_key,
    )
    return check_team_certificate_evidence(
        checked,
        revoked_certificate_ids=revoked_certificate_ids,
        registered_certificate_ids=registered_certificate_ids,
    )


@dataclass(frozen=True)
class CheckedTeamCertificate:
    """Immutable verified claims and the exact artifact used by retained proofs.

    The fingerprint is lowercase SHA256 hex of canonical_artifact, including the
    original signature. Its team key is independently selected authority, not a
    claim copied from the certificate (docs/team-auth-envelope-v2.md:60-70).
    """

    claims: Mapping[str, Any]
    team_did_key: str
    canonical_artifact: bytes
    fingerprint: str


def _freeze_certificate_value(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType(
            {key: _freeze_certificate_value(item) for key, item in value.items()}
        )
    if isinstance(value, list):
        return tuple(_freeze_certificate_value(item) for item in value)
    return value


def _copy_certificate_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _copy_certificate_value(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_copy_certificate_value(item) for item in value]
    return value


def verify_team_certificate_claims(
    header: str,
    *,
    subject_did_key: str,
    team_did_key: str,
) -> CheckedTeamCertificate:
    """Check shape, subject and crypto once (docs/team-auth-envelope-v2.md:60-61)."""
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
    if _SIGNATURE.fullmatch(certificate["signature"]) is None:
        raise TeamCertificateError("malformed")
    verify_team_certificate_signature(certificate, team_did_key)
    canonical_artifact = canonical_json_bytes(certificate)
    return CheckedTeamCertificate(
        claims=_freeze_certificate_value(certificate),
        team_did_key=team_did_key,
        canonical_artifact=canonical_artifact,
        fingerprint=hashlib.sha256(canonical_artifact).hexdigest(),
    )


class TeamCertificateStanding(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"
    UNREGISTERED = "unregistered"


def evaluate_team_certificate_standing(
    *,
    revoked: bool,
    registered: bool | None,
) -> TeamCertificateStanding:
    """Apply acquired standing evidence. None deliberately omits registration.

    A caller handles unavailable evidence before applying required registration.
    A revocation takes precedence over any registration result.
    """
    if revoked:
        return TeamCertificateStanding.REVOKED
    if registered is False:
        return TeamCertificateStanding.UNREGISTERED
    return TeamCertificateStanding.ACTIVE


def check_team_certificate_evidence(
    checked: CheckedTeamCertificate,
    *,
    revoked_certificate_ids: Collection[str],
    registered_certificate_ids: Collection[str] | None,
) -> dict[str, Any]:
    """Apply standing to checked claims; no crypto or parsing is repeated.

    Publication/revocation authority remains external (docs/team-auth-envelope-v2.md:63-70).
    A revocation-only continuation receives the checked result from its caller,
    not an exception that can bypass malformed/subject/signature refusals.
    """
    certificate = checked.claims
    certificate_id = certificate["certificate_id"]
    standing = evaluate_team_certificate_standing(
        revoked=certificate_id in revoked_certificate_ids,
        registered=(
            certificate_id in registered_certificate_ids
            if registered_certificate_ids is not None
            else None
        ),
    )
    if standing is not TeamCertificateStanding.ACTIVE:
        raise TeamCertificateError(standing.value)
    return _copy_certificate_value(certificate)


def refusal_answer(error: TeamCertificateError) -> tuple[int, str]:
    """The status and diagnostic for a refused certificate before transport mapping.

    A fault of the certificate is an invalid credential: 401, with the reason
    and, for ``invalid_field``, the field's name. A team key from the registry
    that does not decode is the registry's fault: 503 ``authority_unavailable``.
    403 is never a certificate's answer: it is for a valid member who is not
    allowed the action, which is the caller's to decide.
    """
    if error.reason == "invalid_team_key":
        return 503, "authority_unavailable"
    return 401, str(error)


def issue_team_certificate(
    *,
    team_id: str,
    team_signing_key: bytes,
    member_did_key: str,
    alias: str,
    identity_scope: str | None = None,
    member_did_aw: str | None = None,
    member_address: str | None = None,
    certificate_id: str | None = None,
    issued_at: str | None = None,
    lifetime: str | None = None,
) -> tuple[dict[str, Any], str]:
    """Issue public certificate bytes using held team authority, without I/O.

    The caller establishes custody and controller authority. Explicit IDs/times
    are preserved so retained operations replay the same artifact. Legacy lifetime
    is an input alias; emitted certificates use identity_scope.
    """
    for name, value in (
        ("team_id", team_id),
        ("member_did_key", member_did_key),
        ("alias", alias),
    ):
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"Provide a nonempty {name} to issue a team certificate.")
    certificate = {
        "version": CERTIFICATE_VERSION,
        "certificate_id": str(uuid4()) if certificate_id is None else certificate_id,
        "team_id": team_id,
        "team_did_key": did_key_from_signing_key(team_signing_key),
        "member_did_key": member_did_key,
        "alias": alias,
        "identity_scope": normalize_identity_scope(
            identity_scope if identity_scope is not None else lifetime
        ),
        "issued_at": (
            datetime.now(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
            if issued_at is None
            else issued_at
        ),
    }
    if member_did_aw:
        certificate["member_did_aw"] = member_did_aw
    if member_address:
        certificate["member_address"] = member_address
    certificate["signature"] = sign_message(
        team_signing_key, canonical_json_bytes(certificate)
    )
    return certificate, base64.b64encode(canonical_json_bytes(certificate)).decode(
        "ascii"
    )
