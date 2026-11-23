"""Canonical unowned-team claim artifacts (docs/unowned-team-claim.md).

This codec checks signature integrity. The host establishes controller authority.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from awid.did import did_key_from_signing_key
from awid.signing import canonical_json_bytes, sign_message, verify_did_key_signature

_CLAIM_OPERATION = "claim_unowned_team"
_MAX_ARTIFACT_BYTES = 16384


class ClaimArtifactError(ValueError):
    """The claim request or artifact has an invalid shape or value."""


class ClaimSignatureError(ValueError):
    """The signature does not bind the request to the supplied key."""


def _text(value: object, *, field: str) -> str:
    if not isinstance(value, str):
        raise ClaimArtifactError(
            f"{field} must be text; correct the request and retry."
        )
    try:
        value.encode("utf-8")
    except UnicodeError as exc:
        raise ClaimArtifactError(
            f"{field} must contain valid Unicode; correct the request and retry."
        ) from exc
    return value


def _sign(*, signing_key: bytes, payload: bytes) -> str:
    if not isinstance(signing_key, bytes) or len(signing_key) != 32:
        raise ClaimArtifactError("Use a 32-byte Ed25519 signing seed and retry.")
    return sign_message(signing_key, payload)


def _verify(*, signer_did_key: str, signature: str, payload: bytes) -> None:
    try:
        verify_did_key_signature(
            did_key=signer_did_key, payload=payload, signature_b64=signature
        )
    except (ValueError, TypeError) as exc:
        raise ClaimSignatureError(
            "The claim signature is invalid; regenerate it with the controller key and retry."
        ) from exc


@dataclass(frozen=True, kw_only=True)
class UnownedTeamClaimRequest:
    """Bind the prospective account without copying the host's account policy.

    docs/unowned-team-claim.md: email and username are already normalized
    by their account owner and are signed verbatim, before ownership effects.
    """

    awid_team_id: str
    email: str
    username: str
    timestamp: str

    def __post_init__(self) -> None:
        for field in ("awid_team_id", "email", "username", "timestamp"):
            if not _text(getattr(self, field), field=field).strip():
                raise ClaimArtifactError(
                    f"{field} is required; correct the request and retry."
                )

    def _payload(self) -> dict[str, str]:
        return {
            "operation": _CLAIM_OPERATION,
            "awid_team_id": self.awid_team_id.strip(),
            "email": self.email,
            "username": self.username,
            "timestamp": self.timestamp.strip(),
        }

    def signing_bytes(self) -> bytes:
        return canonical_json_bytes(self._payload())

    def sign(self, *, signing_key: bytes) -> SignedUnownedTeamClaim:
        signature = _sign(signing_key=signing_key, payload=self.signing_bytes())
        return SignedUnownedTeamClaim(
            request=self,
            signer_did_key=did_key_from_signing_key(signing_key),
            signature=signature,
        )

    def verify_signature(self, *, signer_did_key: str, signature: str) -> None:
        _verify(
            signer_did_key=signer_did_key,
            signature=signature,
            payload=self.signing_bytes(),
        )


@dataclass(frozen=True, kw_only=True)
class SignedUnownedTeamClaim:
    """Immutable carrier. The embedded signer is an integrity key, not authority."""

    request: UnownedTeamClaimRequest
    signer_did_key: str
    signature: str

    def __post_init__(self) -> None:
        if not isinstance(self.request, UnownedTeamClaimRequest):
            raise ClaimArtifactError("Use a claim request artifact and retry.")
        _text(self.signer_did_key, field="signer_did_key")
        _text(self.signature, field="signature")

    def to_dict(self) -> dict[str, object]:
        return {
            "request": self.request._payload(),
            "signer_did_key": self.signer_did_key,
            "signature": self.signature,
        }

    def to_json(self) -> bytes:
        return canonical_json_bytes(self.to_dict())

    def verify_integrity(self) -> None:
        self.request.verify_signature(
            signer_did_key=self.signer_did_key, signature=self.signature
        )


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ClaimArtifactError(
                "Duplicate claim field; regenerate the artifact and retry."
            )
        value[key] = item
    return value


def _object(value: object, *, fields: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ClaimArtifactError(
            "Unexpected claim fields; regenerate the artifact and retry."
        )
    return value


def read_unowned_team_claim(value: object) -> SignedUnownedTeamClaim:
    """Read the exact shared schema, without claiming freshness or authority.

    docs/unowned-team-claim.md: reject extra/duplicate fields and trailing
    JSON so every consumer checks the same signed artifact.
    """
    if isinstance(value, (bytes, str)):
        try:
            raw = value.encode("utf-8") if isinstance(value, str) else value
            if len(raw) > _MAX_ARTIFACT_BYTES:
                raise ClaimArtifactError(
                    "Claim artifact is too large; regenerate it and retry."
                )
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
        except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
            raise ClaimArtifactError(
                "Invalid claim JSON; regenerate the artifact and retry."
            ) from exc
    artifact = _object(value, fields={"request", "signer_did_key", "signature"})
    request = _object(
        artifact["request"],
        fields={"operation", "awid_team_id", "email", "username", "timestamp"},
    )
    if request["operation"] != _CLAIM_OPERATION:
        raise ClaimArtifactError(
            "Wrong claim operation; regenerate the artifact and retry."
        )
    return SignedUnownedTeamClaim(
        request=UnownedTeamClaimRequest(
            awid_team_id=_text(request["awid_team_id"], field="awid_team_id"),
            email=_text(request["email"], field="email"),
            username=_text(request["username"], field="username"),
            timestamp=_text(request["timestamp"], field="timestamp"),
        ),
        signer_did_key=_text(artifact["signer_did_key"], field="signer_did_key"),
        signature=_text(artifact["signature"], field="signature"),
    )
