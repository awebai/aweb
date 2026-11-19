"""Team-control preimages and claim artifacts (docs/team-control-requests.md).

These pure codecs establish signature integrity, never controller authority.
The host checks its independently acquired current controller and freshness.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from awid.did import did_key_from_signing_key
from awid.signing import canonical_json_bytes, sign_message, verify_did_key_signature

_CLAIM_OPERATION = "claim_unowned_team"
_MAX_ARTIFACT_BYTES = 16384


class TeamControlRequestError(ValueError):
    """The request or artifact has an invalid shape or value."""


class TeamControlSignatureError(ValueError):
    """The signature does not bind the request to the supplied key."""


def _text(value: object, *, field: str) -> str:
    if not isinstance(value, str):
        raise TeamControlRequestError(
            f"{field} must be text; correct the request and retry."
        )
    try:
        value.encode("utf-8")
    except UnicodeError as exc:
        raise TeamControlRequestError(
            f"{field} must contain valid Unicode; correct the request and retry."
        ) from exc
    return value


def _sign(*, signing_key: bytes, payload: bytes) -> str:
    if not isinstance(signing_key, bytes) or len(signing_key) != 32:
        raise TeamControlRequestError("Use a 32-byte Ed25519 signing seed and retry.")
    return sign_message(signing_key, payload)


def _verify(*, signer_did_key: str, signature: str, payload: bytes) -> None:
    try:
        verify_did_key_signature(
            did_key=signer_did_key, payload=payload, signature_b64=signature
        )
    except (ValueError, TypeError) as exc:
        raise TeamControlSignatureError(
            "The team-control signature is invalid; regenerate it with the controller key and retry."
        ) from exc


@dataclass(frozen=True, kw_only=True)
class TeamImportRequest:
    """Released six-field import preimage; nullable body selectors stay intact.

    docs/team-control-requests.md:10-24: ordinary import retains trim/empty-string
    preimage rules. This metadata signature does not cover member certificates.
    """

    awid_team_id: str
    timestamp: str
    dry_run: bool
    organization_id: str | None = None
    team_id: str | None = None

    def __post_init__(self) -> None:
        _text(self.awid_team_id, field="awid_team_id")
        _text(self.timestamp, field="timestamp")
        for field in ("organization_id", "team_id"):
            value = getattr(self, field)
            if value is not None:
                _text(value, field=field)
        if type(self.dry_run) is not bool:
            raise TeamControlRequestError(
                "dry_run must be a boolean; correct the request and retry."
            )

    def signing_bytes(self) -> bytes:
        return canonical_json_bytes(
            {
                "operation": "byoidt_import",
                "awid_team_id": self.awid_team_id.strip(),
                "organization_id": (self.organization_id or "").strip(),
                "team_id": (self.team_id or "").strip(),
                "dry_run": self.dry_run,
                "timestamp": self.timestamp.strip(),
            }
        )

    def sign(self, *, signing_key: bytes) -> str:
        return _sign(signing_key=signing_key, payload=self.signing_bytes())

    def verify_signature(self, *, signer_did_key: str, signature: str) -> None:
        _verify(
            signer_did_key=signer_did_key,
            signature=signature,
            payload=self.signing_bytes(),
        )


@dataclass(frozen=True, kw_only=True)
class UnownedTeamClaimRequest:
    """Bind the prospective account without copying the host's account policy.

    docs/team-control-requests.md:28-43: email and username are already normalized
    by their account owner and are signed verbatim, before ownership effects.
    """

    awid_team_id: str
    email: str
    username: str
    timestamp: str

    def __post_init__(self) -> None:
        for field in ("awid_team_id", "email", "username", "timestamp"):
            if not _text(getattr(self, field), field=field).strip():
                raise TeamControlRequestError(
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
            raise TeamControlRequestError("Use a claim request artifact and retry.")
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

    def verify_signature(self, *, signer_did_key: str) -> None:
        if self.signer_did_key != signer_did_key:
            raise TeamControlSignatureError(
                "The claim signer differs from the current controller; regenerate the claim and retry."
            )
        self.request.verify_signature(
            signer_did_key=signer_did_key, signature=self.signature
        )


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise TeamControlRequestError(
                "Duplicate claim field; regenerate the artifact and retry."
            )
        value[key] = item
    return value


def _object(value: object, *, fields: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise TeamControlRequestError(
            "Unexpected claim fields; regenerate the artifact and retry."
        )
    return value


def read_unowned_team_claim(value: object) -> SignedUnownedTeamClaim:
    """Read the exact shared schema, without claiming freshness or authority.

    docs/team-control-requests.md:60-67: reject extra/duplicate fields and trailing
    JSON so every consumer checks the same signed artifact.
    """
    if isinstance(value, (bytes, str)):
        try:
            raw = value.encode("utf-8") if isinstance(value, str) else value
            if len(raw) > _MAX_ARTIFACT_BYTES:
                raise TeamControlRequestError(
                    "Claim artifact is too large; regenerate it and retry."
                )
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
        except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
            raise TeamControlRequestError(
                "Invalid claim JSON; regenerate the artifact and retry."
            ) from exc
    artifact = _object(value, fields={"request", "signer_did_key", "signature"})
    request = _object(
        artifact["request"],
        fields={"operation", "awid_team_id", "email", "username", "timestamp"},
    )
    if request["operation"] != _CLAIM_OPERATION:
        raise TeamControlRequestError(
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
