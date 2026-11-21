"""Released BYOT import preimage (docs/team-control-requests.md).

This codec verifies signature integrity.
The host checks its independently acquired current controller and freshness.
"""

from __future__ import annotations

from dataclasses import dataclass

from awid.signing import canonical_json_bytes, verify_did_key_signature


class TeamControlRequestError(ValueError):
    """The import request has an invalid shape or value."""


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


@dataclass(frozen=True, kw_only=True)
class TeamImportRequest:
    """Released six-field import preimage; nullable body selectors stay intact.

    docs/team-control-requests.md:3: ordinary import retains trim/empty-string
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

    def verify_signature(self, *, signer_did_key: str, signature: str) -> None:
        try:
            verify_did_key_signature(
                did_key=signer_did_key, payload=self.signing_bytes(), signature_b64=signature
            )
        except (ValueError, TypeError) as exc:
            raise TeamControlSignatureError(
                "The team-control signature is invalid. Regenerate it with the controller key and retry."
            ) from exc
