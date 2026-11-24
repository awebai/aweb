"""Address discovery outcomes, separate from identity and team authority."""

from dataclasses import dataclass, field, replace
from enum import StrEnum

from fastapi import HTTPException


class AddressResolutionState(StrEnum):
    NOT_REQUESTED = "not_requested"
    EMPTY = "empty"
    WITHHELD = "withheld"
    VERIFIED = "verified"
    UNKNOWN = "unknown"
    CONTEXT_REQUIRED = "context_required"
    UNSELECTED = "unselected"


@dataclass(frozen=True)
class AddressResolution:
    state: AddressResolutionState = AddressResolutionState.NOT_REQUESTED
    cause: Exception | None = field(default=None, repr=False, compare=False)
    stored_binding_verified: bool = False
    stored_address: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "state", AddressResolutionState(self.state))

    def with_stored_bindings(self, rows, *, did_key: str, did_aw: str):
        """Use only unambiguous bindings verified for this exact current key.

        Empty is a verified value too. Conflicting stored addresses do not
        choose a new From, and an unverified projection supplies no fallback.
        """
        addresses = {
            (row.get("address") or "").strip() or None
            for row in rows
            if row.get("did_aw_verified_key") == did_key and row.get("did_aw") == did_aw
        }
        if len(addresses) != 1:
            return self
        return replace(self, stored_binding_verified=True, stored_address=addresses.pop())


def require_address_evidence(auth) -> None:
    """Refuse address-dependent effects without turning a failed read empty."""
    outcome = getattr(auth, "address_resolution", None)
    if outcome is not None and outcome.state is AddressResolutionState.CONTEXT_REQUIRED:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "sender_context_required",
                "message": "This identity has multiple sender contexts. Present the intended team's certificate in X-AWID-Team-Certificate. With aw 1.36.59 or later, pass --team to select the intended sender address.",
            },
        )
    if (
        outcome is not None
        and outcome.state is AddressResolutionState.UNKNOWN
        and not outcome.stored_binding_verified
    ):
        raise HTTPException(
            status_code=503,
            detail={
                "code": "address_evidence_unavailable",
                "message": "Address evidence is unavailable. Retry in a moment.",
            },
        ) from outcome.cause
