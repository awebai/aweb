"""Address discovery outcomes, separate from identity and team authority."""

from dataclasses import dataclass, field, replace
from typing import Literal

from fastapi import HTTPException


@dataclass(frozen=True)
class AddressResolution:
    state: Literal["not_requested", "empty", "verified", "unknown"] = "not_requested"
    cause: Exception | None = field(default=None, repr=False, compare=False)
    stored_binding_verified: bool = False
    stored_address: str | None = None

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
        return replace(
            self, stored_binding_verified=True, stored_address=addresses.pop()
        )


def require_address_evidence(auth) -> None:
    """Refuse address-dependent effects without turning a failed read empty."""
    outcome = getattr(auth, "address_resolution", None)
    if (
        outcome is not None
        and outcome.state == "unknown"
        and not outcome.stored_binding_verified
    ):
        raise HTTPException(
            status_code=503,
            detail={
                "code": "address_evidence_unavailable",
                "message": "Address evidence is unavailable. Retry in a moment.",
            },
        ) from outcome.cause
