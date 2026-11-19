"""Stable serialization helpers for strict authority-core failures."""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

from awid.federation_errors import FederationAuthorityError

if TYPE_CHECKING:
    from aweb.messaging.delivery_policy import DeliveryPolicyRefused


class FederationPolicyRefused(FederationAuthorityError):
    """A stable federation reason retaining the canonical policy's next action."""

    def __init__(self, refusal: DeliveryPolicyRefused) -> None:
        self.detail = refusal.detail
        super().__init__(refusal.code.value)


class RecipientNotResidentError(FederationAuthorityError):
    """An admitted address routes here but its exact identity is not resident."""

    detail = (
        "The recipient is not set up for messaging on the server this address points to. "
        "Ask the recipient or the person who manages that server to check the address "
        "and the recipient's messaging setup."
    )

    def __init__(self) -> None:
        super().__init__("recipient_identity_not_found")


class LocalRecipientNotFoundError(FederationAuthorityError):
    """A local namespace has no selectable current-member recipient."""

    @property
    def detail(self) -> str:
        from aweb.member_team_key import RECIPIENT_RECONNECT_DETAIL

        address = f" {self.address}" if self.address is not None else ""
        return f"Recipient not found. Check the address{address}. " + RECIPIENT_RECONNECT_DETAIL

    def __init__(self, *, address: str | None = None) -> None:
        self.address = address
        super().__init__("recipient_identity_not_found")


def authority_error_body(
    error: FederationAuthorityError,
    *,
    correlation_id: str,
) -> dict[str, Any]:
    """Serialize the canonical federation reason, retryability and correlation identifier."""
    body: dict[str, Any] = {
        "detail": error.detail
        if isinstance(
            error, (RecipientNotResidentError, LocalRecipientNotFoundError, FederationPolicyRefused)
        )
        else error.reason,
        "reason": error.reason,
        "retryable": error.retryable,
        "correlation_id": correlation_id,
    }
    if error.did_aw is not None:
        body["did_aw"] = error.did_aw
    if error.observed_sequence is not None:
        body["observed_sequence"] = error.observed_sequence
    return body
