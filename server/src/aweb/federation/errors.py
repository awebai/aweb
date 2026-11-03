"""Stable serialization helpers for strict authority-core failures."""

from __future__ import annotations

from typing import Any

from awid.federation_errors import FederationAuthorityError


class RecipientNotResidentError(FederationAuthorityError):
    """An admitted address routes here but its exact identity is not resident."""

    detail = (
        "Recipient identity is not available for messaging at this server. "
        "Ask the recipient or server operator to check the address and messaging enrollment."
    )

    def __init__(self) -> None:
        super().__init__("recipient_identity_not_found")


def authority_error_body(
    error: FederationAuthorityError,
    *,
    correlation_id: str,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "detail": error.detail if isinstance(error, RecipientNotResidentError) else error.reason,
        "reason": error.reason,
        "retryable": error.retryable,
        "correlation_id": correlation_id,
    }
    if error.did_aw is not None:
        body["did_aw"] = error.did_aw
    if error.observed_sequence is not None:
        body["observed_sequence"] = error.observed_sequence
    return body
