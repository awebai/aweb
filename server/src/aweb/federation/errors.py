"""Stable serialization helpers for strict authority-core failures."""

from __future__ import annotations

from typing import Any

from awid.federation_errors import FederationAuthorityError


def authority_error_body(
    error: FederationAuthorityError,
    *,
    correlation_id: str,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "detail": error.reason,
        "reason": error.reason,
        "retryable": error.retryable,
        "correlation_id": correlation_id,
    }
    if error.did_aw is not None:
        body["did_aw"] = error.did_aw
    if error.observed_sequence is not None:
        body["observed_sequence"] = error.observed_sequence
    return body
