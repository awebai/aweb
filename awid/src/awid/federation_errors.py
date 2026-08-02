"""Stable typed failures shared by strict federation authority primitives."""

from __future__ import annotations

from dataclasses import dataclass


_ERROR_SPECS: dict[str, tuple[int, bool]] = {
    "contact_identity_binding_required": (409, False),
    "federation_authority_cas_conflict": (503, True),
    "federation_authority_coordination_unavailable": (503, True),
    "federation_conversation_invalid": (409, False),
    "federation_envelope_invalid": (422, False),
    "federation_message_replay_conflict": (409, False),
    "federation_rate_limited": (429, True),
    "federation_resolver_busy": (503, True),
    "federation_route_rejected": (502, False),
    "federation_route_timeout": (504, True),
    "federation_route_unavailable": (503, True),
    "federation_signature_invalid": (422, False),
    "federation_timestamp_invalid": (422, False),
    "local_recipient_route_missing": (404, False),
    "local_sender_route_mismatch": (422, False),
    "recipient_address_did_mismatch": (422, False),
    "recipient_current_key_mismatch": (422, False),
    "recipient_encryption_assertion_invalid_or_stale": (422, False),
    "recipient_encryption_assertion_missing": (424, False),
    "recipient_identity_not_found": (404, False),
    "recipient_policy_rejected": (403, False),
    "recipient_route_mismatch": (422, False),
    "recipient_route_missing": (424, False),
    "sender_address_did_mismatch": (422, False),
    "sender_address_required": (422, False),
    "sender_address_wrapper_mismatch": (422, False),
    "sender_current_key_mismatch": (422, False),
    "sender_did_log_invalid": (422, False),
    "sender_did_log_rollback": (409, False),
    "sender_did_log_split_view": (409, False),
    "sender_identity_evidence_too_large": (502, False),
    "sender_identity_not_found": (404, False),
    "sender_identity_unverifiable": (503, True),
    "sender_registry_discovery_failed": (503, True),
    "sender_registry_origin_forbidden": (422, False),
    "sender_registry_protocol_invalid": (502, False),
    "sender_registry_tls_invalid": (502, False),
    "sender_registry_unavailable": (503, True),
    "sender_registry_unresolvable": (422, False),
    "sender_route_mismatch": (422, False),
    "sender_route_missing": (424, False),
    "target_route_mismatch": (421, False),
}


@dataclass(frozen=True)
class FederationErrorSpec:
    reason: str
    http_status: int
    retryable: bool
    retry_after_required: bool


def federation_error_spec(reason: str) -> FederationErrorSpec:
    try:
        status, retryable = _ERROR_SPECS[reason]
    except KeyError as exc:
        raise ValueError(f"unknown federation authority reason: {reason}") from exc
    return FederationErrorSpec(
        reason=reason,
        http_status=status,
        retryable=retryable,
        retry_after_required=reason == "federation_rate_limited",
    )


def federation_error_specs() -> tuple[FederationErrorSpec, ...]:
    return tuple(federation_error_spec(reason) for reason in sorted(_ERROR_SPECS))


class FederationAuthorityError(Exception):
    """A stable, non-secret failure from the strict authority core."""

    def __init__(
        self,
        reason: str,
        *,
        did_aw: str | None = None,
        observed_sequence: int | None = None,
    ) -> None:
        self.spec = federation_error_spec(reason)
        self.reason = reason
        self.http_status = self.spec.http_status
        self.retryable = self.spec.retryable
        self.retry_after_required = self.spec.retry_after_required
        self.did_aw = did_aw
        self.observed_sequence = observed_sequence
        super().__init__(reason)
