"""Holder-owned failures and the explicit shared-library HTTP boundary.

The key-holder README's refusal contract distinguishes caller input, authority,
conflicting state and unavailable infrastructure. A new unmapped library code is
an internal failure, never an accusation of invalid caller credentials.
"""

from enum import StrEnum
from http import HTTPStatus
from typing import Self

from approval_service.verify import Refused as ApprovalRefused


class Refusal(StrEnum):
    """Closed holder wire codes with their HTTP meanings beside their names."""

    http_status: HTTPStatus

    def __new__(cls, code: str, status: HTTPStatus) -> Self:
        member = str.__new__(cls, code)
        member._value_ = code
        member.http_status = status
        return member

    ALREADY_INITIALIZED = ("already_initialized", HTTPStatus.CONFLICT)
    APPROVAL_NOT_CONFIGURED = ("approval_not_configured", HTTPStatus.FORBIDDEN)
    APPROVER_NOT_ACTIVE = ("approver_not_active", HTTPStatus.FORBIDDEN)
    AUDIT_PAGE_INVALID = ("audit_page_invalid", HTTPStatus.BAD_REQUEST)
    BINDING_REFRESH_ENROLLMENT_CHANGED = (
        "binding_refresh_enrollment_changed",
        HTTPStatus.CONFLICT,
    )
    BINDING_REFRESH_IDENTITY_KEY_CHANGED = (
        "binding_refresh_identity_key_changed",
        HTTPStatus.CONFLICT,
    )
    BINDING_REFRESH_PERSON_REQUIRED = (
        "binding_refresh_person_required",
        HTTPStatus.FORBIDDEN,
    )
    BINDING_REFRESH_REQUEST_INVALID = (
        "binding_refresh_request_invalid",
        HTTPStatus.BAD_REQUEST,
    )
    BOOTSTRAP_CLOSED = ("bootstrap_closed", HTTPStatus.FORBIDDEN)
    CALLER_REQUIRED = ("caller_required", HTTPStatus.UNAUTHORIZED)
    CERTIFICATE_MISMATCH = ("certificate_mismatch", HTTPStatus.BAD_REQUEST)
    CONTROLLER_MISMATCH = ("controller_mismatch", HTTPStatus.FORBIDDEN)
    CREATION_CHANGED = ("creation_changed", HTTPStatus.CONFLICT)
    CREATION_MISMATCH = ("creation_mismatch", HTTPStatus.BAD_REQUEST)
    CREATION_REQUIRED = ("creation_required", HTTPStatus.CONFLICT)
    CREDENTIAL_DUPLICATE = ("credential_duplicate", HTTPStatus.BAD_REQUEST)
    ENFORCER_MISMATCH = ("enforcer_mismatch", HTTPStatus.BAD_REQUEST)
    ENFORCER_ORIGIN_INVALID = (
        "enforcer_origin_invalid",
        HTTPStatus.SERVICE_UNAVAILABLE,
    )
    ENROLLMENT_CHANGED = ("enrollment_changed", HTTPStatus.CONFLICT)
    ENROLLMENT_EXPIRED = ("enrollment_expired", HTTPStatus.CONFLICT)
    ENROLLMENT_IDENTITY_MISMATCH = (
        "enrollment_identity_mismatch",
        HTTPStatus.BAD_REQUEST,
    )
    ENROLLMENT_REPLACEMENT_UNAVAILABLE = (
        "enrollment_replacement_unavailable",
        HTTPStatus.CONFLICT,
    )
    ENROLLMENT_UNKNOWN = ("enrollment_unknown", HTTPStatus.NOT_FOUND)
    FRESH_ENROLLMENT_REQUIRED = ("fresh_enrollment_required", HTTPStatus.CONFLICT)
    HUMAN_APPROVAL_HARDWARE_GRADING_REQUIRED = (
        "human_approval_hardware_grading_required",
        HTTPStatus.SERVICE_UNAVAILABLE,
    )
    HUMAN_APPROVAL_INVALID = ("human_approval_invalid", HTTPStatus.SERVICE_UNAVAILABLE)
    HUMAN_APPROVAL_REQUIRED = ("human_approval_required", HTTPStatus.FORBIDDEN)
    HUMAN_APPROVAL_SOURCE_REQUIRED = (
        "human_approval_source_required",
        HTTPStatus.SERVICE_UNAVAILABLE,
    )
    IDENTITY_CHAIN_REQUIRED = ("identity_chain_required", HTTPStatus.UNAUTHORIZED)
    IDENTITY_KEY_MISMATCH = ("identity_key_mismatch", HTTPStatus.BAD_REQUEST)
    IDENTITY_UNAVAILABLE = ("identity_unavailable", HTTPStatus.SERVICE_UNAVAILABLE)
    ISSUER_CHANGED = ("issuer_changed", HTTPStatus.CONFLICT)
    KEY_ALREADY_EXISTS = ("key_already_exists", HTTPStatus.CONFLICT)
    KEY_UNAVAILABLE = ("key_unavailable", HTTPStatus.SERVICE_UNAVAILABLE)
    LEGACY_HUMAN_ISSUANCE_WRITE_HUMAN_APPROVAL = (
        "legacy_human_issuance_write_human_approval",
        HTTPStatus.SERVICE_UNAVAILABLE,
    )
    NONCE_CONFLICT = ("nonce_conflict", HTTPStatus.CONFLICT)
    OPERATION_INVALID = ("operation_invalid", HTTPStatus.BAD_REQUEST)
    OPERATION_NOT_SERVED = ("operation_not_served", HTTPStatus.FORBIDDEN)
    ORGANISATION_MISMATCH = ("organisation_mismatch", HTTPStatus.FORBIDDEN)
    PERSON_ALREADY_EXISTS = ("person_already_exists", HTTPStatus.CONFLICT)
    PERSON_RETIRED = ("person_retired", HTTPStatus.FORBIDDEN)
    REGISTRATION_CHANGED = ("registration_changed", HTTPStatus.CONFLICT)
    REGISTRATION_COUNT_MISMATCH = (
        "registration_count_mismatch",
        HTTPStatus.BAD_REQUEST,
    )
    REQUEST_INVALID = ("request_invalid", HTTPStatus.BAD_REQUEST)
    REQUESTER_MISMATCH = ("requester_mismatch", HTTPStatus.FORBIDDEN)
    SCHEMA_UNAVAILABLE = ("schema_unavailable", HTTPStatus.SERVICE_UNAVAILABLE)
    STATE_CHANGED = ("state_changed", HTTPStatus.CONFLICT)
    STATUS_UNAVAILABLE = ("status_unavailable", HTTPStatus.SERVICE_UNAVAILABLE)
    STORAGE_PERMISSIONS = ("storage_permissions", HTTPStatus.SERVICE_UNAVAILABLE)
    STORAGE_UNAVAILABLE = ("storage_unavailable", HTTPStatus.SERVICE_UNAVAILABLE)
    TARGET_IS_APPROVER = ("target_is_approver", HTTPStatus.FORBIDDEN)


class Refused(ApprovalRefused):
    """An owned failure; callers must select a declared reason."""

    def __init__(self, reason: Refusal) -> None:
        if not isinstance(reason, Refusal):
            raise TypeError("holder refusals require a named Refusal")
        self.reason = reason
        super().__init__(reason)


# The library owns these wire strings; this reviewed table owns only their
# holder HTTP projection. New upstream failures must be classified explicitly.
_APPROVAL_STATUSES: dict[str, HTTPStatus] = {
    "act_identifier_invalid": HTTPStatus.UNAUTHORIZED,
    "activation_invalid": HTTPStatus.UNAUTHORIZED,
    "approval_act_mismatch": HTTPStatus.UNAUTHORIZED,
    "approval_action_unknown": HTTPStatus.UNAUTHORIZED,
    "approval_assertion_invalid": HTTPStatus.UNAUTHORIZED,
    "approver_not_person": HTTPStatus.UNAUTHORIZED,
    "attestation_aaguid_mismatch": HTTPStatus.UNAUTHORIZED,
    "attestation_certificate_invalid": HTTPStatus.UNAUTHORIZED,
    "attestation_chain_invalid": HTTPStatus.UNAUTHORIZED,
    "attestation_extension_invalid": HTTPStatus.UNAUTHORIZED,
    "attestation_profile_unsupported": HTTPStatus.UNAUTHORIZED,
    "binding_credential_mismatch": HTTPStatus.UNAUTHORIZED,
    "binding_mismatch": HTTPStatus.UNAUTHORIZED,
    "binding_unavailable": HTTPStatus.UNAUTHORIZED,
    "body_invalid": HTTPStatus.UNAUTHORIZED,
    "body_too_large": HTTPStatus.UNAUTHORIZED,
    "challenge_binding_mismatch": HTTPStatus.UNAUTHORIZED,
    "challenge_expired": HTTPStatus.UNAUTHORIZED,
    "challenge_not_found": HTTPStatus.UNAUTHORIZED,
    "creation_invalid": HTTPStatus.UNAUTHORIZED,
    "creation_target_mismatch": HTTPStatus.UNAUTHORIZED,
    "credential_conflict": HTTPStatus.UNAUTHORIZED,
    "credential_key_invalid": HTTPStatus.UNAUTHORIZED,
    "credential_limit": HTTPStatus.UNAUTHORIZED,
    "credential_not_enrolled": HTTPStatus.UNAUTHORIZED,
    "credentials_invalid": HTTPStatus.UNAUTHORIZED,
    "csrf_invalid": HTTPStatus.UNAUTHORIZED,
    "deadline_invalid": HTTPStatus.UNAUTHORIZED,
    "deadline_mismatch": HTTPStatus.UNAUTHORIZED,
    "definition_invalid": HTTPStatus.UNAUTHORIZED,
    "definition_mismatch": HTTPStatus.UNAUTHORIZED,
    "definition_unavailable": HTTPStatus.UNAUTHORIZED,
    "discoverable_credential_required": HTTPStatus.UNAUTHORIZED,
    "duplicate_credential": HTTPStatus.UNAUTHORIZED,
    "enrollment_already_confirming": HTTPStatus.UNAUTHORIZED,
    "enrollment_browser_expired": HTTPStatus.UNAUTHORIZED,
    "enrollment_certificate_mismatch": HTTPStatus.UNAUTHORIZED,
    "enrollment_challenge_invalid": HTTPStatus.UNAUTHORIZED,
    "enrollment_conflict": HTTPStatus.UNAUTHORIZED,
    "enrollment_creation_committed": HTTPStatus.UNAUTHORIZED,
    "enrollment_evidence_invalid": HTTPStatus.UNAUTHORIZED,
    "enrollment_evidence_unsupported": HTTPStatus.UNAUTHORIZED,
    "enrollment_identity_changed": HTTPStatus.UNAUTHORIZED,
    "enrollment_identity_unchanged": HTTPStatus.UNAUTHORIZED,
    "enrollment_intent_mismatch": HTTPStatus.UNAUTHORIZED,
    "enrollment_invalid": HTTPStatus.UNAUTHORIZED,
    "enrollment_lifetime_invalid": HTTPStatus.UNAUTHORIZED,
    "enrollment_not_active": HTTPStatus.UNAUTHORIZED,
    "enrollment_not_found": HTTPStatus.UNAUTHORIZED,
    "enrollment_not_pending": HTTPStatus.UNAUTHORIZED,
    "enrollment_previous_mismatch": HTTPStatus.UNAUTHORIZED,
    "enrollment_previous_unavailable": HTTPStatus.UNAUTHORIZED,
    "enrollment_proof_invalid": HTTPStatus.UNAUTHORIZED,
    "enrollment_purpose_mismatch": HTTPStatus.UNAUTHORIZED,
    "enrollment_request_invalid": HTTPStatus.UNAUTHORIZED,
    "enrollment_scope_invalid": HTTPStatus.UNAUTHORIZED,
    "enrollment_user_invalid": HTTPStatus.UNAUTHORIZED,
    "enterprise_attestation_refused": HTTPStatus.UNAUTHORIZED,
    "evidence_binding_mismatch": HTTPStatus.UNAUTHORIZED,
    "evidence_subject_mismatch": HTTPStatus.UNAUTHORIZED,
    "grade_insufficient": HTTPStatus.UNAUTHORIZED,
    "grade_invalid": HTTPStatus.UNAUTHORIZED,
    "http_authorization_invalid": HTTPStatus.UNAUTHORIZED,
    "http_authorization_noncanonical": HTTPStatus.UNAUTHORIZED,
    "http_binding_mismatch": HTTPStatus.UNAUTHORIZED,
    "http_body_mismatch": HTTPStatus.UNAUTHORIZED,
    "http_expired": HTTPStatus.UNAUTHORIZED,
    "http_invalid": HTTPStatus.UNAUTHORIZED,
    "http_status_invalid": HTTPStatus.UNAUTHORIZED,
    "human_approval_unavailable": HTTPStatus.SERVICE_UNAVAILABLE,
    "identifying_attestation_refused": HTTPStatus.UNAUTHORIZED,
    "identity_chain_mismatch": HTTPStatus.UNAUTHORIZED,
    "identity_trust_invalid": HTTPStatus.UNAUTHORIZED,
    "invalid_encoding": HTTPStatus.UNAUTHORIZED,
    "invalid_shape": HTTPStatus.UNAUTHORIZED,
    "issuer_key_invalid": HTTPStatus.UNAUTHORIZED,
    "issuer_mismatch": HTTPStatus.UNAUTHORIZED,
    "issuer_signature_invalid": HTTPStatus.UNAUTHORIZED,
    "issuer_unavailable": HTTPStatus.SERVICE_UNAVAILABLE,
    "locator_mismatch": HTTPStatus.UNAUTHORIZED,
    "login_assertion_invalid": HTTPStatus.UNAUTHORIZED,
    "namespace_authority_unavailable": HTTPStatus.SERVICE_UNAVAILABLE,
    "needs_human_invalid": HTTPStatus.UNAUTHORIZED,
    "nonce_invalid": HTTPStatus.UNAUTHORIZED,
    "origin_invalid": HTTPStatus.UNAUTHORIZED,
    "pending_limit": HTTPStatus.TOO_MANY_REQUESTS,
    "person_mismatch": HTTPStatus.UNAUTHORIZED,
    "presentation_invalid": HTTPStatus.UNAUTHORIZED,
    "public_evidence_invalid": HTTPStatus.UNAUTHORIZED,
    "purpose_invalid": HTTPStatus.UNAUTHORIZED,
    "rate_limited": HTTPStatus.TOO_MANY_REQUESTS,
    "receipt_unavailable": HTTPStatus.UNAUTHORIZED,
    "registration_attestation_invalid": HTTPStatus.UNAUTHORIZED,
    "registration_authenticator_invalid": HTTPStatus.UNAUTHORIZED,
    "registration_authenticator_trailing": HTTPStatus.UNAUTHORIZED,
    "registration_credential_mismatch": HTTPStatus.UNAUTHORIZED,
    "registration_extensions_invalid": HTTPStatus.UNAUTHORIZED,
    "registration_invalid": HTTPStatus.UNAUTHORIZED,
    "registration_uv_required": HTTPStatus.UNAUTHORIZED,
    "request_digest_mismatch": HTTPStatus.UNAUTHORIZED,
    "request_expired": HTTPStatus.UNAUTHORIZED,
    "request_lifetime_invalid": HTTPStatus.UNAUTHORIZED,
    "request_mismatch": HTTPStatus.UNAUTHORIZED,
    "request_not_found": HTTPStatus.UNAUTHORIZED,
    "requester_certificate_inactive": HTTPStatus.UNAUTHORIZED,
    "requester_certificate_invalid": HTTPStatus.UNAUTHORIZED,
    "requester_certificate_mismatch": HTTPStatus.UNAUTHORIZED,
    "requester_identity_invalid": HTTPStatus.UNAUTHORIZED,
    "requester_invalid": HTTPStatus.UNAUTHORIZED,
    "requester_kind_invalid": HTTPStatus.UNAUTHORIZED,
    "requester_namespace_mismatch": HTTPStatus.UNAUTHORIZED,
    "requester_pending_invalid": HTTPStatus.UNAUTHORIZED,
    "requester_status_mismatch": HTTPStatus.UNAUTHORIZED,
    "requester_status_unavailable": HTTPStatus.SERVICE_UNAVAILABLE,
    "root_act_invalid": HTTPStatus.UNAUTHORIZED,
    "root_enforcer_invalid": HTTPStatus.UNAUTHORIZED,
    "root_enforcer_mismatch": HTTPStatus.UNAUTHORIZED,
    "root_history_unavailable": HTTPStatus.UNAUTHORIZED,
    "root_identity_mismatch": HTTPStatus.UNAUTHORIZED,
    "root_key_discontinuous": HTTPStatus.UNAUTHORIZED,
    "root_key_mismatch": HTTPStatus.UNAUTHORIZED,
    "root_person_mismatch": HTTPStatus.UNAUTHORIZED,
    "root_proof_invalid": HTTPStatus.UNAUTHORIZED,
    "root_proof_unsupported": HTTPStatus.UNAUTHORIZED,
    "root_revision_mismatch": HTTPStatus.UNAUTHORIZED,
    "root_team_not_owned": HTTPStatus.UNAUTHORIZED,
    "root_team_organisation_mismatch": HTTPStatus.UNAUTHORIZED,
    "root_teams_not_supported": HTTPStatus.UNAUTHORIZED,
    "selection_conflict": HTTPStatus.UNAUTHORIZED,
    "service_response_invalid": HTTPStatus.UNAUTHORIZED,
    "session_expired": HTTPStatus.UNAUTHORIZED,
    "session_invalid": HTTPStatus.UNAUTHORIZED,
    "session_token_invalid": HTTPStatus.UNAUTHORIZED,
    "signature_invalid": HTTPStatus.UNAUTHORIZED,
    "snapshot_expired": HTTPStatus.UNAUTHORIZED,
    "snapshot_invalid": HTTPStatus.UNAUTHORIZED,
    "snapshot_unavailable": HTTPStatus.UNAUTHORIZED,
    "snapshot_validation_expired": HTTPStatus.UNAUTHORIZED,
    "statement_unavailable": HTTPStatus.UNAUTHORIZED,
    "transition_approver_mismatch": HTTPStatus.UNAUTHORIZED,
    "transition_before_mismatch": HTTPStatus.UNAUTHORIZED,
    "transition_mode_invalid": HTTPStatus.UNAUTHORIZED,
    "transition_receipt_mismatch": HTTPStatus.UNAUTHORIZED,
    "transition_receipt_unavailable": HTTPStatus.UNAUTHORIZED,
    "transition_target_mismatch": HTTPStatus.UNAUTHORIZED,
    "version_invalid": HTTPStatus.UNAUTHORIZED,
}


def refusal_status(error: ApprovalRefused) -> HTTPStatus:
    """Project known failures; an unreviewed code is visible as a server error."""
    if isinstance(error, Refused):
        return error.reason.http_status
    try:
        reason = Refusal(error.code)
    except ValueError:
        return _APPROVAL_STATUSES.get(error.code, HTTPStatus.INTERNAL_SERVER_ERROR)
    return reason.http_status
