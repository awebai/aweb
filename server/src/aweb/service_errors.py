"""Domain exceptions for aweb service layers."""

from __future__ import annotations

from enum import StrEnum


RESOURCE_NOT_FOUND_DETAIL = "Not found"
INTERNAL_SERVICE_ERROR_MESSAGE = "The server could not complete this request. Try again; if it keeps failing, contact the server operator."


class ServiceError(Exception):
    """Base for service-layer errors with an HTTP-compatible status code."""

    status_code: int = 500
    headers: dict[str, str] | None = None
    recovery_action: str | None = None

    def __init__(self, detail: str | dict = "Internal service error") -> None:
        self.detail = detail
        super().__init__(detail)


class AuthenticationError(ServiceError):
    status_code = 401


class NotFoundError(ServiceError):
    status_code: int = 404

    def __init__(self, detail: str = RESOURCE_NOT_FOUND_DETAIL) -> None:
        super().__init__(detail)


class ValidationError(ServiceError):
    status_code: int = 422

    def __init__(self, detail: str | dict = "Validation error") -> None:
        super().__init__(detail)


class ConflictError(ServiceError):
    status_code: int = 409

    def __init__(self, detail: str | dict = "Conflict") -> None:
        super().__init__(detail)


class ForbiddenError(ServiceError):
    status_code: int = 403

    def __init__(self, detail: str = "Forbidden") -> None:
        super().__init__(detail)


class CurrentMembershipRefusal(ForbiddenError):
    """A current-member refusal with a stable reason beside its string detail."""

    reason = "team_membership_not_current"


class BadRequestError(ServiceError):
    status_code: int = 400

    def __init__(self, detail: str = "Bad request") -> None:
        super().__init__(detail)


class IdentityBindingCode(StrEnum):
    """Wire reasons distinguishing invalid authority from unavailable evidence."""

    MISMATCH = "identity_binding_mismatch"
    UNAVAILABLE = "identity_binding_unavailable"


class IdentityBindingError(ServiceError):
    """Native binding refusal; HTTP and MCP adapters retain its reason and retry hint."""

    def __init__(self, code: IdentityBindingCode, *, headers: dict[str, str] | None = None):
        self.code = IdentityBindingCode(code)
        self.status_code = 403 if self.code is IdentityBindingCode.MISMATCH else 503
        self.headers = headers
        self.message = (
            "The claimed identity and signing key do not match. "
            "Check the identity and its current public-key binding, "
            "then correct the request and retry."
            if self.code is IdentityBindingCode.MISMATCH
            else "Identity verification is unavailable. Retry when the identity registry is available."
        )
        super().__init__(self.code.value)
