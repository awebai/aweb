"""Domain exceptions for aweb service layers."""

from __future__ import annotations


RESOURCE_NOT_FOUND_DETAIL = "Not found"


class ServiceError(Exception):
    """Base for service-layer errors with an HTTP-compatible status code."""

    status_code: int = 500

    def __init__(self, detail: str | dict = "Internal service error") -> None:
        self.detail = detail
        super().__init__(detail)


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

    def __init__(self, detail: str = "Conflict") -> None:
        super().__init__(detail)


class ForbiddenError(ServiceError):
    status_code: int = 403

    def __init__(self, detail: str = "Forbidden") -> None:
        super().__init__(detail)


class BadRequestError(ServiceError):
    status_code: int = 400

    def __init__(self, detail: str = "Bad request") -> None:
        super().__init__(detail)
