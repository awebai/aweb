"""Domain exceptions for aweb service layers.

Service modules raise these instead of fastapi.HTTPException so they
remain transport-agnostic. The REST layer registers an exception handler
that converts them to appropriate HTTP responses; the MCP layer catches
them and returns JSON error payloads.
"""

from __future__ import annotations


class ServiceError(Exception):
    """Base for all service-layer errors. Carries a status code and detail string."""

    status_code: int = 500

    def __init__(self, detail: str = "Internal service error") -> None:
        self.detail = detail
        super().__init__(detail)


class NotFoundError(ServiceError):
    status_code: int = 404

    def __init__(self, detail: str = "Not found") -> None:
        super().__init__(detail)


class ValidationError(ServiceError):
    status_code: int = 422

    def __init__(self, detail: str = "Validation error") -> None:
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
