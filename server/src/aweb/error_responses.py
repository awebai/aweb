"""HTTP serialization of service errors, independent of delivery decisions."""

import logging
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from aweb.messaging.refusals import DeliveryRefusal
from aweb.messaging.delivery_policy import DeliveryPolicyRefused
from aweb.service_errors import ServiceError, INTERNAL_SERVICE_ERROR_MESSAGE
from aweb.auth_error_transport import install_auth_error_handlers

logger = logging.getLogger(__name__)


def install_service_error_handlers(app: FastAPI) -> None:
    """Install the native service-to-HTTP boundary on the serving application."""
    app.add_exception_handler(ServiceError, service_error_handler)
    install_auth_error_handlers(app)


async def service_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """Preserve expected refusal data and hide unexpected server internals.

    docs/mail-and-chat.md's shared HTTP/MCP send contract carries one refusal
    from its service owner; this adapter does not reinterpret its human detail.
    """
    if not isinstance(exc, ServiceError):
        raise TypeError("Service error handler received a different exception type")
    if exc.status_code >= 500 and not isinstance(exc, DeliveryRefusal):
        logger.error("Unhandled service error failure_type=%s", type(exc).__name__)
        return JSONResponse(
            status_code=500,
            content={
                "detail": "Internal server error",
                "message": INTERNAL_SERVICE_ERROR_MESSAGE,
            },
        )
    if exc.status_code >= 500:
        logger.warning(
            "Delivery dependency refused status=%s failure_type=%s",
            exc.status_code,
            type(exc).__name__,
        )
    content = {"detail": exc.detail}
    if isinstance(exc, DeliveryPolicyRefused):
        content["reason"] = exc.code.value
    if exc.recovery_action is not None:
        content["recovery_action"] = exc.recovery_action
    return JSONResponse(
        status_code=exc.status_code, content=content, headers=exc.headers
    )
