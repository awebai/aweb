"""Expected native authentication failures at HTTP and MCP transport boundaries."""

from fastapi import FastAPI, Request
from starlette.responses import JSONResponse

from aweb.application_state import RegistryClientUnavailable
from aweb.service_errors import IdentityBindingError


def identity_binding_error_response(error: IdentityBindingError) -> JSONResponse:
    """Preserve binding status/reason/retry metadata with an actionable message."""
    return JSONResponse(
        status_code=error.status_code,
        content={"detail": error.detail, "message": error.message},
        headers=error.headers,
    )


def registry_client_error_response(error: RegistryClientUnavailable) -> JSONResponse:
    """Report unavailable serving configuration as the expected actionable 503."""
    return JSONResponse(status_code=error.status_code, content={"detail": error.detail})


def mcp_auth_error_response(
    error: IdentityBindingError | RegistryClientUnavailable,
) -> JSONResponse:
    """Keep MCP authentication's error field and the same typed status/action."""
    headers = error.headers if isinstance(error, IdentityBindingError) else None
    return JSONResponse(
        status_code=error.status_code,
        content={"error": error.detail, "message": error.message},
        headers=headers,
    )


async def _binding_handler(request: Request, error: Exception) -> JSONResponse:
    if not isinstance(error, IdentityBindingError):
        raise error
    return identity_binding_error_response(error)


async def _registry_handler(request: Request, error: Exception) -> JSONResponse:
    if not isinstance(error, RegistryClientUnavailable):
        raise error
    return registry_client_error_response(error)


def install_auth_error_handlers(app: FastAPI) -> None:
    """Install the same expected native auth mapping on standalone and host apps."""
    app.add_exception_handler(IdentityBindingError, _binding_handler)
    app.add_exception_handler(RegistryClientUnavailable, _registry_handler)
