"""Expected generation refusals at native and embedding HTTP boundaries."""

from fastapi import FastAPI, Request
from starlette.responses import JSONResponse

from aweb.certificate_auth import TeamControllerUnavailable


def team_controller_error_response(error: TeamControllerUnavailable) -> JSONResponse:
    """Keep no-proof creation retryable, with its exact admission-pending action.

    Antares0ffc3028 distinguishes an unusable admission from a working agent
    whose registration is pending. This maps only the expected domain error;
    unrelated service failures remain the application's generic error policy.
    """
    return JSONResponse(status_code=error.status_code, content={"detail": error.detail})


async def _controller_handler(request: Request, error: Exception) -> JSONResponse:
    assert isinstance(error, TeamControllerUnavailable)
    return team_controller_error_response(error)


def install_certificate_error_handlers(app: FastAPI) -> None:
    """Use the identical generation mapping on native and outer host boundaries."""
    app.add_exception_handler(TeamControllerUnavailable, _controller_handler)
