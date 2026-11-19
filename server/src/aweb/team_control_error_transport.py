"""One expected-error mapping for native and hosted controller operations."""

from fastapi import FastAPI, Request
from starlette.responses import JSONResponse

from aweb.team_control_authority import TeamControlError


def team_control_error_response(error: TeamControlError) -> JSONResponse:
    """Preserve the owner's status/code/action; middleware may call this too."""
    return JSONResponse(status_code=error.status_code, content={"detail": error.detail})


async def _team_control_handler(
    request: Request, error: TeamControlError
) -> JSONResponse:
    return team_control_error_response(error)


def install_team_control_error_handlers(app: FastAPI) -> None:
    """Map only expected controller refusals; unrelated failures keep host policy."""
    app.add_exception_handler(TeamControlError, _team_control_handler)
