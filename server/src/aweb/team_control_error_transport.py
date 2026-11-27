"""One expected-error mapping for native and hosted controller operations."""

import logging

from fastapi import FastAPI, Request
from starlette.responses import JSONResponse

from aweb.team_control_authority import TeamControlError, TeamControlRegistryDataInvalid

logger = logging.getLogger(__name__)


def team_control_error_response(error: TeamControlError) -> JSONResponse:
    """Preserve the owner's status/code/action; middleware may call this too."""
    if isinstance(error, TeamControlRegistryDataInvalid):
        logger.error(
            "Invalid team-control registry data",
            exc_info=(type(error), error, error.__traceback__),
        )
    elif error.status_code >= 500:
        logger.warning(
            "Team-control evidence unavailable",
            exc_info=(type(error), error, error.__traceback__),
        )
    return JSONResponse(status_code=error.status_code, content={"detail": error.detail})


async def _team_control_handler(request: Request, error: Exception) -> JSONResponse:
    assert isinstance(error, TeamControlError)
    return team_control_error_response(error)


def install_team_control_error_handlers(app: FastAPI) -> None:
    """Map only expected controller refusals; unrelated failures keep host policy."""
    app.add_exception_handler(TeamControlError, _team_control_handler)
