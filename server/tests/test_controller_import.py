"""Controller imports retain released signatures and refuse unknown evidence."""

from datetime import datetime, timezone

import pytest
from awid.signing import sign_message
from awid.team_control_requests import TeamImportRequest

from aweb.controller_import import verify_controller_import
from aweb.team_control_authority import (
    TeamControlAuthorityUnavailable,
    TeamControlRequestInvalid,
    TeamControlRequestReason,
)
from tests.test_team_control_authority import unreachable_context


@pytest.mark.asyncio
async def test_import_cannot_accept_signed_metadata_when_current_controller_is_unknown():
    request = TeamImportRequest(
        awid_team_id="import:local",
        organization_id="organization-1",
        team_id=None,
        dry_run=False,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
    signature = sign_message(bytes([81]) * 32, request.signing_bytes())
    async with unreachable_context() as context:
        with pytest.raises(TeamControlAuthorityUnavailable):
            await verify_controller_import(
                context=context, request=request, controller_signature=signature
            )


@pytest.mark.asyncio
async def test_import_rejects_stale_signed_request_before_acquisition():
    request = TeamImportRequest(
        awid_team_id="import:local",
        dry_run=True,
        timestamp="1990-01-01T00:00:00Z",
    )
    async with unreachable_context() as context:
        with pytest.raises(TeamControlRequestInvalid) as error:
            await verify_controller_import(
                context=context,
                request=request,
                controller_signature=sign_message(bytes([81]) * 32, request.signing_bytes()),
            )
    assert error.value.reason is TeamControlRequestReason.TIMESTAMP_INVALID


@pytest.mark.asyncio
async def test_import_rejects_noncanonical_team_before_acquisition():
    request = TeamImportRequest(
        awid_team_id="Import:local",
        dry_run=True,
        timestamp=datetime.now(timezone.utc).isoformat(),
    )
    async with unreachable_context() as context:
        with pytest.raises(TeamControlRequestInvalid) as error:
            await verify_controller_import(
                context=context,
                request=request,
                controller_signature=sign_message(bytes([81]) * 32, request.signing_bytes()),
            )
    assert error.value.reason is TeamControlRequestReason.TEAM_SCOPE_INVALID
