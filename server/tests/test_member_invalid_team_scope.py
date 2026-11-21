"""Malformed revocation scope is not evidence of an unrevoked certificate."""

import pytest
from aweb.service_errors import AuthenticationError
from aweb.team_registry import registered_certificates, revoked_certificates


@pytest.mark.asyncio
@pytest.mark.parametrize("reader", [revoked_certificates, registered_certificates])
async def test_invalid_team_scope_is_refused_before_registry_lookup(reader):
    # The real reader must reject malformed scope even with no registry wired;
    # an empty revocation set would instead bless every admitting certificate.
    with pytest.raises(AuthenticationError) as refused:
        await reader(None, "malformed-team-scope")
    assert refused.value.status_code == 401
    assert (
        refused.value.detail
        == "Team identity is invalid. Reconnect using a certificate for a canonical team ID."
    )
