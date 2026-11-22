"""Real unreachable transport produces no generation; no database is contacted."""

from contextlib import aclosing
import socket

import pytest
from awid.did import did_key_from_signing_key
from awid.external_authority import SystemTXTOutcomeResolver
from awid.registry import RegistryClient
from awid.team_certificate import issue_team_certificate
from pgdbm import AsyncDatabaseManager, DatabaseConfig

from aweb.certificate_auth import (
    CertificateAuthorityContext,
    TeamControllerUnavailable,
    verify_certificate_generation,
)


@pytest.mark.asyncio
async def test_no_current_controller_proof_returns_no_accepted_generation():
    team, member = bytes([51]) * 32, bytes([52]) * 32
    _, header = issue_team_certificate(
        team_id="generation:local",
        team_signing_key=team,
        member_did_key=did_key_from_signing_key(member),
        alias="worker",
        identity_scope="local",
    )
    # A real manager is supplied, but deliberately not connected: the owner
    # must fail its controller read before attempting a pin/projection query.
    db = AsyncDatabaseManager(
        DatabaseConfig(connection_string="postgresql://unused/test")
    )
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        origin = f"http://127.0.0.1:{reserved.getsockname()[1]}"
        async with aclosing(
            RegistryClient(registry_url=origin, timeout_seconds=0.1)
        ) as sdk:
            context = CertificateAuthorityContext(
                db=db,
                registry_client=sdk,
                txt_resolver=SystemTXTOutcomeResolver(),
            )
            with pytest.raises(TeamControllerUnavailable) as refused:
                await verify_certificate_generation(
                    context=context,
                    team_id="generation:local",
                    encoded_certificate=header,
                    member_did_key=did_key_from_signing_key(member),
                )
    assert refused.value.status_code == 503
    assert refused.value.code == "team_controller_evidence_unavailable"
    assert refused.value.message == (
        "The team's current controller could not be confirmed. "
        "The agent is not usable yet. Repeat the creation request when the "
        "registry is reachable and the team's controller can be confirmed."
    )
    assert refused.value.__cause__ is not None
