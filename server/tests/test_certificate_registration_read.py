"""Unit boundary: registry-read unavailability never enforces off-mode policy."""

import pytest
from awid.registry import RegistryError
from aweb.certificate_registration import (
    RegistrationMode,
    RegistrationState,
    evaluate_certificate_registration,
    observe_certificate_registrations,
)
from aweb.service_errors import AuthenticationError


class UnavailableCertificateReader:
    """SDK-input stand-in; this test asserts policy adaptation, not authority."""

    async def list_team_certificates(self, domain, name, *, active_only):
        raise RegistryError("test registry unavailable", status_code=503)


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", list(RegistrationMode))
async def test_registration_unavailability_preserves_the_configured_requirement(mode):
    facts = await observe_certificate_registrations(
        registry_client=UnavailableCertificateReader(),
        team_id="backend:example.test",
        mode=mode,
    )
    decision = evaluate_certificate_registration(
        observation=facts,
        certificate_id="member",
        mode=mode,
    )
    assert decision.state is RegistrationState.UNAVAILABLE
    assert decision.unavailable_cause is not None
    assert decision.allows_registration is (mode is RegistrationMode.NOT_REQUIRED)


@pytest.mark.asyncio
async def test_invalid_registration_scope_is_not_an_unavailable_measurement():
    with pytest.raises(AuthenticationError, match="canonical team ID"):
        await observe_certificate_registrations(
            registry_client=UnavailableCertificateReader(),
            team_id="example.test/backend",
            mode=RegistrationMode.NOT_REQUIRED,
        )
