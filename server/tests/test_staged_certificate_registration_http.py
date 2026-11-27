"""Native authentication checks revocation without observing off-mode registration."""

from enum import StrEnum

import pytest
from prometheus_client import REGISTRY

from aweb.application_state import application_registry_client
from aweb.certificate_registration import RegistrationMode, RegistrationState
from aweb.member_team_key import read_certificate_standings
from awid.team_certificate import decode_team_certificate
from test_dashboard_privacy import TEAM, privacy_app
from test_member_team_key import _connect
from test_messages_http import _signed_identity_headers

__all__ = ["privacy_app"]


class AuthenticationCredential(StrEnum):
    CERTIFICATE = "certificate"
    IDENTITY_ONLY = "identity-only"


@pytest.mark.asyncio
@pytest.mark.parametrize("credential", list(AuthenticationCredential))
async def test_off_mode_authentication_does_not_read_registration(
    privacy_app,
    monkeypatch,
    credential,
):
    env = privacy_app
    actor = env.actors["alice"]
    monkeypatch.setenv("AWEB_REQUIRE_REGISTERED_CERTIFICATES", "false")
    if credential is AuthenticationCredential.IDENTITY_ONLY:
        connected = await _connect(
            env,
            (actor.sk, actor.did, "alice"),
            actor.certificate,
        )
        assert connected.status_code == 200, connected.text
    metric = "aweb_certificate_registration_observations_total"
    labels = {"enforcement": "not_required", "outcome": "would_refuse"}
    before = REGISTRY.get_sample_value(metric, labels) or 0
    started = len(env.registry.transport.calls)
    if credential is AuthenticationCredential.CERTIFICATE:
        response = await _connect(
            env,
            (actor.sk, actor.did, "alice"),
            actor.certificate,
        )
    else:
        response = await env.client.get(
            "/v1/messages/inbox",
            headers=_signed_identity_headers(actor.sk, actor.did, ""),
        )
    assert response.status_code == 200, response.text
    registry_paths = [
        request.url.path for request in env.registry.transport.calls[started:]
    ]
    assert any("/revocations" in path for path in registry_paths), registry_paths
    assert all(not path.endswith("/certificates") for path in registry_paths), (
        registry_paths
    )
    assert (REGISTRY.get_sample_value(metric, labels) or 0) == before

    registry = application_registry_client(env.app.state)
    certificate_id = decode_team_certificate(actor.certificate)["certificate_id"]
    configured = await read_certificate_standings(registry, TEAM, [certificate_id])
    assert (
        configured[certificate_id].registration.state is RegistrationState.NOT_OBSERVED
    )
    explicit = await read_certificate_standings(
        registry,
        TEAM,
        [certificate_id],
        mode=RegistrationMode.NOT_REQUIRED,
    )
    assert explicit[certificate_id].registration.state is RegistrationState.UNREGISTERED
