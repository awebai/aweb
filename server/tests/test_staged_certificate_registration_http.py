"""Native authentication measures usable unregistered facts while enforcement is off."""

from enum import StrEnum

import pytest
from prometheus_client import REGISTRY

from test_dashboard_privacy import privacy_app as privacy_app
from test_member_team_key import _connect
from test_messages_http import _signed_identity_headers

__all__ = ["privacy_app"]


class AuthenticationCredential(StrEnum):
    CERTIFICATE = "certificate"
    IDENTITY_ONLY = "identity-only"


@pytest.mark.asyncio
@pytest.mark.parametrize("credential", list(AuthenticationCredential))
async def test_off_mode_authentication_counts_a_valid_unregistered_certificate(
    privacy_app,
    monkeypatch,
    credential,
):
    # Staged certificate-registration observations (docs/aweb-sot.md:2176-2186):
    # measure a usable would-refuse fact without failing the legacy flow.
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
    assert REGISTRY.get_sample_value(metric, labels) == before + 1
