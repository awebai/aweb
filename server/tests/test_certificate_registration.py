"""Staged registration observations never turn unavailable facts into empty ones."""

from dataclasses import FrozenInstanceError

import pytest
from aweb.certificate_registration import (
    CertificateRegistrationObservation,
    RegistrationMode,
    RegistrationState,
    evaluate_certificate_registration,
    record_certificate_registration,
)
from aweb.service_errors import AuthenticationError
from prometheus_client import REGISTRY
from starlette.requests import Request

TEAM = "backend:example.test"


@pytest.mark.parametrize(
    "registered_ids,cause,expected",
    [
        (frozenset({"member"}), None, RegistrationState.REGISTERED),
        (frozenset(), None, RegistrationState.UNREGISTERED),
        (None, ConnectionError("unavailable"), RegistrationState.UNAVAILABLE),
    ],
)
@pytest.mark.parametrize("mode", list(RegistrationMode))
def test_staged_facts_preserve_ordinary_flow_and_required_facts_preserve_refusal(
    registered_ids, cause, expected, mode
):
    observation = CertificateRegistrationObservation(
        team_id=TEAM,
        registered_certificate_ids=registered_ids,
        unavailable_cause=cause,
    )
    decision = evaluate_certificate_registration(
        observation=observation,
        certificate_id="member",
        mode=mode,
    )
    assert decision.state is expected
    assert decision.allows_registration == (
        mode is RegistrationMode.NOT_REQUIRED
        or expected is RegistrationState.REGISTERED
    )
    if expected is RegistrationState.UNAVAILABLE:
        assert observation.unavailable_cause is cause
        assert observation.registered_certificate_ids is None


def test_would_refuse_is_counted_once_per_certificate_observation_in_one_request():
    request = Request(
        {"type": "http", "method": "GET", "path": "/v1/agents", "headers": []}
    )
    observation = CertificateRegistrationObservation(
        team_id=TEAM, registered_certificate_ids=frozenset()
    )
    labels = {"enforcement": "not_required", "outcome": "would_refuse"}
    before = (
        REGISTRY.get_sample_value(
            "aweb_certificate_registration_observations_total", labels
        )
        or 0
    )
    for _ in range(2):
        decision = record_certificate_registration(
            request,
            observation=observation,
            certificate_id="member",
            mode=RegistrationMode.NOT_REQUIRED,
        )
        assert decision.allows_registration
    after = REGISTRY.get_sample_value(
        "aweb_certificate_registration_observations_total", labels
    )
    assert after == before + 1


@pytest.mark.parametrize(
    "registered_ids,cause",
    [(frozenset(), None), (None, ConnectionError("unavailable"))],
)
def test_invalid_authority_scope_is_never_measurement_unavailability(
    registered_ids, cause
):
    with pytest.raises(AuthenticationError) as refused:
        CertificateRegistrationObservation(
            team_id="invalid-team",
            registered_certificate_ids=registered_ids,
            unavailable_cause=cause,
        )
    assert refused.value.status_code == 401
    assert (
        "Reconnect using a certificate for a canonical team ID." in refused.value.detail
    )


def test_observed_registration_ids_are_an_immutable_snapshot():
    ids = {"member"}
    observation = CertificateRegistrationObservation(
        team_id=TEAM, registered_certificate_ids=ids
    )
    ids.clear()
    assert (
        evaluate_certificate_registration(
            observation=observation,
            certificate_id="member",
            mode=RegistrationMode.REQUIRED,
        ).state
        is RegistrationState.REGISTERED
    )
    with pytest.raises(FrozenInstanceError):
        observation.registered_certificate_ids = frozenset()


@pytest.mark.parametrize(
    "ids,cause", [(None, None), (frozenset(), ConnectionError("unavailable"))]
)
def test_observation_requires_known_ids_or_a_distinct_unavailability_cause(ids, cause):
    with pytest.raises(
        ValueError, match="known registrations or an unavailability cause"
    ):
        CertificateRegistrationObservation(
            team_id=TEAM, registered_certificate_ids=ids, unavailable_cause=cause
        )
