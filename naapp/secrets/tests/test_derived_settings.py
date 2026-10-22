"""Deployment bounds do not silently admit a fractional or boolean lifetime."""

import pytest
from aweb_naapp.egress import InternalDestinations
from pydantic import ValidationError

from aweb_secrets.config import SecretsSettings


def test_default_lifetime_and_network_policy_are_bounded():
    settings = SecretsSettings(_env_file=None)
    assert settings.derived_max_ttl_s == 3600
    assert settings.internal_destinations is InternalDestinations.DISABLED


def test_deployment_can_tighten_lifetime_and_explicitly_enable_internal_destinations(monkeypatch):
    monkeypatch.setenv("SECRETS_DERIVED_MAX_TTL_S", "60")
    monkeypatch.setenv("SECRETS_INTERNAL_DESTINATIONS", "allowed")
    settings = SecretsSettings(_env_file=None)
    assert settings.derived_max_ttl_s == 60
    assert settings.internal_destinations is InternalDestinations.ALLOWED


@pytest.mark.parametrize("cap", [True, False, 0, -1, 1.5, "1.5", "1.0", "invalid"])
def test_invalid_lifetime_fails_configuration(cap):
    with pytest.raises(ValidationError):
        SecretsSettings(derived_max_ttl_s=cap, _env_file=None)
