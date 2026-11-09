"""Operator inputs fail closed before the packaged service starts."""

import json
import secrets

import pytest
from pydantic import ValidationError

from aweb_secrets.deployment import DeploymentSettings


def inputs():
    return dict(
        database_url="postgresql://lab@postgres/lab",
        public_origin="https://secrets.lab.test",
        console_origin="https://console.lab.test",
        app_id="lab-secrets",
        awid_registry_url="https://registry.lab.test",
        custody_key_file="/run/keys/custody",
        secret_request_key_file="/run/keys/request",
        secret_params_key_file="/run/keys/params",
        response_key_file="/run/keys/response",
        runner_service_key_file="/run/keys/runner",
        email_smtp_host="smtp.lab.test",
        email_username="lab",
        email_password_file="/run/keys/smtp",
        email_from="secrets@lab.test",
    )


@pytest.mark.parametrize(
    "name", ["database_url", "public_origin", "console_origin", "app_id", "awid_registry_url"]
)
def test_customer_identity_and_authority_inputs_are_required(name):
    configured = inputs()
    configured.pop(name)
    with pytest.raises(ValidationError):
        DeploymentSettings(_env_file=None, **configured)


INTERNAL = {
    "SECRETS_HOOK_INTERNAL_DESTINATIONS": "allowed",
    "SECRETS_HOOK_INTERNAL_CIDR": "10.20.0.0/24",
    "SECRETS_HOOK_INTERNAL_ORIGINS": json.dumps(["https://logs.lab.test"]),
}


@pytest.mark.parametrize("mask", range(1, 7))
def test_partial_internal_environment_refuses_startup(monkeypatch, mask):
    for index, (name, value) in enumerate(INTERNAL.items()):
        monkeypatch.delenv(name, raising=False)
        if mask & (1 << index):
            monkeypatch.setenv(name, value)
    with pytest.raises(ValidationError):
        DeploymentSettings(_env_file=None, **inputs())


@pytest.mark.parametrize(
    "name,value",
    [
        ("SECRETS_HOOK_INTERNAL_DESTINATIONS", "true"),
        ("SECRETS_HOOK_INTERNAL_DESTINATIONS", "disabled"),
        ("SECRETS_HOOK_INTERNAL_CIDR", "10.20.0.1/24"),
        ("SECRETS_HOOK_INTERNAL_CIDR", "127.0.0.0/8"),
        ("SECRETS_HOOK_INTERNAL_CIDR", "10.0.0.0/7"),
        ("SECRETS_HOOK_INTERNAL_ORIGINS", "[]"),
        ("SECRETS_HOOK_INTERNAL_ORIGINS", '["https://*.lab.test"]'),
        ("SECRETS_HOOK_INTERNAL_ORIGINS", '["https://logs.lab.test/path"]'),
        ("SECRETS_HOOK_INTERNAL_ORIGINS", '["http://logs.lab.test"]'),
    ],
)
def test_invalid_internal_environment_refuses_startup(monkeypatch, name, value):
    for key, configured in INTERNAL.items():
        monkeypatch.setenv(key, configured)
    monkeypatch.setenv(name, value)
    with pytest.raises(ValidationError):
        DeploymentSettings(_env_file=None, **inputs())


def test_internal_origin_uses_the_installed_canonical_form(monkeypatch):
    for key, configured in INTERNAL.items():
        monkeypatch.setenv(key, configured)
    monkeypatch.setenv(
        "SECRETS_HOOK_INTERNAL_ORIGINS",
        '["https://LOGS.lab.test:443", "https://logs.lab.test:9443"]',
    )
    configured = DeploymentSettings(_env_file=None, **inputs())
    assert configured.hook_internal_origins == frozenset(
        {"https://logs.lab.test", "https://logs.lab.test:9443"}
    )


def test_broker_options_do_not_enable_hooks_or_supply_hook_trust(monkeypatch):
    for name in INTERNAL:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("SECRETS_INTERNAL_DESTINATIONS", "allowed")
    monkeypatch.setenv("SECRETS_EGRESS_CA_FILE", "/run/keys/broker-ca")
    configured = DeploymentSettings(_env_file=None, **inputs())
    assert configured.hook_internal_cidr is None
    assert configured.hook_internal_origins is None
    assert configured.hook_ca_file is None


def test_invalid_private_input_is_not_printed_by_startup_validation():
    configured = inputs()
    marker = "private-input-" + secrets.token_hex(16)
    with pytest.raises(ValidationError) as failure:
        DeploymentSettings(_env_file=None, **configured, awid_service_token=marker[:20])
    assert marker[:20] not in str(failure.value)
