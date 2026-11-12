"""deployment.yaml rendered to the env file the Compose layer reads."""

import copy
import importlib.util
from pathlib import Path

import pytest
import yaml

TEAM = Path(__file__).resolve().parents[2] / "deploy" / "team"
EXAMPLE = yaml.safe_load((TEAM / "deployment.example.yaml").read_text(encoding="utf-8"))

spec = importlib.util.spec_from_file_location("render_env", TEAM / "render_env.py")
render_env = importlib.util.module_from_spec(spec)
spec.loader.exec_module(render_env)


def test_each_input_becomes_the_setting_its_service_reads_with_defaults_filled():
    assert render_env.render(EXAMPLE) == {
        "AWEB_IMAGE": EXAMPLE["aweb"]["image"],
        "AWEB_PUBLIC_ORIGIN": "https://aweb.example.com",
        "AWEB_BIND_ADDRESS": "127.0.0.1",
        "AWEB_PORT": "8000",
        "AWEB_SECRETS": "aweb",
        "AWID_REGISTRY_URL": "https://api.awid.ai",
        "POSTGRES_BUNDLED": "true",
        "POSTGRES_HOST": "postgres",
        "POSTGRES_PORT": "5432",
        "POSTGRES_SECRETS": "postgres",
        "SECRETS_DIR": "/etc/aweb-secrets",
        "TEAM_ID": "devteam:example.com",
    }


def test_a_given_value_replaces_the_default():
    config = copy.deepcopy(EXAMPLE)
    config["aweb"]["compose"] = {"port": 8443}
    config["team"]["registryUrl"] = "https://registry.example.com"
    rendered = render_env.render(config)
    assert (rendered["AWEB_PORT"], rendered["AWID_REGISTRY_URL"]) == ("8443", "https://registry.example.com")


def test_a_file_the_schema_refuses_is_not_rendered_and_the_refusal_names_the_key():
    config = copy.deepcopy(EXAMPLE)
    config["aweb"]["databaseUrl"] = "postgresql://aweb:s3cret@postgres:5432/aweb"
    with pytest.raises(render_env.Refused) as refused:
        render_env.render(config)
    assert "aweb" in str(refused.value) and "databaseUrl" in str(refused.value)
    assert "s3cret" not in str(refused.value)


def test_the_compose_layer_needs_its_own_section():
    config = copy.deepcopy(EXAMPLE)
    del config["compose"]
    with pytest.raises(render_env.Refused, match="compose"):
        render_env.render(config)


def test_the_env_file_is_sorted_lines_and_refuses_a_value_that_would_break_one():
    assert render_env.env_file({"B": "2", "A": "1"}) == "A=1\nB=2\n"
    with pytest.raises(render_env.Refused, match="A"):
        render_env.env_file({"A": "1\nINJECTED=2"})


SIGNER = {
    "image": "ghcr.io/awebai/aweb-protected@sha256:" + "1" * 64,
    "profileFile": "/etc/aweb-team/signer/profile.json",
    "scopeFile": "/etc/aweb-team/signer/scope.json",
    "requestOrigin": "https://sign.example.com",
    "humanOrigin": "https://approve.example.com",
    "workerUids": [20001],
    "emailSmtpHost": "smtp.example.com",
    "emailSmtpPort": 587,
    "emailUsername": "notifications",
    "emailFrom": "notifications@example.com",
}


def test_the_signer_section_keeps_a_list_as_json_and_fills_its_defaults():
    rendered = render_env.render({**EXAMPLE, "signer": SIGNER})
    signer = {name: value for name, value in rendered.items() if "PROTECTED" in name or name.startswith("SIGNER_")}
    assert signer == {
        "SIGNER_IMAGE": SIGNER["image"],
        "SIGNER_PROFILE_FILE": "/etc/aweb-team/signer/profile.json",
        "SIGNER_SCOPE_FILE": "/etc/aweb-team/signer/scope.json",
        "SIGNER_REQUEST_ORIGIN": "https://sign.example.com",
        "SIGNER_HUMAN_ORIGIN": "https://approve.example.com",
        "SIGNER_SECRETS": "signer",
        "SIGNER_BIND_ADDRESS": "127.0.0.1",
        "SIGNER_PORT": "8080",
        "AWEB_PROTECTED_WORKER_UIDS": "[20001]",
        "AWEB_PROTECTED_DATABASE_SCHEMA": "protected_signer",
        "AWEB_PROTECTED_DATABASE_USES_TRANSACTION_POOLER": "false",
        "AWEB_PROTECTED_HUMAN_CSRF_KEY": "aweb.protected.console.csrf",
        "AWEB_PROTECTED_EMAIL_SMTP_HOST": "smtp.example.com",
        "AWEB_PROTECTED_EMAIL_SMTP_PORT": "587",
        "AWEB_PROTECTED_EMAIL_USERNAME": "notifications",
        "AWEB_PROTECTED_EMAIL_FROM": "notifications@example.com",
        "AWEB_PROTECTED_EMAIL_TLS": "starttls",
    }


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("workerUids", []),
        ("workerUids", [1001]),
        ("emailTls", "none"),
        ("requestOrigin", "http://sign.example.com"),
        ("databaseUrl", "postgresql://signer:s3cret@postgres:5432/signer"),
        ("controllerKey", "00" * 32),
    ],
)
def test_the_signer_section_refuses_its_own_uid_as_a_worker_plain_smtp_and_credentials(key, value):
    with pytest.raises(render_env.Refused):
        render_env.render({**EXAMPLE, "signer": {**SIGNER, key: value}})
