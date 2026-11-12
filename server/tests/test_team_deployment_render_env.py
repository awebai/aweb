"""deployment.yaml rendered to the env file the Compose layer reads."""

import copy
import importlib.util
import json
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
        "COMPOSE_FILE": "compose.yaml",
        "COMPOSE_PROFILES": "postgres",
        "POSTGRES_BUNDLED": "true",
        "POSTGRES_HOST": "postgres",
        "POSTGRES_PORT": "5432",
        "POSTGRES_SECRETS": "postgres",
        "SECRETS_DIR": "/etc/aweb-secrets",
        "SERVICES_CIDR": "172.31.0.0/24",
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


def test_the_compose_layer_needs_the_range_it_creates_the_services_network_with():
    config = copy.deepcopy(EXAMPLE)
    del config["network"]
    with pytest.raises(render_env.Refused, match="network.servicesCidr"):
        render_env.render(config)


def test_an_operator_who_brings_a_postgres_server_gets_none_started():
    config = copy.deepcopy(EXAMPLE)
    config["postgres"] = {"bundled": False, "host": "db.internal"}
    assert "COMPOSE_PROFILES" not in render_env.render(config)


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

PROFILE = {
    "v": 1,
    "service_id": "devteam-signer",
    "request_origin": "https://sign.example.com",
    "human_origin": "https://approve.example.com",
    "rp_id": "approve.example.com",
    "registry_origin": "https://api.awid.ai",
}


@pytest.fixture
def signer(tmp_path):
    """The signer section, with its profile file on this machine."""
    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps(PROFILE), encoding="utf-8")
    return {**SIGNER, "profileFile": str(profile)}


def test_the_signer_section_keeps_a_list_as_json_and_fills_its_defaults(signer):
    rendered = render_env.render({**EXAMPLE, "signer": signer})
    settings = {name: value for name, value in rendered.items() if "PROTECTED" in name or name.startswith("SIGNER_")}
    assert settings == {
        "SIGNER_IMAGE": SIGNER["image"],
        "SIGNER_PROFILE_SOURCE": signer["profileFile"],
        "SIGNER_SCOPE_SOURCE": "/etc/aweb-team/signer/scope.json",
        "SIGNER_PROFILE_FILE": "/etc/aweb/signer/profile.json",
        "SIGNER_SCOPE_FILE": "/etc/aweb/signer/scope.json",
        "SIGNER_REQUEST_ORIGIN": "https://sign.example.com",
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
    assert rendered["COMPOSE_FILE"] == "compose.yaml:compose.signer.yaml"


def test_the_signer_trusts_a_private_smtp_authority_through_a_file_mounted_outside_its_secrets(signer):
    rendered = render_env.render({**EXAMPLE, "signer": {**signer, "emailCaFile": "/etc/aweb-team/signer/smtp-ca.pem"}})
    assert rendered["SIGNER_EMAIL_CA_SOURCE"] == "/etc/aweb-team/signer/smtp-ca.pem"
    assert rendered["AWEB_PROTECTED_EMAIL_CA_FILE"] == "/etc/aweb/signer/email-ca.pem"
    rendered = render_env.render({**EXAMPLE, "signer": signer})
    assert "SIGNER_EMAIL_CA_SOURCE" not in rendered and "AWEB_PROTECTED_EMAIL_CA_FILE" not in rendered


@pytest.mark.parametrize(
    ("field", "value", "key"),
    [
        ("request_origin", "https://other-sign.example.com", "signer.requestOrigin"),
        ("human_origin", "https://other-approve.example.com", "signer.humanOrigin"),
        ("registry_origin", "https://registry.example.com", "team.registryUrl"),
    ],
)
def test_the_signer_is_refused_when_its_profile_names_other_origins_or_another_registry(signer, field, value, key):
    Path(signer["profileFile"]).write_text(json.dumps({**PROFILE, field: value}), encoding="utf-8")
    with pytest.raises(render_env.Refused, match=key):
        render_env.render({**EXAMPLE, "signer": signer})


def test_the_signer_is_refused_when_its_profile_cannot_be_read(signer, tmp_path):
    for broken in (str(tmp_path / "missing.json"), signer["profileFile"]):
        if broken == signer["profileFile"]:
            Path(broken).write_text("{not json", encoding="utf-8")
        with pytest.raises(render_env.Refused, match="signer.profileFile"):
            render_env.render({**EXAMPLE, "signer": {**signer, "profileFile": broken}})


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
def test_the_signer_section_refuses_its_own_uid_as_a_worker_plain_smtp_and_credentials(signer, key, value):
    with pytest.raises(render_env.Refused):
        render_env.render({**EXAMPLE, "signer": {**signer, key: value}})


AGENTS = {
    "image": "ghcr.io/oats-project/team-agent@sha256:" + "2" * 64,
    "resolverIp": "172.30.0.2",
    "network": {"address": "172.30.0.10"},
    "compose": {
        "stateDir": "/srv/team/state",
        "authorizedKeysFile": "/srv/team/authorized_keys",
        "pidsLimit": 512,
        "name": "devteam",
    },
}


def test_the_agents_section_renders_limits_in_bytes_and_the_address_plan():
    rendered = render_env.render({**EXAMPLE, "network": {"servicesCidr": "172.31.0.0/24"}, "agents": AGENTS})
    agents = {name: value for name, value in rendered.items() if name.startswith(("AGENT", "TEAM_", "AUTHORIZED")) or name in ("TEAM", "SERVICES_CIDR")}
    assert agents == {
        "AGENT_IMAGE": AGENTS["image"],
        "AGENT_UID": "20001",
        "AGENT_GID": "20001",
        "AGENTS_SECRETS": "agents",
        "AGENT_CPUS": "2",
        "AGENT_MEMORY": "4294967296",
        "AGENT_TMP_SIZE": "134217728",
        "AGENT_RESOLVER_IP": "172.30.0.2",
        "AGENTS_SUBNET": "172.30.0.0/24",
        "AGENT_IP": "172.30.0.10",
        "TEAM_STATE_DIR": "/srv/team/state",
        "AUTHORIZED_KEYS_FILE": "/srv/team/authorized_keys",
        "AGENT_PIDS": "512",
        "TEAM": "devteam",
        "TEAM_ID": "devteam:example.com",
        "SERVICES_CIDR": "172.31.0.0/24",
    }


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("memory",), "4Gi"),
        (("memory",), 4294967297),
        (("cpus",), 3),
        (("image",), "ghcr.io/oats-project/team-agent:latest"),
        (("compose", "name"), "devteam:example.com"),
        (("loginToken",), "sk-not-here"),
        (("compose",), None),
    ],
)
def test_the_agents_section_refuses_quantity_spellings_a_raw_team_id_as_a_name_and_credentials(path, value):
    agents = copy.deepcopy(AGENTS)
    target = agents
    for key in path[:-1]:
        target = target[key]
    if value is None:
        del target[path[-1]]
    else:
        target[path[-1]] = value
    with pytest.raises(render_env.Refused):
        render_env.render({**EXAMPLE, "agents": agents})


def test_the_signer_must_name_the_agents_uid_as_a_worker(signer):
    config = {**EXAMPLE, "signer": {**signer, "workerUids": [30000]}, "agents": AGENTS}
    with pytest.raises(render_env.Refused, match="signer.workerUids"):
        render_env.render(config)
    config["signer"]["workerUids"] = [20001]
    assert render_env.render(config)["AWEB_PROTECTED_WORKER_UIDS"] == "[20001]"


def app(name: str) -> dict:
    return {
        "image": f"ghcr.io/awebai/aweb-{name}@sha256:" + "3" * 64,
        "appId": f"{name}-devteam",
        "publicOrigin": f"https://{name}.example.com",
        "consoleOrigin": f"https://{name}-console.example.com",
        "emailSmtpHost": "smtp.example.com",
        "emailFrom": f"{name}@example.com",
        "egressDeniedNetworks": ["169.254.0.0/16"],
    }


def test_secrets_and_logs_render_the_settings_each_app_reads():
    config = {**EXAMPLE, "secrets": app("secrets"), "logs": {**app("logs"), "hookInternalOrigins": ["https://logs.example.com"]}}
    rendered = render_env.render(config)
    assert {name: value for name, value in rendered.items() if name.startswith("SECRETS_") and name != "SECRETS_DIR"} == {
        "SECRETS_IMAGE": config["secrets"]["image"],
        "SECRETS_SECRETS": "secrets",
        "SECRETS_APP_ID": "secrets-devteam",
        "SECRETS_PUBLIC_ORIGIN": "https://secrets.example.com",
        "SECRETS_CONSOLE_ORIGIN": "https://secrets-console.example.com",
        "SECRETS_DB_SCHEMA": "public",
        "SECRETS_EMAIL_SMTP_HOST": "smtp.example.com",
        "SECRETS_EMAIL_SMTP_PORT": "587",
        "SECRETS_EMAIL_TLS": "starttls",
        "SECRETS_EMAIL_FROM": "secrets@example.com",
        "SECRETS_EGRESS_DENIED_NETWORKS": '["169.254.0.0/16"]',
        "SECRETS_BIND_ADDRESS": "127.0.0.1",
        "SECRETS_PORT": "8770",
        "SECRETS_CUSTODY_KEY_FILE": "/run/secrets/secrets/custody-key",
    }
    assert rendered["COMPOSE_FILE"] == "compose.yaml:compose.secrets.yaml:compose.logs.yaml"
    assert {name: value for name, value in rendered.items() if "HOOK_INTERNAL" in name} == {
        "LOGS_HOOK_INTERNAL_ORIGINS": '["https://logs.example.com"]',
        "LOGS_HOOK_INTERNAL_DESTINATIONS": "allowed",
        "LOGS_HOOK_INTERNAL_CIDR": "172.31.0.0/24",
    }
    assert (rendered["LOGS_PORT"], rendered["LOGS_CHECKPOINT_INTERVAL_SECONDS"]) == ("8765", "300")


def test_an_app_trusts_a_private_authority_through_a_file_the_operator_names():
    secrets = {
        **app("secrets"),
        "emailCaFile": "/run/secrets/secrets/smtp-ca.pem",
        "hookCaFile": "/run/secrets/secrets/hook-ca.pem",
        "egressCaFile": "/run/secrets/secrets/broker-ca.pem",
    }
    logs = {**app("logs"), "hookCaFile": "/run/secrets/logs/hook-ca.pem"}
    rendered = render_env.render({**EXAMPLE, "secrets": secrets, "logs": logs})
    assert rendered["SECRETS_EMAIL_CA_FILE"] == "/run/secrets/secrets/smtp-ca.pem"
    assert rendered["SECRETS_HOOK_CA_FILE"] == "/run/secrets/secrets/hook-ca.pem"
    assert rendered["SECRETS_EGRESS_CA_FILE"] == "/run/secrets/secrets/broker-ca.pem"
    assert rendered["LOGS_HOOK_CA_FILE"] == "/run/secrets/logs/hook-ca.pem"
    assert "LOGS_EMAIL_CA_FILE" not in rendered and "LOGS_EGRESS_CA_FILE" not in rendered


def test_aweb_installs_apps_from_internal_origins_only_inside_the_services_range():
    config = copy.deepcopy(EXAMPLE)
    config["aweb"]["appInternalOrigins"] = ["https://secrets.example.com", "https://logs.example.com"]
    rendered = render_env.render(config)
    assert rendered["AWEB_APP_INTERNAL_ORIGINS"] == '["https://secrets.example.com", "https://logs.example.com"]'
    assert rendered["AWEB_APP_INTERNAL_CIDR"] == "172.31.0.0/24"
    assert "AWEB_APP_INTERNAL_CIDR" not in render_env.render(EXAMPLE)


@pytest.mark.parametrize("value", [[], ["http://secrets.example.com"], ["https://secrets.example.com/manifest"]])
def test_aweb_refuses_internal_app_origins_that_are_not_exact_https_origins(value):
    config = copy.deepcopy(EXAMPLE)
    config["aweb"]["appInternalOrigins"] = value
    with pytest.raises(render_env.Refused, match="aweb.appInternalOrigins"):
        render_env.render(config)


def test_a_kms_key_takes_the_place_of_the_mounted_custody_key():
    secrets = {**app("secrets"), "kmsKeyId": "alias/custody", "kmsRegion": "eu-central-1"}
    rendered = render_env.render({**EXAMPLE, "secrets": secrets})
    assert "SECRETS_CUSTODY_KEY_FILE" not in rendered
    assert rendered["SECRETS_KMS_KEY_ID"] == "alias/custody"


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("consoleOrigin", "http://secrets-console.example.com"),
        ("emailTls", "none"),
        ("emailPassword", "s3cret"),
        ("databaseUrl", "postgresql://secrets:s3cret@postgres:5432/secrets"),
        ("custodyKey", "00" * 32),
        ("hookInternalOrigins", ["https://logs.example.com/path"]),
        ("hookInternalOrigins", []),
        ("hookCaFile", "hook-ca.pem"),
    ],
)
def test_an_app_section_refuses_plain_origins_plain_smtp_and_credentials(key, value):
    with pytest.raises(render_env.Refused):
        render_env.render({**EXAMPLE, "secrets": {**app("secrets"), key: value}})
