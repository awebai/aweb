"""The Secrets e2e lane's composition, read as files: what both lanes run
before any container starts (docker-compose.e2e.yml and the lane fixtures)."""

import json
import re

import yaml

from tests.test_e2e_owner_acts import (
    APP_DIR,
    CONSOLE,
    LANE_SUBNET,
    LOGS_API,
    LOGS_COMPOSE_ENV,
    LOGS_CONSOLE,
    REGISTRY,
    UPSTREAMS,
    front_caddyfile,
    secrets_env,
)

LANE = yaml.safe_load((APP_DIR / "docker-compose.e2e.yml").read_text())
LOGS_BASE = (APP_DIR.parent / "logs" / "compose.logs.yaml").read_text()
REQUIRED = re.compile(r"\$\{([A-Z0-9_]+):\?")


def test_every_setting_the_logs_base_requires_is_in_the_lanes_compose_environment():
    # Compose interpolates every service of the file it loads, whatever the
    # profile: one missing setting fails every command of both lanes.
    required = set(REQUIRED.findall(LOGS_BASE))
    assert required
    assert required <= set(LOGS_COMPOSE_ENV), sorted(required - set(LOGS_COMPOSE_ENV))


def test_the_lanes_logs_is_the_deployments_base_with_its_files_read_only():
    logs = LANE["services"]["logs"]
    assert logs["extends"] == {"file": "../logs/compose.logs.yaml", "service": "logs"}
    assert logs["profiles"] == ["logs"]
    assert "${SECRETS_E2E_RUNTIME:?}/logs:/run/secrets/logs:ro" in logs["volumes"]
    # Every setting reaches it through the base, as in a deployment.
    assert "environment" not in logs and "env_file" not in logs
    assert logs["depends_on"]["postgres"] == {"condition": "service_healthy"}
    assert "logs" in LANE["services"]["smtp-tls"]["profiles"]


def test_the_lanes_logs_uses_the_lanes_registry_and_mail_and_an_id_of_its_own():
    env = LOGS_COMPOSE_ENV
    assert env["AWID_REGISTRY_URL"] == REGISTRY
    assert env["LOGS_EMAIL_SMTP_HOST"] == "mail.svc.test" and env["LOGS_EMAIL_CA_FILE"] == "/runtime/tls/ca.pem"
    # Only the hosted origin may serve the hosted id.
    assert env["LOGS_APP_ID"] != "logs"
    assert (env["LOGS_PUBLIC_ORIGIN"], env["LOGS_CONSOLE_ORIGIN"]) == (LOGS_API, LOGS_CONSOLE)
    assert json.loads(env["LOGS_EGRESS_DENIED_NETWORKS"]) == []


def test_the_front_serves_logs_and_aweb_installs_it_from_its_internal_origin():
    front = LANE["services"]["front"]["networks"]["default"]["aliases"]
    assert {"api.logs.svc.test", "console.logs.svc.test"} <= set(front)
    origins = json.loads(LANE["services"]["aweb"]["environment"]["AWEB_APP_INTERNAL_ORIGINS"])
    assert LOGS_API in origins
    assert UPSTREAMS["api.logs.svc.test"] == UPSTREAMS["console.logs.svc.test"] == "logs:8765"


def test_the_front_routes_each_host_to_its_service_with_the_lanes_certificate():
    text = front_caddyfile({"console.secrets.svc.test": "secrets:8770", "api.logs.svc.test": "logs:8765"},
                           "c.pem", "k.pem")
    assert text == ("{\n  auto_https off\n}\n"
                    "console.secrets.svc.test:443 {\n  tls /tls/c.pem /tls/k.pem\n  reverse_proxy secrets:8770\n}\n"
                    "api.logs.svc.test:443 {\n  tls /tls/c.pem /tls/k.pem\n  reverse_proxy logs:8765\n}\n")


def test_secrets_sends_its_governance_and_use_events_to_the_lanes_logs():
    env = secrets_env()
    assert json.loads(env["SECRETS_HOOK_INTERNAL_ORIGINS"]) == [LOGS_API]
    # The three settings together, inside the lane's network.
    assert env["SECRETS_HOOK_INTERNAL_DESTINATIONS"] == "allowed"
    assert env["SECRETS_HOOK_INTERNAL_CIDR"] == LANE_SUBNET
    assert env["SECRETS_HOOK_CA_FILE"] == "/run/secrets-keys/hook-ca.pem"
    assert env["SECRETS_CONSOLE_ORIGIN"] == CONSOLE


def test_the_lane_subnet_is_the_one_the_compose_file_fixes():
    subnet = LANE["networks"]["default"]["ipam"]["config"][0]["subnet"]
    assert subnet == "${SECRETS_E2E_SUBNET:-" + LANE_SUBNET + "}"
