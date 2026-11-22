"""The Secrets e2e lane's composition, read as files: what both lanes run
before any container starts (docker-compose.e2e.yml and the lane fixtures)."""

import json
import os
import re
import sys
from enum import IntEnum
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest
import yaml

from tests import test_e2e_owner_acts as owner_lane
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
    identity_folder,
    machine_dir,
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


def test_the_owners_identity_is_issued_into_the_folder_the_controller_machine_selects():
    # The namespace root issues the owner's identity on the holder's machine,
    # where its controller key is, into the controller machine's own folder:
    # aw there selects its working directory's .aw.
    assert machine_dir("controller") == "/runtime/controller"
    assert identity_folder("controller") == machine_dir("controller") + "/.aw"
    assert identity_folder("controller") != identity_folder("holder")


def test_bootstrap_credentials_separate_runtime_from_operator(tmp_path):
    (tmp_path / "keys").mkdir()
    owner_lane.write_secrets_database_files(SimpleNamespace(runtime=tmp_path))
    runtime_file = tmp_path / "keys" / "database-url"
    operator_file = tmp_path / "operator" / "database-url"
    runtime = urlsplit(runtime_file.read_text().strip())
    operator = urlsplit(operator_file.read_text().strip())
    if (runtime.username, operator.username) != ("secrets_runtime", "secrets"):
        raise AssertionError("Secrets must use a distinct runtime LOGIN")
    if runtime.path != "/secrets_content" or operator.path != runtime.path:
        raise AssertionError("Both roles must target the dedicated Secrets database")
    if runtime.password == operator.password or not runtime.password:
        raise AssertionError("Runtime credentials must differ from operator credentials")
    assert operator_file.stat().st_mode & 0o777 == 0o400
    assert operator_file.parent.stat().st_mode & 0o777 == 0o700
    assert runtime_file.stat().st_mode & 0o777 == 0o444
    env = secrets_env()
    assert "SECRETS_DATABASE_URL" not in env
    assert env["SECRETS_DATABASE_URL_FILE"] == "/run/secrets-keys/database-url"
    assert all("/operator" not in mount for mount in LANE["services"]["secrets"]["volumes"])


def test_bootstrap_refuses_to_replace_retained_runtime_credentials(tmp_path):
    (tmp_path / "keys").mkdir()
    retained = tmp_path / "keys" / "database-url"
    retained.write_text("retained-lane-credentials")
    with pytest.raises(FileExistsError):
        owner_lane.write_secrets_database_files(SimpleNamespace(runtime=tmp_path))
    if retained.read_text() != "retained-lane-credentials":
        raise AssertionError("Bootstrap replaced existing runtime credentials")


class BootstrapOutcome(IntEnum):
    SUCCESS = 0
    PROVISIONING_REFUSAL = 1
    INITIALIZATION_REFUSAL = 2


@pytest.mark.parametrize(
    "outcome", list(BootstrapOutcome), ids=lambda outcome: outcome.name.lower()
)
def test_bootstrap_and_snapshot_use_the_dedicated_database_and_stop_on_refusal(
    tmp_path, outcome: BootstrapOutcome
):
    # External Docker recorder; it discards SQL stdin without recording keys.
    binary = tmp_path / "bin"
    binary.mkdir()
    recorder = binary / "docker"
    recorder.write_text(
        f"#!{sys.executable}\n"
        + """
import json, os, sys
from pathlib import Path
path = Path(os.environ["BOOTSTRAP_CALLS"])
calls = json.loads(path.read_text()) if path.exists() else []
has_input = bool(sys.stdin.read()) if "psql" in sys.argv and "-At" not in sys.argv else False
calls.append({"args": sys.argv[1:], "sql_stdin": has_input})
path.write_text(json.dumps(calls))
if len(calls) == int(os.environ["BOOTSTRAP_FAIL_STEP"]):
    print("ERROR: 42501", file=sys.stderr)
    sys.exit(77)
"""
    )
    recorder.chmod(0o755)
    (tmp_path / "keys").mkdir()
    journal = tmp_path / "calls.json"
    lane = owner_lane.Lane(
        "synthetic-bootstrap",
        tmp_path,
        {
            **os.environ,
            "PATH": str(binary) + os.pathsep + os.environ["PATH"],
            "BOOTSTRAP_CALLS": str(journal),
            "BOOTSTRAP_FAIL_STEP": str(outcome),
        },
    )
    if outcome is not BootstrapOutcome.SUCCESS:
        with pytest.raises(AssertionError):
            owner_lane.prepare_secrets_database(lane)
    else:
        owner_lane.prepare_secrets_database(lane)
        owner_lane.secrets_query(lane)("SELECT 1")
    entries = json.loads(journal.read_text())
    evidence = [
        json.loads(path.read_text()) for path in (tmp_path / "bootstrap-evidence").glob("*.json")
    ]
    expected_operations = ["provision_database"]
    if outcome is not BootstrapOutcome.PROVISIONING_REFUSAL:
        expected_operations.append("initialize_erasure")
    assert sorted(record["operation"] for record in evidence) == sorted(expected_operations)
    failures = [record for record in evidence if record["exit_code"]]
    if outcome is BootstrapOutcome.SUCCESS:
        assert failures == []
    else:
        assert len(failures) == 1
        assert failures[0]["exit_code"] == 77
        assert failures[0]["error_code"] == "postgres_42501"
    calls = [entry["args"] for entry in entries]
    expected = {
        BootstrapOutcome.SUCCESS: 3,
        BootstrapOutcome.PROVISIONING_REFUSAL: 1,
        BootstrapOutcome.INITIALIZATION_REFUSAL: 2,
    }
    assert len(calls) == expected[outcome]
    assert entries[0]["sql_stdin"] is True
    assert "psql" in calls[0] and "postgres" in calls[0]
    assert "init-erasure" not in calls[0]
    if len(calls) >= 2:
        command = calls[1]
        assert command[-11:] == [
            "-m",
            "aweb_secrets.erasure",
            "init-erasure",
            "--operator-dsn-file",
            "/run/operator/database-url",
            "--application-role",
            "secrets_runtime",
            "--content-schema",
            owner_lane.SECRETS_SCHEMA,
            "--max-backup-age-seconds",
            "604800",
        ]
        assert all(flag in command for flag in ("run", "--rm", "--no-deps", "--build"))
        assert str(tmp_path / "operator") + ":/run/operator:ro" in command
    if outcome is BootstrapOutcome.SUCCESS:
        snapshot = calls[2]
        assert snapshot[snapshot.index("-d") + 1] == "secrets_content"
        assert "BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY" in snapshot
        assert "SELECT 1" in snapshot and "COMMIT" in snapshot
    password = urlsplit((tmp_path / "keys" / "database-url").read_text().strip()).password
    if password in json.dumps(calls):
        raise AssertionError("A runtime credential reached a process argument")
