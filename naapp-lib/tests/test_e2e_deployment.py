"""The naapp e2e deployment helpers place an app's stack and keep each
disposable aw workspace free of the caller's own aw identity."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import httpx
import pytest
from aweb_naapp_testing.deployment import (
    OperatorTeamServer,
    aw_workspace_env,
    candidate_hostname,
    e2e_stack,
    running_app,
)

_CALLER_AW_SETTINGS = (
    "AWEB_IDENTITY_HOME",
    "AW_HOME",
    "AWEB_ALIAS",
    "AWEB_ROLE",
    "AWEB_ROLE_NAME",
    "AWEB_HUMAN",
    "AWEB_HUMAN_NAME",
    "AWEB_AGENT_TYPE",
    "AWEB_DELIVERY",
    "AW_CONFIG",
)
_GATE_ALLOCATION = {
    "NAAPP_E2E_PROJECT": "gate-run-example",
    "NAAPP_E2E_HOST": "aweb-docker.test",
    "NAAPP_E2E_AWID_PORT": "41001",
    "NAAPP_E2E_POSTGRES_PORT": "41002",
}


def test_stack_defaults_to_the_local_make_e2e_stack() -> None:
    stack = e2e_stack({}, project="example-e2e", database="example")

    assert stack.awid_url == "http://127.0.0.1:18010"
    assert stack.postgres_url == "postgresql://example:example@127.0.0.1:55432/example"
    assert stack.compose == [
        "docker",
        "compose",
        "-p",
        "example-e2e",
        "-f",
        "docker-compose.e2e.yml",
    ]
    assert stack.redis_url is None


def test_stack_follows_the_allocation_a_gate_passes_in() -> None:
    stack = e2e_stack(_GATE_ALLOCATION, project="example-e2e", database="example")

    assert stack.awid_url == "http://aweb-docker.test:41001"
    assert stack.postgres_url == "postgresql://example:example@aweb-docker.test:41002/example"
    assert stack.compose == [
        "docker",
        "compose",
        "-p",
        "gate-run-example",
        "-f",
        "docker-compose.e2e.yml",
    ]


def test_candidate_stack_uses_its_owned_compose_network() -> None:
    stack = e2e_stack(
        {**_GATE_ALLOCATION, "NAAPP_E2E_CONTAINER_NETWORK": "1"},
        project="example-e2e",
        database="example",
    )

    def hostname(service: str) -> str:
        return candidate_hostname(project="gate-run-example", service=service)

    assert stack.awid_url == f"http://{hostname('awid')}:8010"
    assert stack.postgres_url == f"postgresql://example:example@{hostname('postgres')}:5432/example"
    assert stack.redis_url == f"redis://{hostname('redis')}:6379/0"


def test_disposable_aw_workspace_carries_only_the_aw_settings_the_test_sets(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Run from an agent session, the caller's own identity, alias, role or config
    # would otherwise reach every disposable `aw` command.
    for name in _CALLER_AW_SETTINGS:
        monkeypatch.setenv(name, "caller")
    monkeypatch.setenv("AWEB_URL", "http://caller.invalid")

    env = aw_workspace_env(home=tmp_path / "home", awid_url="http://awid.test:8010")

    assert {k: v for k, v in env.items() if k.startswith(("AWEB_", "AW_"))} == {
        "AWEB_URL": "http://127.0.0.1:1"
    }
    assert env["AWID_REGISTRY_URL"] == "http://awid.test:8010"
    assert env["HOME"] == str(tmp_path / "home")


def test_an_app_that_has_to_be_killed_fails_its_deployment() -> None:
    # A shutdown that never ends must not pass as a normal stop.
    apps = str(Path(__file__).parent / "deployment_apps")
    with pytest.raises(RuntimeError, match="killed"):
        with running_app(
            name="stuck",
            factory="stuck_shutdown_app:create_app",
            env_for=lambda origin: {"PYTHONPATH": apps},
        ):
            pass


def test_an_app_that_writes_more_than_a_pipe_holds_keeps_answering() -> None:
    apps = str(Path(__file__).parent / "deployment_apps")
    with running_app(
        name="noisy",
        factory="noisy_app:create_app",
        env_for=lambda origin: {"PYTHONPATH": apps},
    ) as app:
        for _ in range(2):
            assert httpx.get(f"{app.origin}/noise", timeout=10.0).status_code == 200


_DEPLOYED_TEST = """
from contextlib import contextmanager

import httpx
import pytest
from aweb_naapp_testing.deployment import running_app


@pytest.fixture(scope="session")
def app():
    with deployed() as app:
        yield app


@contextmanager
def deployed():
    with running_app(
        name="noisy",
        factory="noisy_app:create_app",
        env_for=lambda origin: {"PYTHONPATH": %r},
    ) as app:
        yield app


def test_member(app):
    httpx.get(f"{app.origin}/secret", timeout=10.0)
    assert %s


def test_member_with_its_own_app():
    with deployed() as app:
        httpx.get(f"{app.origin}/secret", timeout=10.0)
        assert %s
"""


def _run_deployed_test(tmp_path: Path, outcome: str) -> subprocess.CompletedProcess[str]:
    """A pytest run, as a package's e2e, of one test on a session-wide app and
    one that starts its own."""
    apps = str(Path(__file__).parent / "deployment_apps")
    (tmp_path / "test_deployed.py").write_text(_DEPLOYED_TEST % (apps, outcome, outcome))
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"]
        + ["-p", "aweb_naapp_testing.deployment_logs", "--rootdir", str(tmp_path), str(tmp_path)],
        cwd=tmp_path,
        env=os.environ.copy(),
        text=True,
        capture_output=True,
        timeout=60,
    )


def test_a_failed_tests_report_carries_the_apps_output_without_its_tokens(tmp_path: Path) -> None:
    from tests.deployment_apps import noisy_app

    result = _run_deployed_test(tmp_path, "False")

    assert result.returncode == 1, result.stdout + result.stderr
    assert result.stdout.count("app-says") == 2
    assert noisy_app.ASSET_ID in result.stdout
    assert "in_a_function_name" in result.stdout
    assert noisy_app.TOKEN not in result.stdout + result.stderr


def test_a_passing_test_prints_none_of_the_apps_output(tmp_path: Path) -> None:
    result = _run_deployed_test(tmp_path, "True")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "app-says" not in result.stdout + result.stderr


def test_the_operator_team_server_settings_are_ones_the_runtime_accepts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The deployment's settings must pass the app's own validators unchanged.
    from tests.runtime.test_served_manifest import ExampleSettings

    ca_file = tmp_path / "ca.pem"
    ca_file.write_text("disposable CA")
    operator = OperatorTeamServer(
        origin="https://aweb-candidate-runner-0123456789abcdef.test:41234",
        subnet="172.30.0.0/16",
        ca_file=ca_file,
    )
    for name, value in operator.settings("EXAMPLE_").items():
        monkeypatch.setenv(name, value)

    settings = ExampleSettings(_env_file=None)

    assert settings.team_server_internal_origins == frozenset({operator.origin})
    assert str(settings.hook_internal_cidr) == operator.subnet
    assert settings.hook_internal_destinations == "allowed"
    assert settings.hook_ca_file == ca_file
