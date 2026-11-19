"""The naapp e2e deployment helpers place an app's stack and keep each
disposable aw workspace free of the caller's own aw identity."""

from __future__ import annotations

from pathlib import Path

import pytest
from aweb_naapp_testing.deployment import aw_workspace_env, candidate_hostname, e2e_stack

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
