"""scripts/e2e-team-deployment.sh: the Compose adapter of the team deployment journey."""

import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
RUNNER = REPO_ROOT / "scripts" / "e2e-team-deployment.sh"
EXAMPLE = yaml.safe_load((REPO_ROOT / "deploy" / "team" / "deployment.example.yaml").read_text(encoding="utf-8"))


def run(tmp_path: Path, *args: str, project: str | None = "teamrun") -> subprocess.CompletedProcess:
    # A docker that records being called: these commands must not start anything.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    docker = bin_dir / "docker"
    docker.write_text(f'#!/bin/sh\necho "$@" >> {tmp_path / "docker-calls"}\nexit 1\n', encoding="utf-8")
    docker.chmod(0o755)
    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "TEAM_DEPLOYMENT_RUN_DIR": str(tmp_path / "run")}
    env.pop("TEAM_DEPLOYMENT_PROJECT", None)
    if project is not None:
        env["TEAM_DEPLOYMENT_PROJECT"] = project
    return subprocess.run([str(RUNNER), *args], env=env, capture_output=True, text=True, timeout=120)


def deployment(tmp_path: Path, config: dict) -> str:
    path = tmp_path / "deployment.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    return str(path)


def test_connect_hands_the_journey_the_origins_and_how_to_reach_and_remove_the_deployment(tmp_path):
    config = {
        **EXAMPLE,
        "secrets": {
            "image": "ghcr.io/awebai/aweb-secrets@sha256:" + "3" * 64,
            "appId": "secrets-devteam",
            "publicOrigin": "https://secrets.example.com",
            "consoleOrigin": "https://secrets-console.example.com",
            "emailSmtpHost": "smtp.example.com",
            "emailFrom": "secrets@example.com",
            "egressDeniedNetworks": ["169.254.0.0/16"],
        },
    }
    path = deployment(tmp_path, config)
    result = run(tmp_path, "compose", "connect", path)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "project": "teamrun",
        "envFile": str(tmp_path / "run" / ".env"),
        "team": "devteam:example.com",
        "registry": "https://api.awid.ai",
        "origins": {
            "aweb": "https://aweb.example.com",
            "secrets": {"api": "https://secrets.example.com", "console": "https://secrets-console.example.com"},
        },
        "agent": None,
        "down": [str(RUNNER), "compose", "down", path],
    }
    assert not (tmp_path / "docker-calls").exists()


def test_up_refuses_a_deployment_the_renderer_refuses_before_starting_anything(tmp_path):
    path = deployment(tmp_path, {**EXAMPLE, "aweb": {**EXAMPLE["aweb"], "databaseUrl": "postgresql://a:s3cret@b/c"}})
    result = run(tmp_path, "compose", "up", path)
    assert result.returncode == 1
    assert "databaseUrl" in result.stderr and "s3cret" not in result.stderr + result.stdout
    assert not (tmp_path / "docker-calls").exists()


@pytest.mark.parametrize(
    ("args", "project"),
    [
        (("compose", "up"), "teamrun"),
        (("kind", "up", "deployment.yaml"), "teamrun"),
        (("compose", "restart", "deployment.yaml"), "teamrun"),
        (("compose", "up", "deployment.yaml"), None),
    ],
)
def test_the_runner_refuses_what_it_cannot_run(tmp_path, args, project):
    result = run(tmp_path, *args, project=project)
    assert result.returncode == 2
    assert "usage" in result.stderr
    assert not (tmp_path / "docker-calls").exists()
