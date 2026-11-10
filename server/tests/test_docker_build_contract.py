import re
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]


def sync_commands(dockerfile: str) -> list[str]:
    return [
        line.strip()
        for line in dockerfile.splitlines()
        if "uv sync" in line
    ]


def test_server_image_installs_from_committed_lock():
    dockerfile = (REPO_ROOT / "server" / "Dockerfile").read_text(encoding="utf-8")

    assert "COPY server/pyproject.toml server/uv.lock server/README.md ./" in dockerfile
    assert sync_commands(dockerfile) == [
        "RUN uv sync --frozen --no-dev --no-install-project",
        "RUN uv sync --frozen --no-dev",
    ]


def test_awid_e2e_image_installs_from_committed_lock():
    dockerfile = (REPO_ROOT / "awid" / "Dockerfile").read_text(encoding="utf-8")

    assert "COPY awid/pyproject.toml awid/uv.lock awid/README.md ./awid/" in dockerfile
    assert sync_commands(dockerfile) == [
        "RUN cd awid && uv sync --frozen --no-dev --no-install-project",
        "RUN cd awid && uv sync --frozen --no-dev",
    ]


SERVICE_DOCKERFILES = (
    "server/Dockerfile",
    "awid/Dockerfile",
    "awid/Dockerfile.release",
    "cli/go/Dockerfile.a2a-gw",
)


def final_user(dockerfile: str) -> str:
    users = [
        line.split(None, 1)[1].strip()
        for line in dockerfile.splitlines()
        if line.startswith("USER ")
    ]
    assert users, "no USER instruction"
    return users[-1]


@pytest.mark.parametrize("path", SERVICE_DOCKERFILES)
def test_service_image_runs_as_numeric_non_root_user(path):
    # Kubernetes verifies runAsNonRoot from the image only when USER is numeric.
    user = final_user((REPO_ROOT / path).read_text(encoding="utf-8"))

    assert re.fullmatch(r"[1-9][0-9]*:[1-9][0-9]*", user), f"{path}: USER {user}"

def healthcheck_probes(text: str, port: int) -> list[str]:
    return re.findall(rf"http://localhost:{port}(/[a-z/]*)", text)


def test_image_healthchecks_probe_liveness():
    # A container healthcheck that fails with a dependency restarts the
    # container into the same outage, so an image probes the process only.
    for dockerfile, port in [
        ("server/Dockerfile", 8000),
        ("awid/Dockerfile", 8010),
        ("awid/Dockerfile.release", 8010),
    ]:
        text = (REPO_ROOT / dockerfile).read_text(encoding="utf-8")
        assert healthcheck_probes(text, port) == ["/live"], dockerfile


def test_compose_healthchecks_gate_startup_on_readiness():
    # Compose healthchecks order start-up: a dependent service starts once the
    # service it waits for can serve, which is what /ready reports.
    for compose, probes in [
        ("docker-compose.e2e.yml", {8010: ["/ready"], 8000: ["/ready"]}),
        ("server/docker-compose.yml", {8010: ["/ready"], 8000: ["/ready"]}),
        ("awid/docker-compose.yml", {8010: ["/ready"]}),
        ("scripts/e2e/folio-wakes.compose.yml", {8010: ["/ready"], 38000: ["/ready"]}),
    ]:
        text = (REPO_ROOT / compose).read_text(encoding="utf-8")
        for port, expected in probes.items():
            assert healthcheck_probes(text, port) == expected, (compose, port)
