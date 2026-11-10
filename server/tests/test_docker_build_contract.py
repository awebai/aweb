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
