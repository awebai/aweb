from pathlib import Path


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
