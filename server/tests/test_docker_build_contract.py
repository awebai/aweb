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
    # AWEB_EXTRA adds an optional extra of the same lock ("protected" for the
    # protected signer); empty, it builds the coordination server alone.
    assert sync_commands(dockerfile) == [
        'RUN uv sync --frozen --no-dev --no-install-project ${AWEB_EXTRA:+--extra "$AWEB_EXTRA"}',
        'RUN uv sync --frozen --no-dev ${AWEB_EXTRA:+--extra "$AWEB_EXTRA"}',
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


def customer_compose() -> dict:
    import yaml

    return yaml.safe_load(
        (REPO_ROOT / "server" / "docker-compose.customer.yml").read_text(encoding="utf-8")
    )


def aweb_service() -> dict:
    """The aweb service that the customer file extends."""
    import yaml

    assert customer_compose()["services"]["aweb"]["extends"] == {
        "file": "compose.aweb.yaml",
        "service": "aweb",
    }
    return yaml.safe_load(
        (REPO_ROOT / "server" / "compose.aweb.yaml").read_text(encoding="utf-8")
    )["services"]["aweb"]


def test_customer_compose_runs_aweb_against_the_public_registry_with_member_keys():
    # A customer's server is a member of the team it serves: it holds an
    # ordinary member key and no registry-wide token, and runs no registry.
    services = customer_compose()["services"]
    assert sorted(services) == ["aweb", "postgres", "redis"]
    environment = aweb_service()["environment"]
    assert "AWID_SERVICE_TOKEN" not in environment
    assert environment["AWID_MEMBER_KEYS_FILE"] == "/run/secrets/aweb/member-keys.json"
    assert environment["AWID_REGISTRY_URL"] == "${AWID_REGISTRY_URL:-https://api.awid.ai}"


def test_customer_compose_takes_every_credential_from_a_read_only_file():
    # No credential is in the environment, so none is in an env file: the
    # database URL, the database password and the member keys are files under
    # the operator's secrets directory.
    services = customer_compose()["services"]
    required = "${SECRETS_DIR:?SECRETS_DIR is required, the directory that holds aweb/ and postgres/}"
    assert services["aweb"]["volumes"] == [f"{required}/aweb:/run/secrets/aweb:ro"]
    assert f"{required}/postgres:/run/secrets/postgres:ro" in services["postgres"]["volumes"]
    aweb, postgres = aweb_service()["environment"], services["postgres"]["environment"]
    assert aweb["AWEB_DATABASE_URL_FILE"] == "/run/secrets/aweb/database-url"
    assert postgres["POSTGRES_PASSWORD_FILE"] == "/run/secrets/postgres/password"
    for environment in (aweb, postgres):
        assert not {"AWEB_DATABASE_URL", "DATABASE_URL", "POSTGRES_PASSWORD"} & set(environment)
        assert not any("PASSWORD}" in str(value) for value in environment.values())
