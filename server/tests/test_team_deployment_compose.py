"""deploy/team/compose.yaml: one team's deployment on one machine."""

import json
import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
TEAM = REPO_ROOT / "deploy" / "team"
COMPOSE = yaml.safe_load((TEAM / "compose.yaml").read_text(encoding="utf-8"))
SERVICES = COMPOSE["services"]
CUSTOMER = yaml.safe_load(
    (REPO_ROOT / "server" / "docker-compose.customer.yml").read_text(encoding="utf-8")
)["services"]
AWEB = yaml.safe_load((REPO_ROOT / "server" / "compose.aweb.yaml").read_text(encoding="utf-8"))[
    "services"
]["aweb"]

APPS = {
    name: yaml.safe_load(
        (REPO_ROOT / "naapp" / name / f"compose.{name}.yaml").read_text(encoding="utf-8")
    )["services"][name]
    for name in ("secrets", "logs")
}
SCHEMA = json.loads((TEAM / "config.schema.json").read_text(encoding="utf-8"))

CREDENTIAL_NAME = re.compile(r"PASSWORD|USERNAME|TOKEN|CREDENTIALS|DATABASE_URL|_KEY$|_KEY_FILE")


def environment(service: dict) -> dict:
    return service.get("environment", {})


def test_the_services_are_on_the_services_network_and_none_is_on_the_agents_network():
    for name in ("aweb", "secrets", "logs", "postgres", "redis"):
        assert SERVICES[name]["networks"] == ["services"], name


def test_the_agents_network_has_no_route_out():
    networks = COMPOSE["networks"]
    assert networks["agents"]["internal"] is True
    assert networks["agents"]["ipam"]["config"] == [{"subnet": "${AGENTS_SUBNET:-172.30.0.0/24}"}]
    assert "internal" not in networks["services"]
    assert networks["services"]["ipam"]["config"] == [
        {"subnet": "${SERVICES_CIDR:?SERVICES_CIDR is required, network.servicesCidr}"}
    ]


def test_no_credential_is_in_an_environment():
    # A setting whose name says credential names a file under /run/secrets,
    # or is a map whose every value is such a file.
    for name, service in {**SERVICES, "aweb (shared)": AWEB, **APPS}.items():
        for key, value in environment(service).items():
            if not CREDENTIAL_NAME.search(key):
                continue
            if key.endswith(("_KEY_FILES", "_MEMBER_CREDENTIALS")):
                paths = re.findall(r'": "([^"]*)"', str(value))
                assert paths and all(path.startswith("/run/secrets/") for path in paths), (name, key)
            elif key == "SECRETS_CUSTODY_KEY_FILE":
                # Rendered as /run/secrets/secrets/custody-key, or left out for a KMS key.
                assert value == "${SECRETS_CUSTODY_KEY_FILE:-}"
            else:
                assert key.endswith("_FILE"), (name, key)
                assert str(value).startswith("/run/secrets/"), (name, key)


def test_each_service_mounts_only_its_own_secrets_read_only():
    secrets_dir = "${SECRETS_DIR:?SECRETS_DIR is required, compose.secretsDir}"
    mounts = {
        name: [volume for volume in service.get("volumes", []) if "/run/secrets" in volume]
        for name, service in SERVICES.items()
    }
    assert mounts == {
        "aweb": [f"{secrets_dir}/${{AWEB_SECRETS:-aweb}}:/run/secrets/aweb:ro"],
        "secrets": [f"{secrets_dir}/${{SECRETS_SECRETS:-secrets}}:/run/secrets/secrets:ro"],
        "logs": [f"{secrets_dir}/${{LOGS_SECRETS:-logs}}:/run/secrets/logs:ro"],
        "postgres": [f"{secrets_dir}/${{POSTGRES_SECRETS:-postgres}}:/run/secrets/postgres:ro"],
        "redis": [],
    }


def test_only_aweb_and_the_apps_are_published_and_on_the_address_the_operator_gave():
    published = {name: service["ports"] for name, service in SERVICES.items() if "ports" in service}
    assert published == {
        "aweb": ["${AWEB_BIND_ADDRESS:-127.0.0.1}:${AWEB_PORT:-8000}:8000"],
        "secrets": ["${SECRETS_BIND_ADDRESS:-127.0.0.1}:${SECRETS_PORT:-8770}:8770"],
        "logs": ["${LOGS_BIND_ADDRESS:-127.0.0.1}:${LOGS_PORT:-8765}:8765"],
    }


def test_aweb_runs_the_pinned_image_and_is_not_built():
    assert SERVICES["aweb"]["image"] == "${AWEB_IMAGE:?AWEB_IMAGE is required, aweb.image}"
    assert "build" not in SERVICES["aweb"]


def test_the_team_and_the_customer_file_run_the_same_aweb_service():
    shared = {"file": "../../server/compose.aweb.yaml", "service": "aweb"}
    assert SERVICES["aweb"]["extends"] == shared
    assert CUSTOMER["aweb"]["extends"] == {"file": "compose.aweb.yaml", "service": "aweb"}
    for service in (SERVICES["aweb"], CUSTOMER["aweb"]):
        assert "environment" not in service


def test_the_bundled_postgres_is_optional_and_aweb_waits_for_it_when_it_runs():
    assert SERVICES["postgres"]["profiles"] == ["postgres"]
    assert SERVICES["aweb"]["depends_on"] == {
        "redis": {"condition": "service_healthy"},
        "postgres": {"condition": "service_healthy", "required": False},
    }


def test_the_bundled_postgres_creates_a_database_and_role_per_component_at_first_start():
    postgres = SERVICES["postgres"]
    assert environment(postgres) == {
        "POSTGRES_PASSWORD_FILE": "/run/secrets/postgres/password",
    }
    assert "./postgres-roles.sh:/docker-entrypoint-initdb.d/roles.sh:ro" in postgres["volumes"]
    script = (TEAM / "postgres-roles.sh").read_text(encoding="utf-8")
    # The password goes from the file to the server inside psql: it is in no
    # argument and no environment.
    assert "\\set password `cat :'file'`" in script
    assert "-v password" not in script and "PGPASSWORD" not in script


def settings_of(section: dict) -> set[str]:
    found = set()
    for child in section.get("properties", {}).values():
        if "x-env" in child:
            found.add(child["x-env"])
        found |= settings_of(child)
    return found


def test_an_app_reads_every_setting_its_section_of_the_schema_renders():
    # An input the operator gives and the service never receives would be
    # silently ignored.
    for name, service in APPS.items():
        rendered = settings_of(SCHEMA["properties"][name])
        wrapper = {f"{name.upper()}_{suffix}" for suffix in ("IMAGE", "SECRETS", "BIND_ADDRESS", "PORT")}
        assert rendered - wrapper <= set(environment(service)), name


def test_an_app_is_an_optional_ordinary_member_with_a_read_only_root():
    for name, service in APPS.items():
        assert SERVICES[name]["profiles"] == [name]
        assert service["read_only"] is True and service["tmpfs"] == ["/tmp"]
        assert not any("AWID_SERVICE_TOKEN" in key for key in environment(service))
        credentials = json.loads(
            environment(service)[f"{name.upper()}_AWID_MEMBER_CREDENTIALS"].replace(
                "${TEAM_ID:?TEAM_ID is required, team.id}", "t"
            )
        )
        assert credentials == {
            "t": {
                "signing_key_file": f"/run/secrets/{name}/awid-member-key",
                "certificate_file": f"/run/secrets/{name}/awid-member-certificate",
            }
        }
