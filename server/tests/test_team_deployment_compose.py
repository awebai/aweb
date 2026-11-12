"""deploy/team/compose.yaml: one team's deployment on one machine."""

import json
import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
TEAM = REPO_ROOT / "deploy" / "team"
COMPOSE = yaml.safe_load((TEAM / "compose.yaml").read_text(encoding="utf-8"))
OPTIONAL = ("secrets", "logs", "signer")
COMPONENT_FILES = {name: (TEAM / f"compose.{name}.yaml").read_text(encoding="utf-8") for name in OPTIONAL}
SERVICES = {
    **COMPOSE["services"],
    **{name: yaml.safe_load(text)["services"][name] for name, text in COMPONENT_FILES.items()},
}
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
SIGNER_FILE = (REPO_ROOT / "server" / "compose.signer.yaml").read_text(encoding="utf-8")
SIGNER = yaml.safe_load(SIGNER_FILE)["services"]["signer"]
SCHEMA = json.loads((TEAM / "config.schema.json").read_text(encoding="utf-8"))

CREDENTIAL_NAME = re.compile(r"PASSWORD|USERNAME|TOKEN|CREDENTIALS|DATABASE_URL|_KEY$|_KEY_FILE")


def environment(service: dict) -> dict:
    return service.get("environment", {})


def test_an_optional_component_is_its_own_file_and_the_core_file_needs_none_of_its_settings():
    # Compose interpolates every service of every file it loads, whatever its
    # profile; a component left out must not be loaded at all.
    # SECRETS_DIR is every component's secrets directory, not the Secrets app's.
    core = set(re.findall(r"\$\{([A-Z_]+)", (TEAM / "compose.yaml").read_text(encoding="utf-8"))) - {"SECRETS_DIR"}
    assert set(COMPOSE["services"]) == {"redis", "postgres", "aweb"}
    for name, text in COMPONENT_FILES.items():
        assert list(yaml.safe_load(text)["services"]) == [name]
        assert not {variable for variable in core if variable.startswith(f"{name.upper()}_")}, name
        assert "profiles" not in yaml.safe_load(text)["services"][name]


def test_the_services_are_on_the_services_network_and_none_is_on_the_agents_network():
    for name in ("aweb", "secrets", "logs", "signer", "postgres", "redis"):
        assert SERVICES[name]["networks"] == ["services"], name


def test_the_agents_network_has_no_route_out():
    networks = COMPOSE["networks"]
    assert networks["agents"]["internal"] is True
    # internal alone still lets a container reach the host through the
    # bridge's gateway address; isolated removes that address's route.
    assert networks["agents"]["driver_opts"] == {"com.docker.network.bridge.gateway_mode_ipv4": "isolated"}
    assert networks["agents"]["enable_ipv6"] is False
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
            elif value is None:
                # Passed through from the rendered env file, where it is a path under /run/secrets.
                assert key == "SECRETS_CUSTODY_KEY_FILE", (name, key)
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
        "signer": [f"{secrets_dir}/${{SIGNER_SECRETS:-signer}}:/run/secrets/signer:ro"],
        "postgres": [f"{secrets_dir}/${{POSTGRES_SECRETS:-postgres}}:/run/secrets/postgres:ro"],
        "redis": [],
    }


def test_only_aweb_and_the_apps_are_published_and_on_the_address_the_operator_gave():
    published = {name: service["ports"] for name, service in SERVICES.items() if "ports" in service}
    assert published == {
        "aweb": ["${AWEB_BIND_ADDRESS:-127.0.0.1}:${AWEB_PORT:-8000}:8000"],
        "secrets": ["${SECRETS_BIND_ADDRESS:-127.0.0.1}:${SECRETS_PORT:-8770}:8770"],
        "logs": ["${LOGS_BIND_ADDRESS:-127.0.0.1}:${LOGS_PORT:-8765}:8765"],
        "signer": ["${SIGNER_BIND_ADDRESS:-127.0.0.1}:${SIGNER_PORT:-8080}:8080"],
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


def test_aweb_is_given_its_internal_app_origins_only_when_the_env_file_has_them():
    assert environment(AWEB)["AWEB_APP_INTERNAL_ORIGINS"] is None
    assert environment(AWEB)["AWEB_APP_INTERNAL_CIDR"] is None


def test_aweb_reads_every_setting_its_section_of_the_schema_renders():
    rendered = settings_of(SCHEMA["properties"]["aweb"])
    wrapper = {f"AWEB_{suffix}" for suffix in ("IMAGE", "SECRETS", "BIND_ADDRESS", "PORT")}
    assert rendered - wrapper <= set(environment(AWEB))


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


def test_an_app_is_an_ordinary_member_with_a_read_only_root():
    for name, service in APPS.items():
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


UNSET_UNLESS_GIVEN = (
    "HOOK_INTERNAL_ORIGINS",
    "HOOK_INTERNAL_DESTINATIONS",
    "HOOK_INTERNAL_CIDR",
    "CLIENT_ADDRESS_HEADER",
    "EMAIL_CA_FILE",
    "HOOK_CA_FILE",
)


def test_a_setting_the_operator_does_not_give_never_reaches_an_app_as_a_blank():
    # The apps tell an absent setting from an empty one, and refuse the empty
    # one. A setting with no value here is passed only when the env file has it.
    for name, service in APPS.items():
        prefix = name.upper()
        optional = [f"{prefix}_{suffix}" for suffix in UNSET_UNLESS_GIVEN]
        if name == "secrets":
            optional += [
                "SECRETS_CUSTODY_KEY_FILE",
                "SECRETS_KMS_KEY_ID",
                "SECRETS_KMS_REGION",
                "SECRETS_EGRESS_CA_FILE",
            ]
        for key in optional:
            assert environment(service)[key] is None, key
        for key, value in environment(service).items():
            assert ":-}" not in str(value) and ":+" not in str(value), key


def test_the_signer_runs_its_owners_service_body_from_the_pinned_image():
    signer = SERVICES["signer"]
    assert signer["extends"] == {"file": "../../server/compose.signer.yaml", "service": "signer"}
    assert signer["image"] == "${SIGNER_IMAGE:?SIGNER_IMAGE is required, signer.image}"
    assert "build" not in signer
    assert signer["depends_on"] == {"postgres": {"condition": "service_healthy", "required": False}}


def test_the_signers_controller_and_member_keys_are_in_its_secrets_mount_at_their_canonical_paths():
    # The controller's directory and key keep the owner and modes the operator
    # gave them on the host: a bind mount does not change them.
    env = environment(SIGNER)
    assert env["AWEB_PROTECTED_CONTROLLER_KEY_FILE"] == "/run/secrets/signer/private-controller/controller.key"
    assert env["AWEB_PROTECTED_MEMBER_KEYS_FILE"] == "/run/secrets/signer/members.json"
    assert env["AWEB_PROTECTED_DATABASE_URL_FILE"] == "/run/secrets/signer/database-url"
    assert env["AWEB_PROTECTED_EMAIL_PASSWORD_FILE"] == "/run/secrets/signer/smtp-password"
    assert "AWEB_PROTECTED_DATABASE_URL" not in env and SIGNER["user"] == "1001:1001"


def test_the_signers_public_configuration_is_mounted_read_only_outside_its_secrets():
    public = [volume for volume in SERVICES["signer"]["volumes"] if "/run/secrets" not in volume]
    assert public == [
        "${SIGNER_PROFILE_SOURCE:?SIGNER_PROFILE_SOURCE is required, signer.profileFile}:/etc/aweb/signer/profile.json:ro",
        "${SIGNER_SCOPE_SOURCE:?SIGNER_SCOPE_SOURCE is required, signer.scopeFile}:/etc/aweb/signer/scope.json:ro",
        # Without a private SMTP authority nothing is mounted at the CA path
        # and the signer is not told of one: it trusts the system roots.
        "${SIGNER_EMAIL_CA_SOURCE:-/dev/null}:/etc/aweb/signer/email-ca.pem:ro",
    ]


def test_a_setting_the_operator_does_not_give_never_reaches_the_signer_as_a_blank():
    assert environment(SERVICES["signer"]) == {"AWEB_PROTECTED_EMAIL_CA_FILE": None}
    assert environment(SIGNER)["AWEB_PROTECTED_TRUSTED_CLIENT_HEADER"] is None


def test_the_signer_reads_every_setting_its_section_of_the_schema_renders():
    rendered = settings_of(SCHEMA["properties"]["signer"])
    wrapper = {f"SIGNER_{suffix}" for suffix in ("IMAGE", "SECRETS", "BIND_ADDRESS", "PORT")}
    sources = {"SIGNER_PROFILE_SOURCE", "SIGNER_SCOPE_SOURCE", "SIGNER_EMAIL_CA_SOURCE"}
    team = yaml.safe_dump(SERVICES["signer"])
    read = set(environment(SIGNER)) | set(re.findall(r"\$\{([A-Z_]+)", SIGNER_FILE + team))
    assert rendered - wrapper - sources <= read
    assert {source for source in sources if source in team} == sources
