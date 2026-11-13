"""deploy/team/compose.yaml: one team's deployment on one machine."""

import json
import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
TEAM = REPO_ROOT / "deploy" / "team"
COMPOSE = yaml.safe_load((TEAM / "compose.yaml").read_text(encoding="utf-8"))
OPTIONAL = ("secrets", "logs", "signer", "front")
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
    for name in ("secrets", "logs", "signer", "postgres", "front"):
        assert SERVICES[name]["networks"] == ["services"], name
    assert SERVICES["aweb"]["networks"] == ["services", "backend"]


def test_redis_is_reachable_by_aweb_alone():
    # aweb is Redis's one client; no app, signer or agent has a route to it.
    assert SERVICES["redis"]["networks"] == ["backend"]
    assert [name for name, service in SERVICES.items() if "backend" in service.get("networks", [])] == ["redis", "aweb"]
    assert COMPOSE["networks"]["backend"] == {"internal": True}


def test_the_agents_network_has_no_route_out():
    networks = COMPOSE["networks"]
    assert networks["agents"]["internal"] is True
    # internal alone still lets a container reach the host through the
    # bridge's gateway address; isolated removes that address's route.
    assert networks["agents"]["driver_opts"] == {"com.docker.network.bridge.gateway_mode_ipv4": "isolated"}
    assert networks["agents"]["enable_ipv6"] is False
    # An explicit gateway: the boundary probe reads the agents network's own
    # IPv4 gateway, which Docker leaves unreported for an isolated bridge it allocates.
    assert networks["agents"]["ipam"]["config"] == [
        {"subnet": "${AGENTS_SUBNET:-172.30.0.0/24}", "gateway": "${AGENTS_GATEWAY:-172.30.0.1}"}
    ]
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
        "front": [f"{secrets_dir}/${{FRONT_SECRETS:-front}}:/run/secrets/front:ro"],
        "redis": [f"{secrets_dir}/redis:/run/secrets/redis:ro"],
    }


def test_redis_refuses_a_client_without_the_password_in_its_acl_file():
    # The ACL file holds the password's SHA-256 alone; the password is in
    # aweb's redis-url and in no argument or environment.
    redis = SERVICES["redis"]
    assert redis["command"] == ["redis-server", "--aclfile", "/run/secrets/redis/users.acl"]
    assert "environment" not in redis
    # Healthy is up and refusing a client that has not authenticated.
    assert redis["healthcheck"]["test"] == ["CMD-SHELL", "redis-cli ping | grep -q '^NOAUTH'"]


def test_aweb_takes_its_redis_url_from_the_env_file_or_the_bundled_default():
    # The team deployment's env file sets the URL empty and names the file;
    # the customer file's env sets neither and keeps the default.
    assert environment(AWEB)["AWEB_REDIS_URL"] == "${AWEB_REDIS_URL-redis://redis:6379/0}"
    assert environment(AWEB)["AWEB_REDIS_URL_FILE"] is None


def test_only_the_front_aweb_and_the_apps_are_published_and_on_the_address_the_operator_gave():
    # The front is the public TLS ingress; the others are its upstreams, on
    # the address an operator's own reverse proxy reaches when there is no front.
    published = {name: service["ports"] for name, service in SERVICES.items() if "ports" in service}
    assert published == {
        "aweb": ["${AWEB_BIND_ADDRESS:-127.0.0.1}:${AWEB_PORT:-8000}:8000"],
        "secrets": ["${SECRETS_BIND_ADDRESS:-127.0.0.1}:${SECRETS_PORT:-8770}:8770"],
        "logs": ["${LOGS_BIND_ADDRESS:-127.0.0.1}:${LOGS_PORT:-8765}:8765"],
        "signer": ["${SIGNER_BIND_ADDRESS:-127.0.0.1}:${SIGNER_PORT:-8080}:8080"],
        "front": ["${FRONT_BIND_ADDRESS:-0.0.0.0}:${FRONT_PORT:-443}:443"],
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


def test_aweb_requires_registered_certificates_only_where_the_env_file_says_so():
    # The team deployment's renderer always says so; the customer file's env does not.
    assert environment(AWEB)["AWEB_REQUIRE_REGISTERED_CERTIFICATES"] is None


def test_aweb_is_given_its_federation_outbound_setting_only_when_the_env_file_has_it():
    # The team deployment's renderer always renders it; unset, aweb delivers anywhere.
    assert environment(AWEB)["AWEB_FEDERATION_OUTBOUND"] is None


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
    # A refused CREATE ROLE logs no statement, so no password reaches the
    # server's log; the server's own role is no component's. Measured on
    # postgres:16-alpine with a pre-created role: the earlier script logged
    # the password, this one logs only the error.
    assert script.index("SET log_min_error_statement = panic;") < script.index('CREATE ROLE :"role"')
    assert "postgres) echo" in script


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


AGENTS_FILE = yaml.safe_load((TEAM / "compose.agents.yaml").read_text(encoding="utf-8"))["services"]
OATS = "${OATS_SOURCE:?OATS_SOURCE is required, agents.compose.oatsSource}"


def test_the_agent_and_its_egress_are_the_oats_sources_own_services():
    assert AGENTS_FILE["egress"] == {
        "extends": {"file": f"{OATS}/container/agent/egress/compose.egress.yaml", "service": "egress"}
    }
    assert AGENTS_FILE["agent"]["extends"] == {"file": f"{OATS}/container/agent/compose.agent.yaml", "service": "agent"}


def test_the_agent_starts_only_once_its_egress_is_healthy_and_adds_no_route_or_mount():
    agent = AGENTS_FILE["agent"]
    assert agent["depends_on"] == {"egress": {"condition": "service_healthy"}}
    # Its networks, mounts and limits are the OATS service's: the deployment adds none.
    assert set(agent) == {"extends", "depends_on"}
    assert set(AGENTS_FILE) == {"egress", "agent"}
