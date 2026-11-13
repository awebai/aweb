"""deploy/team/teamctl's lifecycle commands: stop keeps every volume and
file, destroy removes only the bundle's own containers and volumes and only
when the project is named, backup refuses while a writer runs, and restore
fails closed."""

import json
from pathlib import Path

import pytest

from tests.test_team_deployment_runner import EXAMPLE, TEAMCTL, deployment, run


def calls(tmp_path: Path) -> list[str]:
    log = tmp_path / "docker-calls"
    return log.read_text().splitlines() if log.exists() else []


def test_stop_stops_the_bundle_and_keeps_every_volume(tmp_path):
    path = deployment(tmp_path, EXAMPLE)
    result = run(tmp_path, "stop", path, command=TEAMCTL, docker_ok=True)
    assert result.returncode == 0, result.stderr
    made = calls(tmp_path)
    assert [call for call in made if " stop " in f" {call} "], made
    assert not [call for call in made if "--volumes" in call or " down " in f" {call} " or "volume rm" in call]


def test_destroy_refuses_unless_the_project_is_named(tmp_path):
    path = deployment(tmp_path, EXAMPLE)
    for extra in ((), ("--confirm", "another")):
        result = run(tmp_path, "destroy", path, *extra, command=TEAMCTL, docker_ok=True)
        assert result.returncode == 2 and "--confirm teamrun" in result.stderr
    assert calls(tmp_path) == []


def test_destroy_removes_only_the_bundles_containers_and_named_volumes(tmp_path):
    path = deployment(tmp_path, EXAMPLE)
    result = run(tmp_path, "destroy", path, "--confirm", "teamrun", command=TEAMCTL, docker_ok=True,
                 answers={"config --volumes": "postgres_data\nredis_data\n"})
    assert result.returncode == 0, result.stderr
    made = calls(tmp_path)
    assert [call for call in made if " rm --stop --force" in call], made
    removed = [call.split("volume rm ")[1].split() for call in made if "volume rm " in call]
    assert removed == [["teamrun_postgres_data"], ["teamrun_redis_data"]]
    # Never the project as a whole: the test world beside it is not the bundle's.
    assert not [call for call in made if " down " in f" {call} " or "--remove-orphans" in call]


def test_destroy_ignores_the_compose_files_run_beside_the_bundle(tmp_path):
    # TEAM_DEPLOYMENT_COMPOSE_FILES adds what the project runs beside the
    # bundle (the journey's test world); destroy keeps it out of what it removes.
    beside = tmp_path / "compose.beside.yaml"
    beside.write_text("services: {}\n", encoding="utf-8")
    path = deployment(tmp_path, EXAMPLE)
    result = run(tmp_path, "destroy", path, "--confirm", "teamrun", command=TEAMCTL, docker_ok=True,
                 extra_files=str(beside), answers={"config --volumes": "postgres_data\n"})
    assert result.returncode == 0, result.stderr
    made = calls(tmp_path)
    assert [call for call in made if " rm --stop --force" in call], made
    assert not [call for call in made if "compose.beside.yaml" in call], made


def test_destroy_fails_when_it_cannot_list_the_bundles_volumes(tmp_path):
    # A failed listing is not an empty one: destroy must not report the volumes gone.
    path = deployment(tmp_path, EXAMPLE)
    result = run(tmp_path, "destroy", path, "--confirm", "teamrun", command=TEAMCTL, docker_ok=True,
                 fails={"config --volumes": 77})
    assert result.returncode != 0 and "could not list the bundle's volumes" in result.stderr


def test_backup_refuses_while_a_writer_runs(tmp_path):
    path = deployment(tmp_path, EXAMPLE)
    result = run(tmp_path, "backup", path, str(tmp_path / "backup"), command=TEAMCTL, docker_ok=True,
                 answers={"--status running --services": "postgres\naweb\n"})
    assert result.returncode == 1 and "aweb" in result.stderr and "teamctl stop" in result.stderr
    assert not (tmp_path / "backup").exists()
    assert not [call for call in calls(tmp_path) if "pg_dump" in call]


def test_backup_stops_when_it_cannot_list_the_running_services(tmp_path):
    # A failed listing is not an empty one: no writer is known to be stopped.
    path = deployment(tmp_path, EXAMPLE)
    result = run(tmp_path, "backup", path, str(tmp_path / "backup"), command=TEAMCTL, docker_ok=True,
                 fails={"--status running --services": 78})
    assert result.returncode != 0 and "could not list the running services" in result.stderr
    assert not (tmp_path / "backup").exists()
    assert not [call for call in calls(tmp_path) if "pg_dump" in call]


def test_backup_fails_when_it_cannot_list_the_databases(tmp_path):
    # A failed query is not an empty database list: no manifest says the backup is whole.
    path = deployment(tmp_path, EXAMPLE)
    result = run(tmp_path, "backup", path, str(tmp_path / "backup"), command=TEAMCTL, docker_ok=True,
                 fails={"select datname": 79})
    assert result.returncode != 0 and "could not list the databases" in result.stderr
    assert not (tmp_path / "backup" / "manifest.json").exists()
    assert not [call for call in calls(tmp_path) if "pg_dump" in call]


def test_backup_refuses_an_existing_directory(tmp_path):
    path = deployment(tmp_path, EXAMPLE)
    (tmp_path / "backup").mkdir()
    result = run(tmp_path, "backup", path, str(tmp_path / "backup"), command=TEAMCTL, docker_ok=True)
    assert result.returncode == 1 and "exists" in result.stderr
    assert calls(tmp_path) == []


def test_backup_refuses_an_operators_own_database_server(tmp_path):
    path = deployment(tmp_path, {**EXAMPLE, "postgres": {"bundled": False, "host": "db.internal"}})
    result = run(tmp_path, "backup", path, str(tmp_path / "backup"), command=TEAMCTL, docker_ok=True)
    assert result.returncode == 1 and "bundled PostgreSQL" in result.stderr
    assert not (tmp_path / "backup").exists()


def test_restore_fails_closed_without_the_lab_rehearsal_scope(tmp_path):
    path = deployment(tmp_path, EXAMPLE)
    (tmp_path / "backup").mkdir()
    result = run(tmp_path, "restore", path, str(tmp_path / "backup"), command=TEAMCTL, docker_ok=True)
    assert result.returncode == 1
    for task in ("aweb-acyp", "aweb-acgh.16.23", "aweb-acyw", "aweb-acxy.4"):
        assert task in result.stderr
    assert calls(tmp_path) == []


FRONT = {"image": "docker.io/library/caddy@sha256:" + "4" * 64}


def test_start_checks_the_fronts_certificate_before_anything_starts(tmp_path):
    # The docker that fails stands for a check that refuses the certificate.
    path = deployment(tmp_path, {**EXAMPLE, "front": FRONT})
    result = run(tmp_path, "start", path, command=TEAMCTL)
    assert result.returncode == 1
    made = calls(tmp_path)
    assert len(made) == 1 and made[0].startswith("run --rm --user 0 --network none") and "certificate.pem" in made[0]
    assert (tmp_path / "run" / "front" / "Caddyfile").read_text().startswith("{\n  auto_https off\n")


def test_reload_tls_refuses_a_deployment_without_a_front(tmp_path):
    path = deployment(tmp_path, EXAMPLE)
    result = run(tmp_path, "reload-tls", path, command=TEAMCTL, docker_ok=True)
    assert result.returncode == 1 and "no front" in result.stderr
    assert calls(tmp_path) == []


def test_render_writes_the_env_file_and_the_fronts_configuration_and_starts_nothing(tmp_path):
    path = deployment(tmp_path, {**EXAMPLE, "front": FRONT})
    result = run(tmp_path, "render", path, command=TEAMCTL)
    assert result.returncode == 0, result.stderr
    env = (tmp_path / "run" / ".env").read_text()
    assert f"FRONT_CONFIG_DIR={tmp_path / 'run' / 'front'}\n" in env
    assert (tmp_path / "run" / "front" / "Caddyfile").read_text().startswith("{\n  auto_https off\n")
    assert calls(tmp_path) == []


def test_backup_leaves_the_signers_live_controller_key_out_of_the_secrets_archive(tmp_path):
    # The controller's backup is the owner's separately protected offline copy
    # (HOST.md); the generic backup never holds the live private volume.
    secrets = tmp_path / "secrets"
    (secrets / "signer" / "private-controller").mkdir(parents=True)
    config = {**EXAMPLE, "compose": {**EXAMPLE["compose"], "secretsDir": str(secrets)}}
    path = deployment(tmp_path, config)
    result = run(tmp_path, "backup", path, str(tmp_path / "backup"), command=TEAMCTL, docker_ok=True)
    assert result.returncode == 0, result.stderr
    archived = [call for call in calls(tmp_path) if "tarfile" in call and "/source:ro" in call]
    assert len(archived) == 1 and "./signer/private-controller" in archived[0].split(), archived


def test_backup_leaves_the_agents_harness_login_out_of_the_secrets_archive(tmp_path):
    # The login is a person's account credential: it is minted again, never
    # restored, and a backup is no place for it.
    secrets = tmp_path / "secrets"
    (secrets / "agents").mkdir(parents=True)
    config = {**EXAMPLE, "compose": {**EXAMPLE["compose"], "secretsDir": str(secrets)}}
    path = deployment(tmp_path, config)
    result = run(tmp_path, "backup", path, str(tmp_path / "backup"), command=TEAMCTL, docker_ok=True)
    assert result.returncode == 0, result.stderr
    archived = [call for call in calls(tmp_path) if "tarfile" in call and "/source:ro" in call]
    assert len(archived) == 1 and "./agents" in archived[0].split(), archived


def test_reload_tls_forces_the_reload_though_the_configuration_is_unchanged(tmp_path):
    # Caddy skips a reload whose configuration is unchanged, and with it the
    # replaced certificate files (seen on run35).
    path = deployment(tmp_path, {**EXAMPLE, "front": FRONT})
    result = run(tmp_path, "reload-tls", path, command=TEAMCTL, docker_ok=True)
    assert result.returncode == 0, result.stderr
    reloads = [call for call in calls(tmp_path) if "caddy reload" in call]
    assert len(reloads) == 1 and "--force" in reloads[0].split(), reloads


def test_start_reloads_the_running_front_with_the_rendered_sites(tmp_path):
    # Compose leaves a running front as it is when only its mounted
    # configuration changed, so a component added later (the signer's
    # origins) would get no site (seen on run37).
    path = deployment(tmp_path, {**EXAMPLE, "front": FRONT})
    result = run(tmp_path, "start", path, command=TEAMCTL, docker_ok=True)
    assert result.returncode == 0, result.stderr
    made = calls(tmp_path)
    up = next(i for i, call in enumerate(made) if " up -d " in call)
    reloads = [i for i, call in enumerate(made) if "caddy reload" in call]
    assert len(reloads) == 1 and reloads[0] > up and "--force" in made[reloads[0]].split(), made
    served = [call for call in made[reloads[0] + 1:] if call.startswith("run --rm --user 0 --network teamrun_services")]
    assert len(served) == 1 and "certificate.pem" in served[0], made[reloads[0]:]


def agents_deployment(tmp_path: Path, team: dict) -> str:
    """A deployment with agents, its signer's profile and a clean OATS checkout
    holding the two fragments teamctl records."""
    import json
    import subprocess

    from tests.test_team_deployment_egress_policy import CONTROLLER
    from tests.test_team_deployment_render_env import AGENTS, APPS, EGRESS, PROFILE, SIGNER

    oats = tmp_path / "oats"
    for fragment in ("container/agent/compose.agent.yaml", "container/agent/egress/compose.egress.yaml"):
        (oats / fragment).parent.mkdir(parents=True, exist_ok=True)
        (oats / fragment).write_text("services: {}\n", encoding="utf-8")
    git = ["git", "-C", str(oats), "-c", "user.name=t", "-c", "user.email=t@example.com"]
    subprocess.run(["git", "init", "-q", str(oats)], check=True)
    subprocess.run([*git, "add", "."], check=True)
    subprocess.run([*git, "commit", "-q", "-m", "fragments"], check=True)
    profile = tmp_path / "profile.json"
    profile.write_text(json.dumps({
        **PROFILE, "registry_origin": team.get("registryUrl", "https://api.awid.ai"),
        "namespace_authorities": [{"domain": "example.com", "controller_did": CONTROLLER}],
    }), encoding="utf-8")
    agents = {**AGENTS, "compose": {**AGENTS["compose"], "oatsSource": str(oats)}}
    return deployment(tmp_path, {**EXAMPLE, "team": team, "agents": agents, "egress": EGRESS,
                                 "signer": {**SIGNER, "profileFile": str(profile)}, **APPS})


BASE_SERVICES = ["postgres", "redis", "aweb", "secrets", "logs", "signer", "egress", "agent"]
PUBLIC_REGISTRY_ADDRESSES = ["104.21.0.10", "172.67.0.10"]


def start_with_agents(tmp_path: Path, team: dict, services: list[str], registry: list[str],
                      egress_log: str | None = None):
    # The stub docker answers what start asks before the ingress probe: the
    # services, the origins' addresses seen from aweb, the agents network's
    # isolation, a first line from each followed log, and the probe's pass.
    import json

    resolved = {"origins": {role: ["172.31.0.250"] for role in ("aweb", "secrets", "logs", "signer")},
                "backends": {"postgres": "172.31.0.3", "redis": "172.31.0.4"}}
    resolved["origins"]["registry"] = registry
    answers = {
        "config --services": "\n".join(services) + "\n",
        "SOCK_STREAM": json.dumps(resolved),
        "gateway_mode_ipv4": "true false isolated",
        "logs --follow": "attached\n",
        "probe-ingress.mjs": "OATS_EGRESS_INGRESS_PASS",
        "ps -q egress": "egress-container-id\n",
    }
    if egress_log is not None:
        answers["--timestamps --follow"] = egress_log
    path = agents_deployment(tmp_path, team)
    return run(tmp_path, "start", path, command=TEAMCTL, docker_ok=True, answers=answers)


def followed(tmp_path: Path) -> list[str]:
    # The backend logs teamctl followed for the probe: one file per local
    # route. (The followers run concurrently, so their docker calls can
    # interleave in the stub's call log.)
    logs = tmp_path / "run" / "ingress-logs"
    return sorted(path.stem for path in logs.glob("*.log")) if logs.exists() else []


def probes(made: list[str]) -> list[str]:
    return [call for call in made if "probe-ingress.mjs" in call]


def test_start_probes_the_public_registry_as_an_external_route_with_no_backend_log(tmp_path):
    # The default registry is the public one, which is no service of the
    # deployment: before the external route, teamctl refused to probe it.
    result = start_with_agents(tmp_path, {"id": "devteam:example.com"}, BASE_SERVICES, PUBLIC_REGISTRY_ADDRESSES)
    assert "ingress probe: exit 0, OATS_EGRESS_INGRESS_PASS" in result.stdout, result.stdout + result.stderr
    made = calls(tmp_path)
    assert followed(tmp_path) == ["aweb", "logs", "secrets", "signer"]
    assert len(probes(made)) == 1 and "--human-log /logs/signer.log" in probes(made)[0]
    routes = json.loads((tmp_path / "run" / "ingress-logs" / "route-logs.json").read_text())
    assert routes["registry"] == {"path": "/health", "external": True}
    assert routes["signer"] == {"path": "/readyz", "log": "/logs/signer.log"}


def test_start_probes_a_local_registry_through_its_own_log(tmp_path):
    team = {"id": "devteam:example.com", "registryUrl": "https://registry.example.com", "registryRoute": "local"}
    result = start_with_agents(tmp_path, team, [*BASE_SERVICES, "registry"], ["172.31.0.250"])
    assert "ingress probe: exit 0, OATS_EGRESS_INGRESS_PASS" in result.stdout, result.stdout + result.stderr
    assert followed(tmp_path) == ["aweb", "logs", "registry", "secrets", "signer"]
    routes = json.loads((tmp_path / "run" / "ingress-logs" / "route-logs.json").read_text())
    assert routes["registry"] == {"path": "/health", "log": "/logs/registry.log"}


@pytest.mark.parametrize(
    ("team", "services", "registry", "refusal"),
    [
        # A missing local registry never becomes an external route.
        ({"id": "devteam:example.com", "registryUrl": "https://registry.example.com", "registryRoute": "local"},
         BASE_SERVICES, ["172.31.0.250"], "registry: the ingress probe needs its backend log"),
        ({"id": "devteam:example.com"}, [*BASE_SERVICES, "registry"], PUBLIC_REGISTRY_ADDRESSES,
         "registry is a service of this deployment; set team.registryRoute: local"),
        ({"id": "devteam:example.com", "registryUrl": "https://registry.example.com", "registryRoute": "local"},
         [*BASE_SERVICES, "registry"], PUBLIC_REGISTRY_ADDRESSES,
         "104.21.0.10 is not one of the deployment's private ingress addresses"),
        ({"id": "devteam:example.com"}, BASE_SERVICES, ["172.31.0.250"],
         "172.31.0.250 is one of the deployment's own addresses"),
        ({"id": "devteam:example.com"}, [s for s in BASE_SERVICES if s != "logs"], PUBLIC_REGISTRY_ADDRESSES,
         "logs: the ingress probe needs its backend log"),
    ],
)
def test_start_holds_the_agents_when_a_declared_route_does_not_match_the_deployment(
    tmp_path, team, services, registry, refusal
):
    result = start_with_agents(tmp_path, team, services, registry)
    assert result.returncode == 1
    assert "teamctl: no ingress probe: " in result.stderr and refusal in result.stderr, result.stderr
    assert "agents held: the ingress refusal probe did not pass" in result.stderr
    made = calls(tmp_path)
    assert followed(tmp_path) == [] and probes(made) == []


LATER_LINE = "2099-01-01T00:00:00.000000000Z [INFO] 172.30.0.10:4000 - 1 \"A IN denied-x.invalid. udp 40 false 512\" NXDOMAIN"
EARLIER_LINE = "2000-01-01T00:00:00.000000000Z [INFO] replayed history"


def egress_capture(tmp_path: Path, line: str, monkeypatch):
    log = tmp_path / "capture" / "agent-egress-refusals.log"
    log.parent.mkdir()
    monkeypatch.setenv("TEAM_DEPLOYMENT_EGRESS_LOG", str(log))
    monkeypatch.setenv("TEAM_DEPLOYMENT_CAPTURE_SECONDS", "2")
    result = start_with_agents(tmp_path, {"id": "devteam:example.com"}, BASE_SERVICES, PUBLIC_REGISTRY_ADDRESSES,
                               egress_log=line + "\n")
    return result, log


def index_of(made: list[str], fragment: str) -> int:
    return next(i for i, call in enumerate(made) if fragment in call)


def test_the_egress_capture_starts_after_egress_and_before_any_probe_or_the_agent(tmp_path, monkeypatch):
    # The agent's first lookup cannot precede the capture: its follower is
    # attached, and seen streaming, before the agent container exists.
    result, log = egress_capture(tmp_path, LATER_LINE, monkeypatch)
    assert "egress capture: streaming" in result.stdout, result.stdout + result.stderr
    made = calls(tmp_path)
    egress_up = index_of(made, "--wait-timeout 300 egress")
    follower = index_of(made, "logs --timestamps --follow egress-container-id")
    # teamctl starts the agent only after both probes; this stub world stops
    # at the boundary probe, so the agent is checked never to precede them.
    assert egress_up < follower < index_of(made, "probe-ingress.mjs")
    assert all(i > follower for i, call in enumerate(made) if call.rstrip().endswith(" agent"))
    assert log.read_text() == LATER_LINE + "\n"
    receipt = json.loads(log.with_name(log.name + ".receipt.json").read_text())
    assert receipt["container"] == "egress-container-id" and receipt["follower_pid"] > 0
    assert receipt["attached_at"] < receipt["witness_at"]


def test_a_capture_that_shows_no_new_line_holds_the_agent(tmp_path, monkeypatch):
    # Replayed history alone does not show the follower streaming.
    result, log = egress_capture(tmp_path, EARLIER_LINE, monkeypatch)
    assert result.returncode == 1
    assert "egress capture: no line after the follower attached" in result.stderr, result.stderr
    made = calls(tmp_path)
    assert not [call for call in made if "probe-ingress.mjs" in call]
    assert not [call for call in made if call.rstrip().endswith(" agent")]


def test_a_capture_refuses_a_log_file_that_exists(tmp_path, monkeypatch):
    log = tmp_path / "capture" / "agent-egress-refusals.log"
    log.parent.mkdir()
    log.write_text("earlier\n")
    monkeypatch.setenv("TEAM_DEPLOYMENT_EGRESS_LOG", str(log))
    result = start_with_agents(tmp_path, {"id": "devteam:example.com"}, BASE_SERVICES, PUBLIC_REGISTRY_ADDRESSES)
    assert result.returncode == 1 and "already exists" in result.stderr
    assert log.read_text() == "earlier\n"


def test_without_a_capture_path_start_attaches_no_follower(tmp_path):
    start_with_agents(tmp_path, {"id": "devteam:example.com"}, BASE_SERVICES, PUBLIC_REGISTRY_ADDRESSES)
    assert not [call for call in calls(tmp_path) if "--timestamps --follow" in call]
