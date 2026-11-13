"""deploy/team/teamctl's lifecycle commands: stop keeps every volume and
file, destroy removes only the bundle's own containers and volumes and only
when the project is named, backup refuses while a writer runs, and restore
fails closed."""

from pathlib import Path

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
