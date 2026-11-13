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


def test_backup_refuses_while_a_writer_runs(tmp_path):
    path = deployment(tmp_path, EXAMPLE)
    result = run(tmp_path, "backup", path, str(tmp_path / "backup"), command=TEAMCTL, docker_ok=True,
                 answers={"--status running --services": "postgres\naweb\n"})
    assert result.returncode == 1 and "aweb" in result.stderr and "teamctl stop" in result.stderr
    assert not (tmp_path / "backup").exists()
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
    assert len(archived) == 1 and archived[0].rstrip().endswith("./signer/private-controller"), archived
