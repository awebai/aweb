"""Operator orchestration against an external Docker recorder; no services."""

import json

from tests.test_team_deployment_runner import EXAMPLE, TEAMCTL, deployment, run
from tests.test_team_deployment_teamctl import calls


def configuration():
    return {
        **EXAMPLE,
        "secrets": {
            "image": "ghcr.io/awebai/aweb-secrets@sha256:" + "3" * 64,
            "appId": "secrets-devteam",
            "publicOrigin": "https://secrets.example.com",
            "consoleOrigin": "https://secrets-console.example.com",
            "emailSmtpHost": "smtp.example.com",
            "emailFrom": "secrets@example.com",
            "egressDeniedNetworks": ["169.254.0.0/16"],
            "backupMaxAgeSeconds": 604800,
        },
    }


def test_fresh_start_initialises_before_starting_any_service_other_than_postgres(
    tmp_path,
):
    result = run(
        tmp_path,
        "start",
        deployment(tmp_path, configuration()),
        command=TEAMCTL,
        docker_ok=True,
    )
    assert result.returncode == 0, result.stderr
    made = calls(tmp_path)
    init = next(
        i
        for i, call in enumerate(made)
        if "run --rm --no-deps secrets-erasure-init" in call
    )
    starts = [i for i, call in enumerate(made) if " up -d " in call]
    assert len(starts) == 2 and starts[0] < init < starts[1]
    assert made[starts[0]].endswith(" postgres ")


def test_existing_volume_is_never_initialised_by_start(tmp_path):
    result = run(
        tmp_path,
        "start",
        deployment(tmp_path, configuration()),
        command=TEAMCTL,
        docker_ok=True,
        answers={"volume ls": "teamrun_postgres_data\n"},
    )
    assert result.returncode == 0, result.stderr
    assert not any(
        "run --rm --no-deps secrets-erasure-init" in call for call in calls(tmp_path)
    )


def test_failed_volume_listing_does_not_become_a_fresh_install(tmp_path):
    result = run(
        tmp_path,
        "start",
        deployment(tmp_path, configuration()),
        command=TEAMCTL,
        docker_ok=True,
        fails={"volume ls": 78},
    )
    assert result.returncode != 0 and "could not list" in result.stderr
    assert not any(" up " in f" {call} " for call in calls(tmp_path))


def test_failed_initializer_does_not_start_services(tmp_path):
    result = run(
        tmp_path,
        "start",
        deployment(tmp_path, configuration()),
        command=TEAMCTL,
        docker_ok=True,
        fails={"run --rm --no-deps secrets-erasure-init": 79},
    )
    assert result.returncode != 0
    starts = [call for call in calls(tmp_path) if " up -d " in call]
    assert len(starts) == 1 and starts[0].endswith(" postgres ")


def test_fresh_start_requires_an_explicit_backup_expiry_policy(tmp_path):
    config = configuration()
    del config["secrets"]["backupMaxAgeSeconds"]
    result = run(
        tmp_path, "start", deployment(tmp_path, config), command=TEAMCTL, docker_ok=True
    )
    assert result.returncode != 0 and "backupMaxAgeSeconds" in result.stderr
    assert not any(" up " in f" {call} " for call in calls(tmp_path))


def test_explicit_operator_init_calls_the_same_one_shot_service(tmp_path):
    result = run(
        tmp_path,
        "init-erasure",
        deployment(tmp_path, configuration()),
        command=TEAMCTL,
        docker_ok=True,
    )
    assert result.returncode == 0, result.stderr
    assert any(
        "run --rm --no-deps secrets-erasure-init" in call for call in calls(tmp_path)
    )
    assert not any(
        " up -d " in call and not call.endswith(" postgres ")
        for call in calls(tmp_path)
    )


def test_operator_init_requires_secrets_to_be_known_stopped(tmp_path):
    path = deployment(tmp_path, configuration())
    result = run(
        tmp_path,
        "init-erasure",
        path,
        command=TEAMCTL,
        docker_ok=True,
        answers={"--status running --services secrets": "secrets\n"},
    )
    assert result.returncode != 0 and "stop Secrets" in result.stderr
    assert not any(" up " in f" {call} " for call in calls(tmp_path))
    result = run(
        tmp_path,
        "init-erasure",
        path,
        command=TEAMCTL,
        docker_ok=True,
        fails={"--status running --services secrets": 78},
    )
    assert result.returncode != 0 and "could not check" in result.stderr
    assert not any(" up " in f" {call} " for call in calls(tmp_path))


def test_backup_excludes_ledger_only_for_secrets_and_records_it_in_manifest(tmp_path):
    path = deployment(tmp_path, EXAMPLE)
    target = tmp_path / "backup"
    result = run(
        tmp_path,
        "backup",
        path,
        str(target),
        command=TEAMCTL,
        docker_ok=True,
        answers={"select datname": "aweb\nsecrets\n"},
    )
    assert result.returncode == 0, result.stderr
    dumps = [call for call in calls(tmp_path) if " pg_dump " in call]
    assert len(dumps) == 2
    assert "--exclude-schema=secrets_erasure" not in dumps[0]
    assert "--exclude-schema=secrets_erasure" in dumps[1]
    entries = {
        entry["name"]: entry
        for entry in json.loads((target / "manifest.json").read_text())["databases"]
    }
    assert entries["secrets"]["excludedSchemas"] == ["secrets_erasure"]
    assert entries["aweb"].get("excludedSchemas", []) == []


def test_lab_restore_refuses_secrets_before_any_container_or_target_write(tmp_path):
    target = tmp_path / "backup"
    target.mkdir()
    (target / "manifest.json").write_text(
        json.dumps(
            {
                "format": 1,
                "databases": [{"name": "secrets"}],
            }
        )
    )
    result = run(
        tmp_path,
        "restore",
        "--lab-rehearsal",
        deployment(tmp_path, EXAMPLE),
        str(target),
        command=TEAMCTL,
        docker_ok=True,
    )
    assert result.returncode != 0 and "Secrets" in result.stderr
    assert calls(tmp_path) == []
