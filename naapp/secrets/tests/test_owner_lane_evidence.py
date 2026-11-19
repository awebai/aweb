"""Docker bind placement and bootstrap diagnostics work without exposing child text."""

import json
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from aweb_secrets.erasure import ErasureFailure
from e2e.lane_evidence import (
    BootstrapOperation,
    create_runtime_directory,
    record_bootstrap,
    retain_bootstrap_evidence,
)


def test_candidate_runtime_is_unique_and_visible_under_the_daemon_shared_root(
    tmp_path, tmp_path_factory
):
    environment = {"AWEB_DOCKER_BIND_ROOT": str(tmp_path)}
    first = create_runtime_directory(tmp_path_factory, environment=environment)
    second = create_runtime_directory(tmp_path_factory, environment=environment)
    assert first.parent == second.parent == tmp_path
    assert first != second
    assert first.stat().st_mode & 0o777 == 0o755
    (first / "Corefile").write_text("fixture DNS configuration")
    assert (tmp_path / first.name / "Corefile").read_text() == "fixture DNS configuration"


@pytest.mark.parametrize("setting", ["AWEB_DOCKER_BIND_ROOT", "CANDIDATE_LOG_DIR"])
@pytest.mark.parametrize("invalid_root", ["relative", "missing", "file", "symlink"])
def test_shared_directories_refuse_invalid_mounts_before_creating_evidence(
    tmp_path, tmp_path_factory, setting, invalid_root
):
    file = tmp_path / "file"
    file.write_text("not a directory")
    link = tmp_path / "link"
    link.symlink_to(tmp_path, target_is_directory=True)
    roots = {
        "relative": Path("relative"),
        "missing": tmp_path / "missing",
        "file": file,
        "symlink": link,
    }
    environment = {setting: str(roots[invalid_root])}
    with pytest.raises(ValueError, match="existing absolute writable directory"):
        if setting == "AWEB_DOCKER_BIND_ROOT":
            create_runtime_directory(tmp_path_factory, environment=environment)
        else:
            retain_bootstrap_evidence(tmp_path, environment=environment)


@pytest.mark.parametrize(
    "environment", [{"CANDIDATE_LOG_DIR": "/shared/logs"}, {"DOCKER_HOST": "tcp://daemon:2376"}]
)
def test_a_gate_or_remote_daemon_requires_an_explicit_shared_bind_root(
    tmp_path_factory, environment
):
    with pytest.raises(ValueError, match="Set AWEB_DOCKER_BIND_ROOT"):
        create_runtime_directory(tmp_path_factory, environment=environment)


def test_standalone_local_docker_uses_pytests_owned_directory(tmp_path_factory):
    runtime = create_runtime_directory(
        tmp_path_factory, environment={"DOCKER_HOST": "unix:///var/run/docker.sock"}
    )
    assert runtime.parent == tmp_path_factory.getbasetemp()
    assert runtime.is_dir()


@pytest.mark.parametrize("exit_code", [0, 37])
def test_actual_child_outcomes_are_retained_without_arguments_or_output(tmp_path, exit_code):
    runtime, logs = tmp_path / "runtime", tmp_path / "logs"
    runtime.mkdir()
    logs.mkdir()
    private = secrets.token_urlsafe(32)
    (runtime / "key-file").write_text(private)
    child = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; print(sys.argv[1]); print('ERROR: 42501 '+sys.argv[1], file=sys.stderr); sys.exit(int(sys.argv[2]))",
            private,
            str(exit_code),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    record_bootstrap(runtime, operation=BootstrapOperation.PROVISION, result=child)
    destination = retain_bootstrap_evidence(runtime, environment={"CANDIDATE_LOG_DIR": str(logs)})
    assert destination is not None
    payload = (destination / "bootstrap.json").read_text()
    if private in payload:
        raise AssertionError("Child arguments or output reached retained bootstrap evidence")
    assert list(destination.iterdir()) == [destination / "bootstrap.json"]
    record = json.loads(payload)["records"][0]
    assert record == {
        "operation": "provision_database",
        "exit_code": exit_code,
        "error_code": "postgres_42501" if exit_code else None,
        "stdout_bytes": len(child.stdout.encode()),
        "stderr_bytes": len(child.stderr.encode()),
    }
    shutil.rmtree(runtime)
    assert (destination / "bootstrap.json").read_text() == payload


@pytest.mark.parametrize("reason", list(ErasureFailure))
def test_initializer_refusal_retains_its_named_reason_and_not_its_text(tmp_path, reason):
    child = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; sys.exit(sys.argv[1])",
            reason.value + ": private child detail",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    path = record_bootstrap(tmp_path, operation=BootstrapOperation.INITIALIZE, result=child)
    record = json.loads(path.read_text())
    assert record["error_code"] == reason.value
    assert "private child detail" not in path.read_text()


def test_unknown_child_failure_is_explicit_and_never_retained_as_success(tmp_path):
    child = subprocess.run(
        [sys.executable, "-c", "raise SystemExit(9)"], text=True, capture_output=True, check=False
    )
    path = record_bootstrap(tmp_path, operation=BootstrapOperation.INITIALIZE, result=child)
    assert json.loads(path.read_text())["error_code"] == "unclassified_child_failure"


@pytest.mark.parametrize("field", ["operation", "error_code"])
def test_malformed_metadata_refuses_export_instead_of_copying_unchecked_input(tmp_path, field):
    runtime, logs = tmp_path / "runtime", tmp_path / "logs"
    (runtime / "bootstrap-evidence").mkdir(parents=True)
    logs.mkdir()
    record = {
        "operation": "provision_database",
        "exit_code": 0,
        "error_code": None,
        "stdout_bytes": 0,
        "stderr_bytes": 0,
    }
    record[field] = []
    (runtime / "bootstrap-evidence" / "invalid.json").write_text(json.dumps(record))
    with pytest.raises(ValueError, match="record schema"):
        retain_bootstrap_evidence(runtime, environment={"CANDIDATE_LOG_DIR": str(logs)})
    assert list(logs.iterdir()) == []
