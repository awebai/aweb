"""Only live private commands remain; enrollment completion is person-signed."""

import inspect
import subprocess
import sys

import pytest
from aweb_key_holder.enrollment import Holder


@pytest.mark.parametrize("command", ["bind", "finish", "activate", "authorize"])
def test_retired_operator_commands_are_not_accepted(command, tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "aweb_key_holder.cli",
            "--state",
            str(tmp_path / "absent"),
            command,
            "--help",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "invalid choice" in result.stderr


@pytest.mark.parametrize("command", ["bootstrap", "issue-person"])
def test_live_private_issuance_commands_remain_available(command, tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "aweb_key_holder.cli",
            "--state",
            str(tmp_path / "absent"),
            command,
            "--help",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0


def test_controller_authorizer_and_privileged_completion_defaults_are_gone():
    assert not hasattr(Holder, "authorize_bootstrap")
    for operation in [
        Holder.bind_registration,
        Holder.finish_creation,
        Holder.finish,
        Holder.activate,
    ]:
        assert (
            inspect.signature(operation).parameters["caller"].default
            is inspect.Parameter.empty
        )


@pytest.mark.parametrize("startup_bytes", [0, 8 * 1024 * 1024])
def test_hardware_manifest_flag_keeps_unattested_enrollment_available(
    tmp_path,
    monkeypatch,
    startup_bytes,
):
    import os

    if startup_bytes:
        (tmp_path / "sitecustomize.py").write_text(
            f"import sys\nsys.stdout.buffer.write(b'x' * {startup_bytes})\nsys.stdout.flush()\n"
        )
        monkeypatch.setenv(
            "PYTHONPATH",
            os.pathsep.join(
                filter(None, (str(tmp_path), os.environ.get("PYTHONPATH")))
            ),
        )
    import re
    import time

    import httpx
    from aweb_key_holder.keys import KeyStore

    state = tmp_path / "private"
    KeyStore.create(state, organisation="example.test")
    manifest = tmp_path / "pin.json"
    manifest.write_text("{}")
    command = [
        sys.executable,
        "-m",
        "aweb_key_holder.cli",
        "--state",
        str(state),
        "--registry-origin",
        "https://registry.example",
        "--origin",
        "https://holder.example",
        "--approval-origin",
        "https://approval.example",
        "--rp-id",
        "approval.example",
        "--grading",
        "hardware",
        "--mds-cache",
        str(tmp_path / "cache"),
        "--mds-manifest",
        str(manifest),
        "serve",
        "--bind",
        "127.0.0.1",
        "--port",
        "0",
    ]
    log_path = tmp_path / "holder.log"
    with log_path.open("w") as log:
        child = subprocess.Popen(command, stdout=log, stderr=log, text=True)
        try:
            deadline = time.monotonic() + 5
            with httpx.Client(timeout=0.2, trust_env=False) as client:
                while time.monotonic() < deadline and child.poll() is None:
                    listening = re.search(
                        r"Uvicorn running on http://127\.0\.0\.1:(\d+)",
                        log_path.read_text(),
                    )
                    if listening is None:
                        time.sleep(0.02)
                        continue
                    port = int(listening.group(1))
                    try:
                        response = client.get(f"http://127.0.0.1:{port}/")
                        assert response.status_code == 404
                        break
                    except httpx.TransportError:
                        time.sleep(0.02)
                else:
                    raise AssertionError(
                        "holder did not start with unavailable metadata"
                    )
        finally:
            child.terminate()
            child.communicate(timeout=10)
    errors = log_path.read_text()
    assert "metadata load failed" in errors
    assert "unrecognized arguments" not in errors
