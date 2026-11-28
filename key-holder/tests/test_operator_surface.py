"""Only live private commands remain; enrollment completion is person-signed."""

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


def test_privileged_enrollment_steps_cannot_be_called_without_a_caller(tmp_path):
    from aweb_key_holder.keys import KeyStore

    store = KeyStore.create(tmp_path / "private", organisation="example.test")
    holder = Holder(store, registry=None, origin="https://holder.example")
    audit = store.audit()
    calls = [
        lambda: holder.bind_registration("person", {}, registration_count=1),
        lambda: holder.finish_creation("person", {}, issuer=None),
        lambda: holder.finish("person", {}, chain=[]),
        lambda: holder.activate("person", chain=[]),
    ]
    # A required keyword is checked when the call is made, before any
    # coroutine exists or any state is read.
    for call in calls:
        with pytest.raises(TypeError, match="caller"):
            call()
    assert store.audit() == audit


def test_hardware_manifest_flag_keeps_unattested_enrollment_available(tmp_path):
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
        child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=log, text=True)
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
