"""Operator preflight uses real protected files and the actual runner UID."""

import json
import os
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from test_jobs import RUNNER, config_file, definition

from aweb_secrets_runner.protocol import public_did
from aweb_secrets_runner.state import Identity, IdentityStore


def configured(tmp_path):
    body = definition(tmp_path)
    config = config_file(tmp_path, body)
    directory = tmp_path / "state"
    store = IdentityStore(directory)
    identity = Identity(
        origin="https://secrets.example",
        runner_id=RUNNER,
        service_kid=public_did(Ed25519PrivateKey.generate().public_key()),
        signing_key=Ed25519PrivateKey.generate(),
        encryption_key=X25519PrivateKey.generate(),
    )
    with store.registration_lock():
        store.save(identity)
    return config, directory, identity


def command(config, directory):
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "aweb_secrets_runner",
            "doctor",
            "--config",
            str(config),
            "--state-dir",
            str(directory),
        ],
        input=b"",
        capture_output=True,
        timeout=5,
    )


def test_doctor_checks_pins_without_spawning_or_reading_a_code(tmp_path):
    config, directory, identity = configured(tmp_path)
    result = command(config, directory)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"runner_id": RUNNER, "jobs": ["fixture"]}
    assert result.stderr == b""
    assert identity.signing_key.private_bytes_raw().hex().encode() not in result.stdout
    assert identity.encryption_key.private_bytes_raw().hex().encode() not in result.stdout


@pytest.mark.parametrize(
    "defect,code",
    [
        ("same-user", "runner_user_unsafe"),
        ("config-write", "path_permissions"),
        ("file-write", "path_permissions"),
        ("file-changed", "file_pin_mismatch"),
        ("not-registered", "runner_unregistered"),
        ("state-write", "state_permissions"),
    ],
)
def test_doctor_refuses_unsafe_or_stale_setup_with_value_free_output(tmp_path, defect, code):
    config, directory, identity = configured(tmp_path)
    if defect == "same-user":
        document = json.loads(config.read_bytes())
        document["agent_uids"] = [os.geteuid()]
        config.write_text(json.dumps(document))
    elif defect == "config-write":
        config.chmod(0o666)
    elif defect == "file-write":
        (tmp_path / "program").chmod(0o777)
    elif defect == "file-changed":
        (tmp_path / "program").write_bytes(b"changed")
    elif defect == "not-registered":
        with IdentityStore(directory).registration_lock():
            IdentityStore(directory).save(
                Identity(
                    origin=identity.origin,
                    signing_key=identity.signing_key,
                    encryption_key=identity.encryption_key,
                )
            )
    else:
        directory.chmod(0o777)
    result = command(config, directory)
    assert result.returncode == 1
    assert result.stdout == b""
    assert result.stderr == (code + "\n").encode()
