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


def test_hardware_manifest_flag_reaches_the_checked_loader(tmp_path):
    from aweb_key_holder.keys import KeyStore

    state=tmp_path/'private';KeyStore.create(state,organisation='example.test')
    manifest=tmp_path/'pin.json';manifest.write_text('{}')
    result=subprocess.run([sys.executable,'-m','aweb_key_holder.cli','--state',str(state),
        '--registry-origin','https://registry.example','--origin','https://holder.example',
        '--approval-origin','https://approval.example','--rp-id','approval.example','--grading','hardware',
        '--mds-cache',str(tmp_path/'cache'),'--mds-manifest',str(manifest),'serve'],capture_output=True,text=True,check=False,timeout=10)
    assert result.returncode==1
    assert 'manifest_invalid' in result.stderr
    assert 'unrecognized arguments' not in result.stderr
