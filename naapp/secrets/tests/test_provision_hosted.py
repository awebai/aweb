"""Controller-local safety with real files; hosted provisioning is HO6 proof."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from provision_hosted import (
    OwnerLogin,
    ProvisioningError,
    StateStore,
    consent_code,
    identity_from_result,
    provision,
)


def login_file(tmp_path: Path) -> Path:
    path = tmp_path / "owner-login"
    path.write_text("owner@example.test\n" + os.urandom(24).hex() + "\n")
    path.chmod(0o600)
    return path


def test_owner_login_is_private_read_only_and_hidden_in_repr(tmp_path: Path):
    path = login_file(tmp_path)
    before = path.read_bytes()
    login = OwnerLogin.read(path)
    assert login.email == "owner@example.test"
    assert login.password and login.password not in repr(login)
    assert login.email not in repr(login)
    assert path.read_bytes() == before


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o660, 0o644])
def test_owner_login_refuses_shared_files_without_echoing(tmp_path: Path, mode: int):
    path = login_file(tmp_path)
    path.chmod(mode)
    with pytest.raises(ProvisioningError) as caught:
        OwnerLogin.read(path)
    assert str(caught.value) == "owner_login_file_invalid"
    assert str(path) not in str(caught.value)


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b"one-line",
        b"a\nb\nc\n",
        b"a\n\n",
        b" a\nb\n",
        b"a\nb \n",
        b"a\nb\n\n",
        b"a\r\nb\r\n",
        b"\xef\xbb\xbfa\nb\n",
        b"a\n\xff\n",
    ],
)
def test_owner_login_requires_exact_two_line_format(tmp_path: Path, content: bytes):
    path = tmp_path / "owner-login"
    path.write_bytes(content)
    path.chmod(0o600)
    with pytest.raises(ProvisioningError, match="^owner_login_file_invalid$"):
        OwnerLogin.read(path)
    assert path.read_bytes() == content


def test_owner_login_does_not_follow_symlinks(tmp_path: Path):
    target = login_file(tmp_path)
    link = tmp_path / "symlink"
    link.symlink_to(target)
    with pytest.raises(ProvisioningError, match="^owner_login_file_invalid$"):
        OwnerLogin.read(link)


async def test_owner_login_cannot_be_overwritten_by_a_controller_output(tmp_path: Path):
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    source = login_file(tmp_path)
    target = directory / "agent-a.access-token"
    target.hardlink_to(source)
    before = source.read_bytes()
    with pytest.raises(ProvisioningError, match="^owner_login_state_conflict$"):
        await provision("https://cloud.example.test", directory, source)
    assert source.read_bytes() == before
    assert not (directory / "controller-state.json").exists()


def test_cli_refuses_shared_login_before_network_and_keeps_it_unchanged(tmp_path: Path):
    path = login_file(tmp_path)
    before = path.read_bytes()
    path.chmod(0o644)
    script = Path(__file__).parents[1] / "e2e" / "provision_hosted.py"
    result = subprocess.run(
        [
            sys.executable,
            str(script),
            "--cloud-origin",
            "https://cloud.example.invalid",
            "--state-dir",
            str(tmp_path / "state"),
        ],
        env={"AWEB_SECRETS_E2E_CLOUD_OWNER_LOGIN_FILE": str(path)},
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 2
    assert result.stdout == ""
    assert result.stderr == "Provisioning refused: owner_login_file_invalid\n"
    assert path.read_bytes() == before
    assert not (tmp_path / "state" / "controller-state.json").exists()


def test_only_one_controller_can_hold_the_state(tmp_path: Path):
    directory = tmp_path / "state"
    with StateStore(directory):
        script = Path(__file__).parents[1] / "e2e" / "provision_hosted.py"
        result = subprocess.run(
            [
                sys.executable,
                str(script),
                "--cloud-origin",
                "https://cloud.example.test",
                "--state-dir",
                str(directory),
            ],
            env={},
            capture_output=True,
            text=True,
            timeout=10,
        )
    assert result.returncode == 2
    assert result.stdout == ""
    assert result.stderr == "Provisioning refused: state_busy\n"


def test_pending_intent_survives_restart_and_refuses_replay(tmp_path: Path):
    directory = tmp_path / "state"
    with StateStore(directory) as store:
        store.begin("https://cloud.example.test")
        store.before("team_create")
    with StateStore(directory) as store:
        with pytest.raises(ProvisioningError, match="^provisioning_incomplete$"):
            store.begin("https://cloud.example.test")
    saved = json.loads((directory / "controller-state.json").read_text())
    assert saved["step"] == "team_create"
    assert saved["status"] == "in_progress"


def test_private_state_rejects_shared_directory(tmp_path: Path):
    directory = tmp_path / "state"
    directory.mkdir(mode=0o755)
    with pytest.raises(ProvisioningError, match="^state_directory_invalid$"):
        with StateStore(directory):
            pass


def test_access_only_outputs_are_published_from_verified_ready_state(tmp_path: Path):
    directory = tmp_path / "state"
    pairs = {
        agent: {"access_token": os.urandom(24).hex(), "refresh_token": os.urandom(24).hex()}
        for agent in ("a", "b")
    }
    with StateStore(directory) as store:
        store.begin("https://cloud.example.test")
        with pytest.raises(ProvisioningError, match="^outputs_not_ready$"):
            store.publish()
        store.data.update(
            status="ready",
            team_id="proof:example.test",
            agents={"a": {"agent_id": "agent-a"}, "b": {"agent_id": "agent-b"}},
            pairs=pairs,
        )
        store.save()
        outputs = store.publish()
    assert set(outputs) == {
        "AWEB_SECRETS_E2E_" + suffix
        for suffix in (
            "TEAM_ID",
            "AGENT_A_ID",
            "AGENT_B_ID",
            "MCP_URL",
            "AGENT_A_MCP_TOKEN_FILE",
            "AGENT_B_MCP_TOKEN_FILE",
        )
    }
    assert outputs["AWEB_SECRETS_E2E_TEAM_ID"] == "proof:example.test"
    for agent in ("a", "b"):
        path = Path(outputs[f"AWEB_SECRETS_E2E_AGENT_{agent.upper()}_MCP_TOKEN_FILE"])
        assert path.is_absolute()
        assert path.read_text() == pairs[agent]["access_token"]
        assert path.stat().st_mode & 0o777 == 0o600
        assert pairs[agent]["refresh_token"] not in path.read_text()
    for name in ("controller-state.json", "runtime.json"):
        assert (directory / name).stat().st_mode & 0o777 == 0o600
    assert directory.stat().st_mode & 0o777 == 0o700
    assert json.loads((directory / "runtime.json").read_text()) == outputs


def test_consent_redirect_requires_exact_owned_callback_and_single_state_code():
    redirect = "http://localhost:8765/callback"
    assert consent_code(redirect + "?code=opaque-code&state=expected", redirect, "expected")
    for location in (
        "https://other.example.test/callback?code=opaque-code&state=expected",
        redirect + "?code=opaque-code&state=wrong",
        redirect + "?code=one&code=two&state=expected",
        redirect + "?error=access_denied&state=expected",
        redirect + "?code=opaque-code&state=expected#fragment",
    ):
        with pytest.raises(ProvisioningError, match="^consent_response_invalid$"):
            consent_code(location, redirect, "expected")


def test_whoami_checks_semantic_json_in_text_and_sdk_result_wrapper():
    identity = {"team_id": "proof:example.test", "agent_id": "agent-a"}
    value = json.dumps(identity)
    assert (
        identity_from_result({"isError": False, "structuredContent": {"result": value}}) == identity
    )
    assert identity_from_result({"content": [{"type": "text", "text": value}]}) == identity
    with pytest.raises(ProvisioningError, match="^whoami_invalid$"):
        identity_from_result({"isError": True, "content": [{"type": "text", "text": value}]})
