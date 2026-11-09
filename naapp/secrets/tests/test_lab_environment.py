"""The explicit native/KMS BYOT profile never substitutes for release inputs."""

import os
import pwd
import subprocess
import sys
from pathlib import Path

import pytest
from lab_environment import LAB_REQUIRED_NAMES, LabConfigurationError, load_lab_environment
from release_environment import ConfigurationError, load_environment

PREFIX = "AWEB_SECRETS_E2E_"


def configured(tmp_path: Path) -> dict[str, str]:
    runner = next(p for p in pwd.getpwall() if p.pw_uid > 0 and p.pw_uid != os.geteuid())
    inputs = {
        "TEAM_ID": "lab:example.test",
        "API_ORIGIN": "https://api.secrets.test",
        "CONSOLE_ORIGIN": "https://console.secrets.test",
        "LOGS_ORIGIN": "https://logs.secrets.test",
        "LOGS_CONSOLE_ORIGIN": "https://console.logs.secrets.test",
        "KMS_KEY_ARN": "arn:aws:kms:eu-central-1:123456789012:key/lab-key",
        "AWS_REGION": "eu-central-1",
        "RUNNER_BINARY": sys.executable,
        "RUNNER_CONFIG_FILE": str(tmp_path / "runner.json"),
        "RUNNER_USER": runner.pw_name,
        "RUNNER_STATE_DIR": str(tmp_path / "runner-state"),
        "AW_BINARY": sys.executable,
        "AWID_REGISTRY_URL": "https://registry.example.test",
        "COORDINATION_ORIGIN": "https://coordination.example.test",
    }
    credentials = tmp_path / "kms.credentials"
    credentials.write_bytes(os.urandom(32))
    credentials.chmod(0o600)
    inputs["KMS_CREDENTIALS_FILE"] = str(credentials)
    for actor in ("HUMAN", "AGENT_A", "AGENT_B"):
        home = tmp_path / actor / ".aw"
        home.mkdir(parents=True, mode=0o700)
        inputs[actor + "_IDENTITY_HOME"] = str(home)
    return {PREFIX + name: value for name, value in inputs.items()}


def test_eighteen_reference_selectors_need_no_hosted_or_vault_credentials(tmp_path):
    inputs = configured(tmp_path)
    result = load_lab_environment(inputs, private_dns="excluded")
    assert len(result) == len(LAB_REQUIRED_NAMES) == 18
    assert dict(result) == inputs
    with pytest.raises(TypeError):
        result[PREFIX + "TEAM_ID"] = "other:example.test"
    with pytest.raises(ConfigurationError):
        load_environment(inputs)


def test_native_identity_directories_can_be_readable_without_being_writable_by_others(tmp_path):
    inputs = configured(tmp_path)
    for actor in ("HUMAN", "AGENT_A", "AGENT_B"):
        Path(inputs[PREFIX + actor + "_IDENTITY_HOME"]).chmod(0o755)
    assert dict(load_lab_environment(inputs, private_dns="excluded")) == inputs


@pytest.mark.parametrize("name", LAB_REQUIRED_NAMES)
def test_each_required_selector_is_required_without_echoing_values(tmp_path, name):
    inputs = configured(tmp_path)
    inputs.pop(name)
    with pytest.raises(LabConfigurationError) as caught:
        load_lab_environment(inputs, private_dns="excluded")
    assert name in str(caught.value)
    assert str(tmp_path) not in str(caught.value)


@pytest.mark.parametrize("coverage", [None, "", "passed", True])
def test_dns_coverage_must_be_an_explicit_choice(tmp_path, coverage):
    with pytest.raises(LabConfigurationError):
        load_lab_environment(configured(tmp_path), private_dns=coverage)


def test_dns_is_required_only_for_explicit_included_scenario(tmp_path):
    inputs = configured(tmp_path)
    with pytest.raises(LabConfigurationError):
        load_lab_environment(inputs, private_dns="included")
    inputs[PREFIX + "PRIVATE_DNS_NAME"] = "private.lab.example.test"
    assert (
        load_lab_environment(inputs, private_dns="included")[PREFIX + "PRIVATE_DNS_NAME"]
        == "private.lab.example.test"
    )
    assert PREFIX + "PRIVATE_DNS_NAME" not in load_lab_environment(inputs, private_dns="excluded")


@pytest.mark.parametrize("value", ["127.0.0.1", "https://private.example.test", "bad host"])
def test_included_private_dns_is_a_hostname_reference_only(tmp_path, value):
    inputs = configured(tmp_path)
    inputs[PREFIX + "PRIVATE_DNS_NAME"] = value
    with pytest.raises(LabConfigurationError):
        load_lab_environment(inputs, private_dns="included")


@pytest.mark.parametrize(
    "value", ["http://registry.test", "https://u:p@registry.test", "https://registry.test/a"]
)
def test_authority_origins_are_explicit_https_without_credential_material(tmp_path, value):
    inputs = configured(tmp_path)
    name = PREFIX + "AWID_REGISTRY_URL"
    inputs[name] = value
    with pytest.raises(LabConfigurationError) as caught:
        load_lab_environment(inputs, private_dns="excluded")
    assert name in str(caught.value)
    assert value not in str(caught.value)


@pytest.mark.parametrize("name", ["API_ORIGIN", "LOGS_ORIGIN"])
def test_agent_and_human_origins_remain_separate(tmp_path, name):
    inputs = configured(tmp_path)
    inputs[PREFIX + ("CONSOLE_ORIGIN" if name == "API_ORIGIN" else "LOGS_CONSOLE_ORIGIN")] = inputs[
        PREFIX + name
    ]
    with pytest.raises(LabConfigurationError):
        load_lab_environment(inputs, private_dns="excluded")


@pytest.mark.parametrize("problem", ["public", "symlink", "directory"])
def test_kms_credentials_are_private_file_references(tmp_path, problem):
    inputs = configured(tmp_path)
    path = Path(inputs[PREFIX + "KMS_CREDENTIALS_FILE"])
    if problem == "public":
        path.chmod(0o644)
    else:
        path.unlink()
        if problem == "directory":
            path.mkdir()
        else:
            target = tmp_path / "other.credentials"
            target.write_bytes(os.urandom(32))
            target.chmod(0o600)
            path.symlink_to(target)
    with pytest.raises(LabConfigurationError):
        load_lab_environment(inputs, private_dns="excluded")


def test_kms_region_must_match_the_selected_key(tmp_path):
    inputs = configured(tmp_path)
    inputs[PREFIX + "AWS_REGION"] = "us-east-1"
    with pytest.raises(LabConfigurationError):
        load_lab_environment(inputs, private_dns="excluded")


@pytest.mark.parametrize(
    "user", [pwd.getpwuid(os.geteuid()).pw_name, "root", "lab-user-that-does-not-exist"]
)
def test_runner_must_resolve_to_a_real_separate_nonroot_user(tmp_path, user):
    inputs = configured(tmp_path)
    inputs[PREFIX + "RUNNER_USER"] = user
    with pytest.raises(LabConfigurationError):
        load_lab_environment(inputs, private_dns="excluded")


@pytest.mark.parametrize(
    "problem", ["same-home", "writable-home", "relative-binary", "missing-binary"]
)
def test_explicit_actor_and_binary_selection_cannot_fall_back(tmp_path, problem):
    inputs = configured(tmp_path)
    if problem == "same-home":
        inputs[PREFIX + "AGENT_B_IDENTITY_HOME"] = inputs[PREFIX + "AGENT_A_IDENTITY_HOME"]
    elif problem == "writable-home":
        Path(inputs[PREFIX + "HUMAN_IDENTITY_HOME"]).chmod(0o777)
    else:
        inputs[PREFIX + "AW_BINARY"] = (
            "aw" if problem == "relative-binary" else str(tmp_path / "missing-aw")
        )
    with pytest.raises(LabConfigurationError):
        load_lab_environment(inputs, private_dns="excluded")


def test_hosted_and_vault_metadata_is_never_adopted_as_lab_authority(tmp_path):
    inputs = configured(tmp_path)
    extra = {
        PREFIX + name: "not-a-lab-authority"
        for name in ("MCP_URL", "AGENT_A_ID", "AGENT_B_ID", "ONEPASSWORD_TOKEN_FILE")
    }
    assert dict(load_lab_environment({**inputs, **extra}, private_dns="excluded")) == inputs


def test_explicit_lab_command_fails_missing_inputs_without_hosted_requirements():
    script = Path(__file__).parents[1] / "e2e" / "lab_environment.py"
    result = subprocess.run(
        [sys.executable, str(script), "--private-dns", "excluded"],
        env={},
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 2
    assert PREFIX + "KMS_CREDENTIALS_FILE" in result.stderr
    assert PREFIX + "AGENT_A_IDENTITY_HOME" in result.stderr
    assert "MCP_URL" not in result.stderr and "ONEPASSWORD" not in result.stderr
    assert result.stdout == ""
