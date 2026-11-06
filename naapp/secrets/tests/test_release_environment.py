"""Release E2E configuration refuses absent inputs without exposing values."""

import os
import subprocess
import sys
from pathlib import Path

import pytest
from release_environment import ConfigurationError, load_environment

PREFIX = "AWEB_SECRETS_E2E_"


def configured(tmp_path: Path) -> dict[str, str]:
    names = {
        "KMS_KEY_ARN": "arn:aws:kms:eu-central-1:123456789012:key/test-key",
        "AWS_REGION": "eu-central-1",
        "ONEPASSWORD_VAULT_ID": "vault-id",
        "ONEPASSWORD_ITEM_ID": "item-id",
        "ONEPASSWORD_API_FIELD_ID": "api-field-id",
        "ONEPASSWORD_CLI_FIELD_ID": "cli-field-id",
        "API_ORIGIN": "https://api.secrets.test",
        "CONSOLE_ORIGIN": "https://console.secrets.test",
        "LOGS_ORIGIN": "https://logs.secrets.test",
        "LOGS_CONSOLE_ORIGIN": "https://console.logs.secrets.test",
        "PRIVATE_DNS_NAME": "private-e2e.example.test",
        "MCP_URL": "https://mcp.secrets.test/mcp",
        "RUNNER_USER": "secrets-release-runner",
        "TEAM_ID": "release:example.test",
        "AGENT_A_ID": "agent-a",
        "AGENT_B_ID": "agent-b",
        # S19/M7 doctor checks these from the pre-provisioned runner UID.
        "RUNNER_BINARY": str(tmp_path / "runner"),
        "RUNNER_CONFIG_FILE": str(tmp_path / "runner.json"),
        "RUNNER_STATE_DIR": str(tmp_path / "runner-state"),
    }
    for name in (
        "KMS_CREDENTIALS_FILE",
        "ONEPASSWORD_TOKEN_FILE",
        "ONEPASSWORD_WRITER_TOKEN_FILE",
        "AGENT_A_MCP_TOKEN_FILE",
        "AGENT_B_MCP_TOKEN_FILE",
    ):
        path = tmp_path / name
        path.write_bytes(os.urandom(32))
        path.chmod(0o600)
        names[name] = str(path)
    return {PREFIX + name: value for name, value in names.items()}


def test_explicit_release_execution_fails_instead_of_skipping_without_environment():
    script = Path(__file__).parents[1] / "e2e" / "release_environment.py"
    result = subprocess.run(
        [sys.executable, str(script)], env={}, capture_output=True, text=True, timeout=10
    )
    assert result.returncode == 2
    assert PREFIX + "KMS_CREDENTIALS_FILE" in result.stderr
    assert PREFIX + "ONEPASSWORD_TOKEN_FILE" in result.stderr
    assert PREFIX + "MCP_URL" in result.stderr
    assert PREFIX + "RUNNER_USER" in result.stderr
    assert result.stdout == ""


def test_configured_inputs_are_references_and_never_read_as_credentials(tmp_path: Path):
    env = configured(tmp_path)
    result = load_environment(env)
    assert result[PREFIX + "KMS_CREDENTIALS_FILE"] == env[PREFIX + "KMS_CREDENTIALS_FILE"]
    assert result[PREFIX + "MCP_URL"] == env[PREFIX + "MCP_URL"]
    assert result[PREFIX + "PRIVATE_DNS_NAME"] == env[PREFIX + "PRIVATE_DNS_NAME"]


def test_private_dns_name_is_required(tmp_path: Path):
    env = configured(tmp_path)
    name = PREFIX + "PRIVATE_DNS_NAME"
    del env[name]
    with pytest.raises(ConfigurationError) as caught:
        load_environment(env)
    assert name in str(caught.value)


def test_logs_console_origin_is_required_without_fallback(tmp_path: Path):
    env = configured(tmp_path)
    name = PREFIX + "LOGS_CONSOLE_ORIGIN"
    del env[name]
    with pytest.raises(ConfigurationError) as caught:
        load_environment(env)
    assert str(caught.value) == "Release E2E requires valid inputs: " + name


def test_logs_console_origin_survives_the_explicit_mapping(tmp_path: Path):
    env = configured(tmp_path)
    name = PREFIX + "LOGS_CONSOLE_ORIGIN"
    assert load_environment(env)[name] == env[name]


@pytest.mark.parametrize(
    "console",
    [
        "https://logs.secrets.test",
        "https://LOGS.secrets.test:443/",
        "https://logs.secrets.test:8443",
        "https://logs.secrets.test./",
    ],
)
def test_logs_origins_require_distinct_hostnames_even_on_different_ports(
    tmp_path: Path, console: str
):
    env = configured(tmp_path)
    public, human = PREFIX + "LOGS_ORIGIN", PREFIX + "LOGS_CONSOLE_ORIGIN"
    env[human] = console
    with pytest.raises(ConfigurationError) as caught:
        load_environment(env)
    assert str(caught.value) == "Release E2E requires valid inputs: " + ", ".join(
        sorted((public, human))
    )


@pytest.mark.parametrize(
    "console",
    [
        "http://console.logs.secrets.test",
        "https://console.logs.secrets.test/path",
        "https://user:private-marker@console.logs.secrets.test",
        "https://console.logs.secrets.test?token=private-marker",
        "https://console.logs.secrets.test#private-marker",
    ],
)
def test_logs_console_requires_a_plain_https_origin_without_echoing_values(
    tmp_path: Path, console: str
):
    env = configured(tmp_path)
    name = PREFIX + "LOGS_CONSOLE_ORIGIN"
    env[name] = console
    with pytest.raises(ConfigurationError) as caught:
        load_environment(env)
    assert str(caught.value) == "Release E2E requires valid inputs: " + name


@pytest.mark.parametrize(
    "hostname",
    ["private-e2e.example.test", "PRIVATE-E2E.EXAMPLE.TEST", "private-e2e.example.test."],
)
def test_private_dns_accepts_hostnames_without_requiring_https(tmp_path: Path, hostname: str):
    env = configured(tmp_path)
    name = PREFIX + "PRIVATE_DNS_NAME"
    env[name] = hostname
    assert load_environment(env)[name] == hostname


@pytest.mark.parametrize(
    "hostname",
    [
        "https://private-e2e.example.test",
        "private-e2e.example.test:443",
        "10.255.255.1",
        "::1",
        "[::1]",
        "private-e2e.example.test/path",
        "private-e2e.example.test?token=untrusted-text",
        "*.example.test",
        "-private.example.test",
        "private-.example.test",
        "private_name.example.test",
        "private..example.test",
        "private name.example.test",
        "a" * 64 + ".example.test",
        ".".join(["a" * 63] * 4),
    ],
)
def test_private_dns_rejects_non_hostnames_without_echoing_them(tmp_path: Path, hostname: str):
    env = configured(tmp_path)
    name = PREFIX + "PRIVATE_DNS_NAME"
    env[name] = hostname
    with pytest.raises(ConfigurationError) as caught:
        load_environment(env)
    assert str(caught.value) == "Release E2E requires valid inputs: " + name
    assert hostname not in str(caught.value)


@pytest.mark.parametrize("problem", ["missing", "public-file", "directory", "relative"])
def test_bad_test_token_references_fail_without_echoing_paths(tmp_path: Path, problem: str):
    env = configured(tmp_path)
    name = PREFIX + "ONEPASSWORD_TOKEN_FILE"
    path = Path(env[name])
    if problem == "missing":
        path.unlink()
    elif problem == "public-file":
        path.chmod(0o644)
    elif problem == "directory":
        path.unlink()
        path.mkdir()
    else:
        env[name] = "private-token-location"
    with pytest.raises(ConfigurationError) as caught:
        load_environment(env)
    assert name in str(caught.value)
    assert str(path) not in str(caught.value)
    assert "private-token-location" not in str(caught.value)


def test_invalid_urls_fail_without_echoing_url_tokens(tmp_path: Path):
    env = configured(tmp_path)
    marker = os.urandom(24).hex()
    name = PREFIX + "MCP_URL"
    env[name] = f"https://user:{marker}@mcp.secrets.test/mcp?token={marker}"
    with pytest.raises(ConfigurationError) as caught:
        load_environment(env)
    assert name in str(caught.value)
    assert marker not in str(caught.value)


@pytest.mark.parametrize("suffix", ["ID", "MCP_TOKEN_FILE"])
def test_two_agents_require_distinct_public_ids_and_token_files(tmp_path: Path, suffix: str):
    env = configured(tmp_path)
    a, b = PREFIX + "AGENT_A_" + suffix, PREFIX + "AGENT_B_" + suffix
    env[b] = env[a]
    with pytest.raises(ConfigurationError) as caught:
        load_environment(env)
    assert a in str(caught.value)
    assert b in str(caught.value)


@pytest.mark.parametrize("console", ["https://api.secrets.test", "https://API.secrets.test:443/"])
def test_agent_and_console_origins_must_be_separate(tmp_path: Path, console: str):
    env = configured(tmp_path)
    env[PREFIX + "CONSOLE_ORIGIN"] = console
    with pytest.raises(ConfigurationError) as caught:
        load_environment(env)
    assert PREFIX + "CONSOLE_ORIGIN" in str(caught.value)
