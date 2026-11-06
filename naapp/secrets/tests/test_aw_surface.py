"""The real generic aw binary renders the served secrets manifest unchanged."""

import os
import subprocess
from pathlib import Path

import pytest
from aweb_naapp.manifest import fill_manifest
from aweb_naapp_testing import Member

from aweb_secrets.manifest import MANIFEST

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(scope="module")
def aw_binary(tmp_path_factory):
    binary = tmp_path_factory.mktemp("secrets-aw") / "aw"
    subprocess.run(
        ["go", "build", "-o", str(binary), "./cmd/aw"],
        cwd=ROOT / "cli/go",
        env={**os.environ, "GOMAXPROCS": "2"},
        check=True,
        capture_output=True,
        timeout=120,
    )
    return binary


@pytest.fixture
def invoke(aw_binary, tmp_path):
    directory = tmp_path / "config" / "plugins" / "secrets"
    directory.mkdir(parents=True)
    resolved = fill_manifest(
        MANIFEST,
        app_id="secrets",
        origin="https://secrets.example.com",
        did_keys={
            item["kid"]: Member(team_id="test:example.com").did_key for item in MANIFEST["app_keys"]
        },
    )
    (directory / "manifest.json").write_bytes(resolved)
    env = {
        **os.environ,
        "AW_HOME": str(tmp_path / "config"),
        "AWEB_IDENTITY_HOME": "",
        "AW_CONFIG_PATH": "",
        "AW_NO_UPDATE_CHECK": "1",
        "NO_COLOR": "1",
    }

    def call(*arguments):
        return subprocess.run(
            [str(aw_binary), "secrets", *arguments],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
            timeout=20,
        )

    return call


def test_only_agent_tools_are_rendered_and_surface_tools_are_refused(invoke):
    result = invoke("--help")
    assert result.returncode == 0, result.stderr
    verbs = {
        line.split()[0]
        for line in result.stdout.splitlines()
        if line.startswith("  ") and not line.strip().startswith("aw ")
    }
    assert verbs == {"list", "describe", "request", "run", "status", "cancel", "contain"}
    for verb in ("propose-change", "activity"):
        response = invoke(verb, "--help")
        assert response.returncode == 1
        assert "tool_context_denied" in response.stderr


def test_generic_flags_cover_named_open_and_runner_requests(invoke):
    for verb, expected in {
        "request": {
            "--secret",
            "--request_id",
            "--operation",
            "--params",
            "--method",
            "--url",
            "--headers",
            "--data",
            "--reason",
        },
        "run": {"--job", "--request_id", "--runner", "--params", "--reason"},
        "status": {"--ref"},
    }.items():
        result = invoke(verb, "--help")
        assert result.returncode == 0, result.stderr
        for flag in expected:
            assert flag in result.stdout
    assert "--request_id" not in invoke("list", "--help").stdout


@pytest.mark.parametrize("tool", ["get-value", "set-value", "export"])
def test_no_value_tool_can_be_invoked_or_rendered(invoke, tool):
    assert invoke("--help").returncode == 0
    assert invoke(tool, "--help").returncode == 1
