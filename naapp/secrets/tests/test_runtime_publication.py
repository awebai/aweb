"""S19 publishes a private snapshot without mutating hosted controller outputs."""

import json
import secrets
import stat

import pytest
from release_environment import ConfigurationError, load_environment
from runtime_publication import publish_runtime

from tests.test_release_environment import PREFIX, configured

HOSTED = {
    PREFIX + key
    for key in (
        "TEAM_ID",
        "MCP_URL",
        "AGENT_A_ID",
        "AGENT_B_ID",
        "AGENT_A_MCP_TOKEN_FILE",
        "AGENT_B_MCP_TOKEN_FILE",
    )
}


def inputs(tmp_path):
    environment = configured(tmp_path)
    controller = tmp_path / "hosted"
    controller.mkdir(mode=0o700)
    hosted = controller / "runtime.json"
    hosted.write_text(json.dumps({k: v for k, v in environment.items() if k in HOSTED}))
    hosted.chmod(0o600)
    local = {k: v for k, v in environment.items() if k not in HOSTED}
    return environment, hosted, local


def test_snapshot_is_explicit_private_and_removed_without_touching_controller(tmp_path):
    environment, hosted, local = inputs(tmp_path)
    original = hosted.read_bytes()
    directory = tmp_path / "combined"
    with publish_runtime(hosted_runtime=hosted, local=local, directory=directory) as path:
        assert path.is_absolute() and path.parent == directory
        assert path != hosted
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
        mapping = json.loads(path.read_text())
        assert dict(load_environment(mapping)) == environment
        for name in (PREFIX + "AGENT_A_MCP_TOKEN_FILE", PREFIX + "AGENT_B_MCP_TOKEN_FILE"):
            assert mapping[name] == environment[name]
        assert sorted(p.name for p in directory.iterdir()) == ["runtime.json"]
    assert not path.exists()
    assert hosted.read_bytes() == original


@pytest.mark.parametrize("problem", ["unknown", "conflict", "invalid-type", "missing", "duplicate"])
def test_invalid_inputs_refuse_by_name_without_a_partial_publication(tmp_path, problem):
    _, hosted, local = inputs(tmp_path)
    marker = secrets.token_urlsafe(32)
    name = PREFIX + "TEAM_ID"
    if problem == "unknown":
        name = PREFIX + "CLOUD_OWNER_LOGIN_FILE"
        local[name] = marker
    elif problem == "conflict":
        local[name] = marker
    elif problem == "invalid-type":
        mapping = json.loads(hosted.read_text())
        mapping[name] = {"private": marker}
        hosted.write_text(json.dumps(mapping))
    elif problem == "missing":
        hosted.unlink()
    else:
        hosted.write_text('{"' + name + '":"' + marker + '","' + name + '":"other"}')
    directory = tmp_path / "combined"
    with pytest.raises(ConfigurationError) as error:
        with publish_runtime(hosted_runtime=hosted, local=local, directory=directory):
            pytest.fail("invalid runtime must never be published")
    assert marker not in str(error.value)
    if problem != "missing":
        assert name in str(error.value)
    assert not (directory / "runtime.json").exists()


def test_teardown_on_failure_and_no_reuse_after_hosted_withdrawal(tmp_path):
    _, hosted, local = inputs(tmp_path)
    directory = tmp_path / "combined"
    with pytest.raises(RuntimeError):
        with publish_runtime(hosted_runtime=hosted, local=local, directory=directory) as path:
            raise RuntimeError("startup_failed")
    assert not path.exists()
    hosted.unlink()
    with pytest.raises(ConfigurationError):
        with publish_runtime(hosted_runtime=hosted, local=local, directory=directory):
            pytest.fail("a withdrawn hosted runtime must not be cached")
    assert not path.exists()


def test_existing_publication_is_not_adopted_or_removed(tmp_path):
    _, hosted, local = inputs(tmp_path)
    directory = tmp_path / "combined"
    directory.mkdir(mode=0o700)
    prior = directory / "runtime.json"
    prior.write_text("existing")
    with pytest.raises(ConfigurationError):
        with publish_runtime(hosted_runtime=hosted, local=local, directory=directory):
            pytest.fail("another publication must not be overwritten")
    assert prior.read_text() == "existing"
