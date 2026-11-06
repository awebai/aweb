"""Operator runtime settings share the protected, reread local configuration."""

import json
import sys
from pathlib import Path

import pytest
from test_jobs import config_file, definition

from aweb_secrets_runner.errors import Refused
from aweb_secrets_runner.jobs import RunnerConfig
from aweb_secrets_runner.protocol import canonical


def runtime_spec(tmp_path):
    pin = {"path": str(Path(sys.executable)), "sha256": "a" * 64}
    return {
        "kind": "runc",
        "engine": dict(pin),
        "unpacker": dict(pin),
        "supervisor": dict(pin),
        "images": str(tmp_path / "images"),
        "workspace": str(tmp_path / "memory"),
    }


def configured(tmp_path, spec):
    path = config_file(tmp_path, definition(tmp_path))
    value = json.loads(path.read_bytes())
    value["runtime"] = spec
    path.write_bytes(canonical(value))
    return path


def test_runtime_is_explicit_and_detached_from_caller_mutation(tmp_path):
    spec = runtime_spec(tmp_path)
    path = configured(tmp_path, spec)
    config = RunnerConfig.load(path)
    runtime = config.runtime()
    assert runtime.engine.path == Path(sys.executable)
    assert runtime.engine.sha256 == "a" * 64
    assert runtime.supervisor.path == Path(sys.executable)
    assert runtime.images == tmp_path / "images"
    assert runtime.workspace == tmp_path / "memory"
    spec["engine"]["sha256"] = "b" * 64
    assert config.runtime() == runtime


def test_exec_configuration_does_not_invent_an_oci_runtime(tmp_path):
    path = config_file(tmp_path, definition(tmp_path))
    assert RunnerConfig.load(path).runtime() is None


@pytest.mark.parametrize(
    "defect",
    [
        "null",
        "kind",
        "extra",
        "missing",
        "relative",
        "traversal",
        "nul",
        "pin-extra",
        "pin-hash",
        "pin-path",
        "pin-missing",
    ],
)
def test_invalid_runtime_configuration_refuses_at_load(tmp_path, defect):
    spec = runtime_spec(tmp_path)
    if defect == "null":
        spec = None
    elif defect == "kind":
        spec["kind"] = "daemon-fallback"
    elif defect == "extra":
        spec["disk_fallback"] = True
    elif defect == "missing":
        del spec["workspace"]
    elif defect == "relative":
        spec["images"] = "relative"
    elif defect == "traversal":
        spec["workspace"] = "/private/../disk"
    elif defect == "nul":
        spec["workspace"] = "/private\0memory"
    elif defect == "pin-extra":
        spec["engine"]["args"] = ["--fallback"]
    elif defect == "pin-hash":
        spec["engine"]["sha256"] = "not-a-hash"
    elif defect == "pin-path":
        spec["engine"]["path"] = False
    else:
        del spec["supervisor"]
    with pytest.raises(Refused, match="runtime_config_invalid"):
        RunnerConfig.load(configured(tmp_path, spec))


def test_runtime_rereads_protected_config_and_refuses_changes(tmp_path):
    path = configured(tmp_path, runtime_spec(tmp_path))
    config = RunnerConfig.load(path)
    document = json.loads(path.read_bytes())
    document["runtime"]["workspace"] += "-changed"
    path.write_bytes(canonical(document))
    with pytest.raises(Refused, match="config_changed"):
        config.runtime()
