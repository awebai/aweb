"""The accepted OCI process argv is complete and independently locally pinned."""

import pytest
from test_jobs import RUNNER, config_file, definition, prepared

from aweb_secrets_runner.errors import Refused
from aweb_secrets_runner.jobs import RunnerConfig, job_digest


def oci(tmp_path, argv):
    body = definition(tmp_path)
    body.update(
        kind="oci",
        exec=None,
        oci={"image": "fixture/image@sha256:" + "a" * 64, "read_only_paths": []},
        argv=argv,
    )
    # Keep the parameter used independently so an empty argv used to be valid.
    body["env"]["NAME"] = {"$param": "name"}
    return body


@pytest.mark.parametrize(
    "argv", [[], ["relative"], [""], ["/bin/../tool"], [{"$param": "name", "slot": "option_value"}]]
)
def test_oci_requires_a_fixed_absolute_executable_at_zero(tmp_path, argv):
    with pytest.raises(Refused, match="job_invalid"):
        RunnerConfig.load(config_file(tmp_path, oci(tmp_path, argv)))


def test_complete_absolute_oci_argv_stays_pinned_but_does_not_enable_runtime(tmp_path):
    body = oci(tmp_path, ["/bin/tool", "--", {"$param": "name", "slot": "positional"}])
    config = RunnerConfig.load(config_file(tmp_path, body))
    digest = job_digest(body)
    with pytest.raises(Refused, match="runner_runtime_unavailable"):
        config.doctor(RUNNER)
    with pytest.raises(Refused, match="runner_runtime_unavailable"):
        prepared(config, body)
    assert job_digest(body) == digest


def test_exec_keeps_prepend_semantics_including_empty_argument_template(tmp_path):
    body = definition(tmp_path)
    body["argv"] = []
    body["env"]["NAME"] = {"$param": "name"}
    config = RunnerConfig.load(config_file(tmp_path, body))
    assert prepared(config, body).argv == (body["exec"]["path"],)
