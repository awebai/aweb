"""Validate and freeze public inputs without requesting credential plaintext."""

import pytest
from test_jobs import RUNNER, config_file, definition

from aweb_secrets_runner.errors import Refused
from aweb_secrets_runner.jobs import RunnerConfig, job_digest
from aweb_secrets_runner.oci_platform import require_runc_environment


def oci_definition(tmp_path):
    body = definition(tmp_path)
    body.update(
        kind="oci",
        exec=None,
        oci={"image": "fixture/image@sha256:" + "a" * 64, "read_only_paths": []},
    )
    body["argv"].insert(0, "/bin/tool")
    body["env"]["HOME"] = "/pinned-home"
    return body


def inputs(tmp_path, body, *, params=None, refs=("db",), **overrides):
    config = RunnerConfig.load(config_file(tmp_path, body))
    kwargs = dict(
        job_id="fixture",
        digest=job_digest(body),
        runner_id=RUNNER,
        params={"name": "orders"} if params is None else params,
        credential_refs=refs,
    )
    kwargs.update(overrides)
    return config.inputs(**kwargs)


def test_oci_public_inputs_do_not_require_keys_or_plaintext(tmp_path):
    body = oci_definition(tmp_path)
    selected = inputs(tmp_path, body)
    assert selected.argv == ("/bin/tool", "--", "orders")
    assert selected.environment == {"HOME": "/pinned-home", "PASSWORD": None}
    assert selected.definition == body
    require_runc_environment(selected.environment)


def test_frozen_parameter_home_is_preserved_and_detached_from_mutable_callers(tmp_path):
    body = oci_definition(tmp_path)
    body["env"]["HOME"] = {"$param": "name"}
    params = {"name": "pinned-home"}
    selected = inputs(tmp_path, body, params=params)
    params["name"] = "changed-after-check"
    selected.definition["env"]["HOME"] = "changed-copy"
    selected.environment["HOME"] = "changed-copy"
    assert selected.argv == ("/bin/tool", "--", "pinned-home")
    assert selected.environment == {"HOME": "pinned-home", "PASSWORD": None}
    assert selected.params == {"name": "pinned-home"}
    require_runc_environment(selected.environment)


@pytest.mark.parametrize("form", ["absent", "empty", "empty-parameter", "credential"])
def test_unknown_or_empty_home_refuses_before_any_value_can_be_requested(tmp_path, form):
    body = oci_definition(tmp_path)
    params = {"name": "orders"}
    if form == "absent":
        del body["env"]["HOME"]
    elif form == "empty":
        body["env"]["HOME"] = ""
    elif form == "empty-parameter":
        body["env"]["HOME"] = {"$param": "name"}
        params["name"] = ""
    else:
        body["env"]["HOME"] = {"$credential": "db", "field": "password"}
    selected = inputs(tmp_path, body, params=params)
    with pytest.raises(Refused, match="oci_environment_unsupported"):
        require_runc_environment(selected.environment)


def test_env_parameter_is_not_a_positional_command_flag(tmp_path):
    body = oci_definition(tmp_path)
    body["argv"] = ["/bin/tool"]
    body["env"]["HOME"] = {"$param": "name"}
    selected = inputs(tmp_path, body, params={"name": "-env-value"})
    assert selected.argv == ("/bin/tool",)
    assert selected.environment["HOME"] == "-env-value"
    require_runc_environment(selected.environment)


@pytest.mark.parametrize("defect", ["digest", "runner", "params", "missing-ref", "foreign-ref"])
def test_public_input_phase_keeps_live_local_pin_parameter_and_slot_checks(tmp_path, defect):
    body = oci_definition(tmp_path)
    overrides = {}
    expected = "job_not_allowed"
    if defect == "digest":
        overrides["digest"] = "0" * 64
    elif defect == "runner":
        overrides["runner_id"] = "rnr_" + "b" * 22
    elif defect == "params":
        overrides["params"] = {"name": "-flag"}
        expected = "params_invalid"
    else:
        overrides["refs"] = () if defect == "missing-ref" else ("another-slot",)
        expected = "credential_invalid"
    with pytest.raises(Refused, match=expected):
        inputs(tmp_path, body, **overrides)


def test_exec_inputs_keep_the_effective_executable_and_argument_boundary(tmp_path):
    body = definition(tmp_path)
    selected = inputs(tmp_path, body)
    assert selected.argv == (body["exec"]["path"], "--", "orders")
    assert selected.environment == {"PASSWORD": None}


def test_config_change_cannot_be_hidden_by_an_earlier_public_input_snapshot(tmp_path):
    body = oci_definition(tmp_path)
    config = RunnerConfig.load(config_file(tmp_path, body))
    kwargs = dict(
        job_id="fixture",
        digest=job_digest(body),
        runner_id=RUNNER,
        params={"name": "orders"},
        credential_refs=("db",),
    )
    snapshot = config.inputs(**kwargs)
    body["timeout_s"] += 1
    config_file(tmp_path, body)
    assert snapshot.definition["timeout_s"] + 1 == body["timeout_s"]
    with pytest.raises(Refused, match="config_changed"):
        config.inputs(**kwargs)
