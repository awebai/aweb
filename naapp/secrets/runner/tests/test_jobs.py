import copy
import hashlib
import os

import pytest
from aweb_secrets_values import encode_value

from aweb_secrets_runner.jobs import RunnerConfig, job_digest
from aweb_secrets_runner.protocol import Refused, canonical

RUNNER = "rnr_Unqp9DFTnajhUdVDTR1eYQ"


def definition(tmp_path):
    program = tmp_path / "program"
    program.write_bytes(b"fixture-executable")
    program.chmod(0o700)
    return {
        "v": 1,
        "job_id": "fixture",
        "runner_ids": [RUNNER],
        "kind": "exec",
        "exec": {
            "path": str(program),
            "sha256": hashlib.sha256(program.read_bytes()).hexdigest(),
            "files": [],
        },
        "oci": None,
        "argv": ["--", {"$param": "name", "slot": "positional"}],
        "env": {"PASSWORD": {"$credential": "db", "field": "password"}},
        "cwd": str(tmp_path),
        "timeout_s": 5,
        "output": {"max_bytes": 1024, "projection": ["/exit_code", "/stdout"]},
        "params": {"name": {"schema": {"type": "string", "maxLength": 20}, "charset": None}},
        "credentials": [{"secret_ref": "db", "delivery": "durable", "mint": None}],
        "allow_durable": True,
    }


def config_file(tmp_path, body):
    path = tmp_path / "runner.json"
    path.write_bytes(
        canonical(
            {
                "v": 1,
                "agent_uids": [os.geteuid() + 1],
                "jobs": {"fixture": {"digest": job_digest(body), "definition": body}},
            }
        )
    )
    return path


def prepared(config, body, params=None, credentials=None):
    return config.prepare(
        job_id="fixture",
        digest=job_digest(body),
        runner_id=RUNNER,
        params={"name": "orders"} if params is None else params,
        credentials=[encode_value("basic", {"username": "", "password": "fixture-password"})]
        if credentials is None
        else credentials,
    )


def test_local_pin_and_whole_mapping_produce_literal_argv_and_empty_base_env(tmp_path):
    body = definition(tmp_path)
    config = RunnerConfig.load(config_file(tmp_path, body))
    run = prepared(config, body)
    assert run.argv == (body["exec"]["path"], "--", "orders")
    assert run.env == {"PASSWORD": "fixture-password"}
    assert run.timeout_s == 5 and run.output_max_bytes == 1024
    assert "fixture-password" not in repr(run)
    assert "fixture-password" not in repr(run.known)


def test_digest_is_domain_separated_and_excludes_only_v(tmp_path):
    body = definition(tmp_path)
    expected = hashlib.sha256(
        b"aweb.secrets.job/1\n" + canonical({k: v for k, v in body.items() if k != "v"})
    ).hexdigest()
    assert job_digest(body) == expected
    changed = copy.deepcopy(body)
    changed["env"]["PASSWORD"]["field"] = "username"
    assert job_digest(changed) != expected


@pytest.mark.parametrize("change", ["unlisted", "wrong-digest", "other-runner", "changed-file"])
def test_service_assignment_cannot_expand_the_local_pin(tmp_path, change):
    body = definition(tmp_path)
    config = RunnerConfig.load(config_file(tmp_path, body))
    kwargs = dict(
        job_id="fixture",
        digest=job_digest(body),
        runner_id=RUNNER,
        params={"name": "orders"},
        credentials=[encode_value("basic", {"username": "", "password": "fixture"})],
    )
    if change == "unlisted":
        kwargs["job_id"] = "other"
    elif change == "wrong-digest":
        kwargs["digest"] = "0" * 64
    elif change == "other-runner":
        kwargs["runner_id"] = "rnr_" + "a" * 22
    else:
        (tmp_path / "program").write_bytes(b"changed")
    with pytest.raises(Refused):
        config.prepare(**kwargs)


@pytest.mark.parametrize(
    "params", [{"name": "-flag"}, {"name": "x" * 21}, {"name": 42}, {"name": "a\0b"}, {}]
)
def test_parameter_refusals(tmp_path, params):
    body = definition(tmp_path)
    config = RunnerConfig.load(config_file(tmp_path, body))
    with pytest.raises(Refused, match="params_invalid"):
        prepared(config, body, params=params)


def test_option_value_accepts_a_leading_dash_as_one_argument(tmp_path):
    body = definition(tmp_path)
    body["argv"] = ["--name", {"$param": "name", "slot": "option_value"}]
    config = RunnerConfig.load(config_file(tmp_path, body))
    assert prepared(config, body, params={"name": "-x"}).argv[-2:] == ("--name", "-x")


@pytest.mark.parametrize(
    "name",
    [
        "LD_PRELOAD",
        "PATH",
        "GIT_SSH_COMMAND",
        "NODE_OPTIONS",
        "NODE_PATH",
        "https_proxy",
        "BASH_ENV",
    ],
)
def test_dangerous_environment_targets_refuse_even_when_fixed(tmp_path, name):
    body = definition(tmp_path)
    body["env"][name] = "fixed"
    with pytest.raises(Refused, match="job_invalid"):
        RunnerConfig.load(config_file(tmp_path, body))


@pytest.mark.parametrize("defect", ["missing", "extra", "nul", "count", "duplicate"])
def test_entire_credential_mapping_and_selected_field_are_checked(tmp_path, defect):
    body = definition(tmp_path)
    config = RunnerConfig.load(config_file(tmp_path, body))
    raw = b'{"username":"","password":"fixture"}'
    if defect == "missing":
        raw = b'{"username":""}'
    elif defect == "extra":
        raw = b'{"username":"","password":"fixture","value":"extra"}'
    elif defect == "nul":
        raw = encode_value("basic", {"username": "", "password": "a\0b"})
    elif defect == "duplicate":
        raw = b'{"username":"","password":"one","password":"two"}'
    with pytest.raises(Refused, match="credential_invalid"):
        prepared(config, body, credentials=[] if defect == "count" else [raw])


def test_missing_optional_selected_aws_field_is_not_empty_fallback(tmp_path):
    body = definition(tmp_path)
    body["env"]["PASSWORD"]["field"] = "session_token"
    config = RunnerConfig.load(config_file(tmp_path, body))
    with pytest.raises(Refused, match="credential_invalid"):
        prepared(
            config,
            body,
            credentials=[
                encode_value(
                    "aws-sigv4", {"access_key_id": "fixture", "secret_access_key": "fixture"}
                )
            ],
        )


def test_configuration_checks_real_uid_before_work(tmp_path):
    body = definition(tmp_path)
    path = config_file(tmp_path, body)
    raw = path.read_bytes().replace(str(os.geteuid() + 1).encode(), str(os.geteuid()).encode(), 1)
    path.write_bytes(raw)
    with pytest.raises(Refused, match="runner_user_unsafe"):
        RunnerConfig.load(path)


@pytest.mark.parametrize(
    "kind,fields,selected",
    [
        ("bearer", {"value": "fixture"}, "value"),
        ("header", {"value": "fixture"}, "value"),
        ("query", {"value": "fixture"}, "value"),
        ("basic", {"username": "", "password": "fixture"}, "username"),
        (
            "oauth2-client-credentials",
            {"client_id": "fixture-id", "client_secret": "fixture"},
            "client_secret",
        ),
        (
            "aws-sigv4",
            {
                "access_key_id": "fixture-id",
                "secret_access_key": "fixture",
                "session_token": "fixture-token",
            },
            "session_token",
        ),
    ],
)
def test_all_kinds_use_the_shared_whole_mapping_codec(tmp_path, kind, fields, selected):
    body = definition(tmp_path)
    body["env"]["PASSWORD"]["field"] = selected
    body["output"]["projection"] = ["/"]
    config = RunnerConfig.load(config_file(tmp_path, body))
    assert prepared(config, body, credentials=[encode_value(kind, fields)]).env == {
        "PASSWORD": fields[selected]
    }


def test_mixed_and_unknown_field_families_refuse_before_preparation(tmp_path):
    for selected in ("value", "unknown"):
        body = definition(tmp_path)
        body["env"]["OTHER"] = {"$credential": "db", "field": selected}
        with pytest.raises(Refused, match="job_invalid"):
            RunnerConfig.load(config_file(tmp_path, body))


def test_removing_a_local_pin_stops_a_previously_loaded_configuration(tmp_path):
    body = definition(tmp_path)
    path = config_file(tmp_path, body)
    config = RunnerConfig.load(path)
    path.write_bytes(canonical({"v": 1, "agent_uids": [os.geteuid() + 1], "jobs": {}}))
    with pytest.raises(Refused, match="config_changed"):
        prepared(config, body)
