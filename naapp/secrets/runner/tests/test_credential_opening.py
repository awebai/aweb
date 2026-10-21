"""Real HPKE opening is deferred until the fixed-selector job is locally checked."""

import pytest
from aweb_secrets_values import encode_value
from runner_helpers import credential
from test_jobs import RUNNER, config_file, definition

from aweb_secrets_runner.errors import Refused
from aweb_secrets_runner.jobs import RunnerConfig, job_digest


def encrypted(ref, password, *, wrong_dispatch=False):
    return credential(
        ref,
        encode_value("basic", {"username": "", "password": password}),
        wrong_dispatch=wrong_dispatch,
    )


def prepare(config, body, credentials, **overrides):
    kwargs = dict(
        job_id="fixture",
        digest=job_digest(body),
        runner_id=RUNNER,
        params={"name": "orders"},
        credentials=credentials,
    )
    kwargs.update(overrides)
    return config.prepare(**kwargs)


@pytest.mark.parametrize("defect", ["local-pin", "runner", "params", "file"])
def test_failed_local_check_precedes_real_hpke_failure(tmp_path, defect):
    body = definition(tmp_path)
    config = RunnerConfig.load(config_file(tmp_path, body))
    ciphertext = encrypted("db", "fixture-password", wrong_dispatch=True)
    overrides = {}
    if defect == "local-pin":
        overrides["digest"] = "0" * 64
        expected = "job_not_allowed"
    elif defect == "runner":
        overrides["runner_id"] = "rnr_" + "b" * 22
        expected = "job_not_allowed"
    elif defect == "params":
        overrides["params"] = {"name": "-flag"}
        expected = "params_invalid"
    else:
        (tmp_path / "program").write_bytes(b"changed")
        expected = "file_pin_mismatch"
    with pytest.raises(Refused, match=expected):
        prepare(config, body, [ciphertext], **overrides)


def test_correct_pin_opens_dispatch_bound_mapping_and_wrong_dispatch_refuses(tmp_path):
    body = definition(tmp_path)
    config = RunnerConfig.load(config_file(tmp_path, body))
    assert prepare(config, body, [encrypted("db", "fixture-password")]).env == {
        "PASSWORD": "fixture-password"
    }
    with pytest.raises(Refused, match="credential_invalid"):
        prepare(config, body, [encrypted("db", "fixture-password", wrong_dispatch=True)])


def test_unavailable_oci_runtime_refuses_before_hpke_opening(tmp_path):
    body = definition(tmp_path)
    body["kind"] = "oci"
    body["exec"] = None
    body["oci"] = {"image": "fixture/image@sha256:" + "a" * 64, "read_only_paths": []}
    config = RunnerConfig.load(config_file(tmp_path, body))
    with pytest.raises(Refused, match="runner_runtime_unavailable"):
        prepare(config, body, [encrypted("db", "fixture-password", wrong_dispatch=True)])


@pytest.mark.parametrize("defect", ["swap", "substitution", "missing", "extra"])
def test_fixed_slot_labels_and_count_refuse_swaps_and_substitution(tmp_path, defect):
    body = definition(tmp_path)
    body["credentials"].append({"secret_ref": "other", "delivery": "durable", "mint": None})
    body["env"]["OTHER"] = {"$credential": "other", "field": "password"}
    config = RunnerConfig.load(config_file(tmp_path, body))
    credentials = [encrypted("db", "fixture-db"), encrypted("other", "fixture-other")]
    if defect == "swap":
        credentials.reverse()
    elif defect == "substitution":
        credentials[1] = encrypted("child-ref", "fixture-child")
    elif defect == "missing":
        credentials.pop()
    else:
        credentials.append(encrypted("third", "fixture-third"))
    with pytest.raises(Refused, match="credential_invalid"):
        prepare(config, body, credentials)
