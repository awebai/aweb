"""Run replay equality binds every caller-controlled effect and the original pin."""

import copy

import pytest

from aweb_secrets.admission import AdmissionRefused
from aweb_secrets.run_input import RunInput

RUNNER = "rnr_" + "r" * 22
PIN = "a" * 64


def body():
    return {
        "request_id": "nightly-17",
        "runner": RUNNER,
        "params": {"database": "orders"},
        "reason": "nightly backup",
    }


@pytest.mark.parametrize(
    "field", ["job", "pin", "request_id", "runner", "params", "reason", "secret"]
)
def test_changed_effect_conflicts_with_original_run_equality(field):
    job, pin, submitted = "backup", PIN, body()
    original = RunInput.from_body(job, submitted, job_digest=pin)
    if field == "job":
        job = "restore"
    elif field == "pin":
        pin = "b" * 64
    elif field == "runner":
        submitted[field] = "rnr_" + "s" * 22
    elif field == "params":
        submitted[field]["database"] = "customers"
    else:
        submitted[field] = "selected-child" if field == "secret" else "changed"
    assert (
        RunInput.from_body(job, submitted, job_digest=pin).request_sha256 != original.request_sha256
    )


def test_defaults_and_json_key_order_preserve_logical_equality():
    minimal = {"request_id": "nightly-17", "runner": RUNNER}
    explicit = {**minimal, "params": {}, "reason": ""}
    assert (
        RunInput.from_body("backup", minimal, job_digest=PIN).request_sha256
        == RunInput.from_body("backup", explicit, job_digest=PIN).request_sha256
    )
    first = {**minimal, "params": {"database": "orders", "limit": 1}}
    second = {**minimal, "params": {"limit": 1, "database": "orders"}}
    assert (
        RunInput.from_body("backup", first, job_digest=PIN).request_sha256
        == RunInput.from_body("backup", second, job_digest=PIN).request_sha256
    )


def test_normalized_params_are_detached_from_caller_and_returned_views():
    submitted = body()
    submitted["params"]["nested"] = [1, {"kind": "original"}]
    expected = copy.deepcopy(submitted["params"])
    frozen = RunInput.from_body("backup", submitted, job_digest=PIN)
    submitted["params"]["nested"][1]["kind"] = "changed"
    exposed = frozen.params
    exposed["nested"].clear()
    assert frozen.params == expected
    assert frozen.secret_ref is None


@pytest.mark.parametrize(
    "change",
    [
        {"request_id": ""},
        {"request_id": False},
        {"runner": "https://runner.example"},
        {"runner": []},
        {"params": []},
        {"params": {"value": 1.1}},
        {"params": {"value": float("nan")}},
        {"params": {"value": "\ud800"}},
        {"secret": None},
        {"secret": ""},
        {"secret": "../child"},
        {"reason": False},
        {"reason": "x" * 1025},
        {"value": "caller-credential"},
        {"job": "replacement"},
        {"source_version": 7},
        {"grant_id": "grt_untrusted"},
        {"slot": 0},
        {"approval_id": "apv_untrusted"},
        {"job_digest": "b" * 64},
    ],
)
def test_authority_overrides_and_invalid_values_refuse_without_echo(change):
    with pytest.raises(AdmissionRefused) as refused:
        RunInput.from_body("backup", {**body(), **change}, job_digest=PIN)
    assert str(refused.value) == "params_invalid"
