"""Runner output goes through the existing redaction/detection/projection path."""

import base64
import json
import secrets

import pytest

from aweb_secrets.jobs import JobDefinition
from aweb_secrets.redaction import KnownValues
from aweb_secrets.runner_results import RunnerResultInvalid, process_runner_result
from tests.test_jobs import after


def job(*, maximum=4096, projection=None):
    body = after()
    body["output"] = {
        "max_bytes": maximum,
        "projection": projection or ["/exit_code", "/stdout", "/stderr"],
    }
    return JobDefinition.from_after(body)


def report(**changes):
    return json.dumps(
        {
            "exit_code": 0,
            "stdout": "done",
            "stderr": "",
            "truncated": False,
            "result_withheld": False,
            "redaction_count": 0,
            **changes,
        }
    ).encode()


def test_result_returns_only_the_pinned_projection():
    result = process_runner_result(
        report(stdout="unprojected output"),
        job=job(projection=["/exit_code"]),
        known=KnownValues(),
    )
    assert json.loads(result.body) == {"/exit_code": 0}
    assert not result.result_withheld and not result.truncated


@pytest.mark.parametrize("encode", [lambda s: s, lambda s: base64.b64encode(s.encode()).decode()])
def test_server_redacts_even_when_runner_reports_no_redactions(encode):
    value = secrets.token_urlsafe(32)
    known = KnownValues()
    known.add("job-password", value)
    result = process_runner_result(report(stdout=encode(value)), job=job(), known=known)
    assert value.encode() not in result.body
    assert encode(value).encode() not in result.body
    assert b"[REDACTED:job-password]" in result.body
    assert result.redaction_count > 0 and result.runner_redaction_count == 0
    assert value not in repr(result)


def test_credential_shape_in_a_stream_is_detected_before_json_framing():
    value = secrets.token_urlsafe(32)
    result = process_runner_result(
        report(stdout=json.dumps({"access_token": value})), job=job(), known=KnownValues()
    )
    assert result.result_withheld and result.body is None
    assert result.withheld_reason == "credential_shaped"


def test_local_withholding_and_counts_are_preserved_as_metadata():
    result = process_runner_result(
        report(stdout="", stderr="", result_withheld=True, redaction_count=3, truncated=True),
        job=job(),
        known=KnownValues(),
    )
    assert result.body is None and result.result_withheld
    assert result.withheld_reason == "runner_withheld"
    assert result.truncated and result.runner_redaction_count == 3


def test_missing_original_release_context_withholds_even_a_new_live_item_value():
    result = process_runner_result(report(stdout=secrets.token_urlsafe(32)), job=job(), known=None)
    assert result.body is None and result.result_withheld
    assert result.withheld_reason == "release_context_unavailable"


@pytest.mark.parametrize("known", [None, KnownValues()])
@pytest.mark.parametrize("local_withheld", [False, True])
def test_local_observations_survive_server_withholding(known, local_withheld):
    result = process_runner_result(
        report(
            exit_code=23,
            stdout="",
            result_withheld=local_withheld,
            truncated=True,
            redaction_count=7,
        ),
        job=job(projection=["/stdout"]),
        known=known,
    )
    assert result.exit_code == 23
    assert result.runner_result_withheld is local_withheld
    assert result.runner_truncated is True
    assert result.runner_redaction_count == 7
    if known is None or local_withheld:
        assert result.body is None and result.result_withheld
    else:
        assert json.loads(result.body) == {"/stdout": ""}
        assert not result.result_withheld


@pytest.mark.parametrize("exit_code", [-(2**53 - 1), 2**53 - 1])
def test_exit_status_is_metadata_even_when_projection_omits_it(exit_code):
    result = process_runner_result(
        report(exit_code=exit_code), job=job(projection=["/stdout"]), known=KnownValues()
    )
    assert result.exit_code == exit_code
    assert json.loads(result.body) == {"/stdout": "done"}
    assert not result.runner_truncated and not result.runner_result_withheld


def test_server_shape_withhold_does_not_claim_runner_withheld_output():
    result = process_runner_result(
        report(exit_code=-9, stdout=json.dumps({"access_token": secrets.token_urlsafe(32)})),
        job=job(),
        known=KnownValues(),
    )
    assert result.result_withheld and result.body is None
    assert result.exit_code == -9
    assert not result.runner_result_withheld and not result.runner_truncated


def test_truncated_stream_tail_is_redacted_and_complete_exit_projection_survives():
    value = secrets.token_urlsafe(32)
    known = KnownValues()
    known.add("job-password", value)
    result = process_runner_result(
        report(stdout=value[:12], truncated=True), job=job(), known=known
    )
    assert value[:12].encode() not in result.body
    assert json.loads(result.body)["/exit_code"] == 0
    assert result.truncated and result.redaction_count > 0


def test_output_limit_counts_combined_utf8_bytes_not_json_framing():
    result = process_runner_result(
        report(stdout="é", stderr="xy"), job=job(maximum=4), known=KnownValues()
    )
    assert json.loads(result.body)["/stdout"] == "é"
    with pytest.raises(RunnerResultInvalid):
        process_runner_result(
            report(stdout="é", stderr="xyz"), job=job(maximum=4), known=KnownValues()
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"exit_code": True},
        {"exit_code": 1.0},
        {"exit_code": 2**53},
        {"stdout": None},
        {"stdout": "\ud800"},
        {"truncated": 1},
        {"result_withheld": 0},
        {"redaction_count": True},
        {"redaction_count": -1},
        {"redaction_count": 2**53},
        {"result_withheld": True},
        {"extra": "refused"},
    ],
)
def test_bad_reports_have_a_constant_value_free_refusal(changes):
    with pytest.raises(RunnerResultInvalid) as refused:
        process_runner_result(report(**changes), job=job(), known=KnownValues())
    assert str(refused.value) == "runner_result_invalid"


def test_duplicate_fields_and_oversized_raw_frames_refuse():
    for raw in [b'{"exit_code":0,"exit_code":1}', b" " * 4000]:
        with pytest.raises(RunnerResultInvalid):
            process_runner_result(raw, job=job(maximum=4), known=KnownValues())
