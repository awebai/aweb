"""Real disposable Oracle Free and the actual pinned daemonless OCI execution."""

import json
import time

import pytest

from lab import docker, oracle_lab


@pytest.fixture(scope="module")
def lab():
    with oracle_lab() as running:
        yield running


@pytest.mark.parametrize("dataset,counts", [("orders", (4, 1, 1)), ("inventory", (1, 0, 0))])
def test_real_oci_job_returns_only_the_fixed_report(lab, dataset, counts):
    report = lab.execute({"dataset": dataset, "week_start": "2026-11-02"})
    assert report["exit_code"] == 0 and not report["result_withheld"]
    assert len(report["stdout"].encode()) <= 1024 and report["stderr"] == ""
    result = json.loads(report["stdout"])
    assert result == {
        "v": 1,
        "report": "weekly-data-quality",
        "dataset": dataset,
        "week_start": "2026-11-02",
        "week_end_exclusive": "2026-11-09",
        "rows_total": counts[0],
        "missing_required": counts[1],
        "invalid_status": counts[2],
    }
    if lab.password in json.dumps(report) or lab.private_payload in json.dumps(report):
        raise AssertionError("private lab data reached report")


def test_disallowed_parameter_is_refused_without_database_effect(lab):
    before = lab.count()
    refused = lab.execute({"dataset": "orders' OR 1=1 --", "week_start": "2026-11-02"})
    assert refused == {"refused": "params_invalid"}
    assert lab.count() == before
    # Calendar validation belongs to the fixed report as well as typed job input.
    report = lab.execute({"dataset": "orders", "week_start": "2026-02-30"})
    assert report["exit_code"] != 0 and report["stdout"] == ""
    assert lab.count() == before


def test_database_account_refuses_real_writes_without_read_only_transaction_mask(lab):
    result = lab.permissions()
    assert result["before"] == result["after"] == 7
    assert result["created"] == 0
    # Oracle must refuse valid DML, DDL and row locking on permission grounds.
    assert result["errors"] == [41900, 41900, 41900, 28194, 41900]


def test_real_database_outage_is_bounded_and_returns_no_data(lab):
    docker("pause", lab.database)
    try:
        started = time.monotonic()
        report = lab.execute({"dataset": "orders", "week_start": "2026-11-02"})
        assert time.monotonic() - started < 30
        assert report["exit_code"] != 0 and report["stdout"] == ""
        assert report["stderr"] in {"report_unavailable\n", "report_deadline_exceeded\n"}
        assert not report["result_withheld"]
    finally:
        docker("unpause", lab.database)
