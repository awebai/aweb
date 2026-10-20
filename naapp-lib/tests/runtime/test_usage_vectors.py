"""The frozen usage vectors (docs/app-usage.md)."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from awid.signing import canonical_json_bytes
from nacl.signing import SigningKey

from aweb_naapp.runtime.usage import (
    UsageReportRefused,
    app_usage_credential,
    check_lifecycle_report,
    report_sha256,
    validate_report,
)

AWEB_ROOT = Path(__file__).resolve().parents[3]
REPORTS = json.loads((AWEB_ROOT / "docs" / "vectors" / "usage-report-v1.json").read_text())
CREDENTIAL = json.loads(
    (AWEB_ROOT / "docs" / "vectors" / "app-usage-credential-v1.json").read_text()
)


@pytest.mark.parametrize("case", REPORTS["valid"], ids=lambda case: case["name"])
def test_valid_batches(case):
    validate_report(case["batch"])
    assert report_sha256(case["batch"]) == case["report_sha256"]


@pytest.mark.parametrize("case", REPORTS["refusals"], ids=lambda case: case["name"])
def test_refused_batches(case):
    batch = json.loads(case["batch_json"]) if "batch_json" in case else case["batch"]
    with pytest.raises(UsageReportRefused) as refused:
        validate_report(batch)
    assert refused.value.code == case["expect"]


@pytest.mark.parametrize(
    "case",
    [case for case in REPORTS["lifecycle_grant"] if case["checked_by"] == "batch"],
    ids=lambda case: case["name"],
)
def test_lifecycle_batch_rules(case):
    validate_report(case["report"])
    if case["result"]["status"] == 201:
        check_lifecycle_report(case["report"])
        return
    with pytest.raises(UsageReportRefused) as refused:
        check_lifecycle_report(case["report"])
    assert refused.value.code == case["result"]["code"]


def test_collector_reports_are_valid_batches():
    for step in REPORTS["collector"]:
        validate_report(step["report"])
        if "report_sha256" in step["result"]:
            assert report_sha256(step["report"]) == step["result"]["report_sha256"]


def test_app_usage_credential():
    request = CREDENTIAL["request"]
    payload = CREDENTIAL["payload"]
    headers = app_usage_credential(
        signing_key=SigningKey(bytes.fromhex(CREDENTIAL["keys"]["app"]["seed_hex"])),
        aud=payload["aud"],
        method=request["method"],
        path=request["path"],
        team_id=payload["team_id"],
        app_id=payload["app_id"],
        kid=payload["kid"],
        installation_id=payload["installation_id"],
        installation_generation=payload["installation_generation"],
        body=request["body"].encode("utf-8"),
        timestamp=payload["timestamp"],
    )
    assert headers == CREDENTIAL["headers"]
    signed = base64.urlsafe_b64decode(headers["X-AWEB-Signed-Payload"] + "==")
    assert signed == CREDENTIAL["canonical_payload"].encode("utf-8")


def test_the_largest_valid_batch_fits_under_the_body_limit():
    """§3's field bounds keep every valid batch's canonical JSON under 1 MiB, so
    the collector's raw-body limit never refuses a valid batch."""
    long_id = "a" * 128
    entries = [
        {
            "seq": seq,
            "occurred_at": "2026-10-20T10:00:00Z",
            "operation_id": long_id,
            "attempt_id": long_id,
            "source": "background",
            "outcome": "refused_validation",
            "deltas": {metric: 2**53 - 1 for metric in REPORTS["counters"]},
        }
        for seq in range(1, REPORTS["max_entries"] + 1)
    ]
    batch = {
        "format": "aweb.usage/1",
        "team_id": "backend:" + "a" * 60 + ".com",
        "app_id": "a" * 128,
        "installation_id": "a" * 128,
        "installation_generation": 2**53 - 1,
        "reporter": "r" * 64,
        "epoch": 2**53 - 1,
        "report_id": long_id,
        "first_seq": 1,
        "last_seq": REPORTS["max_entries"],
        "metric_version": 1,
        "entries": entries,
        "inventory": {
            "at_seq": REPORTS["max_entries"],
            **{g: 2**53 - 1 for g in REPORTS["gauges"]},
        },
    }
    validate_report(batch)
    assert len(canonical_json_bytes(batch)) < REPORTS["max_bytes"]
